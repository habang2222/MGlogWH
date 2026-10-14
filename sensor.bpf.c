// SPDX-License-Identifier: GPL-2.0
// Exec/ring scaffold adapted from libbpf/libbpf-bootstrap, Copyright (c) 2020 Facebook.
// Open entry/exit pairing adapted from iovisor/bcc libbpf-tools/opensnoop.bpf.c,
// Copyright (c) 2019 Facebook, Copyright (c) 2020 Netflix.
// MGlogWH changes: bounded capture, separate lanes, cgroup budgets and accounting.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "event.h"
#include "tenant.h"
#include "quarantine.h"
#include "rules.h"
char LICENSE[] SEC("license") = "GPL";

struct pending_open { char path[EQ_PATH]; __u32 flags, captured_len, quality; };
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} critical SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} quarantine SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} quarantine_control SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} general SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, EQ_TENANTS);
    __type(key, __u64);
    __type(value, struct eq_tenant_stats);
} tenants SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, EQ_STREAMS);
    __type(key, struct eq_quarantine_key);
    __type(value, struct eq_quarantine_stream);
} quarantine_streams SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct eq_quarantine_global);
} quarantine_global SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct pending_open);
} pending SEC(".maps");
/* Successful exec path capture is temporary and CPU-local; keeping it out of
 * the caller's 512-byte BPF stack allows the bounded rule evaluator to share
 * the same emit subprogram as openat. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pending_open);
} exec_scratch SEC(".maps");
/* Unsharded sequence per cgroup; only additive diagnostics use per-CPU storage. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} faults SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, EQ_RULES);
    __type(key, __u32);
    __type(value, struct eq_rule_stats);
} rule_stats SEC(".maps");
/* String alternatives are installed before any tracepoint is attached. The
 * NUL byte is included in exact keys; prefix keys stop before that byte. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, EQ_RULES * EQ_RULE_TOKENS * EQ_RULE_VALUES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct eq_rule_trie_key);
    __type(value, __u8);
} rule_strings SEC(".maps");
struct eq_rule_lookup_scratch {
    struct eq_rule_trie_key path, comm;
    volatile unsigned long long eval_stack;
    volatile unsigned eval_depth;
    unsigned long long busy;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct eq_rule_lookup_scratch);
} rule_lookup_scratch SEC(".maps");
const volatile __u32 bulk_rate = 500, bulk_burst = 1000;
const volatile struct eq_quarantine_config quarantine_config = {
    10000, 3000, 2000, 10000, 8, 100
};
const volatile struct eq_rule_program event_rules[EQ_RULES] = {};
const volatile __u32 rule_count = 0;
/* Avoid constructing an approximately 1 KiB map value on the BPF stack. */
const struct eq_quarantine_stream empty_stream = {};
const struct eq_tenant_stats empty_tenant = {};
const volatile __u32 self_pid = 0;
const volatile __u64 self_ns_dev = 0, self_ns_ino = 0;

static __always_inline void fault(__u32 key) {
    __u64 *value = bpf_map_lookup_elem(&faults, &key);
    if (value) (*value)++;
}
static __always_inline int is_collector(void) {
    struct bpf_pidns_info info = {};
    /* WSL has a PID namespace: userspace getpid() is not a host BPF TGID. */
    return !bpf_get_ns_current_pid_tgid(self_ns_dev, self_ns_ino, &info, sizeof(info)) &&
           info.tgid == self_pid;
}
/* One callback per rule keeps the verifier's rule state bounded. String
 * predicates use the populated trie, so no byte or value loop runs in BPF. */
struct eq_match_walk {
    const struct eq_rule_input *input;
    struct eq_rule_lookup_scratch *lookup;
    int winner;
};
static __noinline unsigned eq_bpf_numeric_predicate(
    const volatile struct eq_rule_token *token, const struct eq_rule_input *input) {
    return eq_rule_numeric_predicate(token, input);
}
static __noinline unsigned eq_bpf_evaluate(
    const volatile struct eq_rule_program *program,
    const struct eq_rule_input *input,
    struct eq_rule_lookup_scratch *lookup, unsigned rule_slot) {
    lookup->eval_stack = 0;
    lookup->eval_depth = 0;
#pragma clang loop unroll(disable)
    for (unsigned t = 0; t < EQ_RULE_TOKENS; t++) {
        if (t >= program->token_count) break;
        const volatile struct eq_rule_token *token = &program->tokens[t];
        if (token->opcode == EQ_TEST) {
            unsigned depth = lookup->eval_depth;
            if (depth >= EQ_RULE_TOKENS) return EQ_UNKNOWN;
            unsigned truth;
            if (token->field == EQ_FIELD_PATH || token->field == EQ_FIELD_COMM) {
                struct eq_rule_trie_key *key;
                if (token->field == EQ_FIELD_PATH) {
                    if ((input->path_quality & EQ_CAPTURE_QUALITY_MASK) ||
                        !input->path || input->path[0] != '/') truth = EQ_UNKNOWN;
                    else {
                        key = &lookup->path;
                        key->rule_slot = rule_slot;
                        key->token_slot = t;
                        truth = bpf_map_lookup_elem(&rule_strings, key) ?
                                EQ_TRUE : EQ_FALSE;
                    }
                } else {
                    if (!input->comm) truth = EQ_UNKNOWN;
                    else {
                        key = &lookup->comm;
                        key->rule_slot = rule_slot;
                        key->token_slot = t;
                        truth = bpf_map_lookup_elem(&rule_strings, key) ?
                                EQ_TRUE : EQ_FALSE;
                    }
                }
                if (token->comparison == EQ_OP_NE ||
                    token->comparison == EQ_OP_NOT_IN) truth = eq_rule_not(truth);
            } else truth = eq_bpf_numeric_predicate(token, input);
            unsigned shift = 2 * depth;
            lookup->eval_stack = (lookup->eval_stack & ~(3ULL << shift)) |
                                 ((unsigned long long)truth << shift);
            lookup->eval_depth = depth + 1;
        } else if (token->opcode == EQ_NOT) {
            unsigned depth = lookup->eval_depth;
            if (!depth) return EQ_UNKNOWN;
            unsigned shift = 2 * (depth - 1);
            unsigned truth = eq_rule_not((lookup->eval_stack >> shift) & 3u);
            lookup->eval_stack = (lookup->eval_stack & ~(3ULL << shift)) |
                                 ((unsigned long long)truth << shift);
        } else if (token->opcode == EQ_ALL || token->opcode == EQ_ANY) {
            unsigned depth = lookup->eval_depth;
            if (depth < 2) return EQ_UNKNOWN;
            unsigned right = (lookup->eval_stack >> (2 * (depth - 1))) & 3u;
            unsigned shift = 2 * (depth - 2);
            unsigned left = (lookup->eval_stack >> shift) & 3u;
            unsigned truth = token->opcode == EQ_ALL ?
                eq_rule_all(left, right) : eq_rule_any(left, right);
            lookup->eval_stack = (lookup->eval_stack & ~(3ULL << shift)) |
                                 ((unsigned long long)truth << shift);
            lookup->eval_depth = depth - 1;
        } else return EQ_UNKNOWN;
    }
    return lookup->eval_depth == 1 ? lookup->eval_stack & 3u : EQ_UNKNOWN;
}
static long eq_match_rule_step(unsigned index, void *context) {
    struct eq_match_walk *walk = context;
    if (index >= EQ_RULES || index >= rule_count) return 1;
    const volatile struct eq_rule_program *candidate = &event_rules[index];
    if (!candidate->enabled) return 0;
    __u32 key = index;
    struct eq_rule_stats *stats = bpf_map_lookup_elem(&rule_stats, &key);
    if (stats) __sync_fetch_and_add(&stats->evaluated, 1);
    unsigned truth = eq_bpf_evaluate(candidate, walk->input, walk->lookup, index);
    if (truth == EQ_UNKNOWN && stats) __sync_fetch_and_add(&stats->unknown, 1);
    if (truth == EQ_TRUE) {
        if (stats) __sync_fetch_and_add(&stats->matched, 1);
        if (walk->winner < 0 || walk->winner >= EQ_RULES ||
            eq_rule_better(candidate, &event_rules[walk->winner]))
            walk->winner = index;
    }
    return 0;
}
static __always_inline int match_rule(const struct eq_rule_input *input) {
    if (!rule_count) return -1;
    __u32 zero = 0;
    struct eq_rule_lookup_scratch *lookup =
        bpf_map_lookup_elem(&rule_lookup_scratch, &zero);
    if (!lookup) { fault(3); return -1; }
    /* Per-CPU storage is shared by a nested tracepoint on the same CPU.
     * A failed acquisition uses the default event route and records a fault
     * instead of evaluating a partially overwritten rule state. */
    if (__sync_val_compare_and_swap(&lookup->busy, 0, 1) != 0) {
        fault(3);
        return -1;
    }
    lookup->path.prefixlen = EQ_RULE_TRIE_QUERY_BITS;
    lookup->comm.prefixlen = EQ_RULE_TRIE_QUERY_BITS;
    if (input->path)
        __builtin_memcpy(lookup->path.text, input->path, EQ_PATH);
    if (input->comm)
        __builtin_memcpy(lookup->comm.text, input->comm, 16);
    struct eq_match_walk walk = {.input = input, .lookup = lookup, .winner = -1};
    if (bpf_loop(EQ_RULES, eq_match_rule_step, &walk, 0) < 0) {
        fault(3);
        __sync_val_compare_and_swap(&lookup->busy, 1, 0);
        return -1;
    }
    if (walk.winner >= 0 && walk.winner < EQ_RULES) {
        __u32 key = walk.winner;
        struct eq_rule_stats *stats = bpf_map_lookup_elem(&rule_stats, &key);
        if (stats) __sync_fetch_and_add(&stats->selected, 1);
    }
    __sync_val_compare_and_swap(&lookup->busy, 1, 0);
    return walk.winner;
}
/* Return 0 on admission, 1 on budget exhaustion, 2 on CAS contention. No
 * locks, unbounded retries, sleeps or refunds: a later ring failure still
 * spends the admitted token, keeping admission bounded under pressure. */
static __always_inline int admit(unsigned long long *next_ns, __u64 now,
                                 __u32 configured_rate, __u32 burst) {
    __u64 rate = configured_rate ? configured_rate : 1;
    __u64 interval = (1000000000ULL + rate - 1) / rate;
    __u64 slack = interval * (burst ? burst - 1 : 0);
    for (int retry = 0; retry < 8; retry++) {
        __u64 old = *(volatile unsigned long long *)next_ns;
        if (old > now && old - now > slack) return 1;
        __u64 next = (old > now ? old : now) + interval;
        if (__sync_val_compare_and_swap(next_ns, old, next) == old) return 0;
    }
    return 2;
}
static __always_inline int acquire_stream(struct eq_quarantine_stream *stream) {
    for (int retry = 0; retry < 8; retry++)
        if (__sync_val_compare_and_swap(&stream->lock, 0, 1) == 0) return 1;
    return 0;
}
static __always_inline int fallback_sample(struct eq_quarantine_global *global,
                                           __u64 now, __u64 interval) {
    for (int retry = 0; retry < 8; retry++) {
        __u64 old = *(volatile unsigned long long *)&global->fallback_next_ns;
        if (now < old) return 0;
        if (__sync_val_compare_and_swap(&global->fallback_next_ns, old, now + interval) == old) return 1;
    }
    return 0;
}
static __noinline int emit(__u32 kind, long result, const struct pending_open *capture) {
    __u32 length = capture->captured_len, quality = capture->quality, flags = capture->flags;
    const char *path = capture->path;
    __u64 now = bpf_ktime_get_ns(), cg = bpf_get_current_cgroup_id();
    __u32 priority = kind == EQ_OPEN && result < 0 ? EQ_BULK : EQ_NORMAL;
    __u64 ids = bpf_get_current_pid_tgid();
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    char comm[16] = {};
    int comm_ok = !bpf_get_current_comm(comm, sizeof(comm));
    struct eq_rule_input input = {
        .kind = kind, .flags = flags, .path_quality = quality,
        .uid = uid, .pid = ids >> 32, .result = result,
        .cgroup_id = cg, .path = path, .comm = comm_ok ? comm : 0,
    };
    int rule_slot = match_rule(&input);
    if (rule_slot < 0 || rule_slot >= EQ_RULES) rule_slot = -1;
    /* The verifier loses the signed range of a callback-produced winner at
     * the later policy branch; keep every rodata index explicitly bounded. */
    __u32 bounded_slot = (__u32)rule_slot & (EQ_RULES - 1u);
    __u32 rule = 0, configured_policy = EQ_COLLECTION;
    quality |= EQ_RULE_VERSION_V1 | EQ_POLICY_VERSION_V1;
    if (rule_slot >= 0) {
        const volatile struct eq_rule_program *chosen = &event_rules[bounded_slot];
        rule = chosen->id;
        priority = chosen->priority;
        configured_policy = chosen->overload_policy;
        quality |= rule << EQ_RULE_SHIFT;
        quality |= configured_policy << EQ_CONFIGURED_POLICY_SHIFT;
        if (configured_policy == EQ_POLICY_EXEMPT) quality |= EQ_Q_PROTECTED;
    }
    int protected_rule = configured_policy == EQ_POLICY_EXEMPT;
    struct eq_quarantine_global *global = 0;
    if (priority == EQ_CRITICAL) {
        __u32 key = 0;
        global = bpf_map_lookup_elem(&quarantine_global, &key);
        if (global) {
            __sync_fetch_and_add(&global->critical_events_total, 1);
            if (protected_rule) __sync_fetch_and_add(&global->protected_events_total, 1);
        } else fault(3);
    }
    struct eq_tenant_stats *t = bpf_map_lookup_elem(&tenants, &cg);
    if (!t) {
        bpf_map_update_elem(&tenants, &cg, &empty_tenant, BPF_NOEXIST);
        t = bpf_map_lookup_elem(&tenants, &cg);
        if (!t) { fault(0); return 0; }
    }
    __u64 seq = __sync_fetch_and_add(&t->sequence, 1) + 1;
    if (priority == EQ_BULK) {
        /* GCRA/token-bucket equivalent. One shared cgroup budget across CPUs.
         * Tracepoints cannot use bpf_spin_lock. Bounded CAS retries never spin
         * indefinitely; contention suppression has its own counter. */
        int admission = admit(&t->next_ns, now, bulk_rate, bulk_burst);
        if (admission == 1) {
            if (rule_slot >= 0) {
                __u32 key = rule_slot;
                struct eq_rule_stats *stats = bpf_map_lookup_elem(&rule_stats, &key);
                if (stats) __sync_fetch_and_add(&stats->budget_suppress, 1);
            }
            __sync_fetch_and_add(&t->budget_suppress, 1); return 0;
        }
        if (admission == 2) {
            if (rule_slot >= 0) {
                __u32 key = rule_slot;
                struct eq_rule_stats *stats = bpf_map_lookup_elem(&rule_stats, &key);
                if (stats) __sync_fetch_and_add(&stats->budget_contention, 1);
            }
            __sync_fetch_and_add(&t->budget_contention, 1); return 0;
        }
    }
    struct eq_quarantine_key stream_key = {cg, rule, kind};
    struct eq_quarantine_stream *stream = 0;
    struct eq_q_decision decision = {};
    const volatile struct eq_quarantine_config *config = 0;
    int owner = 0, untracked = 0, quarantined = 0;
    if (priority == EQ_CRITICAL && configured_policy != EQ_COLLECTION) {
        config = &event_rules[bounded_slot].quarantine;
        stream = bpf_map_lookup_elem(&quarantine_streams, &stream_key);
        if (!stream) {
            bpf_map_update_elem(&quarantine_streams, &stream_key, &empty_stream, BPF_NOEXIST);
            stream = bpf_map_lookup_elem(&quarantine_streams, &stream_key);
        }
        if (stream) {
            __sync_fetch_and_add(&stream->seen, 1);
            owner = acquire_stream(stream);
            if (owner) {
                /* Serial policy time avoids one CPU moving the window backwards.
                 * Keep ownership through ring accounting, making episode selected
                 * = submitted + ring_failed coherent after detach/drain. */
                now = bpf_ktime_get_ns();
                if (protected_rule) __sync_fetch_and_add(&stream->protected_seen, 1);
                __u64 seen = __sync_fetch_and_add(&stream->seen, 0);
                __u64 errors = __sync_fetch_and_add(&stream->tracking_failed, 0);
                eq_q_step(&stream->engine, config, now, seq, (__u32)(bpf_get_current_pid_tgid() >> 32),
                          (__u32)bpf_get_current_uid_gid(), seen, errors, protected_rule, &decision);
                quarantined = decision.route != EQ_Q_NORMAL;
            } else {
                untracked = 1;
                __sync_fetch_and_add(&stream->tracking_failed, 1);
                __sync_fetch_and_add(&t->stream_contention, 1);
                if (global) __sync_fetch_and_add(&global->state_contention, 1);
            }
        } else {
            untracked = 1;
            __sync_fetch_and_add(&t->stream_map_full, 1);
            if (global) __sync_fetch_and_add(&global->stream_map_full, 1);
        }
        if (untracked) {
            quality |= EQ_Q_UNTRACKED;
            if (stream) __sync_fetch_and_add(&stream->untracked_seen, 1);
            if (global) __sync_fetch_and_add(&global->untracked_seen, 1);
            if (protected_rule) {
                if (global) __sync_fetch_and_add(&global->untracked_protected, 1);
            } else {
                quarantined = 1;
                if (global && fallback_sample(global, now, config->sample_interval_ms * EQ_Q_MS_NS)) {
                    decision.route = EQ_Q_SAMPLE;
                    __sync_fetch_and_add(&global->untracked_selected, 1);
                    if (stream) __sync_fetch_and_add(&stream->untracked_selected, 1);
                } else {
                    decision.route = EQ_Q_SUMMARIZE;
                    if (global) __sync_fetch_and_add(&global->untracked_summarized, 1);
                    if (stream) __sync_fetch_and_add(&stream->untracked_summarized, 1);
                }
            }
        }
        if (quarantined) {
            if (global) __sync_fetch_and_add(&global->quarantined_events_total, 1);
            quality |= EQ_QUARANTINED;
            if (decision.route == EQ_Q_FULL) quality |= EQ_Q_INITIAL;
            else if (decision.route == EQ_Q_SAMPLE) quality |= EQ_Q_PERIODIC;
        }
    }
    int submitted = 0;
    if (quarantined && decision.route == EQ_Q_SUMMARIZE) {
        if (rule_slot >= 0) {
            __u32 key = rule_slot;
            struct eq_rule_stats *stats = bpf_map_lookup_elem(&rule_stats, &key);
            if (stats) __sync_fetch_and_add(&stats->summarized, 1);
        }
        __sync_fetch_and_add(&t->quarantine_summarized, 1);
        goto policy_done;
    }
    struct eq_event *e = 0;
    if (quarantined) e = bpf_ringbuf_reserve(&quarantine, sizeof(*e), 0);
    else if (priority == EQ_CRITICAL) e = bpf_ringbuf_reserve(&critical, sizeof(*e), 0);
    else e = bpf_ringbuf_reserve(&general, sizeof(*e), 0);
    if (!e) {
        if (rule_slot >= 0) {
            __u32 key = rule_slot;
            struct eq_rule_stats *stats = bpf_map_lookup_elem(&rule_stats, &key);
            if (stats) __sync_fetch_and_add(&stats->ring_failed, 1);
        }
        if (quarantined) __sync_fetch_and_add(&t->quarantine_full, 1);
        else if (priority == EQ_CRITICAL) __sync_fetch_and_add(&t->critical_full, 1);
        else __sync_fetch_and_add(&t->general_full, 1);
        goto policy_done;
    }
    __builtin_memset(e, 0, sizeof(*e));
    struct task_struct *task = (void *)bpf_get_current_task();
    e->monotonic_ns = now; e->cgroup_id = cg; e->sequence = seq;
    e->process_start_ns = BPF_CORE_READ(task, group_leader, start_time);
    e->result = result; e->magic = EQ_MAGIC; e->schema = EQ_SCHEMA;
    e->kind = kind; e->priority = priority; e->pid = ids >> 32;
    e->tid = (__u32)ids; e->uid = uid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->cpu = bpf_get_smp_processor_id(); e->op_flags = flags;
    e->captured_len = length; e->quality = quality;
    __builtin_memcpy(e->comm, comm, sizeof(comm));
    __builtin_memcpy(e->path, path, EQ_PATH);
    bpf_ringbuf_submit(e, 0);
    submitted = 1;
    if (rule_slot >= 0) {
        __u32 key = rule_slot;
        struct eq_rule_stats *stats = bpf_map_lookup_elem(&rule_stats, &key);
        if (stats) __sync_fetch_and_add(&stats->submitted, 1);
    }
    if (quarantined) __sync_fetch_and_add(&t->quarantine_submitted, 1);
    if (priority == EQ_CRITICAL) __sync_fetch_and_add(&t->submitted[2], 1);
    else if (priority == EQ_NORMAL) __sync_fetch_and_add(&t->submitted[1], 1);
    else __sync_fetch_and_add(&t->submitted[0], 1);
policy_done:
    if (owner) {
        if (quarantined) eq_q_note_submission(&stream->engine, decision.route, submitted);
        else if (submitted) __sync_fetch_and_add(&stream->critical_submitted, 1);
        else __sync_fetch_and_add(&stream->critical_ring_failed, 1);
        if (decision.transition) {
            struct eq_quarantine_control *control = bpf_ringbuf_reserve(&quarantine_control, sizeof(*control), 0);
            if (control) {
                eq_q_make_control(control, &stream_key, &stream->engine, config, &decision);
                bpf_ringbuf_submit(control, 0);
            } else {
                __sync_fetch_and_add(&stream->transition_ring_failed, 1);
                if (global) __sync_fetch_and_add(&global->transition_ring_failed, 1);
            }
        }
        __sync_val_compare_and_swap(&stream->lock, 1, 0);
    } else if (untracked) {
        if (protected_rule) {
            if (global && submitted) __sync_fetch_and_add(&global->untracked_protected_submitted, 1);
            else if (global) __sync_fetch_and_add(&global->untracked_protected_ring_failed, 1);
        } else if (decision.route == EQ_Q_SAMPLE) {
            if (submitted) {
                if (global) __sync_fetch_and_add(&global->untracked_submitted, 1);
                if (stream) __sync_fetch_and_add(&stream->untracked_submitted, 1);
            } else {
                if (global) __sync_fetch_and_add(&global->untracked_ring_failed, 1);
                if (stream) __sync_fetch_and_add(&stream->untracked_ring_failed, 1);
            }
        }
    }
    return 0;
}
SEC("tp/syscalls/sys_enter_openat")
int open_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 key = bpf_get_current_pid_tgid();
    if (is_collector()) return 0;
    struct pending_open p = {};
    long len = bpf_probe_read_user_str(p.path, sizeof(p.path), (void *)ctx->args[1]);
    p.flags = ctx->args[2];
    if (len < 0) p.quality = EQ_READ_ERROR;
    else {
        p.captured_len = len - 1;
        /* At the bound, original length is unknown; conservative truncation flag. */
        if (len == EQ_PATH) p.quality = EQ_TRUNCATED;
    }
    if (bpf_map_update_elem(&pending, &key, &p, BPF_ANY)) fault(1);
    return 0;
}
SEC("tp/syscalls/sys_exit_openat")
int open_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 key = bpf_get_current_pid_tgid();
    if (is_collector()) return 0;
    struct pending_open *p = bpf_map_lookup_elem(&pending, &key);
    if (!p) { fault(2); return 0; }
    emit(EQ_OPEN, ctx->ret, p);
    bpf_map_delete_elem(&pending, &key);
    return 0;
}
SEC("tp/sched/sched_process_exec")
int exec_event(struct trace_event_raw_sched_process_exec *ctx) {
    __u32 key = 0;
    struct pending_open *capture = bpf_map_lookup_elem(&exec_scratch, &key);
    if (!capture) { fault(0); return 0; }
    __builtin_memset(capture, 0, sizeof(*capture));
    unsigned off = ctx->__data_loc_filename & 0xffff;
    long len = bpf_probe_read_kernel_str(capture->path, sizeof(capture->path), (void *)ctx + off);
    capture->captured_len = len > 0 ? len - 1 : 0;
    capture->quality = len < 0 ? EQ_READ_ERROR : len == EQ_PATH ? EQ_TRUNCATED : 0;
    return emit(EQ_EXEC, 0, capture);
}
SEC("tp/sched/sched_process_exit")
int cleanup_thread(struct trace_event_raw_sched_process_template *ctx) {
    __u64 key = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&pending, &key);
    return 0;
}
