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
/* Unsharded sequence per cgroup; only additive diagnostics use per-CPU storage. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} faults SEC(".maps");
const volatile __u32 bulk_rate = 500, bulk_burst = 1000;
const volatile struct eq_quarantine_config quarantine_config = {
    10000, 3000, 2000, 10000, 8, 100
};
const volatile struct eq_quarantine_rule critical_rules[EQ_RULES] = {
    {1, EQ_OPEN, 0, 1, "/tmp/mglogwh-decoy.txt"}
};
const volatile __u32 rule_count = 1;
/* Avoid constructing an approximately 1 KiB map value on the BPF stack. */
const struct eq_quarantine_stream empty_stream = {};
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
static __always_inline __u32 match_rule(__u32 kind, const char *path,
                                       __u32 quality, int *protected_rule) {
    if (quality & EQ_CAPTURE_QUALITY_MASK) return 0;
    for (int rule = 0; rule < EQ_RULES; rule++) {
        if (rule >= rule_count) break;
        const volatile struct eq_quarantine_rule *candidate = &critical_rules[rule];
        if (!candidate->enabled || candidate->kind != kind || !candidate->id || candidate->id > 255) continue;
        int matched = 0;
        for (int i = 0; i < EQ_PATH; i++) {
            if (path[i] != candidate->path[i]) break;
            if (!path[i]) { matched = 1; break; }
        }
        if (matched) { *protected_rule = candidate->protected_rule != 0; return candidate->id; }
    }
    return 0;
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
static __always_inline int emit(__u32 kind, long result, const char *path,
                                __u32 length, __u32 quality, __u32 flags) {
    __u64 now = bpf_ktime_get_ns(), cg = bpf_get_current_cgroup_id();
    __u32 priority = kind == EQ_OPEN && result < 0 ? EQ_BULK : EQ_NORMAL;
    int protected_rule = 0;
    __u32 rule = match_rule(kind, path, quality, &protected_rule);
    if (rule) {
        priority = EQ_CRITICAL; quality |= rule << EQ_RULE_SHIFT;
        if (protected_rule) quality |= EQ_Q_PROTECTED;
    }
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
        struct eq_tenant_stats initial = {};
        bpf_map_update_elem(&tenants, &cg, &initial, BPF_NOEXIST);
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
            __sync_fetch_and_add(&t->budget_suppress, 1); return 0;
        }
        if (admission == 2) {
            __sync_fetch_and_add(&t->budget_contention, 1); return 0;
        }
    }
    struct eq_quarantine_key stream_key = {cg, rule, kind};
    struct eq_quarantine_stream *stream = 0;
    struct eq_q_decision decision = {};
    struct eq_quarantine_config config = {};
    int owner = 0, untracked = 0, quarantined = 0;
    if (priority == EQ_CRITICAL) {
        config.threshold_eps = quarantine_config.threshold_eps;
        config.duration_ms = quarantine_config.duration_ms;
        config.recovery_eps = quarantine_config.recovery_eps;
        config.cooldown_ms = quarantine_config.cooldown_ms;
        config.initial_full = quarantine_config.initial_full;
        config.sample_interval_ms = quarantine_config.sample_interval_ms;
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
                eq_q_step(&stream->engine, &config, now, seq, (__u32)(bpf_get_current_pid_tgid() >> 32),
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
                if (global && fallback_sample(global, now, config.sample_interval_ms * EQ_Q_MS_NS)) {
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
        __sync_fetch_and_add(&t->quarantine_summarized, 1);
        goto policy_done;
    }
    struct eq_event *e = 0;
    if (quarantined) e = bpf_ringbuf_reserve(&quarantine, sizeof(*e), 0);
    else if (priority == EQ_CRITICAL) e = bpf_ringbuf_reserve(&critical, sizeof(*e), 0);
    else e = bpf_ringbuf_reserve(&general, sizeof(*e), 0);
    if (!e) {
        if (quarantined) __sync_fetch_and_add(&t->quarantine_full, 1);
        else if (priority == EQ_CRITICAL) __sync_fetch_and_add(&t->critical_full, 1);
        else __sync_fetch_and_add(&t->general_full, 1);
        goto policy_done;
    }
    __builtin_memset(e, 0, sizeof(*e));
    __u64 ids = bpf_get_current_pid_tgid();
    struct task_struct *task = (void *)bpf_get_current_task();
    e->monotonic_ns = now; e->cgroup_id = cg; e->sequence = seq;
    e->process_start_ns = BPF_CORE_READ(task, group_leader, start_time);
    e->result = result; e->magic = EQ_MAGIC; e->schema = EQ_SCHEMA;
    e->kind = kind; e->priority = priority; e->pid = ids >> 32;
    e->tid = (__u32)ids; e->uid = (__u32)bpf_get_current_uid_gid();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->cpu = bpf_get_smp_processor_id(); e->op_flags = flags;
    e->captured_len = length; e->quality = quality;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memcpy(e->path, path, EQ_PATH);
    bpf_ringbuf_submit(e, 0);
    submitted = 1;
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
                eq_q_make_control(control, &stream_key, &stream->engine, &config, &decision);
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
    emit(EQ_OPEN, ctx->ret, p->path, p->captured_len, p->quality, p->flags);
    bpf_map_delete_elem(&pending, &key);
    return 0;
}
SEC("tp/sched/sched_process_exec")
int exec_event(struct trace_event_raw_sched_process_exec *ctx) {
    char path[EQ_PATH] = {};
    unsigned off = ctx->__data_loc_filename & 0xffff;
    long len = bpf_probe_read_kernel_str(path, sizeof(path), (void *)ctx + off);
    return emit(EQ_EXEC, 0, path, len > 0 ? len - 1 : 0,
                len < 0 ? EQ_READ_ERROR : len == EQ_PATH ? EQ_TRUNCATED : 0, 0);
}
SEC("tp/sched/sched_process_exit")
int cleanup_thread(struct trace_event_raw_sched_process_template *ctx) {
    __u64 key = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&pending, &key);
    return 0;
}
