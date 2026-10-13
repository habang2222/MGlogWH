/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef MGLOGWH_RULES_H
#define MGLOGWH_RULES_H
#include "quarantine.h"

/* The on-disk compiled rule file is little-endian. This project only builds
 * for Linux x86_64; fixed-width fields keep the Python compiler and C loader
 * on the same ABI. It is an input to the collector, not an evidence format. */
#define EQ_RULE_FILE_MAGIC 0x3147524du
#define EQ_RULE_FILE_VERSION 1u
#define EQ_RULE_TOKENS 24u
#define EQ_RULE_STRINGS 1024u
#define EQ_RULE_VALUES 4u
/* The trie separates rule/token namespaces before the observed string. */
struct eq_rule_trie_key {
    unsigned prefixlen;
    unsigned char rule_slot, token_slot;
    char text[EQ_PATH];
} __attribute__((packed));
#define EQ_RULE_TRIE_META_BITS 16u
#define EQ_RULE_TRIE_QUERY_BITS (EQ_RULE_TRIE_META_BITS + 8u * EQ_PATH)
/* Linux x86_64 O_PATH opens a path descriptor without read/write access. */
#define EQ_OPEN_PATH_ONLY 010000000u

enum eq_rule_opcode { EQ_TEST = 1, EQ_ALL = 2, EQ_ANY = 3, EQ_NOT = 4 };
enum eq_rule_field {
    EQ_FIELD_KIND = 1, EQ_FIELD_SUCCESS, EQ_FIELD_RESULT,
    EQ_FIELD_ACCESS_MODE, EQ_FIELD_CREATE, EQ_FIELD_TRUNCATE,
    EQ_FIELD_PATH, EQ_FIELD_UID, EQ_FIELD_PID, EQ_FIELD_COMM,
    EQ_FIELD_CGROUP, EQ_FIELD_ROOT, EQ_FIELD_WRITE_ACCESS
};
enum eq_rule_operator {
    EQ_OP_EQ = 1, EQ_OP_NE, EQ_OP_IN, EQ_OP_NOT_IN, EQ_OP_PREFIX,
    EQ_OP_GT, EQ_OP_GE, EQ_OP_LT, EQ_OP_LE
};
enum eq_overload_policy {
    EQ_COLLECTION = 0, EQ_POLICY_QUARANTINE = 1,
    EQ_POLICY_EXEMPT = 2
};
enum eq_truth { EQ_FALSE = 0, EQ_TRUE = 1, EQ_UNKNOWN = 2 };

struct eq_rule_token {
    unsigned opcode, field, comparison, value_count;
    long long values[EQ_RULE_VALUES];
};
struct eq_rule_program {
    unsigned id, enabled, precedence, priority;
    unsigned overload_policy, token_count, string_bytes, reserved;
    struct eq_quarantine_config quarantine;
    struct eq_rule_token tokens[EQ_RULE_TOKENS];
    char strings[EQ_RULE_STRINGS];
};
struct eq_rule_file_header {
    unsigned magic, version, count, program_size, payload_crc32;
};
struct eq_rule_input {
    unsigned kind, flags, path_quality, uid, pid;
    long long result;
    unsigned long long cgroup_id;
    const char *path, *comm;
};
struct eq_rule_stats {
    unsigned long long evaluated, matched, unknown, selected;
    unsigned long long submitted, summarized, ring_failed;
    unsigned long long budget_suppress, budget_contention;
};

/* The fourth comparison value is not a sentinel: value_count bounds access.
 * UNKNOWN is deliberately not converted to FALSE before NOT, so truncated or
 * unreadable paths cannot satisfy negative path predicates. */
#define EQ_RULE_INLINE static __inline__ __attribute__((always_inline))
EQ_RULE_INLINE unsigned eq_rule_not(unsigned value) {
    return value == EQ_UNKNOWN ? EQ_UNKNOWN : value == EQ_TRUE ? EQ_FALSE : EQ_TRUE;
}
EQ_RULE_INLINE unsigned eq_rule_all(unsigned left, unsigned right) {
    return left == EQ_FALSE || right == EQ_FALSE ? EQ_FALSE :
           left == EQ_UNKNOWN || right == EQ_UNKNOWN ? EQ_UNKNOWN : EQ_TRUE;
}
EQ_RULE_INLINE unsigned eq_rule_any(unsigned left, unsigned right) {
    return left == EQ_TRUE || right == EQ_TRUE ? EQ_TRUE :
           left == EQ_UNKNOWN || right == EQ_UNKNOWN ? EQ_UNKNOWN : EQ_FALSE;
}
EQ_RULE_INLINE unsigned eq_rule_numeric(const volatile struct eq_rule_token *token,
                                        long long actual) {
    long long expected = token->values[0];
    switch (token->comparison) {
    case EQ_OP_EQ: return actual == expected;
    case EQ_OP_NE: return actual != expected;
    case EQ_OP_GT: return actual > expected;
    case EQ_OP_GE: return actual >= expected;
    case EQ_OP_LT: return actual < expected;
    case EQ_OP_LE: return actual <= expected;
    case EQ_OP_IN:
    case EQ_OP_NOT_IN: {
        unsigned found = 0;
        for (unsigned i = 0; i < EQ_RULE_VALUES; i++) {
            if (i >= token->value_count) break;
            if (actual == token->values[i]) found = 1;
        }
        return token->comparison == EQ_OP_IN ? found : !found;
    }
    default: return EQ_UNKNOWN;
    }
}
/* Userspace reference matcher; the sensor resolves strings through the
 * preloaded LPM trie so verifier complexity is independent of string length. */
EQ_RULE_INLINE unsigned eq_rule_one_string(const volatile struct eq_rule_program *program,
                                           const char *actual, unsigned actual_limit,
                                           unsigned offset, unsigned length, unsigned prefix) {
    if (!length || length >= actual_limit || offset >= program->string_bytes ||
        offset >= EQ_RULE_STRINGS || length >= EQ_RULE_STRINGS - offset ||
        length >= program->string_bytes - offset)
        return EQ_UNKNOWN;
    unsigned difference = 0;
    for (unsigned i = 0; i < EQ_PATH; i++) {
        if (i >= length) {
            if (!prefix) difference |= (unsigned char)actual[i];
            return difference ? EQ_FALSE : EQ_TRUE;
        }
        difference |= (unsigned char)actual[i] ^
                      (unsigned char)program->strings[offset + i];
    }
    return EQ_UNKNOWN;
}
EQ_RULE_INLINE unsigned eq_rule_string(const volatile struct eq_rule_program *program,
                                       const volatile struct eq_rule_token *token,
                                       const char *actual, unsigned actual_limit) {
    unsigned found = EQ_FALSE, unknown = 0;
    for (unsigned i = 0; i < EQ_RULE_VALUES; i++) {
        if (i >= token->value_count) break;
        if (token->values[i] < 0) return EQ_UNKNOWN;
        unsigned long long encoded = (unsigned long long)token->values[i];
        unsigned offset = (unsigned)encoded;
        unsigned length = (unsigned)(encoded >> 32);
        unsigned result = eq_rule_one_string(program, actual, actual_limit,
                                             offset, length,
                                             token->comparison == EQ_OP_PREFIX);
        if (result == EQ_TRUE) found = EQ_TRUE;
        if (result == EQ_UNKNOWN) unknown = 1;
    }
    if (found != EQ_TRUE && unknown) return EQ_UNKNOWN;
    return token->comparison == EQ_OP_NE || token->comparison == EQ_OP_NOT_IN ?
           eq_rule_not(found) : found;
}
EQ_RULE_INLINE unsigned eq_rule_numeric_predicate(const volatile struct eq_rule_token *token,
                                                  const struct eq_rule_input *input) {
    long long actual = 0;
    switch (token->field) {
    case EQ_FIELD_KIND: actual = input->kind; break;
    case EQ_FIELD_SUCCESS: actual = input->result >= 0; break;
    case EQ_FIELD_RESULT: actual = input->result; break;
    case EQ_FIELD_ACCESS_MODE:
        if (input->kind != EQ_OPEN || (input->flags & EQ_OPEN_PATH_ONLY) ||
            (input->flags & 3u) == 3u) return EQ_UNKNOWN;
        actual = input->flags & 3u; break;
    case EQ_FIELD_CREATE:
        if (input->kind != EQ_OPEN) return EQ_UNKNOWN;
        actual = !!(input->flags & 0100u); break;
    case EQ_FIELD_TRUNCATE:
        if (input->kind != EQ_OPEN) return EQ_UNKNOWN;
        actual = !!(input->flags & 01000u); break;
    case EQ_FIELD_UID: actual = input->uid; break;
    case EQ_FIELD_PID: actual = input->pid; break;
    case EQ_FIELD_CGROUP:
        if (input->cgroup_id > 0x7fffffffffffffffULL) return EQ_UNKNOWN;
        actual = (long long)input->cgroup_id; break;
    case EQ_FIELD_ROOT: actual = input->uid == 0; break;
    case EQ_FIELD_WRITE_ACCESS:
        if (input->kind != EQ_OPEN || (input->flags & EQ_OPEN_PATH_ONLY) ||
            (input->flags & 3u) == 3u) return EQ_UNKNOWN;
        actual = (input->flags & 3u) == 1u || (input->flags & 3u) == 2u; break;
    default: return EQ_UNKNOWN;
    }
    return eq_rule_numeric(token, actual);
}
EQ_RULE_INLINE unsigned eq_rule_predicate(const volatile struct eq_rule_program *program,
                                          const volatile struct eq_rule_token *token,
                                          const struct eq_rule_input *input) {
    if (token->field == EQ_FIELD_PATH) {
        if (input->path_quality & EQ_CAPTURE_QUALITY_MASK || !input->path ||
            input->path[0] != '/') return EQ_UNKNOWN;
        return eq_rule_string(program, token, input->path, EQ_PATH);
    }
    if (token->field == EQ_FIELD_COMM) {
        if (!input->comm) return EQ_UNKNOWN;
        return eq_rule_string(program, token, input->comm, 16);
    }
    return eq_rule_numeric_predicate(token, input);
}
EQ_RULE_INLINE unsigned eq_rule_evaluate(const volatile struct eq_rule_program *program,
                                         const struct eq_rule_input *input) {
    /* Three-valued postfix results fit in two bits each (24 * 2 < 64),
     * avoiding a variable-indexed BPF stack array and its verifier states. */
    unsigned long long stack = 0;
    unsigned depth = 0;
    for (unsigned i = 0; i < EQ_RULE_TOKENS; i++) {
        if (i >= program->token_count) break;
        const volatile struct eq_rule_token *token = &program->tokens[i];
        if (token->opcode == EQ_TEST) {
            if (depth >= EQ_RULE_TOKENS) return EQ_UNKNOWN;
            unsigned shift = 2 * depth;
            stack = (stack & ~(3ULL << shift)) |
                    ((unsigned long long)eq_rule_predicate(program, token, input) << shift);
            depth++;
        } else if (token->opcode == EQ_NOT) {
            if (!depth) return EQ_UNKNOWN;
            unsigned shift = 2 * (depth - 1);
            unsigned value = (stack >> shift) & 3u;
            stack = (stack & ~(3ULL << shift)) |
                    ((unsigned long long)eq_rule_not(value) << shift);
        } else if (token->opcode == EQ_ALL || token->opcode == EQ_ANY) {
            if (depth < 2) return EQ_UNKNOWN;
            unsigned right = (stack >> (2 * --depth)) & 3u;
            unsigned shift = 2 * (depth - 1);
            unsigned left = (stack >> shift) & 3u;
            unsigned value = token->opcode == EQ_ALL ?
                eq_rule_all(left, right) : eq_rule_any(left, right);
            stack = (stack & ~(3ULL << shift)) | ((unsigned long long)value << shift);
        } else return EQ_UNKNOWN;
    }
    return depth == 1 ? stack & 3u : EQ_UNKNOWN;
}
EQ_RULE_INLINE int eq_rule_better(const volatile struct eq_rule_program *candidate,
                                 const volatile struct eq_rule_program *current) {
    if (!current) return 1;
    if (candidate->precedence != current->precedence)
        return candidate->precedence > current->precedence;
    if (candidate->priority != current->priority)
        return candidate->priority > current->priority;
    if (candidate->overload_policy != current->overload_policy) {
        unsigned a = candidate->overload_policy == EQ_POLICY_QUARANTINE ? 3 :
                     candidate->overload_policy == EQ_POLICY_EXEMPT ? 2 : 1;
        unsigned b = current->overload_policy == EQ_POLICY_QUARANTINE ? 3 :
                     current->overload_policy == EQ_POLICY_EXEMPT ? 2 : 1;
        return a > b;
    }
    return candidate->id < current->id;
}
#undef EQ_RULE_INLINE

#endif
