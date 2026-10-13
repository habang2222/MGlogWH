/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef EVIDENCE_EVENT_H
#define EVIDENCE_EVENT_H
#define EQ_MAGIC 0x31514f45u
#define EQ_SCHEMA 3
#define EQ_PREVIOUS_SCHEMA 2
#define EQ_LEGACY_SCHEMA 1
#define EQ_PATH 128
#define EQ_TENANTS 1024
enum eq_kind { EQ_EXEC = 1, EQ_OPEN = 2 };
enum eq_priority { EQ_BULK, EQ_NORMAL, EQ_CRITICAL };
enum eq_quality { EQ_TRUNCATED = 1, EQ_READ_ERROR = 2,
    EQ_QUARANTINED = 1u << 8, EQ_Q_INITIAL = 1u << 9,
    EQ_Q_PERIODIC = 1u << 10, EQ_Q_PROTECTED = 1u << 11,
    EQ_Q_UNTRACKED = 1u << 12 };
#define EQ_CAPTURE_QUALITY_MASK 3u
#define EQ_CONFIGURED_POLICY_SHIFT 13u
#define EQ_CONFIGURED_POLICY_MASK (3u << EQ_CONFIGURED_POLICY_SHIFT)
#define EQ_RULE_SHIFT 16u
#define EQ_RULE_MASK (255u << EQ_RULE_SHIFT)
#define EQ_RULE_VERSION_SHIFT 24u
#define EQ_RULE_VERSION_MASK (15u << EQ_RULE_VERSION_SHIFT)
#define EQ_POLICY_VERSION_SHIFT 28u
#define EQ_POLICY_VERSION_MASK (15u << EQ_POLICY_VERSION_SHIFT)
#define EQ_RULE_VERSION_V1 (1u << EQ_RULE_VERSION_SHIFT)
#define EQ_POLICY_VERSION_V1 (1u << EQ_POLICY_VERSION_SHIFT)
/* Schema 3 keeps the schema 1/2 size/layout. Rule id now also applies to
 * BULK/NORMAL; configured overload policy and encoding versions occupy quality
 * bits. The run manifest's config_sha256 identifies the actual rule revision. */
struct eq_event {
    unsigned long long monotonic_ns, cgroup_id, sequence, process_start_ns;
    long long result;
    unsigned magic, schema, kind, priority, pid, tid, uid, ppid, cpu;
    unsigned op_flags, captured_len, quality;
    char comm[16], path[EQ_PATH];
};
struct eq_record { struct eq_event event; unsigned crc32, reserved; };
#endif
