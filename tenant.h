/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef MGLOGWH_TENANT_H
#define MGLOGWH_TENANT_H

/* Shared BPF tenant metadata. Raw framing is independent of this map layout. */
struct eq_tenant_stats {
    unsigned long long sequence, next_ns;
    unsigned long long submitted[3], budget_suppress, general_full, critical_full;
    unsigned long long budget_contention;
    unsigned long long quarantine_submitted, quarantine_full, quarantine_summarized;
    unsigned long long stream_map_full, stream_contention;
};

#endif
