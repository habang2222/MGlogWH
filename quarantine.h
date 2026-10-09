/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef MGLOGWH_QUARANTINE_H
#define MGLOGWH_QUARANTINE_H
#include "event.h"

#define EQ_RULES 8
#define EQ_STREAMS 1024
#define EQ_Q_BITMAP_WORDS 4
#define EQ_Q_SECOND_NS 1000000000ULL
#define EQ_Q_MS_NS 1000000ULL

struct eq_quarantine_rule {
    unsigned id, kind, protected_rule, enabled;
    char path[EQ_PATH];
};
struct eq_quarantine_config {
    unsigned long long threshold_eps, duration_ms, recovery_eps, cooldown_ms;
    unsigned long long initial_full, sample_interval_ms;
};
struct eq_quarantine_key {
    unsigned long long cgroup_id;
    unsigned rule_id, kind;
};
/* Bitmap cardinalities are explicitly lower bounds, never exact distinct PID
 * or UID counts. first/last_sequence identify chronological first/last policy
 * observations, not numeric bounds: earlier allocated IDs can arrive later.
 * They cannot enumerate the summarized event IDs. */
struct eq_quarantine_episode {
    unsigned long long episode_id, start_ns, end_ns;
    unsigned long long last_event_ns, burst_start_ns, peak_rate_eps, high_rate_duration_ms;
    unsigned long long threshold_eps, observed_eps, duration_ms;
    unsigned long long first_sequence, last_sequence;
    unsigned long long first_pid, first_uid, last_pid, last_uid;
    unsigned long long seen, full_selected, sample_selected, summarized;
    unsigned long long full_submitted, sample_submitted, ring_failed;
    unsigned long long pid_bitmap[EQ_Q_BITMAP_WORDS], uid_bitmap[EQ_Q_BITMAP_WORDS];
    unsigned long long unique_pid_lower_bound, unique_uid_lower_bound;
    unsigned long long tracking_failed_start, tracking_failed_end, tracking_complete;
};
struct eq_quarantine_engine {
    unsigned long long initialized, window_start_ns, window_count, window_complete;
    unsigned long long accounted_seen, high_windows, low_windows;
    unsigned long long current_rate_eps, peak_rate_eps, burst_start_ns;
    unsigned long long quarantined, next_sample_ns;
    unsigned long long q_seen, full_selected, sample_selected, summarized;
    unsigned long long full_submitted, sample_submitted, ring_failed;
    unsigned long long enter_count, exit_count;
    struct eq_quarantine_episode current, last;
};
/* lock is a bounded CAS guard, not a BPF spin lock. seen and failure/fallback
 * counters remain atomic even when the guard cannot be acquired. */
struct eq_quarantine_stream {
    unsigned long long lock, seen, tracking_failed, protected_seen;
    unsigned long long critical_submitted, critical_ring_failed;
    unsigned long long untracked_seen, untracked_selected, untracked_summarized;
    unsigned long long untracked_submitted, untracked_ring_failed, transition_ring_failed;
    struct eq_quarantine_engine engine;
};
enum eq_q_transition { EQ_Q_ENTER = 1, EQ_Q_EXIT = 2 };
enum eq_q_reason { EQ_Q_HIGH_RATE = 1, EQ_Q_LOW_RATE = 2 };
enum eq_q_route { EQ_Q_NORMAL, EQ_Q_FULL, EQ_Q_SAMPLE, EQ_Q_SUMMARIZE };
struct eq_quarantine_control {
    struct eq_quarantine_key key;
    unsigned transition, reason;
    unsigned long long monotonic_ns, transition_sequence;
    unsigned long long threshold_eps, observed_eps, duration_ms;
    struct eq_quarantine_episode episode;
};
struct eq_quarantine_global {
    unsigned long long critical_events_total, protected_events_total, quarantined_events_total;
    unsigned long long fallback_next_ns, stream_map_full, state_contention;
    unsigned long long untracked_seen, untracked_selected, untracked_summarized;
    unsigned long long untracked_submitted, untracked_ring_failed;
    unsigned long long untracked_protected, untracked_protected_submitted;
    unsigned long long untracked_protected_ring_failed, transition_ring_failed;
};

struct eq_q_decision {
    unsigned route, transition;
    unsigned long long monotonic_ns, transition_sequence, observed_eps;
};

/* This portable policy engine performs no I/O, allocation, atomics or clock
 * reads. Its caller owns the stream CAS guard; tests supply virtual time.
 * Cumulative seen snapshots include failed guard acquisitions. At a window
 * boundary their still-unaccounted delta belongs to the new window, so EPS
 * windows are conservative snapshots rather than timestamp-perfect buckets. */
#define EQ_Q_INLINE static __inline__ __attribute__((always_inline))
EQ_Q_INLINE void eq_q_distinct(unsigned long long *bitmap,
                               unsigned long long *count, unsigned value) {
    unsigned hash = value * 2654435761u;
    unsigned bit = hash >> 24;
    unsigned long long mask = 1ULL << (bit & 63);
    unsigned word = bit >> 6;
    if (!(bitmap[word] & mask)) { bitmap[word] |= mask; (*count)++; }
}
EQ_Q_INLINE void eq_q_observe_window(struct eq_quarantine_engine *engine,
                                     const struct eq_quarantine_config *config,
                                     unsigned long long count,
                                     unsigned long long start_ns) {
    engine->current_rate_eps = count;
    if (count > engine->peak_rate_eps) engine->peak_rate_eps = count;
    if (count >= config->threshold_eps) {
        if (!engine->high_windows) engine->burst_start_ns = start_ns;
        engine->high_windows++;
    } else {
        engine->high_windows = 0; engine->burst_start_ns = 0;
    }
    if (engine->quarantined) {
        if (count <= config->recovery_eps) engine->low_windows++;
        else engine->low_windows = 0;
        if (count > engine->current.peak_rate_eps) engine->current.peak_rate_eps = count;
        if (engine->high_windows * 1000 > engine->current.high_rate_duration_ms)
            engine->current.high_rate_duration_ms = engine->high_windows * 1000;
    }
}
EQ_Q_INLINE void eq_q_step(struct eq_quarantine_engine *engine,
                           const struct eq_quarantine_config *config,
                           unsigned long long now_ns, unsigned long long sequence,
                           unsigned pid, unsigned uid, unsigned long long seen_snapshot,
                           unsigned long long tracking_failed, int protected_rule,
                           struct eq_q_decision *decision) {
    __builtin_memset(decision, 0, sizeof(*decision));
    decision->monotonic_ns = now_ns; decision->transition_sequence = sequence;
    unsigned long long start = now_ns - now_ns % EQ_Q_SECOND_NS;
    unsigned long long delta = seen_snapshot >= engine->accounted_seen ?
                               seen_snapshot - engine->accounted_seen : 0;
    engine->accounted_seen = seen_snapshot;
    if (!engine->initialized) {
        engine->initialized = 1; engine->window_start_ns = start;
        engine->window_count = delta;
        /* An initial partial window cannot satisfy the sustained duration. */
        engine->window_complete = now_ns == start;
    } else if (start > engine->window_start_ns) {
        unsigned long long gap = (start - engine->window_start_ns) / EQ_Q_SECOND_NS;
        if (engine->window_complete)
            eq_q_observe_window(engine, config, engine->window_count, engine->window_start_ns);
        if (gap > 1) {
            engine->high_windows = 0; engine->burst_start_ns = 0;
            engine->current_rate_eps = 0;
            /* No attempts since the prior snapshot proves the skipped windows
             * idle. Otherwise their distribution is unknown, so do not infer
             * a recovery interval from the missing policy observations. */
            if (engine->quarantined && delta <= 1) engine->low_windows += gap - 1;
            else engine->low_windows = 0;
        }
        engine->window_start_ns = start; engine->window_count = delta;
        engine->window_complete = 1;
        if (!protected_rule && !engine->quarantined &&
            engine->high_windows * 1000 >= config->duration_ms) {
            engine->quarantined = 1; engine->low_windows = 0; engine->enter_count++;
            __builtin_memset(&engine->current, 0, sizeof(engine->current));
            engine->current.episode_id = sequence;
            engine->current.start_ns = now_ns;
            engine->current.first_sequence = sequence;
            engine->current.first_pid = pid; engine->current.first_uid = uid;
            engine->current.burst_start_ns = engine->burst_start_ns;
            engine->current.peak_rate_eps = engine->current_rate_eps;
            engine->current.high_rate_duration_ms = engine->high_windows * 1000;
            engine->current.threshold_eps = config->threshold_eps;
            engine->current.observed_eps = engine->current_rate_eps;
            engine->current.duration_ms = config->duration_ms;
            engine->current.tracking_failed_start = tracking_failed;
            engine->current.tracking_failed_end = tracking_failed;
            engine->current.tracking_complete = tracking_failed == 0;
            engine->next_sample_ns = now_ns;
            decision->transition = EQ_Q_ENTER;
            decision->observed_eps = engine->current_rate_eps;
        } else if (!protected_rule && engine->quarantined &&
                   engine->low_windows * 1000 >= config->cooldown_ms) {
            engine->current.end_ns = now_ns;
            engine->current.tracking_failed_end = tracking_failed;
            engine->current.tracking_complete = tracking_failed == 0;
            engine->last = engine->current;
            __builtin_memset(&engine->current, 0, sizeof(engine->current));
            engine->quarantined = 0; engine->low_windows = 0; engine->exit_count++;
            decision->transition = EQ_Q_EXIT;
            decision->observed_eps = engine->current_rate_eps;
        }
    } else engine->window_count += delta;
    if (protected_rule || !engine->quarantined) return;
    struct eq_quarantine_episode *episode = &engine->current;
    episode->seen++; engine->q_seen++;
    episode->last_event_ns = now_ns; episode->last_sequence = sequence;
    episode->last_pid = pid; episode->last_uid = uid;
    episode->tracking_failed_end = tracking_failed;
    episode->tracking_complete = tracking_failed == 0;
    eq_q_distinct(episode->pid_bitmap, &episode->unique_pid_lower_bound, pid);
    eq_q_distinct(episode->uid_bitmap, &episode->unique_uid_lower_bound, uid);
    if (episode->full_selected < config->initial_full) {
        episode->full_selected++; engine->full_selected++;
        engine->next_sample_ns = now_ns + config->sample_interval_ms * EQ_Q_MS_NS;
        decision->route = EQ_Q_FULL;
    } else if (now_ns >= engine->next_sample_ns) {
        episode->sample_selected++; engine->sample_selected++;
        engine->next_sample_ns = now_ns + config->sample_interval_ms * EQ_Q_MS_NS;
        decision->route = EQ_Q_SAMPLE;
    } else {
        episode->summarized++; engine->summarized++;
        decision->route = EQ_Q_SUMMARIZE;
    }
}
EQ_Q_INLINE void eq_q_note_submission(struct eq_quarantine_engine *engine,
                                      unsigned route, int submitted) {
    if (route != EQ_Q_FULL && route != EQ_Q_SAMPLE) return;
    if (!submitted) { engine->ring_failed++; engine->current.ring_failed++; }
    else if (route == EQ_Q_FULL) {
        engine->full_submitted++; engine->current.full_submitted++;
    } else {
        engine->sample_submitted++; engine->current.sample_submitted++;
    }
}
EQ_Q_INLINE void eq_q_make_control(struct eq_quarantine_control *control,
                                    const struct eq_quarantine_key *key,
                                    const struct eq_quarantine_engine *engine,
                                    const struct eq_quarantine_config *config,
                                    const struct eq_q_decision *decision) {
    __builtin_memset(control, 0, sizeof(*control));
    control->key = *key; control->transition = decision->transition;
    control->reason = decision->transition == EQ_Q_ENTER ? EQ_Q_HIGH_RATE : EQ_Q_LOW_RATE;
    control->monotonic_ns = decision->monotonic_ns;
    control->transition_sequence = decision->transition_sequence;
    control->observed_eps = decision->observed_eps;
    control->threshold_eps = decision->transition == EQ_Q_ENTER ?
                             config->threshold_eps : config->recovery_eps;
    control->duration_ms = decision->transition == EQ_Q_ENTER ?
                           config->duration_ms : config->cooldown_ms;
    if (decision->transition == EQ_Q_ENTER) control->episode = engine->current;
    else control->episode = engine->last;
}
#undef EQ_Q_INLINE

#endif
