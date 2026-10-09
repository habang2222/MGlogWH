/* SPDX-License-Identifier: BSD-3-Clause */
/* Authored virtual-time tests. This binary is compiled, never run by Codex. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "quarantine.h"

_Static_assert(sizeof(struct eq_event) == 232, "schema 2 preserves event size");
_Static_assert(sizeof(struct eq_record) == 240, "schema 2 preserves raw frame size");
struct fixture {
    struct eq_quarantine_key key;
    struct eq_quarantine_config config;
    struct eq_quarantine_engine engine;
    struct eq_quarantine_control entered, exited;
    unsigned long long seen, sequence, normal;
    unsigned pid, uid, transitions;
    int protected_rule;
};
static struct fixture fixture(unsigned long long cgroup, unsigned rule) {
    return (struct fixture){.key = {cgroup, rule, EQ_OPEN},
        .config = {10000, 3000, 2000, 10000, 8, 100}, .pid = 10, .uid = 0};
}
static unsigned observe(struct fixture *f, unsigned long long now, int submitted) {
    struct eq_q_decision decision;
    f->seen++; f->sequence++;
    eq_q_step(&f->engine, &f->config, now, f->sequence, f->pid, f->uid,
              f->seen, 0, f->protected_rule, &decision);
    eq_q_note_submission(&f->engine, decision.route, submitted);
    if (decision.route == EQ_Q_NORMAL) f->normal++;
    if (decision.transition) {
        struct eq_quarantine_control *control = decision.transition == EQ_Q_ENTER ? &f->entered : &f->exited;
        eq_q_make_control(control, &f->key, &f->engine, &f->config, &decision);
        f->transitions++;
    }
    return decision.route;
}
static void window(struct fixture *f, unsigned second, unsigned count) {
    for (unsigned n = 0; n < count; n++)
        observe(f, second * EQ_Q_SECOND_NS + (unsigned long long)n * EQ_Q_SECOND_NS / count, 1);
}
static void enter(struct fixture *f, int submitted) {
    for (unsigned second = 0; second < 3; second++) window(f, second, 10000);
    assert(observe(f, 3 * EQ_Q_SECOND_NS, submitted) == EQ_Q_FULL);
    assert(f->engine.quarantined && f->transitions == 1);
}
/* 1. A low stream keeps the original critical route. */
static void test_low_rate_stays_critical(void) {
    struct fixture f = fixture(1, 1);
    for (unsigned second = 0; second < 20; second++) window(&f, second, 10);
    assert(!f.engine.quarantined && !f.transitions && f.normal == f.seen);
    assert(f.engine.current_rate_eps == 10);
}
/* 2. A spike shorter than the configured duration does not quarantine. */
static void test_spike_without_duration(void) {
    struct fixture f = fixture(1, 1);
    window(&f, 0, 10001); window(&f, 1, 10001);
    window(&f, 2, 10); window(&f, 3, 10);
    assert(!f.engine.quarantined && !f.transitions && f.normal == f.seen);
    assert(!f.engine.high_windows);
}
/* 3. The threshold plus three completed seconds produces one enter. */
static void test_threshold_and_duration_enter(void) {
    struct fixture f = fixture(1, 1); enter(&f, 1);
    assert(f.entered.transition == EQ_Q_ENTER && f.entered.reason == EQ_Q_HIGH_RATE);
    assert(f.entered.observed_eps == 10000 && f.entered.threshold_eps == 10000);
    assert(f.entered.duration_ms == 3000 && f.entered.episode.start_ns == 3 * EQ_Q_SECOND_NS);
    assert(f.entered.episode.burst_start_ns == 0 && f.entered.episode.high_rate_duration_ms == 3000);
    assert(f.engine.current.full_selected == 1 && f.engine.current.full_submitted == 1);
    /* Policy values are configurable, not folded into the engine. */
    struct fixture custom = fixture(2, 2); custom.config.threshold_eps = 50;
    custom.config.recovery_eps = 10; custom.config.duration_ms = 2000;
    window(&custom, 0, 50); window(&custom, 1, 50);
    assert(observe(&custom, 2 * EQ_Q_SECOND_NS, 1) == EQ_Q_FULL);
    assert(custom.entered.threshold_eps == 50 && custom.entered.duration_ms == 2000);
    /* Allocation of cgroup IDs precedes policy ownership. A delayed handler
     * can have a smaller ID than the episode's first policy observation. */
    struct eq_q_decision delayed;
    f.seen++;
    eq_q_step(&f.engine, &f.config, 3 * EQ_Q_SECOND_NS + EQ_Q_MS_NS,
              f.engine.current.first_sequence - 1, f.pid, f.uid, f.seen, 0, 0, &delayed);
    eq_q_note_submission(&f.engine, delayed.route, 1);
    assert(delayed.route == EQ_Q_FULL);
    assert(f.engine.current.last_sequence < f.engine.current.first_sequence);
    assert(f.engine.current.last_event_ns > f.engine.current.start_ns);
}
/* 4. Both rule identity and cgroup identity isolate the state machine. */
static void test_stream_isolation(void) {
    struct fixture flood = fixture(100, 1), other_rule = fixture(100, 2), other_tenant = fixture(200, 1);
    enter(&flood, 1);
    for (unsigned second = 0; second < 5; second++) {
        window(&other_rule, second, 10); window(&other_tenant, second, 10);
    }
    assert(flood.engine.quarantined);
    assert(!other_rule.engine.quarantined && !other_tenant.engine.quarantined);
    assert(!other_rule.transitions && !other_tenant.transitions);
    assert(other_rule.normal == other_rule.seen && other_tenant.normal == other_tenant.seen);
    assert(flood.entered.key.cgroup_id == 100 && flood.entered.key.rule_id == 1);
}
/* 5. An explicitly protected rule retains critical capture during a flood. */
static void test_protected_rule_bypasses(void) {
    struct fixture f = fixture(1, 1); f.protected_rule = 1;
    for (unsigned second = 0; second < 5; second++) window(&f, second, 10001);
    observe(&f, 5 * EQ_Q_SECOND_NS, 1);
    assert(!f.engine.quarantined && !f.transitions && f.normal == f.seen);
    assert(f.engine.current_rate_eps == 10001 && f.engine.peak_rate_eps == 10001);
}
/* 6. Recovery includes exactly the low threshold, and idle recovery is event driven. */
static void test_low_cooldown_exit(void) {
    struct fixture f = fixture(1, 1); enter(&f, 1);
    for (unsigned n = 1; n < 2000; n++)
        observe(&f, 3 * EQ_Q_SECOND_NS + (unsigned long long)n * EQ_Q_SECOND_NS / 2000, 1);
    for (unsigned second = 4; second < 13; second++) window(&f, second, 2000);
    assert(f.engine.quarantined && f.transitions == 1);
    unsigned long long last = f.engine.current.last_sequence;
    assert(observe(&f, 13 * EQ_Q_SECOND_NS, 1) == EQ_Q_NORMAL);
    assert(!f.engine.quarantined && f.exited.reason == EQ_Q_LOW_RATE);
    assert(f.exited.observed_eps == 2000 && f.exited.duration_ms == 10000);
    assert(f.exited.episode.last_sequence == last && f.exited.transition_sequence > last);
    struct fixture idle = fixture(2, 1); enter(&idle, 1);
    assert(observe(&idle, 14 * EQ_Q_SECOND_NS, 1) == EQ_Q_NORMAL);
    assert(idle.exited.transition == EQ_Q_EXIT && idle.exited.observed_eps == 0);
}
/* 7. Selection, summarization and ring outcomes reconcile without claiming durability. */
static void test_sampling_reconciliation(void) {
    struct fixture f = fixture(1, 1); enter(&f, 1);
    for (unsigned n = 1; n < 8; n++)
        assert(observe(&f, 3 * EQ_Q_SECOND_NS + n * EQ_Q_MS_NS, n != 7) == EQ_Q_FULL);
    for (unsigned n = 0; n < 50; n++)
        assert(observe(&f, 3 * EQ_Q_SECOND_NS + (8 + n) * EQ_Q_MS_NS, 1) == EQ_Q_SUMMARIZE);
    assert(observe(&f, 3 * EQ_Q_SECOND_NS + 107 * EQ_Q_MS_NS, 1) == EQ_Q_SAMPLE);
    assert(observe(&f, 3 * EQ_Q_SECOND_NS + 108 * EQ_Q_MS_NS, 1) == EQ_Q_SUMMARIZE);
    assert(observe(&f, 3 * EQ_Q_SECOND_NS + 207 * EQ_Q_MS_NS, 0) == EQ_Q_SAMPLE);
    const struct eq_quarantine_episode *e = &f.engine.current;
    assert(e->full_selected == 8 && e->sample_selected == 2 && e->summarized == 51);
    assert(e->seen == e->full_selected + e->sample_selected + e->summarized);
    assert(e->full_selected + e->sample_selected == e->full_submitted + e->sample_submitted + e->ring_failed);
    assert(e->full_submitted == 7 && e->sample_submitted == 1 && e->ring_failed == 2);
    assert(f.engine.q_seen == e->seen && f.engine.summarized == e->summarized);
}
/* 8. Enter/exit controls preserve policy, sequence bounds, identity and storage outcomes. */
static void test_control_metadata_accuracy(void) {
    struct fixture f = fixture(100, 77); enter(&f, 0);
    assert(f.entered.episode.seen == 1 && f.entered.episode.ring_failed == 1);
    for (unsigned n = 1; n < 8; n++) observe(&f, 3 * EQ_Q_SECOND_NS + n * EQ_Q_MS_NS, 1);
    observe(&f, 3 * EQ_Q_SECOND_NS + 107 * EQ_Q_MS_NS, 0);
    f.pid = 11; f.uid = 1;
    observe(&f, 3 * EQ_Q_SECOND_NS + 108 * EQ_Q_MS_NS, 1);
    assert(observe(&f, 14 * EQ_Q_SECOND_NS, 1) == EQ_Q_NORMAL);
    const struct eq_quarantine_control *c = &f.exited;
    const struct eq_quarantine_episode *e = &c->episode;
    assert(c->key.cgroup_id == 100 && c->key.rule_id == 77 && c->key.kind == EQ_OPEN);
    assert(c->transition == EQ_Q_EXIT && c->reason == EQ_Q_LOW_RATE);
    assert(c->threshold_eps == 2000 && c->duration_ms == 10000);
    assert(e->episode_id == e->first_sequence && e->first_sequence == 30001);
    assert(e->last_sequence == 30010 && c->transition_sequence == 30011);
    assert(e->start_ns == 3 * EQ_Q_SECOND_NS && e->end_ns == 14 * EQ_Q_SECOND_NS);
    assert(e->last_event_ns == 3 * EQ_Q_SECOND_NS + 108 * EQ_Q_MS_NS);
    assert(e->seen == 10 && e->full_selected == 8 && e->sample_selected == 1 && e->summarized == 1);
    assert(e->full_submitted == 7 && e->sample_submitted == 0 && e->ring_failed == 2);
    assert(e->first_pid == 10 && e->last_pid == 11 && e->first_uid == 0 && e->last_uid == 1);
    assert(e->unique_pid_lower_bound == 2 && e->unique_uid_lower_bound == 2);
    assert(e->tracking_complete && e->threshold_eps == 10000 && e->duration_ms == 3000);
    unsigned quality = EQ_TRUNCATED | EQ_QUARANTINED | EQ_Q_INITIAL | (77u << EQ_RULE_SHIFT);
    assert((quality & EQ_CAPTURE_QUALITY_MASK) == EQ_TRUNCATED);
    assert(((quality & EQ_RULE_MASK) >> EQ_RULE_SHIFT) == 77 && EQ_SCHEMA == 2);
}
int main(void) {
    test_low_rate_stays_critical();
    test_spike_without_duration();
    test_threshold_and_duration_enter();
    test_stream_isolation();
    test_protected_rule_bypasses();
    test_low_cooldown_exit();
    test_sampling_reconciliation();
    test_control_metadata_accuracy();
    puts("8 virtual-time Critical Quarantine cases: OK");
    return 0;
}
