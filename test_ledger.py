"""Synthetic recovery fixtures. Authoring/compilation never starts collection.

Run explicitly when desired: python3 -m unittest -v test_ledger.py
"""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
import uuid
import zlib

import ledger


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.run = self.root / str(uuid.uuid4())
        self.run.mkdir()
        config = dict(protected_path='/tmp/protected')
        canonical = json.dumps(config, sort_keys=True, separators=(',', ':')).encode()
        manifest = dict(schema=1, run_id=self.run.name, boot_id=str(uuid.uuid4()),
                        config_sha256=hashlib.sha256(canonical).hexdigest())
        self.write_json('config.json', config)
        self.write_json('manifest.json', manifest)
        self.lineage = dict(run_id=self.run.name, boot_id=manifest['boot_id'],
                            config_sha256=manifest['config_sha256'],
                            manifest_sha256=hashlib.sha256((self.run / 'manifest.json').read_bytes()).hexdigest())
        self.frames = []
        (self.run / 'critical.raw').write_bytes(b'')
        (self.run / 'general.raw').write_bytes(b'')

    def tearDown(self):
        self.temp.cleanup()

    def write_json(self, name, value):
        (self.run / name).write_text(json.dumps(value), encoding='utf-8')

    def append(self, record_type, **value):
        value = dict(schema=1, **self.lineage, journal_seq=len(self.frames)+1,
                     record_type=record_type, **value)
        raw = json.dumps(value, separators=(',', ':')).encode()
        self.frames.append(ledger.FRAME.pack(len(raw), zlib.crc32(raw)) + raw)
        return value

    def checkpoint(self, *, sequence=3, critical=0, general=0, seal=False, **values):
        value = dict(durable_offsets=dict(critical=critical, general=general),
                     tenants=[dict(cgroup_id=9001, sequence=sequence, budget_suppress=900)],
                     faults=[0, 0, 0, 0], summary_kind='AGGREGATE_ONLY',
                     metadata_overflow=0, metadata_dropped=0,
                     exact_loss_available=True, sequence_snapshot_complete=True)
        if seal:
            value['state'] = 'STOPPED'
        value.update(values)
        return self.append('seal' if seal else 'checkpoint', **value)

    def loss(self, seq=2, **values):
        value = dict(cgroup_id=9001, seq=seq, lane='critical', reason='QUEUE_OVERFLOW', monotonic_ns=123)
        value.update(values)
        return self.append('loss', **value)

    def loss_witness(self):
        return dict(version=1, source='USERSPACE_RING_CALLBACK', event_schema=2,
                    kind=2, priority=2, quality=1 << 16, rule_id=1,
                    pid=7, tid=7, uid=1000, process_start_ns=20, result=3,
                    op_flags=0, captured_len=len(b'/tmp/protected'),
                    path_hex=b'/tmp/protected'.hex())

    def commit(self, suffix=b'', count=None):
        prefix = b''.join(self.frames if count is None else self.frames[:count])
        (self.run / 'evidence.meta').write_bytes(prefix + suffix)
        self.write_json('evidence.meta.commit', dict(schema=1, **self.lineage,
                         offset=len(prefix), journal_seq=len(self.frames) if count is None else count))

    def raw(self, seq=1, cgroup=9001, comm=b'fixture', path=b'/tmp/protected', schema=1, quality=0, timestamp=100):
        payload = ledger.EVENT.pack(timestamp, cgroup, seq, 20, 3, 0x31514F45, schema, 2, 2,
                                    7, 7, 1000, 1, 0, 0, len(path), quality, comm, path)
        return payload + struct.pack('<II', zlib.crc32(payload), 0)

    def report(self):
        return ledger.recover(self.run)

    def test_legacy_no_ledger_is_explicitly_unsupported(self):
        self.assertEqual('LEGACY_UNSUPPORTED', self.report()['status'])

    def test_missing_fence_never_promotes_even_valid_journal(self):
        self.checkpoint(seal=True)
        (self.run / 'evidence.meta').write_bytes(b''.join(self.frames))
        value = self.report()
        self.assertEqual('UNCOMMITTED', value['status'])
        self.assertEqual(0, value['journal']['committed_bytes'])
        self.assertFalse(value['absence_set_complete'])

    def test_empty_startup_fence_has_no_recovered_raw_boundary(self):
        self.commit()
        value = self.report()
        self.assertEqual('UNCOMMITTED', value['status'])
        self.assertFalse(value['raw_recovery_supported'])
        self.assertFalse(value['absence_set_complete'])
        self.assertEqual(0, value['durable_unique_events'])

    def test_committed_loss_without_checkpoint_remains_exact_partial_recovery(self):
        self.loss()
        self.commit()
        value = self.report()
        self.assertEqual('PARTIAL_RECOVERY', value['status'])
        self.assertFalse(value['raw_recovery_supported'])
        self.assertEqual(1, value['exact_userspace_loss_count'])
        self.assertEqual('COMMITTED_JOURNAL_FENCE', value['exact_userspace_loss_durability'])
        self.assertIsNone(value['unknown_future']['count'])

    def test_committed_loss_after_last_checkpoint_is_exact_not_bounded_raw(self):
        self.checkpoint(sequence=1)
        self.loss(seq=900)
        self.commit()
        value = self.report()
        self.assertEqual('RECOVERED', value['status'])
        self.assertEqual(1, value['exact_userspace_loss_count'])
        self.assertEqual(900, value['exact_userspace_losses'][0]['ranges'][0]['start'])
        self.assertEqual(1, value['tenant_evidence'][0]['checkpoint_sequence'])
        self.assertNotIn('final_absence', value['tenant_evidence'][0])

    def test_non_utf8_names_do_not_affect_sensor_id_recovery(self):
        (self.run / 'critical.raw').write_bytes(self.raw(comm=b'\xffprocess', path=b'/tmp/\xffprotected'))
        self.checkpoint(sequence=1, critical=ledger.RECORD_SIZE, seal=True)
        self.commit()
        value = self.report()
        self.assertEqual('RECOVERED', value['status'])
        self.assertEqual(1, value['durable_unique_events'])
        self.assertEqual(0, value['tenant_evidence'][0]['final_absence']['count'])

    def episode(self, **values):
        value = dict(episode_id=2, start_ns=100, end_ns=0, first_sequence=2,last_sequence=5,
            last_event_ns=400,seen=4,full_selected=1,sample_selected=1,summarized=2,
            full_submitted=1,sample_submitted=1,ring_failed=0,tracking_complete=1,
            tracking_failed_start=0,tracking_failed_end=0,unique_pid_lower_bound=1,unique_uid_lower_bound=1)
        value.update(values)
        return value

    def stream(self, **values):
        value = dict(cgroup_id=9001,rule_id=1,kind=2,seen=5,tracking_failed=0,protected_seen=0,
            engine=dict(q_seen=4,full_selected=1,sample_selected=1,summarized=2,
                        full_submitted=1,sample_submitted=1,ring_failed=0,current_rate_eps=4000,
                        peak_rate_eps=5000,current=self.episode(),last=self.episode(episode_id=0,first_sequence=0,last_sequence=0)),
            collector=dict(normal_appended=1,normal_durable=1,full_appended=1,full_durable=1,
                           sample_appended=1,sample_durable=1,queue_rejected_full=0,queue_rejected_sample=0,
                           storage_rejected_full=0,storage_rejected_sample=0))
        value.update(values)
        return value

    def control(self, transition='quarantine_enter', episode=None, **values):
        episode = episode or self.episode(last_sequence=2,last_event_ns=100,seen=1,full_selected=1,
                                         sample_selected=0,summarized=0,sample_submitted=0)
        value = dict(cgroup_id=9001,rule_id=1,kind=2,episode_id=episode['episode_id'],
            first_seq=episode['first_sequence'],last_seq=episode['last_sequence'],seq=2,
            monotonic_ns=100,threshold_eps=10000,observed_eps=15000,duration_ms=3000,
            reason='HIGH_RATE' if transition=='quarantine_enter' else 'LOW_RATE',episode=episode)
        value.update(values)
        return self.append(transition, **value)

    def quarantine_checkpoint(self, **values):
        value = dict(sequence=5,seal=True,durable_offsets=dict(critical=ledger.RECORD_SIZE,general=0,
                         quarantine=2*ledger.RECORD_SIZE),streams=[self.stream()],
                         stream_snapshot_complete=True,stream_storage_complete=True,
                         quarantine_global=dict(stream_map_full=0,untracked_seen=0,untracked_protected=0))
        value.update(values)
        return self.checkpoint(**value)

    def quarantine_files(self):
        (self.run / 'critical.raw').write_bytes(self.raw(seq=1,schema=2,quality=1<<16))
        (self.run / 'quarantine.raw').write_bytes(self.raw(seq=2,schema=2,quality=(1<<16)|ledger.Q_QUARANTINE|ledger.Q_INITIAL)+
            self.raw(seq=4,schema=2,quality=(1<<16)|ledger.Q_QUARANTINE|ledger.Q_PERIODIC))

    def test_quarantine_lane_preserves_durable_union_and_scoped_counts(self):
        self.quarantine_files()
        self.control()
        self.quarantine_checkpoint()
        self.commit()
        value = self.report()
        self.assertEqual('RECOVERED', value['status'])
        self.assertEqual(3, value['durable_unique_events'])
        self.assertEqual(2, value['tenant_evidence'][0]['final_absence']['count'])
        q = value['critical_quarantine']
        self.assertEqual((1,1,2),(q['full_saved_total'],q['sampled_total'],q['quarantine_not_stored_total']))
        self.assertEqual(5,q['critical_seen_total'])
        self.assertEqual(2,q['episodes'][0]['reconciliation']['not_durable'])
        self.assertEqual('CRITICAL_QUARANTINE',q['episodes'][0]['reconciliation']['summary_reason'])
        self.assertTrue(all(row['reason']=='UNKNOWN' for row in value['tenant_evidence'][0]['final_absence']['ranges']))

    def test_quarantine_missing_control_keeps_episode_metrics_incomplete(self):
        self.quarantine_files()
        self.quarantine_checkpoint()
        self.commit()
        episode = self.report()['critical_quarantine']['episodes'][0]
        self.assertFalse(episode['controls_complete'])
        self.assertIsNone(episode['actual_durable'])
        self.assertIsNone(episode['reconciliation']['not_durable'])

    def test_live_quarantine_difference_is_not_confirmed_loss(self):
        self.quarantine_files()
        self.control()
        self.quarantine_checkpoint(seal=False)
        self.commit()
        value = self.report()['critical_quarantine']
        self.assertIsNone(value['quarantine_not_stored_total'])
        self.assertEqual(2,value['quarantine_pending_or_not_stored_total'])

    def test_quarantine_transition_conflicts_and_wrong_lane_flags_are_invalid(self):
        self.control()
        self.control(observed_eps=20000)
        self.quarantine_checkpoint()
        self.commit()
        self.assertIn('conflicting quarantine',self.report()['errors'][0])
        self.frames=[]
        self.quarantine_files()
        (self.run/'quarantine.raw').write_bytes(self.raw(seq=2,schema=2,quality=1<<16))
        self.quarantine_checkpoint(durable_offsets=dict(critical=ledger.RECORD_SIZE,general=0,quarantine=ledger.RECORD_SIZE))
        self.commit()
        self.assertIn('quarantine policy/lane',self.report()['errors'][0])

    def test_quarantine_unknown_policy_bits_and_lane_set_change_are_invalid(self):
        self.quarantine_files()
        (self.run/'quarantine.raw').write_bytes(self.raw(seq=2,schema=2,
             quality=(1<<16)|ledger.Q_QUARANTINE|ledger.Q_INITIAL|(1<<7)))
        self.quarantine_checkpoint(durable_offsets=dict(critical=ledger.RECORD_SIZE,general=0,quarantine=ledger.RECORD_SIZE))
        self.commit()
        self.assertIn('unknown raw policy',self.report()['errors'][0])
        self.frames=[]
        self.checkpoint()
        self.quarantine_checkpoint()
        self.commit()
        self.assertIn('lane set changed',self.report()['errors'][0])

    def test_quarantine_episode_membership_uses_time_not_out_of_order_sequence(self):
        episode=self.episode(episode_id=101,first_sequence=101,last_sequence=100,start_ns=100,last_event_ns=200,
                             seen=2,full_selected=1,sample_selected=1,summarized=0)
        stream=self.stream(seen=2,engine=dict(q_seen=2,full_selected=1,sample_selected=1,summarized=0,
                    full_submitted=1,sample_submitted=1,ring_failed=0,current=episode,
                    last=self.episode(episode_id=0,first_sequence=0,last_sequence=0)))
        (self.run/'critical.raw').write_bytes(b'')
        (self.run/'quarantine.raw').write_bytes(self.raw(seq=101,schema=2,timestamp=100,
            quality=(1<<16)|ledger.Q_QUARANTINE|ledger.Q_INITIAL)+self.raw(seq=100,schema=2,timestamp=200,
            quality=(1<<16)|ledger.Q_QUARANTINE|ledger.Q_PERIODIC))
        self.control(episode=episode,seq=101)
        self.quarantine_checkpoint(sequence=101,streams=[stream],
            durable_offsets=dict(critical=0,general=0,quarantine=2*ledger.RECORD_SIZE))
        self.commit()
        value=self.report()
        self.assertEqual('RECOVERED',value['status'])
        actual=value['critical_quarantine']['episodes'][0]['actual_durable']
        self.assertEqual((1,1),(actual['owned_initial_full'],actual['owned_periodic_sample']))

    def test_protected_untracked_fallback_stays_critical_and_tracking_degrades_q_counts(self):
        (self.run/'critical.raw').write_bytes(self.raw(seq=1,schema=2,
                                  quality=(1<<16)|ledger.Q_PROTECTED|ledger.Q_UNTRACKED))
        (self.run/'quarantine.raw').write_bytes(b'')
        self.quarantine_checkpoint(sequence=1,streams=[],quarantine_tracking_complete=False,
            quarantine_global=dict(critical_events_total=1,protected_events_total=1,quarantined_events_total=0,
                                   stream_map_full=1,untracked_seen=1,untracked_protected=1),
            durable_offsets=dict(critical=ledger.RECORD_SIZE,general=0,quarantine=0))
        self.commit()
        value=self.report()
        self.assertEqual('RECOVERED',value['status'])
        self.assertEqual(1,value['durable_unique_events'])
        self.assertEqual(1,value['critical_quarantine']['protected_seen_total'])
        self.assertIsNone(value['critical_quarantine']['quarantine_not_stored_total'])

    def test_quarantine_exit_uses_policy_time_and_retains_closed_metadata(self):
        self.quarantine_files()
        self.control()
        episode=self.episode(end_ns=500)
        self.control('quarantine_exit',episode=episode,seq=1,monotonic_ns=500,
            threshold_eps=2000,observed_eps=1000,duration_ms=10000,
            original_priority='CRITICAL',effective_policy='CRITICAL',trigger_reason='CRITICAL_RATE_RECOVERED')
        stream=self.stream(engine=dict(q_seen=4,full_selected=1,sample_selected=1,summarized=2,
            full_submitted=1,sample_submitted=1,ring_failed=0,
            current=self.episode(episode_id=0,first_sequence=0,last_sequence=0),last=episode))
        self.quarantine_checkpoint(streams=[stream])
        self.commit()
        report=self.report()
        self.assertEqual('RECOVERED',report['status'])
        closed=report['critical_quarantine']['episodes'][0]
        self.assertEqual('last',closed['role'])
        self.assertTrue(closed['controls_complete'])
        self.assertEqual('LOW_RATE',closed['exit_transition']['reason'])
        self.assertEqual('CRITICAL_RATE_RECOVERED',closed['exit_transition']['trigger_reason'])

    def test_quarantine_metric_aliases_and_transition_policy_are_preserved(self):
        self.quarantine_files()
        self.control(original_priority='CRITICAL',effective_policy='QUARANTINE',trigger_reason='CRITICAL_RATE_EXCEEDED')
        self.quarantine_checkpoint(active_quarantined_streams=1,critical_events_total=5,quarantined_events_total=4,
            peak_critical_rate=5000,peak_critical_rate_scope='MAX_TRACKED_STREAM_ONE_SECOND_EPS',
            quarantine_by_reason=dict(CRITICAL_RATE_EXCEEDED=1,CRITICAL_RATE_RECOVERED=0),quarantine_by_reason_scope='TRANSITIONS')
        self.commit()
        value=self.report()['critical_quarantine']
        self.assertEqual(5000,value['declared_metric_aliases']['peak_critical_rate'])
        self.assertEqual('TRANSITIONS',value['quarantine_by_reason_scope'])
        enter=value['episodes'][0]['enter_transition']
        self.assertEqual(('CRITICAL','QUARANTINE','CRITICAL_RATE_EXCEEDED'),
                         (enter['original_priority'],enter['effective_policy'],enter['trigger_reason']))

    def test_quarantine_policy_and_reason_metric_scope_mismatch_are_invalid(self):
        self.control(original_priority='BULK',effective_policy='QUARANTINE',trigger_reason='CRITICAL_RATE_EXCEEDED')
        self.commit()
        self.assertIn('policy mismatch',self.report()['errors'][0])
        self.frames=[]
        self.quarantine_checkpoint(quarantine_by_reason=dict(CRITICAL_RATE_EXCEEDED=1,CRITICAL_RATE_RECOVERED=0),
                                   quarantine_by_reason_scope='EVENTS')
        self.commit()
        self.assertIn('transition scope',self.report()['errors'][0])

    def test_torn_uncommitted_suffix_is_preserved_and_ignored(self):
        self.checkpoint(critical=ledger.RECORD_SIZE)
        (self.run / 'critical.raw').write_bytes(self.raw() + self.raw(seq=2) + b'torn')
        suffix = ledger.FRAME.pack(9000, 0) + b'torn-json'
        self.commit(suffix=suffix)
        before = {path.name:path.read_bytes() for path in self.run.iterdir()}
        value = self.report()
        self.assertEqual('RECOVERED', value['status'])
        self.assertEqual(1, value['durable_unique_events'])
        self.assertEqual(len(suffix), value['journal']['uncommitted_bytes'])
        self.assertFalse(value['clean_seal'])
        self.assertIsNone(value['unknown_future']['count'])
        self.assertEqual(before, {path.name:path.read_bytes() for path in self.run.iterdir()})

    def test_checkpoint_aggregate_counters_never_create_exact_losses(self):
        self.checkpoint(sequence=10, faults=[3, 0, 0, 0])
        self.commit()
        value = self.report()
        self.assertEqual(0, value['exact_userspace_loss_count'])
        self.assertNotIn('final_absence', value['tenant_evidence'][0])
        self.assertIsNone(value['tenant_evidence'][0]['unknown_tail']['count'])

    def test_seal_compacts_missing_ids_and_preserves_exact_tombstone_reason(self):
        (self.run / 'critical.raw').write_bytes(self.raw())
        self.loss()
        self.checkpoint(critical=ledger.RECORD_SIZE, seal=True)
        self.commit()
        value = self.report()
        self.assertTrue(value['absence_set_complete'])
        gaps = value['tenant_evidence'][0]['final_absence']
        self.assertEqual(2, gaps['count'])
        self.assertEqual(['QUEUE_OVERFLOW', 'UNKNOWN'], [entry['reason'] for entry in gaps['ranges']])
        self.assertEqual(1, value['exact_userspace_loss_count'])

    def test_known_rejection_witness_frontiers_and_ambiguous_truth_binding(self):
        (self.run / 'critical.raw').write_bytes(self.raw(schema=2, quality=1 << 16))
        self.loss(seq=2, reason='CRITICAL_QUEUE_FULL', witness=self.loss_witness())
        self.checkpoint(sequence=3, critical=ledger.RECORD_SIZE, seal=True)
        self.commit()
        value = self.report()
        self.assertEqual('RECOVERED', value['status'])
        self.assertTrue(value['userspace_loss_witness_coverage_complete'])
        tenant = value['tenant_evidence'][0]
        self.assertEqual((2, 1, 2), (tenant['max_seen_exact_sequence'],
                         tenant['contiguous_raw_frontier'], tenant['accounted_frontier']))
        self.assertEqual(['CRITICAL_QUEUE_FULL', 'UNKNOWN'],
                         [row['reason'] for row in tenant['final_absence']['ranges']])
        witness = value['exact_userspace_loss_witnesses']['entries'][0]
        self.assertEqual('UNMATCHED', witness['truth_binding'])
        truth = dict(run_id=self.run.name, boot_id=self.lineage['boot_id'],
                     clock_domain='NOTEBOOK_MONOTONIC',
                     cgroup_id=9001, tid=7, kind=2, path_hex=b'/tmp/protected'.hex(),
                     result=3, monotonic_ns=124, truth_seq=17)
        self.assertEqual('UNKNOWN', ledger.match_truth_candidates(witness, [truth], 10)['status'])
        self.assertEqual(dict(status='UNIQUE_CANDIDATE', truth_seq=17, candidate_count=1),
                         ledger.match_truth_candidates(witness, [truth], 10, candidate_set_complete=True))
        self.assertEqual('AMBIGUOUS', ledger.match_truth_candidates(
            witness, [truth, dict(truth, truth_seq=18)], 10, candidate_set_complete=True)['status'])
        self.assertEqual('UNKNOWN', ledger.match_truth_candidates(
            witness, [dict(truth, path_hex=b'/other'.hex())], 10, candidate_set_complete=True)['status'])

    def test_legacy_loss_has_no_witness_and_unsealed_tail_is_unknown(self):
        (self.run / 'critical.raw').write_bytes(self.raw())
        self.loss(seq=2)
        self.checkpoint(sequence=3, critical=ledger.RECORD_SIZE)
        self.commit()
        value = self.report()
        self.assertEqual(1, value['exact_userspace_loss_count'])
        self.assertEqual(0, value['exact_userspace_loss_witnesses']['count'])
        self.assertFalse(value['userspace_loss_witness_coverage_complete'])
        self.assertEqual(2, value['tenant_evidence'][0]['accounted_frontier'])
        self.assertIsNone(value['tenant_evidence'][0]['unknown_tail']['count'])
        self.assertIsNone(value['unknown_future']['count'])

    def test_malformed_loss_witness_cannot_claim_exact_context(self):
        witness = self.loss_witness()
        witness['rule_id'] = 2
        self.loss(witness=witness)
        self.checkpoint()
        self.commit()
        self.assertIn('rule_id/quality mismatch', self.report()['errors'][0])

    def test_selected_quarantine_sample_rejected_before_durable_raw(self):
        witness = self.loss_witness()
        witness['quality'] |= ledger.Q_QUARANTINE | ledger.Q_PERIODIC
        (self.run / 'quarantine.raw').write_bytes(b'')
        self.loss(seq=2, lane='quarantine', reason='Q_QUEUE_FULL', witness=witness)
        self.checkpoint(sequence=2, seal=True,
                        durable_offsets=dict(critical=0, general=0, quarantine=0))
        self.commit()
        value = self.report()
        self.assertEqual('RECOVERED', value['status'])
        entry = value['exact_userspace_loss_witnesses']['entries'][0]
        self.assertEqual('PERIODIC_SAMPLE', entry['quarantine_selection'])
        self.assertFalse(entry['durable_raw'])
        self.assertEqual(0, value['durable_unique_events'])

    def test_failed_seal_remains_unknown_future(self):
        self.checkpoint(seal=True, state='FAILED')
        self.commit()
        value = self.report()
        self.assertFalse(value['clean_seal'])
        self.assertFalse(value['absence_set_complete'])
        self.assertIsNone(value['unknown_future']['count'])

    def test_clean_seal_unsequenced_faults_remain_separate(self):
        self.checkpoint(seal=True, faults=[1, 7, 0, 0])
        self.commit()
        value = self.report()
        self.assertTrue(value['absence_set_complete'])
        self.assertEqual(3, value['tenant_evidence'][0]['final_absence']['count'])
        self.assertIsNone(value['unsequenced_faults']['affected_event_ids'])
        self.assertEqual('UNKNOWN', value['tenant_evidence'][0]['final_absence']['ranges'][0]['reason'])

    def test_post_sequence_fault_is_not_classified_as_unsequenced(self):
        self.checkpoint(seal=True, faults=[0, 0, 0, 8])
        self.commit()
        value = self.report()
        self.assertEqual(0, sum(value['unsequenced_faults']['counters'].values()))
        self.assertEqual(8, value['sequenced_aggregate_faults']['counters']['shared_critical_budget_lookup_failed'])
        self.assertEqual('UNKNOWN', value['tenant_evidence'][0]['final_absence']['ranges'][0]['reason'])

    def test_overflow_degrades_reasons_not_complete_sealed_absence(self):
        self.checkpoint(seal=True, metadata_overflow=5, metadata_dropped=5, exact_loss_available=False)
        self.commit()
        value = self.report()
        self.assertTrue(value['absence_set_complete'])
        self.assertFalse(value['userspace_loss_reason_coverage_complete'])
        self.assertEqual(0, value['exact_userspace_loss_count'])
        self.assertTrue(any('COVERAGE_DEGRADED' in warning for warning in value['warnings']))

    def test_map_snapshot_incomplete_prevents_exact_absence(self):
        self.checkpoint(seal=True, sequence_snapshot_complete=False)
        self.commit()
        self.assertFalse(self.report()['absence_set_complete'])

    def test_uint64_sequence_bound_does_not_require_enumeration(self):
        self.checkpoint(sequence=2**64-1, seal=True)
        self.commit()
        value = self.report()['tenant_evidence'][0]['final_absence']
        self.assertEqual(2**64-1, value['count'])
        self.assertEqual(1, value['range_count'])

    def test_duplicate_tombstone_is_idempotent_conflict_invalid(self):
        self.loss()
        self.loss()
        self.checkpoint()
        self.commit()
        value = self.report()
        self.assertEqual(1, value['duplicate_loss_records'])
        self.assertEqual(1, value['exact_userspace_loss_count'])
        self.frames = []
        self.loss()
        self.loss(reason='PERSIST_FAILED')
        self.checkpoint()
        self.commit()
        self.assertEqual('INVALID', self.report()['status'])

    def test_loss_and_durable_same_id_is_conflicting_evidence(self):
        (self.run / 'critical.raw').write_bytes(self.raw(seq=2))
        self.loss()
        self.checkpoint(critical=ledger.RECORD_SIZE, seal=True)
        self.commit()
        self.assertIn('contradicts', self.report()['errors'][0])

    def test_committed_crc_or_truncated_frame_is_invalid(self):
        self.checkpoint()
        self.commit()
        path = self.run / 'evidence.meta'
        raw = bytearray(path.read_bytes())
        raw[-1] ^= 1
        path.write_bytes(raw)
        self.assertIn('CRC32', self.report()['errors'][0])
        path.write_bytes(raw[:-1])
        self.assertIn('shorter', self.report()['errors'][0])

    def test_invalid_raw_reports_only_verified_prefix_without_modifying_source(self):
        good = self.raw()
        broken = bytearray(self.raw(seq=2))
        broken[40] ^= 1
        original = good + broken
        (self.run / 'critical.raw').write_bytes(original)
        self.checkpoint(critical=2 * ledger.RECORD_SIZE)
        self.commit()
        value = self.report()
        self.assertEqual('INVALID', value['status'])
        self.assertEqual('DIAGNOSTIC_ONLY_NOT_PARTIAL_RECOVERY',
                         value['verification_progress']['scope'])
        self.assertEqual(ledger.RECORD_SIZE,
                         value['verification_progress']['raw_verified_prefix_bytes']['critical'])
        self.assertEqual(len(b''.join(self.frames)),
                         value['verification_progress']['journal_verified_prefix_bytes'])
        self.assertEqual(original, (self.run / 'critical.raw').read_bytes())

    def test_invalid_committed_journal_reports_last_verified_frame(self):
        self.checkpoint()
        first = self.frames[0]
        self.checkpoint(sequence=4)
        self.commit()
        journal = self.run / 'evidence.meta'
        broken = bytearray(journal.read_bytes())
        broken[-1] ^= 1
        journal.write_bytes(broken)
        value = self.report()
        self.assertEqual('INVALID', value['status'])
        self.assertEqual(len(first), value['verification_progress']['journal_verified_prefix_bytes'])
        self.assertEqual(1, value['verification_progress']['journal_verified_frames'])

    def test_fence_sequence_boundary_and_lineage_cannot_be_forged_by_suffix(self):
        self.checkpoint()
        self.commit()
        fence = json.loads((self.run / 'evidence.meta.commit').read_text())
        fence['journal_seq'] = 2
        self.write_json('evidence.meta.commit', fence)
        self.assertEqual('INVALID', self.report()['status'])
        self.commit()
        fence = json.loads((self.run / 'evidence.meta.commit').read_text())
        fence['manifest_sha256'] = 'f' * 64
        self.write_json('evidence.meta.commit', fence)
        self.assertIn('lineage', self.report()['errors'][0])

    def test_snapshot_raw_offset_alignment_and_short_file_are_invalid(self):
        self.checkpoint(critical=1)
        self.commit()
        self.assertIn('aligned', self.report()['errors'][0])
        self.frames = []
        self.checkpoint(critical=ledger.RECORD_SIZE)
        self.commit()
        self.assertIn('shorter', self.report()['errors'][0])

    def test_records_after_seal_and_regressed_offsets_are_invalid(self):
        self.checkpoint(seal=True)
        self.loss()
        self.commit()
        self.assertIn('terminal seal', self.report()['errors'][0])
        self.frames = []
        self.checkpoint(critical=ledger.RECORD_SIZE)
        self.checkpoint(critical=0)
        self.commit()
        self.assertIn('regressed', self.report()['errors'][0])

    def test_final_snapshot_cannot_omit_or_underbound_durable_tenant(self):
        (self.run / 'critical.raw').write_bytes(self.raw(seq=5))
        self.checkpoint(sequence=3, critical=ledger.RECORD_SIZE, seal=True)
        self.commit()
        self.assertIn('exceeds final', self.report()['errors'][0])

    def test_output_refuses_source_mutation_and_existing_report(self):
        self.checkpoint()
        self.commit()
        with self.assertRaises(ledger.LedgerError):
            ledger.recover(self.run, self.run / 'recovery.json')
        path = self.root / 'recovery.json'
        ledger.recover(self.run, path)
        with self.assertRaises(FileExistsError):
            ledger.recover(self.run, path)


if __name__ == '__main__':
    unittest.main()
