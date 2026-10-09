import copy
import json
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib
import manage as eq


def record(seq=1, priority=1, path=b'/tmp/file', schema=1, quality=0):
    payload = eq.EVENT.pack(10, 20, seq, 30, 0, 0x31514f45, schema, 2, priority,
                            40, 40, 1000, 1, 0, 0, len(path), quality, b'test', path)
    return payload + struct.pack('<II', zlib.crc32(payload), 0)


class DataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='eq-unit-')
        self.run = Path(self.temp.name)
        self.cfg = eq.config(eq.ROOT / 'config.json')
        eq.atomic_json(self.run / 'config.json', self.cfg)
        eq.atomic_json(self.run / 'manifest.json', dict(run_id='test', config_sha256='cfg', bpf_sha256='obj'))
        (self.run / 'critical.raw').write_bytes(b'')
        (self.run / 'general.raw').write_bytes(record())
        self.health = dict(state='STOPPED', durable={'critical.raw': 0, 'general.raw': 240})
        self.save_health()

    def tearDown(self):
        self.temp.cleanup()

    def save_health(self):
        eq.atomic_json(self.run / 'health.json', self.health)

    def rows(self):
        with sqlite3.connect(self.run / 'index.sqlite') as db:
            return db.execute('SELECT count(*) FROM events').fetchone()[0]

    def test_abi(self):
        self.assertEqual(eq.RECORD_SIZE, 240)
        self.assertEqual(eq.decode_record(record())['uid'], 1000)

    def test_crc(self):
        raw = bytearray(record()); raw[20] ^= 1
        with self.assertRaises(ValueError): eq.decode_record(raw)

    def test_partial(self):
        with self.assertRaises(ValueError): eq.decode_record(record()[:-1])

    def test_query_and_restart(self):
        self.assertEqual(eq.index_batch(self.run), 1)
        self.assertEqual(eq.index_batch(self.run), 0)
        self.assertEqual(self.rows(), 1)
        result = eq.query(self.run)
        self.assertEqual(result['records'][0]['path'], '/tmp/file')
        self.assertTrue(result['search_complete_to_durable'])
        self.assertEqual(result['index']['lag_records'], 0)
        self.assertEqual(eq.query(self.run, critical=True)['zero_results_mean'],
                         'ABSENT_FROM_INDEXED_DURABLE_RAW_ONLY')

    def test_cursor_replay_dedup(self):
        eq.index_batch(self.run)
        with sqlite3.connect(self.run / 'index.sqlite') as db:
            db.execute('DELETE FROM cursor')
        eq.index_batch(self.run)
        self.assertEqual(self.rows(), 1)

    def test_no_undurable_tail_promotion(self):
        (self.run / 'general.raw').write_bytes(record() + record(2) + b'partial')
        eq.index_batch(self.run)
        self.assertEqual(self.rows(), 1)
        self.assertEqual((self.run / 'general.raw').stat().st_size, 487)

    def test_short_committed_file_rejected(self):
        self.health['durable']['general.raw'] = 480; self.save_health()
        with self.assertRaises(ValueError): eq.index_batch(self.run)

    def test_corruption_rolls_back_batch(self):
        raw = bytearray(record(2)); raw[90] ^= 1
        (self.run / 'general.raw').write_bytes(record() + raw)
        self.health['durable']['general.raw'] = 480; self.save_health()
        with self.assertRaises(ValueError): eq.index_batch(self.run)
        self.assertEqual(self.rows(), 0)

    def test_duplicate_payload_conflict(self):
        (self.run / 'general.raw').write_bytes(record() + record(path=b'/different'))
        self.health['durable']['general.raw'] = 480; self.save_health()
        with self.assertRaisesRegex(ValueError, 'payload'): eq.index_batch(self.run)
        self.assertEqual(self.rows(), 0)

    def test_lineage(self):
        eq.index_batch(self.run)
        eq.atomic_json(self.run / 'manifest.json', dict(run_id='other', config_sha256='cfg', bpf_sha256='obj'))
        with self.assertRaises(ValueError): eq.index_batch(self.run)

    def test_bounded_batch(self):
        (self.run / 'general.raw').write_bytes(b''.join(record(i) for i in range(1, 11)))
        self.health['durable']['general.raw'] = 2400; self.save_health()
        self.assertEqual(eq.index_batch(self.run, max_records=6), 3)
        self.assertEqual(self.rows(), 3)
        index = eq.read_json(self.run / 'index-health.json')
        self.assertEqual(index['state'], 'INDEX_LAG')
        self.assertEqual(index['lane_coverage']['general.raw']['lag_records'], 7)
        self.assertEqual(eq.status(self.run)['index']['lag_records'], 7)
        query = eq.query(self.run, critical=True)
        self.assertFalse(query['search_complete_to_durable'])
        self.assertEqual(query['zero_results_mean'], 'INDEX_INCOMPLETE_OR_RUN_OPEN')

    def test_bounded_final_catchup_and_resume(self):
        (self.run / 'general.raw').write_bytes(b''.join(record(i) for i in range(1, 11)))
        self.health['durable']['general.raw'] = 2400; self.save_health()
        original = eq.index_batch
        with patch.object(eq, 'index_batch', side_effect=lambda run: original(run, max_records=2)):
            eq.index_run(self.run, max_seconds=0)
        self.assertEqual(eq.read_json(self.run / 'index-health.json')['state'], 'INDEX_LAG')
        self.assertEqual(self.rows(), 1)
        eq.index_run(self.run, max_seconds=5)
        self.assertEqual(self.rows(), 10)
        self.assertEqual(eq.read_json(self.run / 'index-health.json')['state'], 'INDEX_COMPLETE')
        self.assertTrue(eq.query(self.run)['search_complete_to_durable'])

    def test_read_only_raw_search_reports_partial_and_exact_hit(self):
        source = record() + record(2, path=b'/tmp/marker')
        (self.run / 'general.raw').write_bytes(source)
        self.health['durable']['general.raw'] = len(source); self.save_health()
        limited = eq.raw_search(self.run, '/tmp/marker', max_bytes=eq.RECORD_SIZE)
        self.assertFalse(limited['search_complete_to_durable'])
        self.assertEqual(limited['limit_reason'], 'MAX_BYTES')
        self.assertEqual(limited['records'], [])
        found = eq.raw_search(self.run, '/tmp/marker')
        self.assertTrue(found['search_complete_to_durable'])
        self.assertEqual([row['sequence'] for row in found['records']], [2])
        self.assertEqual((self.run / 'general.raw').read_bytes(), source)
        self.assertFalse((self.run / 'index.sqlite').exists())

    def test_live_caught_up_is_not_final_search(self):
        self.health['state'] = 'RUNNING'; self.save_health()
        eq.index_batch(self.run)
        self.assertEqual(eq.read_json(self.run / 'index-health.json')['state'], 'LIVE_CAUGHT_UP')
        self.assertFalse(eq.query(self.run)['search_complete_to_durable'])

    def test_critical_lane(self):
        (self.run / 'critical.raw').write_bytes(record(2, priority=2))
        self.health['durable']['critical.raw'] = 240; self.save_health()
        eq.index_batch(self.run)
        self.assertEqual(len(eq.query(self.run, critical=True)['records']), 1)

    def test_wrong_lane(self):
        (self.run / 'general.raw').write_bytes(record(priority=2))
        with self.assertRaisesRegex(ValueError, 'lane'): eq.index_batch(self.run)

    def test_invalid_config(self):
        for key, value in [('bulk_rate', 0), ('bulk_burst', True), ('max_raw_mib', 2048),
                           ('protected_path', '/a/../b'), ('protected_path', '/'+'x'*127),
                           ('critical_reserve_mib', 512), ('critical_rate_threshold', 0),
                           ('critical_rate_duration_seconds', 61), ('critical_recovery_threshold', True),
                           ('critical_recovery_threshold', 10000), ('quarantine_initial_full_events', 65),
                           ('quarantine_sample_interval_ms', 1), ('quarantine_max_mib', 257),
                           ('metadata_max_mib', 7)]:
            cfg = dict(self.cfg, **{key: value})
            eq.atomic_json(self.run / 'config.json', cfg)
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                eq.config(self.run / 'config.json')

    def test_legacy_config_gets_quarantine_defaults(self):
        old = {key: self.cfg[key] for key in eq.REQUIRED_KEYS}
        eq.atomic_json(self.run / 'config.json', old)
        normalized = eq.config(self.run / 'config.json')
        for key, value in eq.POLICY_DEFAULTS.items():
            self.assertEqual(normalized[key], value)
        self.assertEqual(normalized['critical_rules'][0]['path'], old['protected_path'])

    def test_removed_cgroup_guard_is_not_reenabled(self):
        for key in ('critical_rate', 'critical_burst', 'shared_critical_rate',
                    'shared_critical_burst', 'protected_cgroup_id'):
            eq.atomic_json(self.run / 'config.json', dict(self.cfg, **{key: 1}))
            with self.subTest(key=key), self.assertRaises(ValueError):
                eq.config(self.run / 'config.json')

    def test_rule_identity_and_protected_boolean_validation(self):
        rule = dict(id=1, event_type='openat', path='/tmp/first', protected=False)
        for rules in ([rule, rule], [dict(rule, id=0)], [dict(rule, protected=1)],
                      [dict(rule, event_type='credential_change')], None):
            eq.atomic_json(self.run / 'config.json', dict(self.cfg, critical_rules=rules))
            with self.subTest(rules=rules), self.assertRaises(ValueError):
                eq.config(self.run / 'config.json')

    def test_quarantine_original_priority_and_index_lane(self):
        flags = (7 << 16) | eq.Q_QUARANTINED | eq.Q_PERIODIC
        raw = record(2, priority=2, schema=2, quality=flags)
        decoded = eq.decode_record(raw)
        self.assertEqual(decoded['original_priority'], 2)
        self.assertEqual(decoded['effective_policy'], 'QUARANTINE')
        self.assertEqual(decoded['rule_id'], 7)
        (self.run / 'quarantine.raw').write_bytes(raw)
        self.health['durable']['quarantine.raw'] = 240; self.save_health()
        eq.index_batch(self.run)
        self.assertEqual(eq.query(self.run, critical=True)['records'][0]['effective_policy'], 'QUARANTINE')

    def test_invalid_schema2_policy_combinations(self):
        for quality in ((1 << 16) | eq.Q_QUARANTINED,
                        (1 << 16) | eq.Q_INITIAL,
                        (1 << 16) | eq.Q_QUARANTINED | eq.Q_INITIAL | eq.Q_PROTECTED):
            with self.subTest(quality=quality), self.assertRaises(ValueError):
                eq.decode_record(record(priority=2, schema=2, quality=quality))

    def test_protected_tracking_failure_does_not_quarantine(self):
        event = eq.decode_record(record(priority=2, schema=2,
                                 quality=(1 << 16) | eq.Q_PROTECTED | eq.Q_UNTRACKED))
        self.assertEqual(event['effective_policy'], 'PROTECTED_CRITICAL')
        self.assertFalse(event['stream_tracking_complete'])

    def test_recover_rejects_output_inside_source(self):
        # This exercises CLI placement without opening or repairing journal files.
        with patch('sys.argv', ['manage.py', 'recover', '--run-dir', str(self.run),
                                '--out', str(self.run / 'report.json')]):
            with self.assertRaisesRegex(ValueError, 'outside'):
                eq.main()
        self.assertFalse((self.run / 'report.json').exists())

    def test_unknown_and_duplicate_config(self):
        cfg = dict(self.cfg, unexpected=True)
        eq.atomic_json(self.run / 'config.json', cfg)
        with self.assertRaises(ValueError): eq.config(self.run / 'config.json')
        (self.run / 'config.json').write_text('{"bulk_rate":1,"bulk_rate":2}')
        with self.assertRaisesRegex(ValueError, '중복'): eq.config(self.run / 'config.json')

    def test_process_identity(self):
        own = eq.identity()
        self.assertTrue(eq.alive(own))
        self.assertFalse(eq.alive(dict(own, start='wrong')))
        self.assertFalse(eq.alive(dict(own, boot='wrong')))

    def test_lock_contention(self):
        with eq.lock(self.run / 'lock'):
            with self.assertRaises(RuntimeError):
                with eq.lock(self.run / 'lock'): pass

    def test_stale_health(self):
        eq.atomic_json(self.run / 'service.json', dict(supervisor=eq.identity(), collector=eq.identity()))
        self.health.update(state='RUNNING', monotonic_ms=0); self.save_health()
        self.assertEqual(eq.status(self.run)['state'], 'STALE_HEARTBEAT')

    def test_storage_usage_counts_sqlite_sidecars_and_exports(self):
        (self.run / 'index.sqlite-wal').write_bytes(b'w' * 32)
        (self.run / 'index.sqlite-journal').write_bytes(b'j' * 48)
        (self.run / 'evidence.meta').write_bytes(b'm' * 16)
        export = self.run / 'export'
        export.mkdir()
        (export / 'snapshot.json').write_bytes(b'e' * 64)
        usage = eq.storage_usage(self.run)
        categories = usage['categories']
        self.assertEqual(80, categories['sqlite_sidecars_temp']['logical_bytes'])
        self.assertEqual(64, categories['export_derived']['logical_bytes'])
        self.assertGreaterEqual(categories['metadata_control']['logical_bytes'], 16)
        self.assertTrue(usage['allocation_total_complete'])
        self.assertFalse(usage['critical_reserve_physical'])
        self.assertTrue(usage['external_writers_can_exhaust_filesystem'])
        self.assertFalse(eq.storage_usage(self.run, max_entries=2)['allocation_total_complete'])

    def test_storage_pressure_pauses_index_with_hysteresis(self):
        threshold = self.cfg['minimum_free_mib'] * 1024**2
        with patch.object(eq, 'filesystem_free_bytes', return_value=threshold - 1):
            self.assertEqual(eq.index_batch(self.run), 0)
        self.assertFalse((self.run / 'index.sqlite').exists())
        self.assertEqual(eq.read_json(self.run / 'index-health.json')['state'],
                         'INDEX_PAUSED_STORAGE_PRESSURE')
        with patch.object(eq, 'filesystem_free_bytes', return_value=threshold + 4 * 1024**2):
            self.assertEqual(eq.index_batch(self.run), 0)
        self.assertFalse((self.run / 'index.sqlite').exists())
        with patch.object(eq, 'filesystem_free_bytes', return_value=threshold + 8 * 1024**2):
            self.assertEqual(eq.index_batch(self.run), 1)
        self.assertEqual(self.rows(), 1)
        self.assertEqual(eq.read_json(self.run / 'index-health.json')['state'], 'INDEX_COMPLETE')

    def test_enospc_stderr_overrides_stale_running_health(self):
        self.health.update(state='RUNNING', monotonic_ms=0)
        self.save_health()
        (self.run / 'collector.log').write_text('collector failed: No space left on device (28)\n')
        result = eq.status(self.run)
        self.assertEqual(result['state'], 'FAILED_STORAGE_ENOSPC')
        self.assertEqual(result['failure_evidence']['evidence_sources'],
                         ['COLLECTOR_STDERR_ERRNO_28'])


if __name__ == '__main__': unittest.main()
