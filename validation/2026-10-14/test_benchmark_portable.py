"""Check the benchmark's rule-format labels without starting a sensor."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import manage


class BenchmarkConditionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mglogwh-bench-unit-')
        self.addCleanup(self.temp.cleanup)
        work = Path(self.temp.name)
        env = dict(MGLOGWH_BENCH_SOURCE=str(ROOT), MGLOGWH_BENCH_BUILD=str(work / 'build'),
                   MGLOGWH_BENCH_DATA=str(work / 'data'), MGLOGWH_BENCH_DECOY=str(work / 'decoy'),
                   MGLOGWH_BENCH_HEAD='0' * 40, MGLOGWH_BENCH_OUTPUT=str(work / 'out'))
        spec = importlib.util.spec_from_file_location('benchmark_portable',
                                                      Path(__file__).with_name('run_benchmark_portable.py'))
        self.bench = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, env):
            spec.loader.exec_module(self.bench)
        # The product config requires Linux absolute paths even when this unit
        # test runs on Windows.
        self.bench.PATHS = ['/tmp/mglogwh-bench-unit/bulk-missing',
                            '/tmp/mglogwh-bench-unit/critical',
                            '/tmp/mglogwh-bench-unit/normal']
        self.config_path = work / 'config.json'

    def normalized(self, name):
        self.config_path.write_text(json.dumps(self.bench.config_for(name)), encoding='utf-8')
        value = manage.config(self.config_path)
        self.bench.verify_condition(name, value)
        return value

    def test_legacy_condition_has_one_explicit_rule(self):
        value = self.normalized('legacy1')
        self.assertNotIn('event_rules', value)
        self.assertEqual(value['critical_rules'], [dict(id=1, event_type='openat',
                                                        path=self.bench.PATHS[1], protected=False)])
        self.assertEqual(self.bench.RULE_COUNTS['legacy1'], 1)

    @unittest.skipIf(os.name == 'nt', 'event_rules path validation requires POSIX paths')
    def test_advanced_conditions_have_declared_binary_rule_counts(self):
        for name, expected in [('rule1', 1), ('rule4', 4), ('rule8', 8)]:
            with self.subTest(name=name):
                value = self.normalized(name)
                self.assertNotIn('critical_rules', value)
                self.assertEqual(len(value['event_rules']), expected)
                self.assertEqual(struct.unpack('<5I', manage.compile_rule_file(value)[:20])[2], expected)

    def test_mislabeled_legacy_condition_is_rejected(self):
        value = self.normalized('legacy1')
        del value['critical_rules']
        with self.assertRaisesRegex(RuntimeError, 'exactly one'):
            self.bench.verify_condition('legacy1', value)


if __name__ == '__main__':
    unittest.main()
