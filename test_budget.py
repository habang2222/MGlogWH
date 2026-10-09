"""Four ordinary failed opens with a deliberately tiny local test budget."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import manage as eq


def main():
    run = eq.current()
    if run and eq.alive(eq.read_json(run / 'service.json', {}).get('supervisor')):
        raise RuntimeError('실행 중 수집을 변경하지 않습니다.')
    cmd = [sys.executable, str(eq.ROOT / 'manage.py')]
    cfg = dict(eq.config(eq.ROOT / 'config.json'), bulk_rate=1, bulk_burst=1)
    with tempfile.TemporaryDirectory(prefix='eq-budget-test-') as folder:
        cfg_path = Path(folder) / 'config.json'
        cfg_path.write_text(json.dumps(cfg))
        subprocess.run(cmd + ['start', '--config', str(cfg_path)], check=True, stdout=subprocess.DEVNULL)
        run = eq.current()
        try:
            def attempt(path):
                try:
                    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK); os.close(fd)
                except OSError:
                    pass
            attempt(cfg['protected_path'])
            time.sleep(1.2)
            critical = eq.query(run, critical=True)['records']
            ticks = os.sysconf('SC_CLK_TCK')
            start = int(eq.identity()['start'])
            event = next(e for e in critical if abs(e['process_start_ns'] * ticks // 1000000000 - start) <= 1)
            cg = event['cgroup_id']
            before = next(t for t in eq.status(run)['collector']['tenants'] if t['cgroup_id'] == cg)['budget_suppress']
            for i in range(4):
                attempt(str(Path(folder) / f'absent-{i}'))
            time.sleep(1.2)
            after = next(t for t in eq.status(run)['collector']['tenants'] if t['cgroup_id'] == cg)['budget_suppress']
            assert after - before >= 3, (before, after)
            report = dict(run_id=run.name, cgroup_id=cg, test_rate=1, test_burst=1,
                          test_failed_opens=4, observed_suppression_delta=after-before,
                          note='Delta may include unrelated same-cgroup opens; not an exact loss benchmark.')
        finally:
            subprocess.run(cmd + ['stop'], check=True, stdout=subprocess.DEVNULL)
        eq.atomic_json(run / 'budget-test-report.json', report)
        print(json.dumps(report, indent=2))


if __name__ == '__main__': main()
