"""Bounded, benign integration check; creates no flood or exploit workloads.

Run explicitly as WSL root. Refuses to disturb an already active sensor.
Leaves its test run and a JSON report for inspection, then stops collection.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import manage as eq


def main():
    existing = eq.current()
    if existing and eq.alive(eq.read_json(existing / 'service.json', {}).get('supervisor')):
        raise RuntimeError('기존 수집이 실행 중입니다. 테스트가 중지시키지 않습니다.')
    command = [sys.executable, str(eq.ROOT / 'manage.py')]
    def cli(action, check=True):
        value = subprocess.run(command + [action], capture_output=True, text=True, timeout=25)
        if check and value.returncode:
            raise RuntimeError(value.stderr)
        return value
    cli('start')
    run = eq.current()
    report = dict(run_id=run.name, kernel=os.uname().release)
    try:
        duplicate = cli('start', check=False)
        assert duplicate.returncode != 0
        report['duplicate_start_rejected'] = True
        cfg = eq.read_json(run / 'config.json')
        # A read-only attempt to the configured path is critical even if absent.
        try:
            fd = os.open(cfg['protected_path'], os.O_RDONLY | os.O_NONBLOCK)
            os.close(fd)
        except OSError:
            pass
        subprocess.run(['/usr/bin/true'], check=True)
        time.sleep(2)
        state = eq.status(run)
        assert state['state'] == 'RUNNING', state
        assert state['collector']['durable']['critical.raw'] >= 240
        report['critical_capture'] = True
        service = eq.read_json(run / 'service.json')
        assert eq.alive(service['indexer'])
        fd = os.pidfd_open(service['indexer']['pid'])
        try:
            assert eq.alive(service['indexer'])
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        finally:
            os.close(fd)
        before = sum(state['collector']['durable'].values())
        subprocess.run(['/usr/bin/id'], check=True, stdout=subprocess.DEVNULL)
        time.sleep(2)
        state = eq.status(run)
        assert state['state'] == 'RUNNING'
        assert sum(state['collector']['durable'].values()) > before
        assert state['index']['state'] == 'UNAVAILABLE'
        report['indexer_failure_raw_continues'] = True
    finally:
        cli('stop')
    final = eq.status(run)
    assert final['state'] == 'STOPPED', final
    cli('index')
    final = eq.status(run)
    assert final['index']['lag_bytes'] == 0, final
    count = final['index']['indexed_records']
    cli('index')
    assert eq.status(run)['index']['indexed_records'] == count
    report.update(index_resume_no_duplicates=True, indexed_records=count,
                  received=final['collector']['received'], durable=final['collector']['durable'],
                  cpu_seconds=final['collector']['cpu_seconds'], max_rss_kib=final['collector']['max_rss_kib'])
    critical = json.loads(cli('critical').stdout)['records']
    own_start = int(eq.identity()['start'])
    ticks = os.sysconf('SC_CLK_TCK')
    # Event PIDs belong to the host namespace, not this WSL namespace.
    assert any(e['path'] == cfg['protected_path'] and e['comm'] == 'python3' and
               abs(e['process_start_ns'] * ticks // 1000000000 - own_start) <= 1 for e in critical)
    report['critical_query'] = True
    collector_records = 0
    for lane in eq.LANES:
        with (run / lane).open('rb') as file:
            for raw in iter(lambda: file.read(eq.RECORD_SIZE), b''):
                if eq.decode_record(raw)['comm'] == 'collector': collector_records += 1
    assert collector_records == 0
    report['collector_self_exclusion'] = True
    report['final_state'] = final['state']
    eq.atomic_json(run / 'test-report.json', report)
    print(json.dumps(report, indent=2))


if __name__ == '__main__': main()
