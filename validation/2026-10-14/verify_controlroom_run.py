#!/usr/bin/env python3
"""Read-only raw/index/ledger cross-check for a stopped Control Room smoke run."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--probe-path', required=True)
    parser.add_argument('--rule-id', type=int, required=True)
    parser.add_argument('--manager', type=Path, default=Path('/opt/mglogwh/manage.py'))
    args = parser.parse_args()
    run_dir = args.run_dir.resolve(strict=True)
    manager_path = args.manager.resolve(strict=True)
    spec = importlib.util.spec_from_file_location('mglogwh_live_manager', manager_path)
    manager = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manager)

    health = json.loads((run_dir / 'health.json').read_text())
    index = json.loads((run_dir / 'index-health.json').read_text())
    manifest = json.loads((run_dir / 'manifest.json').read_text())
    raw_targets = []
    raw_count = 0
    raw_hashes = {}
    for lane in manager.LANES:
        path = run_dir / lane
        boundary = health.get('durable', {}).get(lane)
        if type(boundary) is not int or boundary < 0 or boundary % manager.RECORD_SIZE or boundary > path.stat().st_size:
            raise ValueError(f'invalid durable boundary: {lane}')
        raw_hashes[lane] = digest(path)
        with path.open('rb') as stream:
            for _ in range(boundary // manager.RECORD_SIZE):
                payload = stream.read(manager.RECORD_SIZE)
                event = manager.decode_record(payload)
                raw_count += 1
                if event['path'] == args.probe_path:
                    raw_targets.append((lane, event['rule_id'], event['priority_name'], payload))

    database = sqlite3.connect((run_dir / 'index.sqlite').as_uri() + '?mode=ro', uri=True)
    try:
        database.execute('PRAGMA query_only=ON')
        indexed_count = database.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        rows = database.execute('SELECT rowid,payload FROM events WHERE path=? ORDER BY rowid',
                                (args.probe_path,)).fetchall()
    finally:
        database.close()
    index_targets = [(rowid, manager.decode_record(payload), payload) for rowid, payload in rows]

    recovery = subprocess.run([sys.executable, str(manager_path), 'recover', '--run-dir', str(run_dir)],
                              capture_output=True, text=True, timeout=45, check=False,
                              env={**os.environ, 'MGLOGWH_DATA_DIR': str(run_dir.parent.parent)})
    report = json.loads(recovery.stdout)
    raw_target_payloads = sorted(item[3] for item in raw_targets)
    index_target_payloads = sorted(item[2] for item in index_targets)
    passed = (health.get('state') == 'STOPPED' and
              index.get('complete_to_durable') is True and
              manifest.get('config_sha256') == health.get('config_sha256') and
              recovery.returncode == 0 and report.get('status') == 'RECOVERED' and
              raw_count == indexed_count == index.get('indexed_records') and
              len(raw_targets) >= 1 and raw_target_payloads == index_target_payloads and
              all(rule == args.rule_id and priority == 'CRITICAL' and lane == 'critical.raw'
                  for lane, rule, priority, _ in raw_targets))
    result = dict(status='PASS' if passed else 'FAIL', run_dir=str(run_dir),
                  manager_sha256=digest(manager_path), manifest_sha256=digest(run_dir / 'manifest.json'),
                  config_sha256=manifest.get('config_sha256'), health_state=health.get('state'),
                  index_complete_to_durable=index.get('complete_to_durable'),
                  recover_status=report.get('status'), recover_errors=report.get('errors'),
                  raw_records=raw_count, indexed_records=indexed_count,
                  probe_path=args.probe_path, rule_id=args.rule_id,
                  raw_probe_records=len(raw_targets), index_probe_records=len(index_targets),
                  probe_rowids=[rowid for rowid, _, _ in index_targets], raw_sha256=raw_hashes)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
