#!/usr/bin/env python3
"""Bounded v0.4.0 openat retention/performance comparison.

Run as root after compiling an immutable source archive and bench_workload.c
as an unprivileged user.  Set MGLOGWH_BENCH_SOURCE, MGLOGWH_BENCH_BUILD,
MGLOGWH_BENCH_DATA, MGLOGWH_BENCH_DECOY, and MGLOGWH_BENCH_HEAD.  The decoy
directory must contain regular files `critical` and `normal` but no
`bulk-missing`.  Optional MGLOGWH_BENCH_OUTPUT defaults to `final` beside this
script.  The sensor run directory is outside the repository.  No prior run
or output file is deleted or overwritten.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import traceback

SOURCE = Path(os.environ['MGLOGWH_BENCH_SOURCE']).resolve()
BUILD = Path(os.environ['MGLOGWH_BENCH_BUILD']).resolve()
OUTPUT = Path(os.environ.get('MGLOGWH_BENCH_OUTPUT', Path(__file__).resolve().parent / 'final')).resolve()
DATA = Path(os.environ['MGLOGWH_BENCH_DATA']).resolve()
DECOY = Path(os.environ['MGLOGWH_BENCH_DECOY']).resolve()
PATHS = [str(DECOY / 'bulk-missing'), str(DECOY / 'critical'), str(DECOY / 'normal')]
EXPECTED_HEAD = os.environ['MGLOGWH_BENCH_HEAD']
SECONDS = 5
RATES = (15000, 100, 250)
ORDER = [('baseline', 1), ('rule1', 1), ('rule4', 1), ('rule8', 1),
         ('rule8', 2), ('rule4', 2), ('rule1', 2), ('baseline', 2),
         ('rule1', 3), ('baseline', 3), ('rule8', 3), ('rule4', 3)]


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as file:
        json.dump(value, file, ensure_ascii=False, indent=2, sort_keys=True)
        file.write('\n')


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def run(args, *, timeout=25, env=None):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
    if p.returncode:
        raise RuntimeError(f'command {args!r} exited {p.returncode}: {p.stderr[-4000:]} {p.stdout[-1000:]}')
    return p.stdout


def free_resources():
    mem = Path('/proc/meminfo').read_text()
    available_kib = int(next(line.split()[1] for line in mem.splitlines() if line.startswith('MemAvailable:')))
    d = shutil.disk_usage(DATA.parent)
    return dict(memory_available_kib=available_kib, filesystem_free_bytes=d.free,
                filesystem_total_bytes=d.total)


def config_for(name):
    source = json.loads((SOURCE / 'config.json').read_text())
    source.pop('critical_rules', None)
    source['protected_path'] = PATHS[1]
    source.update(bulk_rate=1000000, bulk_burst=1000000,
                  max_raw_mib=128, critical_reserve_mib=32,
                  max_index_mib=64, minimum_free_mib=256,
                  metadata_max_mib=8, quarantine_max_mib=8,
                  critical_rate_threshold=1000000,
                  critical_rate_duration_seconds=1)
    count = {'baseline': 0, 'rule1': 1, 'rule4': 4, 'rule8': 8}[name]
    if count:
        rules = []
        for index in range(count):
            path = PATHS[1] if index == 0 else str(DECOY / f'unused-{index}')
            rules.append(dict(id=index + 1, enabled=True, precedence=100,
                              priority='CRITICAL', overload_policy='QUARANTINE',
                              when=dict(all=[dict(field='event_type', op='eq', value='openat'),
                                             dict(field='path', op='eq', value=path)])))
        source['event_rules'] = rules
    return source


def load_manage():
    spec = importlib.util.spec_from_file_location('mglogwh_pinned_manage', SOURCE / 'manage.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect_raw(manage, run_dir, health):
    boundaries = health.get('durable', {})
    result = {'crc_and_schema_valid': True, 'records_total': 0, 'by_path': {},
              'by_lane': {}, 'errors': []}
    for lane in manage.LANES:
        path = run_dir / lane
        boundary = boundaries.get(lane)
        if not isinstance(boundary, int) or boundary < 0 or boundary % manage.RECORD_SIZE or path.stat().st_size < boundary:
            result['crc_and_schema_valid'] = False
            result['errors'].append(f'{lane}: invalid durable boundary {boundary}')
            continue
        result['by_lane'][lane] = boundary // manage.RECORD_SIZE
        with path.open('rb') as file:
            for _ in range(boundary // manage.RECORD_SIZE):
                try:
                    event = manage.decode_record(file.read(manage.RECORD_SIZE))
                except Exception as exc:
                    result['crc_and_schema_valid'] = False
                    result['errors'].append(f'{lane}: {exc}')
                    break
                result['records_total'] += 1
                if event['path'] in PATHS:
                    entry = result['by_path'].setdefault(event['path'], dict(total=0, lanes={},
                                                 priorities={}, rule_ids={}))
                    entry['total'] += 1
                    entry['lanes'][lane] = entry['lanes'].get(lane, 0) + 1
                    key = event['priority_name']
                    entry['priorities'][key] = entry['priorities'].get(key, 0) + 1
                    key = str(event['rule_id'])
                    entry['rule_ids'][key] = entry['rule_ids'].get(key, 0) + 1
    return result


def stop_manage(env, run_id):
    return json.loads(run([sys.executable, str(SOURCE / 'manage.py'), 'stop', '--run', run_id],
                          timeout=85, env=env))


def one_run(manage, name, repeat, env, configs):
    label = f'{name}-r{repeat}'
    result = dict(label=label, condition=name, repeat=repeat, started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  config_file=str(configs[name]), config_file_sha256=sha256(configs[name]),
                  resources_before=free_resources(), command=[str(BUILD / 'bench_workload'), *PATHS,
                                                               str(SECONDS), *(str(x) for x in RATES)])
    if result['resources_before']['memory_available_kib'] < 1024 * 1024 or result['resources_before']['filesystem_free_bytes'] < 2 * 1024**3:
        raise RuntimeError('resource guard: <1GiB available RAM or <2GiB disk free')
    start = json.loads(run([sys.executable, str(SOURCE / 'manage.py'), 'start', '--config', str(configs[name])],
                           timeout=25, env=env))
    run_id = start['run_id']
    run_dir = Path(start['run_path'])
    result['run_id'] = run_id
    result['run_dir'] = str(run_dir)
    result['start_state'] = start['state']
    watchdog_triggered = threading.Event()
    stopping = threading.Event()

    def watchdog():
        if not stopping.is_set():
            watchdog_triggered.set()
            try:
                stop_manage(env, run_id)
            except Exception as exc:
                result['watchdog_stop_error'] = str(exc)

    timer = threading.Timer(20, watchdog)
    timer.daemon = True
    timer.start()
    try:
        if start['state'] != 'RUNNING':
            raise RuntimeError('collector did not enter RUNNING')
        time.sleep(0.5)
        output = run(result['command'], timeout=SECONDS + 8)
        result['truth'] = json.loads(output)
    finally:
        stopping.set()
        timer.cancel()
        result['watchdog_triggered'] = watchdog_triggered.is_set()
        try:
            result['stop_status'] = stop_manage(env, run_id)
        except Exception as exc:
            result['stop_error'] = str(exc)
    health = json.loads((run_dir / 'health.json').read_text())
    manifest = json.loads((run_dir / 'manifest.json').read_text())
    index = json.loads((run_dir / 'index-health.json').read_text()) if (run_dir / 'index-health.json').exists() else {}
    result['health'] = health
    result['manifest_sha256'] = sha256(run_dir / 'manifest.json')
    result['normalized_config_sha256'] = manifest['config_sha256']
    result['rules_bin_sha256'] = manifest.get('rules_bin_sha256')
    result['index_health'] = index
    result['raw'] = inspect_raw(manage, run_dir, health)
    result['resources_after'] = free_resources()
    result['raw_file_bytes'] = {lane: (run_dir / lane).stat().st_size for lane in manage.LANES}
    result['index_file_bytes'] = (run_dir / 'index.sqlite').stat().st_size if (run_dir / 'index.sqlite').exists() else None
    try:
        recover = run([sys.executable, str(SOURCE / 'manage.py'), 'recover', '--run-dir', str(run_dir)],
                      timeout=45, env=env)
        report = json.loads(recover)
        result['recover_status'] = report.get('status')
        result['recover_report'] = report
    except Exception as exc:
        result['recover_error'] = str(exc)
    truth = result.get('truth', {})
    critical = result['raw']['by_path'].get(PATHS[1], {}).get('total', 0)
    expected_critical = truth.get('expected_results', [None, None])[1]
    result['critical_truth_count'] = expected_critical
    result['critical_durable_count'] = critical
    result['critical_durable_recall'] = critical / expected_critical if expected_critical else None
    result['critical_count_difference'] = expected_critical - critical if expected_critical is not None else None
    result['target_actual_eps'] = truth.get('actual_eps')
    result['target_requested_eps'] = truth.get('requested_eps')
    result['valid_workload'] = (truth.get('unexpected_results') == [0, 0, 0] and
                                truth.get('expected_results') == [RATES[0] * SECONDS, RATES[1] * SECONDS, RATES[2] * SECONDS] and
                                truth.get('actual_eps', 0) >= sum(RATES) * 0.9)
    result['valid_run'] = (result['valid_workload'] and health.get('state') == 'STOPPED' and
                           result['raw']['crc_and_schema_valid'] and not result.get('stop_error') and
                           not result['watchdog_triggered'] and
                           result.get('recover_status') == 'RECOVERED')
    return result


def main():
    if os.geteuid() != 0:
        raise RuntimeError('root is required for BPF load; pilot is separate and unprivileged')
    if not (SOURCE / 'manage.py').exists() or not (BUILD / 'collector').exists():
        raise RuntimeError('pinned source/build absent')
    if not EXPECTED_HEAD or len(EXPECTED_HEAD) != 40 or not all(c in '0123456789abcdef' for c in EXPECTED_HEAD):
        raise RuntimeError('MGLOGWH_BENCH_HEAD must be a lowercase 40-character commit hash')
    if OUTPUT.exists() and any(OUTPUT.iterdir()):
        raise RuntimeError('output directory must be new/empty to preserve previous evidence')
    if DATA.exists() and any(DATA.iterdir()):
        raise RuntimeError('data directory must be new/empty to preserve previous runs')
    if not DATA.is_absolute() or not OUTPUT.is_absolute() or not DECOY.is_absolute():
        raise RuntimeError('benchmark paths must be absolute')
    if not DECOY.joinpath('critical').is_file() or not DECOY.joinpath('normal').is_file() or DECOY.joinpath('bulk-missing').exists():
        raise RuntimeError('decoy workload paths have changed')
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(DATA, 0o700)
    manager = load_manage()
    env = os.environ.copy()
    env.update(MGLOGWH_DATA_DIR=str(DATA), MGLOGWH_BUILD_DIR=str(BUILD))
    build_hashes = {name: sha256(path) for name, path in {
        'collector': BUILD / 'collector', 'bpf_object': BUILD / 'sensor.bpf.o',
        'workload': BUILD / 'bench_workload', 'manage': SOURCE / 'manage.py',
        'sensor_source': SOURCE / 'sensor.bpf.c', 'collector_source': SOURCE / 'collector.c'}.items()}
    write_json(OUTPUT / 'environment.json', dict(expected_head=EXPECTED_HEAD, source_snapshot=str(SOURCE),
               build=str(BUILD), data=str(DATA), decoy_paths=PATHS, kernel=os.uname().release,
               cpu_count=os.cpu_count(), initial_resources=free_resources(), build_hashes=build_hashes,
               condition_order=ORDER, duration_seconds=SECONDS, rates=RATES,
               limits=dict(collector_raw_mib=128, index_main_mib=64, metadata_mib=8,
                           memory_available_floor_mib=1024, disk_free_floor_mib=2048,
                           workload_timeout_seconds=SECONDS + 8, collector_watchdog_seconds=20)))
    configs = {}
    for name in ('baseline', 'rule1', 'rule4', 'rule8'):
        path = OUTPUT / 'configs' / f'{name}.json'
        write_json(path, config_for(name))
        manager.config(path)  # Refuse malformed configs before loading any sensor.
        configs[name] = path
    summaries = []
    for name, repeat in ORDER:
        label = f'{name}-r{repeat}'
        print(f'START {label}', flush=True)
        try:
            result = one_run(manager, name, repeat, env, configs)
            write_json(OUTPUT / 'runs' / f'{label}.json', result)
            summaries.append(dict(label=label, valid_run=result['valid_run'], run_id=result['run_id'],
                                  actual_eps=result['target_actual_eps'],
                                  critical_truth=result['critical_truth_count'],
                                  critical_durable=result['critical_durable_count'],
                                  p95_us=result['truth']['p95_us'], p99_us=result['truth']['p99_us'],
                                  recover_status=result.get('recover_status'),
                                  health_state=result['health'].get('state')))
            print(f'END {label} valid={result["valid_run"]} eps={result["target_actual_eps"]} '
                  f'critical={result["critical_durable_count"]}/{result["critical_truth_count"]}', flush=True)
            if not result['valid_run']:
                print('STOP: invalid condition; remaining cases not run', flush=True)
                break
        except Exception as exc:
            error = dict(label=label, error=str(exc), traceback=traceback.format_exc())
            write_json(OUTPUT / 'runs' / f'{label}-error.json', error)
            summaries.append(error)
            print(f'FAILED {label}: {exc}; remaining cases not run', flush=True)
            break
    write_json(OUTPUT / 'summary.json', dict(conditions=summaries, completed=len(summaries),
               requested=len(ORDER), all_valid=len(summaries) == len(ORDER) and all(x.get('valid_run') for x in summaries)))


if __name__ == '__main__':
    main()
