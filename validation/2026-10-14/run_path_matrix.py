#!/usr/bin/env python3
"""Bounded end-to-end path-rule matrix with independent syscall truth.

Run as root after building the current source. Set MGLOGWH_MATRIX_SOURCE,
MGLOGWH_MATRIX_BUILD, and MGLOGWH_MATRIX_HEAD. Optional
MGLOGWH_MATRIX_USER defaults to nobody; MGLOGWH_MATRIX_OUTPUT defaults to
this script's directory. Every invocation creates unique probe, data, and
evidence paths. It never overwrites or removes an earlier run.
"""

import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid


HERE = Path(__file__).resolve().parent
SOURCE = Path(os.environ['MGLOGWH_MATRIX_SOURCE']).resolve()
BUILD = Path(os.environ['MGLOGWH_MATRIX_BUILD']).resolve()
HEAD = os.environ['MGLOGWH_MATRIX_HEAD']
USER = os.environ.get('MGLOGWH_MATRIX_USER', 'nobody')
OUTPUT_BASE = Path(os.environ.get('MGLOGWH_MATRIX_OUTPUT', HERE)).resolve()
CASE_IDS = {
    'absolute_read': 4,
    'absolute_write': 3,
    'absolute_read_write': 3,
    'absolute_create': 3,
    'absolute_truncate': 3,
    'absolute_o_path': 2,
    'relative_cwd': 1,
    'relative_dirfd': 1,
    'symlink': 4,
    'absolute_outside': 7,
    'long_path': 1,
    'permission_denied': 4,
    'missing': 4,
    'bad_pointer': 1,
    'exec_success': 5,
    'exec_failure': None,
}


def write_json(path, value):
    with path.open('x', encoding='utf-8') as file:
        json.dump(value, file, ensure_ascii=False, indent=2, sort_keys=True)
        file.write('\n')


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def command(label, argv, output, *, env=None, timeout=30):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, env=env,
                           timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        write_json(output / (label + '-timeout.json'),
                   {'argv': argv, 'timeout': timeout, 'error': str(exc)})
        raise
    (output / (label + '.stdout')).write_text(p.stdout, encoding='utf-8')
    (output / (label + '.stderr')).write_text(p.stderr, encoding='utf-8')
    if p.returncode:
        raise RuntimeError(f'{label} exited {p.returncode}: {p.stderr[-1000:]}')
    return p.stdout


def load_manage():
    spec = importlib.util.spec_from_file_location('mglogwh_matrix_manage',
                                                  SOURCE / 'manage.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def config_for(probe_root, binary):
    config = json.loads((SOURCE / 'config.json').read_text(encoding='utf-8'))
    config.pop('critical_rules', None)
    config['protected_path'] = str(probe_root / 'target')
    config.update(bulk_rate=1000000, bulk_burst=1000000, max_raw_mib=64,
                  critical_reserve_mib=16, max_index_mib=32,
                  minimum_free_mib=256, metadata_max_mib=8,
                  quarantine_max_mib=8, critical_rate_threshold=1000000,
                  critical_rate_duration_seconds=1)
    kind_open = {'field': 'event_type', 'op': 'eq', 'value': 'openat'}
    kind_exec = {'field': 'event_type', 'op': 'eq', 'value': 'exec'}
    comm = {'field': 'comm', 'op': 'eq', 'value': 'mgmatrixprobe'}
    prefix = {'field': 'path', 'op': 'prefix', 'value': str(probe_root) + '/'}

    def all_(*nodes):
        return {'all': list(nodes)}

    def rule(identifier, precedence, when):
        return dict(id=identifier, enabled=True, precedence=precedence,
                    priority='CRITICAL', overload_policy='QUARANTINE_EXEMPT',
                    when=when)

    config['event_rules'] = [
        rule(1, 1, all_(kind_open, comm)),
        rule(2, 10, all_(kind_open, comm, prefix)),
        rule(3, 20, all_(kind_open, comm, prefix,
                         {'field': 'write_access', 'op': 'eq', 'value': True})),
        rule(4, 20, all_(kind_open, comm, prefix,
                         {'field': 'access_mode', 'op': 'eq', 'value': 'read'})),
        rule(5, 30, all_(kind_exec,
                         {'field': 'path', 'op': 'eq', 'value': str(binary)})),
        rule(6, 5, all_(kind_open, comm,
                        {'field': 'path', 'op': 'not_in',
                         'value': [str(probe_root / 'target')]})),
        rule(7, 6, all_(kind_open, comm, {'not': prefix})),
    ]
    return config


def read_raw(manage, run_dir, health):
    events = []
    hashes = {}
    for lane in manage.LANES:
        raw_path = run_dir / lane
        boundary = health.get('durable', {}).get(lane)
        if (type(boundary) is not int or boundary < 0 or
                boundary % manage.RECORD_SIZE or raw_path.stat().st_size < boundary):
            raise ValueError(f'invalid durable boundary: {lane} {boundary}')
        hashes[lane] = dict(sha256=sha256(raw_path),
                            durable_bytes=boundary,
                            file_bytes=raw_path.stat().st_size)
        with raw_path.open('rb') as file:
            for offset in range(0, boundary, manage.RECORD_SIZE):
                event = manage.decode_record(file.read(manage.RECORD_SIZE))
                event['lane'] = lane
                event['offset'] = offset
                events.append(event)
    return events, hashes


def compare_cases(truth_path, events, binary):
    cases = []
    used = set()
    with truth_path.open(newline='', encoding='utf-8') as file:
        truth = list(csv.DictReader(file))
    if set(row['label'] for row in truth) != set(CASE_IDS) or len(truth) != len(CASE_IDS):
        raise ValueError('probe truth case list differs from the fixed matrix')
    by_label = {row['label']: row for row in truth}
    first_open_ns = min(int(row['before_ns']) for row in truth
                        if not row['label'].startswith('exec_'))
    parent_execs = [event for event in events
                    if event['kind'] == 1 and event['path'] == str(binary) and
                    event['monotonic_ns'] < first_open_ns]
    child_truth = by_label['exec_success']
    child_execs = [event for event in events
                   if event['kind'] == 1 and event['path'] == str(binary) and
                   int(child_truth['before_ns']) <= event['monotonic_ns'] <=
                   int(child_truth['after_ns'])]
    # BPF records the host-initial PID; getpid() in this WSL distro returns a
    # namespace PID. The unique probe binary and disjoint time windows bind
    # each to one host PID. Ambiguous bindings are a hard failure.
    if len(parent_execs) != 1 or len(child_execs) != 1:
        raise ValueError(f'ambiguous host PID binding: parent={len(parent_execs)} '
                         f'child={len(child_execs)}')
    parent_guest = int(by_label['absolute_read']['pid'])
    child_guest = int(child_truth['pid'])
    if parent_guest == child_guest or parent_execs[0]['pid'] == child_execs[0]['pid']:
        raise ValueError('probe parent and child must have distinct PIDs')
    pid_map = {parent_guest: parent_execs[0]['pid'],
               child_guest: child_execs[0]['pid']}
    for row in truth:
        label = row['label']
        # On-disk kind values are 1=successful exec, 2=openat.
        kind = 1 if label.startswith('exec_') else 2
        before = int(row['before_ns'])
        after = int(row['after_ns'])
        pid = pid_map[int(row['pid'])]
        result = int(row['ret'])
        expected_result = result if result >= 0 else -int(row['errno'])
        candidates = [(index, event) for index, event in enumerate(events)
                      if event['pid'] == pid and event['kind'] == kind and
                      before <= event['monotonic_ns'] <= after and
                      (kind == 1 or event['result'] == expected_result)]
        if label == 'exec_failure':
            matched = []
        else:
            matched = candidates
            for index, _ in matched:
                used.add(index)
        expected_id = CASE_IDS[label]
        event = matched[0][1] if len(matched) == 1 else None
        path_ok = False
        if event is not None:
            if label == 'bad_pointer':
                path_ok = event['capture_quality'] == 2 and event['path'] == ''
            elif label == 'long_path':
                path_ok = (event['capture_quality'] == 1 and
                           row['path'].startswith(event['path']) and
                           len(event['path']) < len(row['path']))
            else:
                path_ok = event['capture_quality'] == 0 and event['path'] == row['path']
        observed = None if event is None else dict(
            rule_id=event['rule_id'], path=event['path'],
            capture_quality=event['capture_quality'], result=event['result'],
            priority=event['priority_name'], policy=event['effective_policy'],
            lane=event['lane'], offset=event['offset'],
            monotonic_ns=event['monotonic_ns'])
        passed = ((not candidates) if expected_id is None else
                  len(matched) == 1 and event['rule_id'] == expected_id and
                  event['priority_name'] == 'CRITICAL' and path_ok)
        cases.append(dict(label=label, truth=row, host_pid=pid,
                          expected_rule_id=expected_id,
                          candidate_count=len(candidates), observed=observed,
                          path_ok=path_ok if expected_id is not None else None,
                          passed=passed))
    binding = dict(parent=dict(guest_pid=parent_guest,
                               host_pid=parent_execs[0]['pid'],
                               startup_exec_monotonic_ns=parent_execs[0]['monotonic_ns']),
                   child=dict(guest_pid=child_guest,
                              host_pid=child_execs[0]['pid'],
                              exec_monotonic_ns=child_execs[0]['monotonic_ns']))
    return cases, len(used), binding


def main():
    if os.geteuid() != 0:
        raise RuntimeError('run_path_matrix.py requires root')
    if not (SOURCE / 'manage.py').is_file() or not (BUILD / 'collector').is_file():
        raise RuntimeError('current source or collector build is missing')
    available_kib = int(next(line.split()[1] for line in
                             Path('/proc/meminfo').read_text().splitlines()
                             if line.startswith('MemAvailable:')))
    free_bytes = shutil.disk_usage('/root').free
    if available_kib < 1024 * 1024 or free_bytes < 2 * 1024**3:
        raise RuntimeError('memory or disk free space is below matrix safety floor')
    identity = uuid.uuid4().hex[:12]
    output = OUTPUT_BASE / ('path-matrix-' + identity)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    probe_root = Path('/tmp/mglogwh-matrix-probe-' + identity)
    binary = Path('/tmp/mglogwh-matrix-binary-' + identity)
    data = Path('/root/mglogwh-v040-matrix-' + identity)
    if probe_root.exists() or binary.exists() or data.exists():
        raise RuntimeError('unique matrix path already exists')
    env = os.environ.copy()
    env.update(MGLOGWH_DATA_DIR=str(data), MGLOGWH_BUILD_DIR=str(BUILD))
    config_path = output / 'config.json'
    write_json(config_path, config_for(probe_root, binary))
    command('compile', ['cc', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(HERE / 'path_matrix_probe.c'), '-o', str(binary)],
            output, timeout=30)
    command('validate', [sys.executable, str(SOURCE / 'manage.py'),
                         'validate', '--config', str(config_path)],
            output, env=env, timeout=30)
    manager = [sys.executable, str(SOURCE / 'manage.py')]
    # Attempt a bounded stop even if start raises after spawning the service.
    start_attempted = False
    stop_error = None
    try:
        start_attempted = True
        command('start', manager + ['start', '--config', str(config_path)],
                output, env=env, timeout=30)
        command('probe', ['runuser', '-u', USER, '--', str(binary),
                          str(probe_root), str(probe_root / 'truth.csv'),
                          str(binary)], output, timeout=30)
    finally:
        if start_attempted:
            try:
                command('stop', manager + ['stop'], output, env=env, timeout=100)
            except Exception as exc:
                stop_error = str(exc)
                write_json(output / 'stop-error.json', {'error': stop_error})
    if stop_error:
        raise RuntimeError(stop_error)
    truth_path = output / 'truth.csv'
    shutil.copyfile(probe_root / 'truth.csv', truth_path)
    current = json.loads((data / 'current.json').read_text(encoding='utf-8'))
    run_dir = data / 'runs' / current['run_id']
    health = json.loads((run_dir / 'health.json').read_text(encoding='utf-8'))
    index = json.loads((run_dir / 'index-health.json').read_text(encoding='utf-8'))
    manifest = json.loads((run_dir / 'manifest.json').read_text(encoding='utf-8'))
    for name in ('health.json', 'index-health.json', 'manifest.json'):
        shutil.copyfile(run_dir / name, output / name)
    manage = load_manage()
    events, raw_hashes = read_raw(manage, run_dir, health)
    cases, matched_count, pid_binding = compare_cases(truth_path, events, binary)
    recovery = subprocess.run(manager + ['recover', '--run-dir', str(run_dir)],
                              env=env, capture_output=True, text=True, timeout=30)
    (output / 'recover.stdout').write_text(recovery.stdout, encoding='utf-8')
    (output / 'recover.stderr').write_text(recovery.stderr, encoding='utf-8')
    try:
        recovery_value = json.loads(recovery.stdout)
    except json.JSONDecodeError:
        recovery_value = None
    result = dict(source_head=HEAD,
                  source_manage_sha256=sha256(SOURCE / 'manage.py'),
                  source_sensor_sha256=sha256(SOURCE / 'sensor.bpf.c'),
                  probe_source_sha256=sha256(HERE / 'path_matrix_probe.c'),
                  collector_sha256=sha256(BUILD / 'collector'),
                  bpf_sha256=sha256(BUILD / 'sensor.bpf.o'),
                  config_sha256=sha256(config_path),
                  run_dir=str(run_dir), data_dir=str(data),
                  kernel=os.uname().release,
                  memory_available_kib=available_kib,
                  filesystem_free_bytes_before=free_bytes,
                  manifest_config_sha256=manifest.get('config_sha256'),
                  health_state=health.get('state'),
                  index_complete_to_durable=index.get('complete_to_durable'),
                  recover_exit=recovery.returncode,
                  recovery=recovery_value,
                  raw_record_count=len(events), raw=raw_hashes,
                  pid_binding=pid_binding,
                  target_match_count=matched_count,
                  case_count=len(cases), cases=cases)
    result['pass'] = (all(case['passed'] for case in cases) and
                      matched_count == 15 and health.get('state') == 'STOPPED' and
                      index.get('complete_to_durable') is True and
                      recovery.returncode == 0 and
                      isinstance(recovery_value, dict) and
                      recovery_value.get('status') == 'RECOVERED')
    write_json(output / 'result.json', result)
    print(json.dumps(dict(output=str(output), run_dir=str(run_dir),
                          case_pass=sum(case['passed'] for case in cases),
                          case_total=len(cases),
                          recovery_status=(recovery_value or {}).get('status'),
                          passed=result['pass']), ensure_ascii=False))
    return 0 if result['pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
