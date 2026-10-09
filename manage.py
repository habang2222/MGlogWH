#!/usr/bin/env python3
"""MGlogWH lifecycle and derived index. Python 3.12+, Linux x86_64.

No raw data passes through stdout. The collector has no dependency on SQLite.
"""
import argparse
import contextlib
import datetime as dt
import difflib
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import shutil
import sqlite3
import struct
import subprocess
import sys
import time
import uuid
import zlib

VERSION = '0.3.0'
ROOT = Path(__file__).resolve().parent
DATA = Path('/home/ljw/mglogwh-data')
BINARY = Path('/home/ljw/mglogwh-build/collector')
OBJECT = BINARY.with_name('sensor.bpf.o')
EVENT = struct.Struct('<4Qq12I16s128s')
RECORD_SIZE = EVENT.size + 8
FIELDS = ('monotonic_ns', 'cgroup_id', 'sequence', 'process_start_ns', 'result',
          'magic', 'schema', 'kind', 'priority', 'pid', 'tid', 'uid', 'ppid', 'cpu',
          'op_flags', 'captured_len', 'quality', 'comm', 'path')
LEGACY_LANES = ('critical.raw', 'general.raw')
LANES = (*LEGACY_LANES, 'quarantine.raw')
INDEX_FINAL_CATCHUP_SECONDS = 45.0
INDEX_JOIN_GRACE_SECONDS = 10.0
RAW_SEARCH_DEFAULT_MAX_BYTES = 256 * 1024**2
STORAGE_SCAN_MAX_ENTRIES = 4096
INDEX_PRESSURE_RESUME_EXTRA_BYTES = 8 * 1024**2
Q_QUARANTINED, Q_INITIAL, Q_PERIODIC = 1 << 8, 1 << 9, 1 << 10
Q_PROTECTED, Q_UNTRACKED = 1 << 11, 1 << 12
QUALITY_MASK = 0x00ff1f03
REQUIRED_KEYS = {'bulk_rate', 'bulk_burst', 'protected_path', 'max_raw_mib',
        'critical_reserve_mib', 'max_index_mib', 'minimum_free_mib'}
POLICY_DEFAULTS = dict(critical_rate_threshold=10000, critical_rate_duration_seconds=3,
                      critical_recovery_threshold=2000, critical_recovery_duration_seconds=10,
                      quarantine_initial_full_events=8, quarantine_sample_interval_ms=100,
                      quarantine_max_mib=16, metadata_max_mib=16)
KEYS = REQUIRED_KEYS | POLICY_DEFAULTS.keys() | {'critical_rules'}


def validate_rules(rules):
    if not isinstance(rules, list) or not 1 <= len(rules) <= 8:
        raise ValueError('critical_rules: 1..8개의 규칙이 필요합니다.')
    ids, targets = set(), set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {'id', 'event_type', 'path', 'protected'}:
            raise ValueError('critical_rules: id, event_type, path, protected 키가 필요합니다.')
        if type(rule['id']) is not int or not 1 <= rule['id'] <= 255 or rule['id'] in ids:
            raise ValueError('critical_rules: 중복 없는 정수 id 1..255가 필요합니다.')
        if rule['event_type'] not in ('openat', 'exec') or type(rule['protected']) is not bool:
            raise ValueError('critical_rules: openat/exec 종류와 protected boolean이 필요합니다.')
        path = rule['path']
        if (not isinstance(path, str) or not path.startswith('/') or len(path.encode()) > 126 or
                any(ord(char) < 32 for char in path) or '..' in Path(path).parts):
            raise ValueError('critical_rules: 126바이트 이하의 Linux 절대 경로가 필요합니다.')
        target = (rule['event_type'], path)
        if target in targets:
            raise ValueError('critical_rules: 동일 종류·경로를 중복 지정할 수 없습니다.')
        ids.add(rule['id']); targets.add(target)
    return rules


def raw_lanes(health):
    lanes = health.get('durable', {})
    if not lanes: return LANES  # The index worker can start before the first health snapshot.
    if not isinstance(lanes, dict) or set(lanes) not in (set(LEGACY_LANES), set(LANES)):
        raise ValueError('durable lane 구성 불일치')
    return LANES if 'quarantine.raw' in lanes else LEGACY_LANES


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return default


def atomic_json(path, value):
    path = Path(path)
    temp = path.with_name(path.name + '.tmp')
    with temp.open('w', encoding='utf-8') as file:
        json.dump(value, file, ensure_ascii=False, indent=2)
        file.write('\n')
        file.flush()
        os.fsync(file.fileno())
    temp.replace(path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def config(path):
    with Path(path).open('rb') as file:
        raw = file.read(8193)
    if len(raw) > 8192:
        raise ValueError('설정 파일은 8 KiB 이하여야 합니다.')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('중복 설정 키: ' + key)
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict) or not REQUIRED_KEYS <= set(value) or set(value) - KEYS:
        raise ValueError('지원하는 설정 키만 빠짐없이 입력하세요: ' + ', '.join(sorted(KEYS)))
    value = POLICY_DEFAULTS | value
    for key, low, high in [('bulk_rate', 1, 1000000), ('bulk_burst', 1, 1000000),
                          ('max_raw_mib', 16, 1024), ('max_index_mib', 16, 512),
                          ('critical_reserve_mib', 1, 1023), ('minimum_free_mib', 256, 65536),
                          ('critical_rate_threshold', 1, 1000000), ('critical_rate_duration_seconds', 1, 60),
                          ('critical_recovery_threshold', 0, 999999), ('critical_recovery_duration_seconds', 1, 600),
                          ('quarantine_initial_full_events', 0, 64), ('quarantine_sample_interval_ms', 10, 60000),
                          ('quarantine_max_mib', 1, 256), ('metadata_max_mib', 8, 64)]:
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise ValueError(f'{key}: 정수 {low}..{high} 범위가 필요합니다.')
    if value['critical_reserve_mib'] >= value['max_raw_mib']:
        raise ValueError('critical 예약량은 raw 한도보다 작아야 합니다.')
    if value['quarantine_max_mib'] > value['max_raw_mib'] - value['critical_reserve_mib']:
        raise ValueError('quarantine 저장 한도는 일반 저장 예산 이하여야 합니다.')
    if value['critical_recovery_threshold'] >= value['critical_rate_threshold']:
        raise ValueError('복구 임계치는 quarantine 진입 임계치보다 작아야 합니다.')
    target = value['protected_path']
    if (not isinstance(target, str) or not target.startswith('/') or
            len(target.encode()) > 126 or any(ord(c) < 32 for c in target) or
            '..' in Path(target).parts):
        raise ValueError('protected_path: 126바이트 이하의 Linux 절대 경로가 필요합니다.')
    rules = value.get('critical_rules')
    if rules == [] or 'critical_rules' not in value:
        rules = [dict(id=1, event_type='openat', path=target, protected=False)]
    value['critical_rules'] = validate_rules(rules)
    return value


def fingerprint(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as file:
        for chunk in iter(lambda: file.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def identity(pid=None):
    pid = pid or os.getpid()
    try:
        # comm may contain spaces and parentheses; suffix fields start at state.
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return dict(pid=pid, start=fields[19], state=fields[0],
                    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    except (OSError, IndexError):
        return None


def alive(expected):
    actual = identity(expected['pid']) if expected else None
    return bool(actual and actual['state'] != 'Z' and
                all(actual[k] == expected[k] for k in ('pid', 'start', 'boot')))


@contextlib.contextmanager
def lock(path):
    import fcntl
    with Path(path).open('a') as file:
        try:
            fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('이미 작업 또는 수집이 실행 중입니다.') from exc
        yield


def current(run_id=None):
    run_id = run_id or read_json(DATA / 'current.json', {}).get('run_id')
    if not run_id:
        return None
    if str(uuid.UUID(run_id)) != run_id:
        raise ValueError('잘못된 run ID입니다.')
    path = DATA / 'runs' / run_id
    if not path.is_dir():
        raise ValueError('run 디렉터리를 찾지 못했습니다.')
    return path


def index_coverage(health, offsets):
    """Compare indexed cursor with a published raw fdatasync boundary.

    A live zero lag is a momentary observation, not final search completeness.
    Missing or invalid health never turns an empty index into complete coverage.
    """
    durable = health.get('durable')
    if not isinstance(durable, dict) or not durable:
        return dict(coverage_state='BOUNDARY_UNKNOWN', durable_offsets={}, indexed_offsets=offsets,
                    lane_coverage={}, lag_bytes=None, lag_records=None, complete_to_durable=False)
    lanes = raw_lanes(health)
    lane_coverage, lag_bytes = {}, 0
    for lane in lanes:
        boundary, cursor = durable[lane], offsets.get(lane, 0)
        if (type(boundary) is not int or type(cursor) is not int or boundary < 0 or cursor < 0 or
                boundary % RECORD_SIZE or cursor % RECORD_SIZE or cursor > boundary):
            raise ValueError('색인/원본 durable 경계 불일치: ' + lane)
        lag = boundary - cursor
        lane_coverage[lane] = dict(durable_offset=boundary, indexed_offset=cursor,
                                   lag_bytes=lag, lag_records=lag // RECORD_SIZE)
        lag_bytes += lag
    terminal = health.get('state') in ('STOPPED', 'FAILED')
    state = ('INDEX_COMPLETE' if terminal and not lag_bytes else
             'INDEX_LAG' if terminal else 'LIVE_CAUGHT_UP' if not lag_bytes else 'INDEXING')
    return dict(coverage_state=state, durable_offsets={lane: durable[lane] for lane in lanes},
                indexed_offsets={lane: offsets.get(lane, 0) for lane in lanes},
                lane_coverage=lane_coverage, lag_bytes=lag_bytes,
                lag_records=lag_bytes // RECORD_SIZE,
                complete_to_durable=bool(terminal and not lag_bytes))


def filesystem_free_bytes(path):
    return shutil.disk_usage(path).free


def storage_usage(run, max_entries=STORAGE_SCAN_MAX_ENTRIES):
    """Bounded run-tree usage, including transient SQLite sidecars when present.

    st_blocks is an observed allocation estimate, not a physical reservation;
    exports outside this run tree require the experiment harness inventory.
    """
    cfg = read_json(run / 'config.json', {})
    free = filesystem_free_bytes(run)
    threshold = cfg.get('minimum_free_mib')
    threshold_bytes = threshold * 1024**2 if type(threshold) is int else None
    categories = {name: dict(logical_bytes=0, allocated_bytes=0, file_count=0) for name in
                  ('raw', 'metadata_control', 'sqlite_main', 'sqlite_sidecars_temp', 'export_derived', 'other')}
    tree_allocated, logical, files, entries, truncated, unreadable = 0, 0, 0, 0, False, 0
    pending = [(run, 0)]
    while pending:
        directory, depth = pending.pop()
        try:
            with os.scandir(directory) as listing:
                for entry in listing:
                    if entries >= max_entries:
                        truncated = True
                        break
                    entries += 1
                    try:
                        meta = entry.stat(follow_symlinks=False)
                        allocated = meta.st_blocks * 512 if hasattr(meta, 'st_blocks') else None
                        if allocated is not None:
                            tree_allocated += allocated
                        if entry.is_dir(follow_symlinks=False):
                            if depth < 4:
                                pending.append((Path(entry.path), depth + 1))
                            else:
                                truncated = True
                            continue
                        files += 1
                        logical += meta.st_size
                        name = entry.name
                        parts = set(Path(entry.path).relative_to(run).parts[:-1])
                        if parts & {'export', 'exports', 'derived', 'analysis'}:
                            category = 'export_derived'
                        elif name in LANES:
                            category = 'raw'
                        elif name == 'index.sqlite':
                            category = 'sqlite_main'
                        elif (name.startswith('index.sqlite-') or name.startswith('etilqs_') or
                              name.endswith(('-wal', '-journal', '-shm'))):
                            category = 'sqlite_sidecars_temp'
                        elif name.startswith('evidence.meta') or name.endswith(('health.json', 'service.json')):
                            category = 'metadata_control'
                        else:
                            category = 'other'
                        categories[category]['logical_bytes'] += meta.st_size
                        categories[category]['allocated_bytes'] += allocated or 0
                        categories[category]['file_count'] += 1
                    except OSError:
                        unreadable += 1
        except OSError:
            unreadable += 1
        if truncated and entries >= max_entries:
            break
    previous = read_json(run / 'index-health.json', {})
    was_paused = previous.get('state') == 'INDEX_PAUSED_STORAGE_PRESSURE'
    if threshold_bytes is None:
        pressure = 'UNKNOWN'
    elif free == 0:
        pressure = 'EXHAUSTED_NOW'
    elif free < threshold_bytes:
        pressure = 'LOW_FREE'
    elif was_paused and free < threshold_bytes + INDEX_PRESSURE_RESUME_EXTRA_BYTES:
        pressure = 'RECOVERY_HYSTERESIS'
    else:
        pressure = 'NORMAL'
    return dict(scope='RUN_DIRECTORY_TREE_ONLY', external_exports_included=False,
                measurement='FILE_ST_BLOCKS_TIMES_512_AND_STATVFS_FREE; NOT_A_PHYSICAL_RESERVATION',
                filesystem_free_bytes=free, configured_minimum_free_bytes=threshold_bytes,
                pressure=pressure, file_logical_bytes=logical, tree_allocated_bytes=tree_allocated,
                file_count=files, entries_seen=entries, scan_limit_entries=max_entries,
                scan_truncated=truncated, unreadable_entries=unreadable,
                allocation_total_complete=not truncated and not unreadable,
                critical_reserve_physical=False, external_writers_can_exhaust_filesystem=True,
                categories=categories)


def collector_failure_evidence(run, health):
    sources = []
    if health.get('error_errno') == 28:
        sources.append('COLLECTOR_HEALTH_ERRNO_28')
    log = run / 'collector.log'
    try:
        with log.open('rb') as file:
            file.seek(0, os.SEEK_END)
            file.seek(max(0, file.tell() - 8192))
            tail = file.read().decode('utf-8', 'replace')
        if any('collector failed:' in line and '(28)' in line for line in tail.splitlines()):
            sources.append('COLLECTOR_STDERR_ERRNO_28')
    except OSError:
        pass
    return dict(physical_enospc_observed=bool(sources), evidence_sources=sources,
                evidence_scope='COLLECTOR_HEALTH_OR_BOUNDED_STDERR_TAIL_ONLY')


def status(run):
    if run is None:
        return dict(state='UNCONFIGURED', version=VERSION)
    service = read_json(run / 'service.json', {})
    index = read_json(run / 'index-health.json', {})
    # Read the published raw boundary after index health: a concurrent writer
    # can advance health between reads, but this order cannot invent coverage.
    health = read_json(run / 'health.json', {})
    failure_evidence = collector_failure_evidence(run, health)
    running = alive(service.get('supervisor'))
    raw_state = health.get('state', 'STARTING')
    if running:
        state = raw_state
        if raw_state == 'RUNNING' and not alive(service.get('collector')):
            state = 'FAILED_COLLECTOR'
        elif raw_state == 'RUNNING' and time.monotonic() * 1000 - health.get('monotonic_ms', 0) > 5000:
            state = 'STALE_HEARTBEAT'
    else:
        state = ('FAILED' if service.get('state') == 'FAILED' or raw_state == 'FAILED' else
                 'STOPPED' if service.get('state') == 'STOPPED' and raw_state == 'STOPPED' else 'UNEXPECTED_EXIT')
    if failure_evidence['physical_enospc_observed'] and not alive(service.get('collector')):
        state = 'FAILED_STORAGE_ENOSPC'
    coverage = index_coverage(health, index.get('offsets', {}))
    index_alive = alive(service.get('indexer'))
    index_state = index.get('state') if index.get('state') in ('FAILED', 'INDEX_PARTIAL', 'INDEX_PAUSED_STORAGE_PRESSURE') else coverage['coverage_state']
    if running and not index_alive and index_state not in ('FAILED', 'INDEX_PARTIAL'):
        index_state = 'UNAVAILABLE' if index_state != 'FAILED' else index_state
    return dict(version=VERSION, run_id=run.name, run_path=str(run), state=state,
                collector=health, index=dict(index, **coverage, state=index_state, alive=index_alive), service=service,
                storage=storage_usage(run), failure_evidence=failure_evidence,
                evidence_metadata=health.get('metadata', {'state': 'LEGACY_NOT_AVAILABLE'}))


def capability():
    checks = dict(linux=platform.system() == 'Linux', x86_64=platform.machine() == 'x86_64',
                  root=os.geteuid() == 0, btf=Path('/sys/kernel/btf/vmlinux').is_file(),
                  binary=BINARY.is_file(), bpf_object=OBJECT.is_file())
    checks['tracepoints'] = all(Path('/sys/kernel/tracing/events', p, 'format').is_file()
                               for p in ('syscalls/sys_enter_openat', 'syscalls/sys_exit_openat',
                                         'sched/sched_process_exec', 'sched/sched_process_exit'))
    return dict(checks=checks, ready=all(checks.values()), events=['exec_success', 'openat_enter_exit'],
                all_uid=True, all_syscall=False, file_identity='EXACT_CAPTURED_ABSOLUTE_PATH_ONLY',
                pid_namespace='HOST_INITIAL_PID_NAMESPACE', uid_namespace='HOST_INITIAL_USER_NAMESPACE',
                observation_scope='SHARED_WSL_KERNEL_NOT_QEMU_VM',
                signing='UNSIGNED_CRC32_ONLY', independent_index_process=True,
                remote_collector=False, metadata='BOUNDED_COMMITTED_JOURNAL_AND_AGGREGATE_COUNTERS',
                critical_guard='PER_STREAM_QUARANTINE_WITH_ORIGINAL_PRIORITY_RETAINED',
                critical_stream_key='CGROUP_RULE_EVENT_KIND', protected_critical='CONFIGURED_RULE_EXEMPTION',
                quarantine_release='EVENT_DRIVEN_HYSTERESIS', ledger_recovery='READ_ONLY_COMMITTED_PREFIX',
                bpf_load_verified_only_after_start=True)


def start(cfg):
    cap = capability()
    if not cap['ready']:
        raise RuntimeError('시작 조건 실패: ' + json.dumps(cap['checks']))
    old = current()
    if old and (alive(read_json(old / 'service.json', {}).get('supervisor')) or
                alive(read_json(old / 'service.json', {}).get('collector'))):
        raise RuntimeError('이미 수집 중입니다. 먼저 중지하세요.')
    need = (cfg['minimum_free_mib'] + cfg['max_raw_mib'] + cfg['max_index_mib'] + cfg['metadata_max_mib']) * 1024**2
    free_before = filesystem_free_bytes(DATA)
    if free_before < need:
        raise RuntimeError('저장 공간이 부족합니다. 기존 run은 자동 삭제하지 않습니다.')
    run = DATA / 'runs' / str(uuid.uuid4())
    run.mkdir(parents=True, mode=0o700)
    canonical = json.dumps(cfg, sort_keys=True, separators=(',', ':')).encode()
    manifest = dict(version=VERSION, schema=1, raw_schema=2, raw_record_size=240,
                    quality_extension='RULE_ID_AND_CRITICAL_POLICY_V1',
                    run_id=run.name, created_utc=dt.datetime.now(dt.UTC).isoformat(),
                    clock_anchor=dict(monotonic_ns=time.monotonic_ns(), realtime_ns=time.time_ns(),
                                      precision='SEQUENTIAL_READS_APPROXIMATE_NOT_CLOCK_STEP_PROOF'),
                    kernel=platform.release(), boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                    config_sha256=hashlib.sha256(canonical).hexdigest(),
                    collector_sha256=fingerprint(BINARY), bpf_sha256=fingerprint(OBJECT),
                    storage_preflight=dict(filesystem_free_bytes=free_before, required_free_bytes=need,
                        raw_limit_bytes=cfg['max_raw_mib'] * 1024**2,
                        sqlite_main_limit_bytes=cfg['max_index_mib'] * 1024**2,
                        metadata_limit_bytes=cfg['metadata_max_mib'] * 1024**2,
                        auxiliary_headroom_bytes=cfg['minimum_free_mib'] * 1024**2,
                        physical_reservation=False, critical_reserve_physical=False,
                        external_writers_can_exhaust_filesystem=True,
                        sqlite_journal_not_hard_capped=True, sqlite_temp_store='MEMORY'),
                    capability=cap, ordering='PER_CGROUP_SEQUENCE_NOT_GLOBAL_CAUSAL_ORDER')
    atomic_json(run / 'config.json', cfg)
    atomic_json(run / 'manifest.json', manifest)
    os.chmod(run / 'config.json', 0o400)
    os.chmod(run / 'manifest.json', 0o400)
    atomic_json(DATA / 'current.json', dict(run_id=run.name))
    with (run / 'service.log').open('ab') as log:
        process = subprocess.Popen([sys.executable, str(ROOT / 'manage.py'), 'serve', '--run', run.name],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    for _ in range(70):
        state = status(run)
        if state['state'] == 'RUNNING':
            return state
        if process.poll() is not None:
            raise RuntimeError(f'시작 실패. {run}/collector.log 및 service.log 확인')
        time.sleep(0.1)
    process.terminate()
    raise RuntimeError(f'시작 제한 시간 초과. {run}에서 실제 상태를 확인하세요.')


def serve(run):
    quit_ = False
    def stop_handler(*_):
        nonlocal quit_
        quit_ = True
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    cfg = read_json(run / 'config.json')
    manifest = read_json(run / 'manifest.json')
    child_env = os.environ.copy()
    child_env.update(MGLOGWH_RUN_ID=run.name, MGLOGWH_MANIFEST_SHA256=fingerprint(run / 'manifest.json'),
                     MGLOGWH_CONFIG_SHA256=manifest['config_sha256'], MGLOGWH_BOOT_ID=manifest['boot_id'])
    collector_command = [str(BINARY), str(run), str(cfg['bulk_rate']), str(cfg['bulk_burst']),
                         cfg['protected_path'], str(cfg['max_raw_mib']), str(cfg['critical_reserve_mib']),
                         str(cfg['metadata_max_mib']), str(cfg['quarantine_max_mib']),
                         str(cfg['critical_rate_threshold']), str(cfg['critical_rate_duration_seconds'] * 1000),
                         str(cfg['critical_recovery_threshold']), str(cfg['critical_recovery_duration_seconds'] * 1000),
                         str(cfg['quarantine_initial_full_events']), str(cfg['quarantine_sample_interval_ms']),
                         str(len(cfg['critical_rules']))]
    for rule in cfg['critical_rules']:
        collector_command.extend([str(rule['id']), '2' if rule['event_type'] == 'openat' else '1',
                                  '1' if rule['protected'] else '0', rule['path']])
    with lock(DATA / 'collector.lock'), (run / 'collector.log').open('ab') as log:
        service = dict(supervisor=identity(), state='STARTING')
        atomic_json(run / 'service.json', service)
        child = subprocess.Popen(collector_command,
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=child_env)
        service.update(collector=identity(child.pid), state='RUNNING')
        atomic_json(run / 'service.json', service)
        indexer = None
        try:
            with (run / 'indexer.log').open('ab') as index_log:
                indexer = subprocess.Popen([sys.executable, str(ROOT / 'manage.py'), 'index-worker', '--run', run.name],
                                           stdin=subprocess.DEVNULL, stdout=index_log, stderr=index_log)
            service['indexer'] = identity(indexer.pid)
            atomic_json(run / 'service.json', service)
            while child.poll() is None and not quit_:
                time.sleep(0.2)
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            if indexer:
                try:
                    indexer.wait(timeout=INDEX_FINAL_CATCHUP_SECONDS + INDEX_JOIN_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    indexer.terminate()
                    try:
                        indexer.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        indexer.kill()
                        indexer.wait()
                service['indexer_exit'] = indexer.returncode
                if indexer.returncode != 0:
                    old = read_json(run / 'index-health.json', {})
                    try:
                        coverage = index_coverage(read_json(run / 'health.json', {}), old.get('offsets', {}))
                        if not coverage['complete_to_durable']:
                            atomic_json(run / 'index-health.json', dict(old, **coverage,
                                state='INDEX_PARTIAL', error=old.get('error', 'index worker exited before catch-up'),
                                last_error_monotonic_ns=time.monotonic_ns()))
                    except (OSError, ValueError):
                        # External service/indexer exit status still exposes a failed stop
                        # when a full filesystem prevents writing the index health file.
                        pass
            service.update(state='STOPPED' if child.returncode == 0 else 'FAILED', collector_exit=child.returncode)
            atomic_json(run / 'service.json', service)


def stop_run(run):
    if run is None:
        return status(None)
    expected = read_json(run / 'service.json', {}).get('supervisor')
    # pidfd pins the process: no signalling a reused PID between check and kill.
    if alive(expected):
        fd = os.pidfd_open(expected['pid'])
        try:
            if alive(expected):
                signal.pidfd_send_signal(fd, signal.SIGTERM)
        finally:
            os.close(fd)
        for _ in range(int((INDEX_FINAL_CATCHUP_SECONDS + INDEX_JOIN_GRACE_SECONDS + 20) * 10)):
            if not alive(expected):
                return status(run)
            time.sleep(0.1)
        raise RuntimeError('중지 지연: collector.log와 상태를 확인하세요. 강제 삭제하지 않았습니다.')
    return status(run)


def decode_record(raw):
    if len(raw) != RECORD_SIZE:
        raise ValueError('잘린 레코드')
    payload, checksum, reserved = raw[:-8], *struct.unpack('<II', raw[-8:])
    if reserved or zlib.crc32(payload) != checksum:
        raise ValueError('CRC32 불일치 또는 예약 필드 손상')
    value = dict(zip(FIELDS, EVENT.unpack(payload)))
    if value['magic'] != 0x31514f45 or value['schema'] not in (1, 2) or value['kind'] not in (1, 2) or value['priority'] not in (0, 1, 2):
        raise ValueError('지원하지 않는 schema/event')
    quality = value['quality']
    if quality & ~(3 if value['schema'] == 1 else QUALITY_MASK):
        raise ValueError('지원하지 않는 quality/policy')
    q, protected = bool(quality & Q_QUARANTINED), bool(quality & Q_PROTECTED)
    initial, periodic = bool(quality & Q_INITIAL), bool(quality & Q_PERIODIC)
    rule_id = (quality >> 16) & 255
    if value['schema'] == 2 and ((value['priority'] == 2) != bool(rule_id) or
            (q and protected) or (q and initial == periodic) or
            (not q and (initial or periodic or (quality & Q_UNTRACKED and not protected))) or
            (value['priority'] != 2 and (q or protected))):
        raise ValueError('priority·rule·effective policy 불일치')
    value.update(original_priority=value['priority'], rule_id=rule_id, capture_quality=quality & 3,
                 effective_policy='QUARANTINE' if q else 'PROTECTED_CRITICAL' if protected else
                 'CRITICAL' if value['priority'] == 2 else 'NORMAL' if value['priority'] == 1 else 'BULK',
                 quarantine_sample_kind='INITIAL_FULL' if initial else 'PERIODIC_SAMPLE' if periodic else None,
                 stream_tracking_complete=not bool(quality & Q_UNTRACKED),
                 quarantine_tracking_complete=not bool(quality & Q_UNTRACKED))
    for name in ('comm', 'path'):
        value[name] = value[name].split(b'\0', 1)[0].decode('utf-8', 'replace')
    return value


def index_batch(run, max_records=2048):
    """A transaction commits rows and offsets together; repeat is idempotent.

    Only published fdatasync boundaries are used, including after a crash.
    Uncommitted tails are preserved, not silently promoted to durable evidence.
    """
    previous = read_json(run / 'index-health.json', {})
    health = read_json(run / 'health.json', {})
    manifest = read_json(run / 'manifest.json')
    cfg = read_json(run / 'config.json')
    free = filesystem_free_bytes(run)
    pressure_floor = cfg['minimum_free_mib'] * 1024**2
    resume_floor = pressure_floor + INDEX_PRESSURE_RESUME_EXTRA_BYTES
    if free < pressure_floor or (previous.get('state') == 'INDEX_PAUSED_STORAGE_PRESSURE' and free < resume_floor):
        coverage = index_coverage(health, previous.get('offsets', {}))
        try:
            atomic_json(run / 'index-health.json', dict(previous, **coverage,
                state='INDEX_PAUSED_STORAGE_PRESSURE', filesystem_free_bytes=free,
                pressure_floor_bytes=pressure_floor, resume_floor_bytes=resume_floor,
                last_pressure_monotonic_ns=time.monotonic_ns()))
        except OSError:
            # The external status path can still report free space and stale
            # process identity if the filesystem cannot accept this small file.
            pass
        return 0
    lanes = raw_lanes(health)
    db = sqlite3.connect(run / 'index.sqlite', timeout=2)
    processed = 0
    offsets = {}
    try:
        db.execute('PRAGMA journal_mode=DELETE')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA cache_size=-4096')
        # Keep SQLite sort/work tables out of an untracked /tmp filesystem.
        # SQLite's rollback journal remains beside index.sqlite and is included
        # in the observed run-tree allocation; it is not physically reserved.
        db.execute('PRAGMA temp_store=MEMORY')
        pages = cfg['max_index_mib'] * 1024 * 1024 // db.execute('PRAGMA page_size').fetchone()[0]
        db.execute(f'PRAGMA max_page_count={pages}')
        db.executescript('''CREATE TABLE IF NOT EXISTS events (
            cgroup TEXT NOT NULL, seq INTEGER NOT NULL, monotonic_ns INTEGER,
            priority INTEGER, pid INTEGER, uid INTEGER, kind INTEGER, path TEXT,
            payload BLOB NOT NULL, PRIMARY KEY(cgroup,seq));
            CREATE INDEX IF NOT EXISTS recent ON events(monotonic_ns DESC);
            CREATE INDEX IF NOT EXISTS priority_recent ON events(priority,monotonic_ns DESC);
            CREATE TABLE IF NOT EXISTS cursor(lane TEXT PRIMARY KEY, offset INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS lineage(key TEXT PRIMARY KEY, value TEXT NOT NULL);''')
        with db:
            for key in ('run_id', 'config_sha256', 'bpf_sha256'):
                old = db.execute('SELECT value FROM lineage WHERE key=?', (key,)).fetchone()
                if old and old[0] != manifest[key]:
                    raise ValueError('다른 run/config의 인덱스입니다. 원본은 변경하지 않습니다.')
                db.execute('INSERT OR IGNORE INTO lineage VALUES (?,?)', (key, manifest[key]))
            # Critical first; every lane gets a bounded per-iteration quota.
            for lane in lanes:
                row = db.execute('SELECT offset FROM cursor WHERE lane=?', (lane,)).fetchone()
                offset = row[0] if row else 0
                limit = health.get('durable', {}).get(lane, 0)
                if type(limit) is not int or limit < offset or limit % RECORD_SIZE:
                    raise ValueError('durable 경계 불일치')
                path = run / lane
                if limit > (path.stat().st_size if path.exists() else 0):
                    raise ValueError('durable 경계보다 원본 파일이 짧습니다.')
                if limit > offset:
                    with path.open('rb') as file:
                        file.seek(offset)
                        for _ in range(min((limit - offset) // RECORD_SIZE, max_records // len(lanes))):
                            raw = file.read(RECORD_SIZE)
                            e = decode_record(raw)
                            expected_lane = 'quarantine.raw' if e['effective_policy'] == 'QUARANTINE' else 'critical.raw' if e['priority'] == 2 else 'general.raw'
                            if expected_lane != lane:
                                raise ValueError('lane 분류 불일치')
                            key = (str(e['cgroup_id']), e['sequence'])
                            old = db.execute('SELECT payload FROM events WHERE cgroup=? AND seq=?', key).fetchone()
                            if old and old[0] != raw:
                                raise ValueError('동일 event ID의 다른 payload: 원본 보존, 인덱싱 중단')
                            db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?)',
                                       (*key, e['monotonic_ns'], e['priority'], e['pid'], e['uid'], e['kind'], e['path'], raw))
                            offset += RECORD_SIZE
                            processed += 1
                offsets[lane] = offset
                db.execute('INSERT OR REPLACE INTO cursor VALUES (?,?)', (lane, offset))
        previous = read_json(run / 'index-health.json', {})
        previous.pop('error', None)
        coverage = index_coverage(health, offsets)
        now_ns = time.monotonic_ns()
        atomic_json(run / 'index-health.json', dict(previous, **coverage, state=coverage['coverage_state'],
                    offsets=offsets, indexed_records=sum(offsets.values()) // RECORD_SIZE,
                    last_progress_monotonic_ns=now_ns if processed else previous.get('last_progress_monotonic_ns'),
                    updated_monotonic_ns=now_ns, updated_utc=dt.datetime.now(dt.UTC).isoformat(),
                    config_sha256=manifest['config_sha256']))
    finally:
        db.close()
    return processed


def index_run(run, worker=False, max_seconds=INDEX_FINAL_CATCHUP_SECONDS):
    if run is None:
        raise ValueError('먼저 수집을 시작하세요.')
    if not math.isfinite(max_seconds) or not 0 <= max_seconds <= 120:
        raise ValueError('색인 시간 한도는 0~120초여야 합니다.')
    with lock(run / 'index.lock'):
        if worker:
            os.nice(10)
            import resource
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
        try:
            deadline = None if worker else time.monotonic() + max_seconds
            while True:
                count = index_batch(run)
                index = read_json(run / 'index-health.json', {})
                health = read_json(run / 'health.json', {})
                svc = read_json(run / 'service.json', {})
                coverage = index_coverage(health, index.get('offsets', {}))
                terminal = health.get('state') in ('STOPPED', 'FAILED')
                if coverage['complete_to_durable'] or (not worker and not count):
                    break
                if worker and deadline is None and (terminal or not alive(svc.get('collector')) or
                                                    not alive(svc.get('supervisor'))):
                    deadline = time.monotonic() + max_seconds
                if deadline is not None and time.monotonic() >= deadline:
                    if coverage['lag_bytes']:
                        atomic_json(run / 'index-health.json', dict(index, **coverage, state='INDEX_LAG',
                            catchup_limit_seconds=max_seconds, catchup_deadline_monotonic_ns=time.monotonic_ns()))
                    elif not terminal:
                        atomic_json(run / 'index-health.json', dict(index, **coverage, state='INDEX_PARTIAL',
                            error='collector ended without a final raw health boundary',
                            last_error_monotonic_ns=time.monotonic_ns()))
                    break
                time.sleep(0.1 if count else 0.5)
        except Exception as exc:
            old = read_json(run / 'index-health.json', {})
            atomic_json(run / 'index-health.json', dict(old, state='FAILED', error=str(exc),
                        last_error_monotonic_ns=time.monotonic_ns()))
            raise
    return read_json(run / 'index-health.json', {})


def query(run, critical=False, limit=30):
    if run is None or not (run / 'index.sqlite').exists():
        raise ValueError('아직 인덱스가 없습니다. 상태 확인 또는 인덱스 재개를 실행하세요.')
    with sqlite3.connect(f'file:{run / "index.sqlite"}?mode=ro', uri=True, timeout=2) as db:
        db.execute('PRAGMA temp_store=MEMORY')
        db.execute('BEGIN')  # Cursor and search rows come from one SQLite read snapshot.
        offsets = dict(db.execute('SELECT lane,offset FROM cursor'))
        sql = 'SELECT payload FROM events' + (' WHERE priority=2' if critical else '')
        rows = db.execute(sql + ' ORDER BY monotonic_ns DESC LIMIT ?', (limit,)).fetchall()
    health = read_json(run / 'health.json', {})
    coverage = index_coverage(health, offsets)
    index_health = read_json(run / 'index-health.json', {})
    index_state = index_health.get('state') if index_health.get('state') in ('FAILED', 'INDEX_PARTIAL', 'INDEX_PAUSED_STORAGE_PRESSURE') else coverage['coverage_state']
    return dict(run_id=run.name, source='INDEX', index=dict(index_health, **coverage, state=index_state),
                search_complete_to_durable=bool(coverage['complete_to_durable'] and health.get('state') == 'STOPPED'),
                zero_results_mean='ABSENT_FROM_INDEXED_DURABLE_RAW_ONLY' if
                    coverage['complete_to_durable'] and health.get('state') == 'STOPPED' else 'INDEX_INCOMPLETE_OR_RUN_OPEN',
                records=[decode_record(row[0]) for row in rows])


def raw_search(run, path, limit=30, max_bytes=RAW_SEARCH_DEFAULT_MAX_BYTES, max_seconds=15.0):
    """Bounded read-only exact-path search of the published durable raw prefix.

    This never expands the indexed boundary, repairs an index, or searches an
    uncommitted suffix. A cap hit is reported as partial even if matches exist.
    """
    if run is None or not isinstance(path, str) or not path.startswith('/') or '\x00' in path:
        raise ValueError('검색할 Linux 절대 경로가 필요합니다.')
    if (not 1 <= limit <= 100 or not RECORD_SIZE <= max_bytes <= 1024**3 or
            not math.isfinite(max_seconds) or not 0 < max_seconds <= 120):
        raise ValueError('raw 검색의 결과·바이트·시간 한도가 잘못됐습니다.')
    health = read_json(run / 'health.json', {})
    durable = health.get('durable')
    if not isinstance(durable, dict) or not durable:
        raise ValueError('공표된 raw durable 경계가 없어 검색할 수 없습니다.')
    lanes = raw_lanes(health)
    for lane in lanes:
        boundary = durable[lane]
        source = run / lane
        if type(boundary) is not int or boundary < 0 or boundary % RECORD_SIZE or (source.stat().st_size if source.exists() else 0) < boundary:
            raise ValueError('raw durable 경계/파일 불일치: ' + lane)
    start = time.monotonic()
    offsets = {lane: 0 for lane in lanes}
    records, searched = [], 0
    limit_reason = None
    for lane in lanes:
        boundary = durable[lane]
        if not boundary:
            continue
        with (run / lane).open('rb') as file:
            while offsets[lane] < boundary:
                if searched + RECORD_SIZE > max_bytes:
                    limit_reason = 'MAX_BYTES'
                    break
                if time.monotonic() - start >= max_seconds:
                    limit_reason = 'MAX_SECONDS'
                    break
                event = decode_record(file.read(RECORD_SIZE))
                offsets[lane] += RECORD_SIZE
                searched += RECORD_SIZE
                if event['path'] == path:
                    records.append(event)
                    if len(records) >= limit:
                        limit_reason = 'MAX_RESULTS'
                        break
        if limit_reason:
            break
    remaining = {lane: dict(start=offsets[lane], end=durable[lane]) for lane in lanes if offsets[lane] < durable[lane]}
    complete = not remaining and health.get('state') == 'STOPPED'
    return dict(run_id=run.name, source='RAW_DURABLE_READ_ONLY', match_path=path, records=records,
                published_durable_offsets={lane: durable[lane] for lane in lanes}, searched_offsets=offsets,
                searched_bytes=searched, unsearched_ranges=remaining,
                search_complete_to_durable=complete, limit_reason=limit_reason,
                zero_results_mean='ABSENT_FROM_DURABLE_RAW_ONLY' if complete else 'PARTIAL_OR_RUN_OPEN')


def main():
    parser = argparse.ArgumentParser(description='MGlogWH local sensor')
    parser.add_argument('action', choices=['version', 'capability', 'validate', 'prepare', 'start', 'stop',
                         'status', 'path', 'query', 'critical', 'raw-search', 'index', 'serve', 'index-worker', 'recover'])
    parser.add_argument('--config', default=str(ROOT / 'config.json'))
    parser.add_argument('--run')
    parser.add_argument('--run-dir', type=Path, help='read-only recovery input (exported UUID directory)')
    parser.add_argument('--out', type=Path, help='recovery report JSON output; source is never repaired')
    parser.add_argument('--limit', type=int, default=30, choices=range(1, 101), metavar='1..100')
    parser.add_argument('--match-path', help='raw-search의 정확한 Linux 절대 경로')
    parser.add_argument('--max-bytes', type=int, default=RAW_SEARCH_DEFAULT_MAX_BYTES)
    parser.add_argument('--max-seconds', type=float, default=15.0)
    args = parser.parse_args()
    os.umask(0o077)
    if args.action == 'version':
        print('MGlogWH ' + VERSION)
        return
    if args.action == 'recover':
        import ledger
        run = args.run_dir.resolve() if args.run_dir else current(args.run)
        if run is None: raise ValueError('복구할 run이 없습니다.')
        service = read_json(run / 'service.json', {})
        if alive(service.get('supervisor')) or alive(service.get('collector')):
            raise RuntimeError('수집 중인 run은 복구 보고서 대신 상태 확인을 사용하세요.')
        report = ledger.recover(run, args.out)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        if report.get('status') == 'INVALID': sys.exit(2)
        return
    DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.action == 'serve':
        serve(current(args.run)); return
    if args.action == 'index-worker':
        index_run(current(args.run), worker=True); return
    if args.action in ('validate', 'prepare', 'start'):
        cfg = config(args.config)
    if args.action == 'prepare':
        subprocess.run(['make', '-C', str(ROOT)], check=True)
    with lock(DATA / 'control.lock'):
        run = current(args.run)
        if args.action == 'start':
            result = start(cfg)
        elif args.action == 'stop':
            result = stop_run(run)
        elif args.action in ('capability', 'prepare'):
            result = capability()
            if not result['ready']:
                raise RuntimeError(json.dumps(result))
        elif args.action == 'validate':
            before = read_json(run / 'config.json', {}) if run else {}
            diff = list(difflib.unified_diff(json.dumps(before, indent=2, sort_keys=True).splitlines(),
                                           json.dumps(cfg, indent=2, sort_keys=True).splitlines(),
                                           fromfile='active_run', tofile='next_run', lineterm=''))
            result = dict(valid=True, applies='NEXT_START_ONLY', config=cfg, diff=diff)
        elif args.action == 'status':
            result = status(run)
        elif args.action == 'path':
            if run is None: raise ValueError('저장된 run이 없습니다.')
            if status(run)['state'] != 'STOPPED': raise ValueError('중지 완료 후 저장하세요.')
            print(run); return
        elif args.action in ('query', 'critical'):
            result = query(run, args.action == 'critical', args.limit)
        elif args.action == 'raw-search':
            result = raw_search(run, args.match_path, args.limit, args.max_bytes, args.max_seconds)
        elif args.action == 'index':
            result = index_run(run)
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as exc:
        print('MGlogWH 오류: ' + str(exc), file=sys.stderr)
        sys.exit(1)
