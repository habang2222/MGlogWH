#!/usr/bin/env python3
"""Read-only recovery of the committed MGlogWH metadata journal.

This module never starts a sensor, rewrites health, truncates a journal, or
promotes its uncommitted suffix. CRC32 detects accidental damage, not tampering.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import tempfile
import uuid
import zlib

FRAME = struct.Struct('<II')
EVENT = struct.Struct('<4Qq12I16s128s')
RECORD_SIZE = EVENT.size + 8
LANES = ('critical', 'general')
ALL_LANES = ('critical', 'general', 'quarantine')
Q_QUARANTINE = 1 << 8
Q_INITIAL = 1 << 9
Q_PERIODIC = 1 << 10
Q_PROTECTED = 1 << 11
Q_UNTRACKED = 1 << 12
QUALITY_MASK = 0x00ff1f03
QUARANTINE_METRIC_ALIASES = ('active_quarantined_streams', 'critical_events_total',
                             'quarantined_events_total', 'peak_critical_rate')
MAX_FRAME = 4 * 1024 * 1024
MAX_JOURNAL = 64 * 1024 * 1024
MAX_RANGES = 4096
UINT64 = 2**64 - 1


class LedgerError(ValueError):
    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LedgerError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw, object_pairs_hook=_unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          LedgerError('nonfinite JSON: ' + value)))


def _object(path, limit=MAX_FRAME):
    with Path(path).open('rb') as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise LedgerError('metadata size limit: ' + str(path))
    value = _json(raw)
    if not isinstance(value, dict):
        raise LedgerError('JSON object required: ' + str(path))
    return value


def _integer(value, label, minimum=0, maximum=UINT64):
    if type(value) is not int or not minimum <= value <= maximum:
        raise LedgerError(f'{label}: integer {minimum}..{maximum} required')
    return value


def _uuid(value, label):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except ValueError as exc:
        raise LedgerError(label + ': canonical UUID required') from exc
    return value


def _digest(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _lineage(run):
    manifest = _object(run / 'manifest.json')
    config = _object(run / 'config.json')
    if type(manifest.get('schema')) is not int or manifest['schema'] != 1:
        raise LedgerError('manifest schema mismatch')
    if _uuid(manifest.get('run_id'), 'manifest run_id') != run.name:
        raise LedgerError('directory/manifest run_id mismatch')
    _uuid(manifest.get('boot_id'), 'manifest boot_id')
    canonical = json.dumps(config, sort_keys=True, separators=(',', ':')).encode()
    config_hash = hashlib.sha256(canonical).hexdigest()
    if config_hash != manifest.get('config_sha256'):
        raise LedgerError('config/manifest SHA256 mismatch')
    return dict(run_id=run.name, boot_id=manifest['boot_id'],
                config_sha256=config_hash, manifest_sha256=_digest(run / 'manifest.json'))


def _bound_lineage(value, lineage):
    for key, expected in lineage.items():
        if value.get(key) != expected:
            raise LedgerError('metadata lineage mismatch: ' + key)


def _lane_names(offsets):
    if not isinstance(offsets, dict):
        raise LedgerError('checkpoint durable lane object required')
    if set(offsets) == set(LANES):
        return LANES
    if set(offsets) == set(ALL_LANES):
        return ALL_LANES
    raise LedgerError('checkpoint durable lane set mismatch')


def _policy(schema, quality, priority, lane):
    if schema == 1:
        if quality & ~3 or lane == 'quarantine':
            raise LedgerError('legacy quality/lane mismatch')
        flags, rule_id = 0, 0
    elif schema == 2:
        if quality & ~QUALITY_MASK:
            raise LedgerError('unknown raw policy/quality bits')
        flags, rule_id = quality & 0x1f00, (quality >> 16) & 255
        if (flags or rule_id) and priority != 2:
            raise LedgerError('raw rule/policy requires original critical priority')
        if priority == 2 and not rule_id:
            raise LedgerError('schema 2 critical requires rule_id')
        if flags & Q_INITIAL and flags & Q_PERIODIC:
            raise LedgerError('raw initial/periodic policy conflict')
        if flags & (Q_INITIAL | Q_PERIODIC) and not flags & Q_QUARANTINE:
            raise LedgerError('raw sample policy without quarantine')
    else:
        raise LedgerError('raw schema mismatch')
    if (priority == 2) != (lane in ('critical', 'quarantine')):
        raise LedgerError('raw lane/priority mismatch')
    if bool(flags & Q_QUARANTINE) != (lane == 'quarantine'):
        raise LedgerError('raw quarantine policy/lane mismatch')
    if flags & Q_QUARANTINE and not flags & (Q_INITIAL | Q_PERIODIC):
        raise LedgerError('quarantine raw requires selection policy')
    if flags & Q_PROTECTED and flags & Q_QUARANTINE:
        raise LedgerError('protected rule cannot enter quarantine raw')
    if flags & Q_UNTRACKED and not flags & (Q_QUARANTINE | Q_PROTECTED):
        raise LedgerError('untracked policy requires quarantine or protected fallback')
    return dict(rule_id=rule_id, flags=flags, capture_quality=quality & 3)


def _snapshot(value, previous=None):
    offsets = value.get('durable_offsets')
    lanes = _lane_names(offsets)
    if previous and set(previous['durable_offsets']) != set(offsets):
        raise LedgerError('checkpoint durable lane set changed')
    for lane in lanes:
        offset = _integer(offsets[lane], 'checkpoint offset ' + lane)
        if offset % RECORD_SIZE:
            raise LedgerError('checkpoint offset not record aligned: ' + lane)
        if previous and offset < previous['durable_offsets'][lane]:
            raise LedgerError('checkpoint durable offsets regressed: ' + lane)
    tenants = value.get('tenants')
    if not isinstance(tenants, list) or len(tenants) > 1024:
        raise LedgerError('checkpoint tenants must be bounded list')
    ids = set()
    previous_sequences = {tenant['cgroup_id']: tenant['sequence'] for tenant in
                          previous['tenants']} if previous else {}
    for tenant in tenants:
        if not isinstance(tenant, dict):
            raise LedgerError('checkpoint tenant object required')
        cgroup = _integer(tenant.get('cgroup_id'), 'tenant cgroup_id')
        seq = _integer(tenant.get('sequence'), 'tenant sequence')
        if cgroup in ids or seq < previous_sequences.get(cgroup, 0):
            raise LedgerError('duplicate tenant or regressed sequence')
        ids.add(cgroup)
    if previous and value.get('sequence_snapshot_complete') is True and not set(previous_sequences) <= ids:
        raise LedgerError('checkpoint lost an existing tenant')
    faults = value.get('faults')
    if not isinstance(faults, list) or len(faults) != 4:
        raise LedgerError('checkpoint faults must contain four aggregate counters')
    for item in faults:
        _integer(item, 'fault counter')
    for key in ('metadata_overflow', 'metadata_dropped'):
        _integer(value.get(key), key)
        if previous and value[key] < previous[key]:
            raise LedgerError(key + ' regressed')
    if type(value.get('exact_loss_available')) is not bool:
        raise LedgerError('exact_loss_available must be boolean')
    if value.get('summary_kind') != 'AGGREGATE_ONLY':
        raise LedgerError('snapshot summary_kind must be AGGREGATE_ONLY')
    if 'sequence_snapshot_complete' in value and type(value['sequence_snapshot_complete']) is not bool:
        raise LedgerError('sequence_snapshot_complete must be boolean')
    if value['exact_loss_available'] and (value['metadata_overflow'] or value['metadata_dropped']):
        raise LedgerError('exact loss coverage contradicts metadata overflow')
    if value['record_type'] == 'seal' and value.get('state') not in ('STOPPED', 'FAILED'):
        raise LedgerError('seal state must be STOPPED or FAILED')
    for key in QUARANTINE_METRIC_ALIASES:
        if key in value:
            _integer(value[key], key, maximum=1024 if key == 'active_quarantined_streams' else UINT64)
    if 'peak_critical_rate' in value and value.get('peak_critical_rate_scope') != 'MAX_TRACKED_STREAM_ONE_SECOND_EPS':
        raise LedgerError('peak critical rate scope mismatch')
    if 'quarantine_by_reason' in value:
        reasons = value['quarantine_by_reason']
        if (not isinstance(reasons, dict) or set(reasons) != {'CRITICAL_RATE_EXCEEDED', 'CRITICAL_RATE_RECOVERED'} or
            value.get('quarantine_by_reason_scope') != 'TRANSITIONS'):
            raise LedgerError('quarantine reason counts require exact transition scope')
        for key, item in reasons.items():
            _integer(item, 'quarantine transition reason count ' + key)
    if 'streams' in value:
        streams = value['streams']
        if not isinstance(streams, list) or len(streams) > 1024:
            raise LedgerError('quarantine streams must be bounded list')
        seen_streams = set()
        for stream in streams:
            key = _stream_key(stream)
            if key in seen_streams:
                raise LedgerError('duplicate quarantine stream')
            seen_streams.add(key)
            if not isinstance(stream.get('engine'), dict) or not isinstance(stream.get('collector'), dict):
                raise LedgerError('quarantine engine/collector objects required')
            for section in (stream, stream['collector']):
                for key, item in section.items():
                    if key not in ('engine', 'collector'):
                        _integer(item, 'stream counter ' + key)
            for key, item in stream['engine'].items():
                if key in ('current', 'last'):
                    _episode(item)
                else:
                    _integer(item, 'engine counter ' + key)
        for key in ('stream_snapshot_complete', 'stream_storage_complete'):
            if type(value.get(key)) is not bool:
                raise LedgerError(key + ' must be boolean')
        if 'quarantine_tracking_complete' in value and type(value['quarantine_tracking_complete']) is not bool:
            raise LedgerError('quarantine_tracking_complete must be boolean')
        global_ = value.get('quarantine_global', {})
        if not isinstance(global_, dict):
            raise LedgerError('quarantine_global object required')
        for key, item in global_.items():
            _integer(item, 'global quarantine counter ' + key)
    return value


def _stream_key(value):
    if not isinstance(value, dict):
        raise LedgerError('quarantine stream object required')
    return (str(_integer(value.get('cgroup_id'), 'stream cgroup_id')),
            _integer(value.get('rule_id'), 'stream rule_id', 1, 255),
            _integer(value.get('kind'), 'stream kind', 1, 2))


def _episode(value):
    if not isinstance(value, dict):
        raise LedgerError('quarantine episode object required')
    required = ('episode_id', 'start_ns', 'end_ns', 'first_sequence', 'last_sequence',
                'seen', 'full_selected', 'sample_selected', 'summarized',
                'full_submitted', 'sample_submitted', 'ring_failed')
    for key in required:
        _integer(value.get(key), 'episode ' + key)
    for key, item in value.items():
        if key == 'tracking_complete':
            if type(item) is not bool and (type(item) is not int or item not in (0, 1)):
                raise LedgerError('episode tracking_complete must be boolean or 0/1')
        else:
            _integer(item, 'episode ' + key)
    if value['episode_id']:
        if value['episode_id'] != value['first_sequence']:
            raise LedgerError('episode identity/first sequence mismatch')
        if value['end_ns'] and value['end_ns'] < value['start_ns']:
            raise LedgerError('episode time bounds regressed')
    return value


def _control(db, value, report):
    cgroup, rule, kind = _stream_key(value)
    episode = _episode(value.get('episode'))
    eid = _integer(value.get('episode_id'), 'control episode_id', 1)
    if eid != episode['episode_id']:
        raise LedgerError('control/episode identity mismatch')
    for key in ('first_seq', 'last_seq', 'seq', 'monotonic_ns', 'threshold_eps', 'observed_eps', 'duration_ms'):
        _integer(value.get(key), 'control ' + key)
    if value['first_seq'] != episode['first_sequence'] or value['last_seq'] != episode['last_sequence']:
        raise LedgerError('control/episode sequence bounds mismatch')
    transition = value['record_type']
    if value.get('reason') != ('HIGH_RATE' if transition == 'quarantine_enter' else 'LOW_RATE'):
        raise LedgerError('quarantine transition reason mismatch')
    expected_policy = dict(original_priority='CRITICAL',
        effective_policy='QUARANTINE' if transition == 'quarantine_enter' else 'CRITICAL',
        trigger_reason='CRITICAL_RATE_EXCEEDED' if transition == 'quarantine_enter' else 'CRITICAL_RATE_RECOVERED')
    for key, expected in expected_policy.items():
        if key in value and value[key] != expected:
            raise LedgerError('quarantine transition policy mismatch: ' + key)
    if episode['start_ns'] != value['monotonic_ns'] and transition == 'quarantine_enter':
        raise LedgerError('quarantine enter policy time mismatch')
    if episode['end_ns'] != value['monotonic_ns'] and transition == 'quarantine_exit':
        raise LedgerError('quarantine exit policy time mismatch')
    signature = json.dumps({key:item for key,item in value.items() if key != 'journal_seq'},
                           sort_keys=True, separators=(',', ':'))
    key = (cgroup, rule, kind, _seq_key(eid), transition)
    old = db.execute('SELECT payload FROM controls WHERE cgroup=? AND rule_id=? AND kind=? AND episode_id=? AND transition=?', key).fetchone()
    if old:
        if old[0] != signature:
            raise LedgerError('conflicting quarantine transition')
        report['duplicate_quarantine_controls'] += 1
    else:
        db.execute('INSERT INTO controls VALUES (?,?,?,?,?,?)', (*key, signature))


def _seq_key(seq):
    # Text preserves the whole unsigned 64-bit ABI and lexicographic order.
    return f'{seq:020d}'


def _loss_witness(value, lane):
    """Validate optional v1 per-ID context; old five-field tombstones stay valid."""
    witness = value.get('witness')
    if witness is None:
        return None
    required = {'version', 'source', 'event_schema', 'kind', 'priority', 'quality',
                'rule_id', 'pid', 'tid', 'uid', 'process_start_ns', 'result',
                'op_flags', 'captured_len', 'path_hex'}
    if not isinstance(witness, dict) or set(witness) != required:
        raise LedgerError('loss witness field set mismatch')
    if type(witness['version']) is not int or witness['version'] != 1 or witness['source'] != 'USERSPACE_RING_CALLBACK':
        raise LedgerError('unsupported loss witness version/source')
    if _integer(witness['event_schema'], 'loss event_schema', 2, 2) != 2:
        raise LedgerError('loss witness raw schema mismatch')
    _integer(witness['kind'], 'loss kind', 1, 2)
    priority = _integer(witness['priority'], 'loss priority', 0, 2)
    quality = _integer(witness['quality'], 'loss quality', 0, 0xffffffff)
    policy = _policy(2, quality, priority, lane)
    if _integer(witness['rule_id'], 'loss rule_id', 0, 255) != policy['rule_id']:
        raise LedgerError('loss witness rule_id/quality mismatch')
    for key in ('pid', 'tid', 'uid', 'op_flags'):
        _integer(witness[key], 'loss ' + key, 0, 0xffffffff)
    _integer(witness['process_start_ns'], 'loss process_start_ns')
    if type(witness['result']) is not int or not -(2**63) <= witness['result'] < 2**63:
        raise LedgerError('loss result must be signed 64-bit integer')
    length = _integer(witness['captured_len'], 'loss captured_len', 0, 127)
    path_hex = witness['path_hex']
    if (not isinstance(path_hex, str) or len(path_hex) != length * 2 or
        any(char not in '0123456789abcdef' for char in path_hex)):
        raise LedgerError('loss witness path_hex/captured_len mismatch')
    return json.dumps(witness, sort_keys=True, separators=(',', ':'))


def _loss(db, value, report):
    cgroup = str(_integer(value.get('cgroup_id'), 'loss cgroup_id'))
    seq = _seq_key(_integer(value.get('seq'), 'loss seq', 1))
    lane, reason = value.get('lane'), value.get('reason')
    timestamp = _integer(value.get('monotonic_ns'), 'loss monotonic_ns')
    if lane not in ALL_LANES or not isinstance(reason, str) or not reason or len(reason) > 128 or '\0' in reason:
        raise LedgerError('invalid loss lane/reason')
    witness = _loss_witness(value, lane)
    old = db.execute('SELECT lane,reason,monotonic_ns,witness FROM losses WHERE cgroup=? AND seq=?',
                     (cgroup, seq)).fetchone()
    signature = (lane, reason, str(timestamp), witness)
    if old:
        if old != signature:
            raise LedgerError('conflicting loss tombstones for ' + cgroup + ':' + str(int(seq)))
        report['duplicate_loss_records'] += 1
    else:
        db.execute('INSERT INTO losses VALUES (?,?,?,?,?,?)', (cgroup, seq, *signature))


def _read_journal(run, fence, lineage, db, report):
    boundary = _integer(fence.get('offset'), 'commit offset', 0, MAX_JOURNAL)
    last_seq = _integer(fence.get('journal_seq'), 'commit journal_seq')
    size = (run / 'evidence.meta').stat().st_size
    if boundary > size:
        raise LedgerError('journal shorter than committed fence')
    report['journal'].update(committed_bytes=boundary, uncommitted_bytes=size-boundary,
                             committed_journal_seq=last_seq)
    progress = report['verification_progress']
    progress['journal_committed_boundary_bytes'] = boundary
    seq, offset, last, sealed = 0, 0, None, False
    with (run / 'evidence.meta').open('rb') as handle:
        while offset < boundary:
            if boundary-offset < FRAME.size:
                raise LedgerError('torn frame header inside committed journal')
            length, checksum = FRAME.unpack(handle.read(FRAME.size))
            if not 1 <= length <= MAX_FRAME or FRAME.size+length > boundary-offset:
                raise LedgerError('invalid or torn committed frame length')
            raw = handle.read(length)
            if zlib.crc32(raw) != checksum:
                raise LedgerError('metadata CRC32 mismatch at byte ' + str(offset))
            value = _json(raw)
            if not isinstance(value, dict) or type(value.get('schema')) is not int or value['schema'] != 1:
                raise LedgerError('metadata frame schema mismatch')
            seq += 1
            if _integer(value.get('journal_seq'), 'frame journal_seq', 1) != seq:
                raise LedgerError('metadata journal_seq is not contiguous')
            _bound_lineage(value, lineage)
            if sealed:
                raise LedgerError('records after terminal seal')
            kind = value.get('record_type')
            if kind == 'loss':
                _loss(db, value, report)
            elif kind in ('quarantine_enter', 'quarantine_exit'):
                _control(db, value, report)
            elif kind in ('checkpoint', 'seal'):
                _bound_lineage(value, lineage)
                last = _snapshot(value, last)
                sealed = kind == 'seal'
            else:
                raise LedgerError('unsupported metadata record_type')
            offset += FRAME.size + length
            progress['journal_verified_prefix_bytes'] = offset
            progress['journal_verified_frames'] = seq
            if seq % 4096 == 0:
                db.commit()
    if offset != boundary or seq != last_seq:
        raise LedgerError('commit fence boundary/journal_seq mismatch')
    db.commit()
    return last


def _read_raw(run, snapshot, db, report):
    offsets = snapshot['durable_offsets'] if snapshot else {lane: 0 for lane in
        (ALL_LANES if (run / 'quarantine.raw').exists() else LANES)}
    for lane in _lane_names(offsets):
        path = run / (lane + '.raw')
        size = path.stat().st_size if path.exists() else 0
        limit = offsets[lane]
        if limit > size:
            raise LedgerError('raw shorter than committed checkpoint: ' + lane)
        report['raw'][lane] = dict(file_bytes=size, durable_bytes=limit,
                                   uncommitted_bytes=size-limit,
                                   partial_tail_bytes=(size-limit) % RECORD_SIZE)
        report['verification_progress']['raw_verified_prefix_bytes'][lane] = 0
        if not limit:
            continue
        with path.open('rb') as handle:
            for offset in range(0, limit, RECORD_SIZE):
                raw = handle.read(RECORD_SIZE)
                checksum, reserved = struct.unpack('<II', raw[-8:])
                if reserved or zlib.crc32(raw[:-8]) != checksum:
                    raise LedgerError(f'{lane}.raw:{offset}: CRC32/reserved mismatch')
                event = EVENT.unpack(raw[:-8])
                if event[5] != 0x31514F45 or event[6] not in (1, 2) or event[7] not in (1, 2) or event[8] not in (0, 1, 2):
                    raise LedgerError('raw magic/schema/kind/priority mismatch')
                policy = _policy(event[6], event[16], event[8], lane)
                if event[15] > 127:
                    raise LedgerError('raw capture length mismatch')
                if b'\0' not in event[17] or b'\0' not in event[18]:
                    raise LedgerError('raw string has no NUL')
                path_bytes = event[18].split(b'\0', 1)[0]
                if policy['capture_quality'] == 0 and len(path_bytes) != event[15]:
                    raise LedgerError('raw path/capture length mismatch')
                if not event[2]:
                    raise LedgerError('raw sequence must be positive')
                cgroup, seq = str(event[1]), _seq_key(event[2])
                digest = hashlib.sha256(raw).hexdigest()
                previous = db.execute('SELECT digest FROM durable WHERE cgroup=? AND seq=?',
                                      (cgroup, seq)).fetchone()
                if previous and previous[0] != digest:
                    raise LedgerError('conflicting durable payload for ' + cgroup + ':' + str(event[2]))
                db.execute('INSERT OR IGNORE INTO durable VALUES (?,?,?,?,?,?,?,?)',
                           (cgroup, seq, digest, lane, policy['rule_id'], event[7], policy['flags'], _seq_key(event[0])))
                report['durable_records'] += 1
                report['verification_progress']['raw_verified_prefix_bytes'][lane] = offset + RECORD_SIZE
                if offset % (4096 * RECORD_SIZE) == 0:
                    db.commit()
    db.commit()
    conflict = db.execute('SELECT cgroup,seq FROM durable JOIN losses USING(cgroup,seq) LIMIT 1').fetchone()
    if conflict:
        raise LedgerError('durable record contradicts loss tombstone: ' + conflict[0] + ':' + str(int(conflict[1])))
    report['durable_unique_events'] = db.execute('SELECT count(*) FROM durable').fetchone()[0]


def _ranges(values, label):
    """Compress a sorted iterator while retaining exact counts with capped output."""
    output, start, last, count, total_ranges = [], None, None, 0, 0
    for value in values:
        value = int(value)
        count += 1
        if last is not None and value == last + 1:
            last = value
            continue
        if last is not None:
            total_ranges += 1
            if len(output) < MAX_RANGES:
                output.append(dict(start=start, end=last, status=label))
        start = last = value
    if last is not None:
        total_ranges += 1
        if len(output) < MAX_RANGES:
            output.append(dict(start=start, end=last, status=label))
    return dict(count=count, ranges=output, range_count=total_ranges,
                ranges_truncated=total_ranges > len(output))


def _gaps(db, cgroup, upper):
    """Return intervals, never enumerate 1..upper (which may be 2**64-1)."""
    cursor, count, ranges, total_ranges, pending = 1, 0, [], 0, None

    def append(start, end, reason='UNKNOWN', lane=None):
        nonlocal count, total_ranges, pending
        count += end-start+1
        if pending and pending['end']+1 == start and pending['reason'] == reason and pending.get('lane') == lane:
            pending['end'] = end
            return
        if pending and len(ranges) < MAX_RANGES:
            ranges.append(pending)
        total_ranges += 1
        pending = dict(start=start, end=end, status='ABSENT_FROM_DURABLE_RAW', reason=reason,
                       reason_source='UNKNOWN' if lane is None else 'EXACT_USERSPACE_TOMBSTONE')
        if lane is not None:
            pending['lane'] = lane

    records = db.execute('SELECT seq,kind,reason,lane FROM ('
        'SELECT seq,\'DURABLE\' AS kind,\'\' AS reason,\'\' AS lane FROM durable WHERE cgroup=? AND seq<=? '
        'UNION ALL SELECT seq,\'LOSS\',reason,lane FROM losses WHERE cgroup=? AND seq<=?) ORDER BY seq',
        (str(cgroup), _seq_key(upper), str(cgroup), _seq_key(upper)))
    for text, kind, reason, lane in records:
        seq = int(text)
        if seq > cursor:
            append(cursor, seq-1)
        if kind == 'LOSS':
            append(seq, seq, reason, lane)
        cursor = seq+1
    if cursor <= upper:
        append(cursor, upper)
    if pending and len(ranges) < MAX_RANGES:
        ranges.append(pending)
    return dict(count=count, ranges=ranges, range_count=total_ranges,
                ranges_truncated=total_ranges > len(ranges))


def _contiguous_frontier(db, cgroup, include_losses):
    """A prefix proven by individual IDs, never by aggregate counters."""
    if include_losses:
        query = ('SELECT seq FROM durable WHERE cgroup=? UNION '
                 'SELECT seq FROM losses WHERE cgroup=? ORDER BY seq')
        args = (str(cgroup), str(cgroup))
    else:
        query = 'SELECT seq FROM durable WHERE cgroup=? ORDER BY seq'
        args = (str(cgroup),)
    next_seq = 1
    for (value,) in db.execute(query, args):
        if int(value) != next_seq:
            break
        next_seq += 1
    return next_seq - 1


def match_truth_candidates(loss, candidates, tolerance_ns, *, candidate_set_complete=False):
    """Return a truth ID only for one full-context candidate in one run/clock.

    The caller must assert a complete candidate set from the same run and
    notebook monotonic clock. A nearest timestamp alone never establishes ID.
    """
    _integer(tolerance_ns, 'truth matching tolerance_ns')
    if candidate_set_complete is not True:
        return dict(status='UNKNOWN', truth_seq=None, candidate_count=None)
    witness = loss.get('witness')
    if (not isinstance(witness, dict) or type(witness.get('quality')) is not int or
        witness['quality'] & 3):
        return dict(status='UNKNOWN', truth_seq=None, candidate_count=0)
    needed = ('run_id', 'boot_id', 'cgroup_id', 'monotonic_ns')
    if any(key not in loss for key in needed) or not witness.get('path_hex') or not witness.get('tid'):
        return dict(status='UNKNOWN', truth_seq=None, candidate_count=0)
    matches = set()
    for candidate in candidates:
        if (candidate.get('run_id') != loss['run_id'] or
            candidate.get('boot_id') != loss['boot_id'] or
            candidate.get('clock_domain') != 'NOTEBOOK_MONOTONIC' or
            candidate.get('cgroup_id') != loss['cgroup_id'] or
            candidate.get('tid') != witness['tid'] or
            candidate.get('kind') != witness['kind'] or
            candidate.get('path_hex') != witness['path_hex'] or
            candidate.get('result') != witness['result'] or
            type(candidate.get('monotonic_ns')) is not int or
            abs(candidate['monotonic_ns'] - loss['monotonic_ns']) > tolerance_ns):
            continue
        truth_seq = candidate.get('truth_seq')
        if type(truth_seq) is int and truth_seq >= 0:
            matches.add(truth_seq)
    if len(matches) == 1:
        return dict(status='UNIQUE_CANDIDATE', truth_seq=next(iter(matches)), candidate_count=1)
    return dict(status='AMBIGUOUS' if matches else 'UNKNOWN', truth_seq=None,
                candidate_count=len(matches))


def _raw_counts(db, cgroup=None, rule_id=None, kind=None, start_ns=None, end_ns=None,
                end_inclusive=False, include_untracked=True):
    where, args = ['(flags & ?) != 0'], [Q_QUARANTINE]
    for key, value in (('cgroup', cgroup), ('rule_id', rule_id), ('kind', kind)):
        if value is not None:
            where.append(key + '=?')
            args.append(value)
    for operator, value in (('>=', start_ns), ('<=' if end_inclusive else '<', end_ns)):
        if value is not None:
            where.append('monotonic_ns' + operator + '?')
            args.append(_seq_key(value))
    if not include_untracked:
        where.append('(flags & ?) = 0')
        args.append(Q_UNTRACKED)
    row = db.execute('SELECT '
        'coalesce(sum((flags & 512)!=0 AND (flags & 4096)=0),0),'
        'coalesce(sum((flags & 1024)!=0 AND (flags & 4096)=0),0),'
        'coalesce(sum((flags & 512)!=0 AND (flags & 4096)!=0),0),'
        'coalesce(sum((flags & 1024)!=0 AND (flags & 4096)!=0),0) '
        'FROM durable WHERE ' + ' AND '.join(where), args).fetchone()
    return dict(owned_initial_full=row[0], owned_periodic_sample=row[1],
                untracked_initial_full=row[2], untracked_periodic_sample=row[3],
                initial_full_total=row[0]+row[2], periodic_sample_total=row[1]+row[3])


def _counter_reconciliation(counters, stored, finalized):
    seen = counters.get('seen', counters.get('q_seen', 0))
    full = counters.get('full_selected', 0)
    sampled = counters.get('sample_selected', 0)
    summarized = counters.get('summarized', 0)
    full_submitted = counters.get('full_submitted', 0)
    sample_submitted = counters.get('sample_submitted', 0)
    ring_failed = counters.get('ring_failed', 0)
    result = dict(scope='TRACKED_KERNEL_OWNED_QUARANTINE_EVENTS', seen=seen,
        selected_initial_full=full, selected_periodic_sample=sampled,
        summarized=summarized, ring_failed=ring_failed,
        submitted_initial_full=full_submitted, submitted_periodic_sample=sample_submitted,
        partition_consistent=seen == full+sampled+summarized,
        selection_consistent=full+sampled == full_submitted+sample_submitted+ring_failed,
        summary_reason='CRITICAL_QUARANTINE', summary_kind='AGGREGATE_ONLY', individual_event_ids=None)
    if stored is None:
        result.update(durable_initial_full=None, durable_periodic_sample=None,
                      not_durable=None, reconciliation_complete=False)
        return result
    saved_full, saved_sample = stored['owned_initial_full'], stored['owned_periodic_sample']
    difference = seen-saved_full-saved_sample
    after_ring = full_submitted+sample_submitted-saved_full-saved_sample
    result.update(durable_initial_full=saved_full, durable_periodic_sample=saved_sample,
        durable_selection_consistent=saved_full <= full_submitted and saved_sample <= sample_submitted,
        not_durable=difference if finalized and difference >= 0 else None,
        pending_or_not_durable=difference if difference >= 0 else None,
        submitted_not_durable=after_ring if finalized and after_ring >= 0 else None,
        reconciliation_complete=finalized and result['partition_consistent'] and result['selection_consistent'] and
            saved_full <= full_submitted and saved_sample <= sample_submitted)
    return result


def _episode_report(db, key, episode, label, final_scope):
    cgroup, rule_id, kind = key
    eid = _seq_key(episode['episode_id'])
    rows = dict(db.execute('SELECT transition,payload FROM controls WHERE cgroup=? AND rule_id=? AND kind=? AND episode_id=?',
                           (cgroup, rule_id, kind, eid)))
    enter = _json(rows['quarantine_enter']) if 'quarantine_enter' in rows else None
    exit_ = _json(rows['quarantine_exit']) if 'quarantine_exit' in rows else None
    if enter and exit_:
        if enter['first_seq'] != exit_['first_seq'] or enter['monotonic_ns'] > exit_['monotonic_ns']:
            raise LedgerError('quarantine enter/exit ordering or bounds mismatch')
    closed = bool(episode['end_ns'])
    controls_complete = bool(enter and (exit_ or not closed))
    bounds_match = bool(enter and enter['first_seq'] == episode['first_sequence'] and
                       (not exit_ or exit_['last_seq'] == episode['last_sequence']))
    tracking_complete = bool(episode.get('tracking_complete', False))
    end_ns = episode['end_ns'] if closed else episode.get('last_event_ns', 0)
    actual = _raw_counts(db, cgroup, rule_id, kind, episode['start_ns'], end_ns,
                        end_inclusive=not closed, include_untracked=False) \
        if controls_complete and bounds_match and end_ns >= episode['start_ns'] else None
    finalized = bool(final_scope and controls_complete and bounds_match and tracking_complete)
    span = episode.get('last_event_ns', 0)-episode['start_ns']
    return dict(cgroup_id=int(cgroup), rule_id=rule_id, kind=kind,
        episode_id=episode['episode_id'], role=label, scope_source='COMMITTED_EPISODE_METADATA',
        episode=episode, controls_complete=controls_complete, bounds_match=bounds_match,
        tracking_complete=tracking_complete, transition_records=[name for name in rows],
        enter_transition=enter, exit_transition=exit_,
        sequence_fields_do_not_identify_missing_ids=True,
        membership='same cgroup/rule/kind, Q policy, non-UNTRACKED, start_ns <= monotonic_ns < end_ns; current last_event_ns inclusive',
        first_last_sequences_are_event_ids_not_ordering_bounds=True,
        average_rate_eps=episode['seen']*1_000_000_000/span if span > 0 else None,
        average_rate_definition='seen / (last_event_ns - start_ns), seconds; null for zero span',
        actual_durable=actual, reconciliation=_counter_reconciliation(episode, actual, finalized))


def _quarantine_report(db, snapshot, report):
    if not snapshot or 'quarantine' not in snapshot['durable_offsets']:
        return
    actual = _raw_counts(db)
    result = dict(summary_reason='CRITICAL_QUARANTINE', summary_kind='AGGREGATE_ONLY',
        individual_event_ids=None, actual_durable=actual,
        full_saved_total=actual['initial_full_total'], sampled_total=actual['periodic_sample_total'],
        streams=[], episodes=[], episode_metadata_truncated=False,
        policy='ORIGINAL_CRITICAL_PRIORITY_PRESERVED', global_counters=snapshot.get('quarantine_global', {}))
    result['declared_metric_aliases'] = {key:snapshot[key] for key in QUARANTINE_METRIC_ALIASES if key in snapshot}
    if 'peak_critical_rate_scope' in snapshot:
        result['declared_metric_aliases']['peak_critical_rate_scope'] = snapshot['peak_critical_rate_scope']
    if 'quarantine_by_reason' in snapshot:
        result['quarantine_by_reason'] = snapshot['quarantine_by_reason']
        result['quarantine_by_reason_scope'] = snapshot['quarantine_by_reason_scope']
    stream_complete = snapshot.get('stream_snapshot_complete') is True
    storage_complete = snapshot.get('stream_storage_complete') is True
    tracking_complete = snapshot.get('quarantine_tracking_complete',
        not any(stream.get('tracking_failed', 0) for stream in snapshot.get('streams', [])) and
        not snapshot.get('quarantine_global', {}).get('stream_map_full', 0) and
        not snapshot.get('quarantine_global', {}).get('state_contention', 0)) is True
    final_scope = bool(report['clean_seal'] and stream_complete and storage_complete and tracking_complete)
    result.update(stream_snapshot_complete=stream_complete, stream_storage_complete=storage_complete,
                  tracking_complete=tracking_complete, final_scope_complete=final_scope,
                  selected_pending_total=snapshot.get('quarantine_pending_total'))
    known_episode_ids = set()
    for stream in snapshot.get('streams', []):
        key = _stream_key(stream)
        engine, collector = stream['engine'], stream['collector']
        counts = _raw_counts(db, *key)
        reconciliation = _counter_reconciliation(engine, counts, final_scope and not stream.get('tracking_failed', 0))
        rejections = sum(collector.get(name, 0) for name in ('queue_rejected_full', 'queue_rejected_sample',
                         'storage_rejected_full', 'storage_rejected_sample'))
        reconciliation['userspace_rejected_aggregate'] = rejections
        if reconciliation.get('submitted_not_durable') is not None:
            remainder = reconciliation['submitted_not_durable']-rejections
            reconciliation['unsynced_or_unexplained_after_rejections'] = remainder if remainder >= 0 else None
        result['streams'].append(dict(cgroup_id=int(key[0]), rule_id=key[1], kind=key[2],
            seen_total=stream.get('seen', 0), protected_seen=stream.get('protected_seen', 0),
            tracking_failed=stream.get('tracking_failed', 0),
            untracked_counters={name:value for name,value in stream.items() if name.startswith('untracked_')},
            lifetime=reconciliation, collector=collector, actual_durable=counts,
            current_rate_eps=engine.get('current_rate_eps'), peak_rate_eps=engine.get('peak_rate_eps')))
        for label in ('current', 'last'):
            episode = engine.get(label, {})
            if episode.get('episode_id'):
                known_episode_ids.add((*key, _seq_key(episode['episode_id'])))
                result['episodes'].append(_episode_report(db, key, episode, label, final_scope))
    # Exit controls retain older episodes even after current/last roll forward.
    for cgroup, rule_id, kind, eid, payload in db.execute(
            'SELECT cgroup,rule_id,kind,episode_id,payload FROM controls WHERE transition=\'quarantine_exit\' ORDER BY cgroup,rule_id,kind,episode_id'):
        key = (cgroup, rule_id, kind)
        if (*key, eid) in known_episode_ids:
            continue
        if len(result['episodes']) >= MAX_RANGES:
            result['episode_metadata_truncated'] = True
            break
        result['episodes'].append(_episode_report(db, key, _json(payload)['episode'], 'closed_history', final_scope))
    result['critical_seen_total'] = result['global_counters'].get('critical_events_total',
        sum(stream.get('seen', 0) for stream in snapshot.get('streams', [])) + result['global_counters'].get('stream_map_full', 0))
    result['protected_seen_total'] = result['global_counters'].get('protected_events_total',
        sum(stream.get('protected_seen', 0) for stream in snapshot.get('streams', [])) + result['global_counters'].get('untracked_protected', 0))
    result['critical_seen_scope_complete'] = stream_complete and not snapshot['faults'][3]
    result['quarantine_seen_total'] = result['global_counters'].get('quarantined_events_total',
        sum(stream['engine'].get('q_seen', 0) for stream in snapshot.get('streams', [])) +
        result['global_counters'].get('untracked_seen', 0)-result['global_counters'].get('untracked_protected', 0))
    difference = result['quarantine_seen_total']-actual['initial_full_total']-actual['periodic_sample_total']
    result['quarantine_not_stored_total'] = difference if final_scope and result['critical_seen_scope_complete'] and difference >= 0 else None
    result['quarantine_pending_or_not_stored_total'] = difference if difference >= 0 else None
    result['collector_durable_totals_match_raw'] = (
        snapshot.get('quarantine_full_saved_total') == actual['initial_full_total'] and
        snapshot.get('quarantine_sampled_total') == actual['periodic_sample_total']) \
        if 'quarantine_full_saved_total' in snapshot and 'quarantine_sampled_total' in snapshot else None
    report['critical_quarantine'] = result


def _witness_entry(lineage, row):
    cgroup, seq, lane, reason, timestamp, payload = row
    witness = _json(payload)
    quality = witness['quality']
    return dict(run_id=lineage['run_id'], boot_id=lineage['boot_id'],
                cgroup_id=int(cgroup), seq=int(seq), lane=lane,
                reason=reason, monotonic_ns=int(timestamp), witness=witness,
                truth_binding='UNMATCHED',
                quarantine_selection=('INITIAL_FULL' if quality & Q_INITIAL else
                                      'PERIODIC_SAMPLE' if quality & Q_PERIODIC else 'NONE'),
                durable_raw=False)


def _summarize(db, snapshot, report):
    report['exact_userspace_losses'] = []
    for cgroup, lane, reason in db.execute('SELECT DISTINCT cgroup,lane,reason FROM losses ORDER BY cgroup,lane,reason'):
        values = (row[0] for row in db.execute('SELECT seq FROM losses WHERE cgroup=? AND lane=? AND reason=? ORDER BY seq',
                                              (cgroup, lane, reason)))
        report['exact_userspace_losses'].append(dict(cgroup_id=int(cgroup), lane=lane,
            reason=reason, **_ranges(values, 'CONFIRMED_USERSPACE_LOSS')))
    report['exact_userspace_loss_count'] = db.execute('SELECT count(*) FROM losses').fetchone()[0]
    witness_count = db.execute('SELECT count(*) FROM losses WHERE witness IS NOT NULL').fetchone()[0]
    report['exact_userspace_loss_witnesses'] = dict(count=witness_count,
        entries=[_witness_entry(report['lineage'], row)
                 for row in db.execute(
                     'SELECT cgroup,seq,lane,reason,monotonic_ns,witness FROM losses '
                     'WHERE witness IS NOT NULL ORDER BY cgroup,seq LIMIT ?', (MAX_RANGES,))],
        entries_truncated=witness_count > MAX_RANGES,
        legacy_tombstones_without_witness=report['exact_userspace_loss_count']-witness_count,
        identity_scope='SENSOR_CGROUP_SEQUENCE_WITHIN_RUN_AND_BOOT',
        truth_id_scope='UNBOUND_UNTIL_UNIQUE_NOTEBOOK_MONOTONIC_CONTEXT_MATCH')
    report['committed_quarantine_control_count'] = db.execute('SELECT count(*) FROM controls').fetchone()[0]
    if snapshot is None and report['committed_quarantine_control_count']:
        report['partial_quarantine_controls'] = dict(durability='COMMITTED_JOURNAL_FENCE',
            entries=[_json(row[0]) for row in db.execute('SELECT payload FROM controls LIMIT ?', (MAX_RANGES,))],
            entries_truncated=report['committed_quarantine_control_count'] > MAX_RANGES,
            actual_durable_episode_counts=None)
    report['exact_userspace_loss_durability'] = 'COMMITTED_JOURNAL_FENCE'
    report['raw_recovery_supported'] = snapshot is not None
    report['clean_seal'] = bool(snapshot and snapshot['record_type'] == 'seal' and snapshot.get('state') == 'STOPPED')
    report['absence_set_complete'] = bool(report['clean_seal'] and
        snapshot.get('sequence_snapshot_complete') is True)
    report['checkpoint_userspace_loss_reason_coverage_complete'] = bool(snapshot and snapshot['exact_loss_available'])
    report['userspace_loss_reason_coverage_complete'] = bool(report['clean_seal'] and snapshot['exact_loss_available'])
    report['userspace_loss_witness_coverage_complete'] = bool(
        report['userspace_loss_reason_coverage_complete'] and
        witness_count == report['exact_userspace_loss_count'])
    report['exact_loss_scope'] = 'USERSPACE_REJECTIONS'
    report['tenant_evidence'] = []
    if snapshot:
        # Aggregate counters never enter either exact loss or per-gap reasons.
        report['last_trusted_checkpoint'] = snapshot
        report['unsequenced_faults'] = dict(summary_kind='AGGREGATE_ONLY',
            counters=dict(tenant_map_missing=snapshot['faults'][0],
                          pending_update_failed=snapshot['faults'][1], pending_lookup_missing=snapshot['faults'][2]),
            affected_event_ids=None, exact_unobserved_event_count=None,
            explanation='Pre-sequence observation faults have no recoverable event IDs; counters are not assigned to gaps')
        if 'quarantine' in snapshot['durable_offsets']:
            report['pre_sequence_policy_faults'] = dict(summary_kind='AGGREGATE_ONLY',
                counters=dict(quarantine_global_lookup_failed=snapshot['faults'][3]), affected_event_ids=None,
                explanation='Policy lookup failed before sequence assignment; later fallback may still allocate a sequence. No event IDs or missing counts are inferred')
        else:
            report['sequenced_aggregate_faults'] = dict(summary_kind='AGGREGATE_ONLY',
                counters=dict(shared_critical_budget_lookup_failed=snapshot['faults'][3]), affected_event_ids=None,
                explanation='This legacy fault occurs after sequence allocation; its aggregate count is not assigned to individual missing IDs')
        for tenant in snapshot['tenants']:
            cgroup, upper = tenant['cgroup_id'], tenant['sequence']
            outlier = db.execute('SELECT seq FROM durable WHERE cgroup=? AND seq>? LIMIT 1',
                                  (str(cgroup), _seq_key(upper))).fetchone()
            if outlier and report['absence_set_complete']:
                raise LedgerError('durable event exceeds final tenant sequence')
            row = dict(cgroup_id=cgroup, checkpoint_sequence=upper)
            latest_raw = db.execute('SELECT max(seq) FROM durable WHERE cgroup=?',
                                    (str(cgroup),)).fetchone()[0]
            latest_loss = db.execute('SELECT max(seq) FROM losses WHERE cgroup=?',
                                     (str(cgroup),)).fetchone()[0]
            row['max_seen_exact_sequence'] = max(int(latest_raw or 0), int(latest_loss or 0))
            row['contiguous_raw_frontier'] = _contiguous_frontier(db, cgroup, False)
            row['accounted_frontier'] = _contiguous_frontier(db, cgroup, True)
            row['frontier_scope'] = 'COMMITTED_DURABLE_RAW_AND_EXACT_USERSPACE_TOMBSTONES_ONLY'
            if report['absence_set_complete']:
                row['final_absence'] = _gaps(db, cgroup, upper)
            else:
                row['unknown_tail'] = dict(status='UNBOUNDED_UNKNOWN_TAIL',
                    after_checkpoint_sequence=upper, end=None, count=None,
                    reason='No complete clean-stop sequence boundary; no exact tail count is inferred')
            report['tenant_evidence'].append(row)
        if report['absence_set_complete']:
            snapshot_ids = {str(tenant['cgroup_id']) for tenant in snapshot['tenants']}
            for (cgroup,) in db.execute('SELECT DISTINCT cgroup FROM durable UNION SELECT DISTINCT cgroup FROM losses'):
                if cgroup not in snapshot_ids:
                    raise LedgerError('final snapshot omits sequenced durable/loss tenant')
            for tenant in snapshot['tenants']:
                if db.execute('SELECT 1 FROM losses WHERE cgroup=? AND seq>? LIMIT 1',
                              (str(tenant['cgroup_id']), _seq_key(tenant['sequence']))).fetchone():
                    raise LedgerError('loss tombstone exceeds final tenant sequence')
        if snapshot['metadata_overflow'] or snapshot['metadata_dropped']:
            report['warnings'].append('METADATA_COVERAGE_DEGRADED: some exact userspace reasons were not committed')
    if not report['absence_set_complete']:
        report['unknown_future'] = dict(status='UNBOUNDED_UNKNOWN_TAIL', count=None,
            reason='No complete clean seal; tenants/events after the last committed snapshot may be unknown')
    if snapshot and snapshot.get('metadata_failed'):
        report['warnings'].append('METADATA_IO_FAILURE: checkpoint reports failed metadata persistence')
    if report['clean_seal'] and not report['absence_set_complete']:
        report['warnings'].append('SEQUENCE_BOUNDARY_INCOMPLETE: clean stop lacks a complete sequence snapshot')
    _quarantine_report(db, snapshot, report)


def recover(run, out=None):
    """Return a serializable report; optional out must be outside the source run.

    INVALID reports make no partial evidence claims. Legacy runs and journals
    lacking a commit fence have explicit unsupported/uncommitted states.
    """
    run = Path(run).resolve()
    report = dict(schema=1, program='MGlogWHLedger', version='0.3.0', run_path=str(run),
                  status='INVALID', errors=[], warnings=[], journal={}, raw={},
                  clean_seal=False, absence_set_complete=False, raw_recovery_supported=False, durable_records=0,
                  durable_unique_events=0, duplicate_loss_records=0,
                  duplicate_quarantine_controls=0,
                  source_modified=False, recovery_policy='COMMITTED_FENCE_ONLY_NO_TAIL_PROMOTION',
                  verification_progress=dict(scope='DIAGNOSTIC_ONLY_NOT_PARTIAL_RECOVERY',
                    journal_committed_boundary_bytes=None, journal_verified_prefix_bytes=0,
                    journal_verified_frames=0, raw_verified_prefix_bytes={}),
                  counter_reason_policy='AGGREGATE_ONLY_NEVER_ASSIGN_TO_GAPS')
    journal, fence_path = run / 'evidence.meta', run / 'evidence.meta.commit'
    try:
        if not run.is_dir():
            raise LedgerError('source run directory does not exist')
        if not journal.exists() and not fence_path.exists():
            report.update(status='LEGACY_UNSUPPORTED', unsupported_reason='This run has no metadata ledger')
        else:
            lineage = _lineage(run)
            report['lineage'] = lineage
            if not journal.is_file():
                raise LedgerError('commit fence exists without metadata journal')
            report['journal']['file_bytes'] = journal.stat().st_size
            if not fence_path.exists():
                report.update(status='UNCOMMITTED', unknown_future=dict(status='UNBOUNDED_UNKNOWN_TAIL', count=None))
                report['journal'].update(committed_bytes=0, uncommitted_bytes=journal.stat().st_size)
                for lane in (ALL_LANES if (run / 'quarantine.raw').exists() else LANES):
                    path = run / (lane + '.raw')
                    size = path.stat().st_size if path.exists() else 0
                    report['raw'][lane] = dict(file_bytes=size, durable_bytes=0,
                        uncommitted_bytes=size, partial_tail_bytes=size % RECORD_SIZE)
                report['warnings'].append('NO_COMMIT_FENCE: journal bytes are preserved and provide no durable evidence')
            else:
                fence = _object(fence_path)
                if type(fence.get('schema')) is not int or fence['schema'] != 1:
                    raise LedgerError('commit fence schema mismatch')
                _bound_lineage(fence, lineage)
                with tempfile.TemporaryDirectory(prefix='mglogwh-ledger-') as temporary:
                    db = sqlite3.connect(str(Path(temporary) / 'recover.sqlite'))
                    try:
                        db.execute('PRAGMA cache_size=-4096')
                        db.execute('PRAGMA journal_mode=OFF')
                        db.execute('PRAGMA synchronous=OFF')
                        db.executescript('CREATE TABLE durable(cgroup TEXT,seq TEXT,digest TEXT,lane TEXT,rule_id INTEGER,kind INTEGER,flags INTEGER,monotonic_ns TEXT,PRIMARY KEY(cgroup,seq));'
                                         'CREATE INDEX durable_stream ON durable(cgroup,rule_id,kind,seq);'
                                         'CREATE INDEX durable_stream_time ON durable(cgroup,rule_id,kind,monotonic_ns);'
                                         'CREATE TABLE losses(cgroup TEXT,seq TEXT,lane TEXT,reason TEXT,monotonic_ns TEXT,witness TEXT,PRIMARY KEY(cgroup,seq));'
                                         'CREATE TABLE controls(cgroup TEXT,rule_id INTEGER,kind INTEGER,episode_id TEXT,transition TEXT,payload TEXT,PRIMARY KEY(cgroup,rule_id,kind,episode_id,transition));')
                        snapshot = _read_journal(run, fence, lineage, db, report)
                        _read_raw(run, snapshot, db, report)
                        _summarize(db, snapshot, report)
                        if snapshot is None:
                            report['status'] = 'PARTIAL_RECOVERY' if report['exact_userspace_loss_count'] or report['committed_quarantine_control_count'] else 'UNCOMMITTED'
                            report['unsupported_reason'] = 'No committed checkpoint supplies raw durable boundaries'
                            report['warnings'].append('NO_COMMITTED_CHECKPOINT: raw bytes remain uncommitted; independently committed loss/transition metadata remain exact')
                        else:
                            report['status'] = 'RECOVERED'
                    finally:
                        db.close()
    except (OSError, ValueError, UnicodeError, sqlite3.Error, struct.error) as exc:
        report.update(status='INVALID', clean_seal=False, absence_set_complete=False)
        report['errors'].append(str(exc))
        for key in ('last_trusted_checkpoint', 'exact_userspace_losses', 'exact_userspace_loss_count', 'tenant_evidence',
                    'checkpoint_userspace_loss_reason_coverage_complete', 'unsequenced_faults', 'sequenced_aggregate_faults',
                    'pre_sequence_policy_faults', 'critical_quarantine', 'partial_quarantine_controls', 'committed_quarantine_control_count',
                    'exact_userspace_loss_witnesses'):
            report.pop(key, None)
        report['durable_unique_events'] = 0
        report['durable_records'] = 0
        report['userspace_loss_reason_coverage_complete'] = False
        report['userspace_loss_witness_coverage_complete'] = False
        report['raw_recovery_supported'] = False
        report.pop('exact_userspace_loss_durability', None)
    if out is not None:
        destination = Path(out).resolve()
        if destination == run or run in destination.parents:
            raise LedgerError('Recovery output must be outside the source run')
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Do not overwrite a previous recovery report.
        with destination.open('x', encoding='utf-8', newline='\n') as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2, allow_nan=False)
            handle.write('\n')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, type=Path, help='Existing sensor run directory')
    parser.add_argument('--out', type=Path, help='New report JSON outside the source run')
    args = parser.parse_args(argv)
    try:
        result = recover(args.run, args.out)
    except (OSError, ValueError) as exc:
        parser.exit(2, f'Recovery report failed: {exc}\n')
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    return 2 if result['status'] == 'INVALID' else 0


if __name__ == '__main__':
    raise SystemExit(main())
