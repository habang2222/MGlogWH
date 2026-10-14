#!/usr/bin/env python3
"""Derive all-lane, read-only correction from preserved original run JSON."""
from collections import defaultdict
import hashlib
import json
from pathlib import Path
from statistics import median

HERE = Path(__file__).resolve().parent
CRITICAL = '/tmp/mglogwh-perf-2026-10-14-decoy/critical'
NORMAL = '/tmp/mglogwh-perf-2026-10-14-decoy/normal'
BULK = '/tmp/mglogwh-perf-2026-10-14-decoy/bulk-missing'
CASES = ('baseline', 'rule1', 'rule4', 'rule8')


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def get_count(item, path, lane=None):
    entry = item['raw']['by_path'].get(path, {})
    return entry.get('lanes', {}).get(lane, 0) if lane else entry.get('total', 0)


def summarize_one(path):
    item = json.loads(path.read_text())
    health = item['health']
    truth = item['truth']
    stop_index = item.get('stop_status', {}).get('index', {})
    tenant = health.get('tenants', [])
    raw_counts = {kind: get_count(item, key) for kind, key in
                  (('critical', CRITICAL), ('normal', NORMAL), ('bulk', BULK))}
    by_lane = item['raw']['by_path'].get(CRITICAL, {}).get('lanes', {})
    result = dict(label=item['label'], condition=item['condition'], repeat=item['repeat'],
                  original_json_sha256=sha256(path), source_run_id=item['run_id'],
                  source_run_dir=item['run_dir'],
                  config_file_sha256=item['config_file_sha256'],
                  normalized_config_sha256=item['normalized_config_sha256'],
                  truth_counts=dict(zip(('bulk', 'critical', 'normal'), truth['expected_results'])),
                  truth_unexpected_results=truth['unexpected_results'],
                  requested_eps=truth['requested_eps'], actual_eps=truth['actual_eps'],
                  actual_over_requested=truth['actual_eps'] / truth['requested_eps'],
                  critical_durable_all_lanes=raw_counts['critical'],
                  critical_by_lane=by_lane,
                  critical_durable_recall=raw_counts['critical'] / truth['expected_results'][1],
                  critical_unpaired_count=truth['expected_results'][1] - raw_counts['critical'],
                  normal_durable_all_lanes=raw_counts['normal'],
                  bulk_durable_all_lanes=raw_counts['bulk'],
                  raw_file_bytes=item['raw_file_bytes'],
                  raw_durable_bytes=sum(health.get('durable', {}).values()),
                  raw_crc_and_schema_valid=item['raw']['crc_and_schema_valid'],
                  all_raw_records=item['raw']['records_total'],
                  critical_seen_global=health.get('critical_seen_total'),
                  quarantine_seen_global=health.get('quarantine_seen_total'),
                  quarantine_summary_global=health.get('quarantine_summarized_total'),
                  quarantine_enter_global=health.get('quarantine_enter_total'),
                  policy_bulk_suppression_global=sum(t.get('budget_suppress', 0) for t in tenant),
                  ring_failed_global=sum(t.get('critical_full', 0) + t.get('general_full', 0) +
                                         t.get('quarantine_full', 0) for t in tenant),
                  queue_overflow_global=sum(health.get('queue_overflow', [])),
                  fault_counters_global=health.get('faults', []),
                  collector_cpu_seconds=health.get('cpu_seconds'),
                  collector_max_rss_kib=health.get('max_rss_kib'),
                  workload_cpu_seconds=truth.get('workload_cpu_seconds'),
                  workload_max_rss_kib=truth.get('workload_max_rss_kib'),
                  openat_p95_us=truth.get('p95_us'), openat_p99_us=truth.get('p99_us'),
                  index_lag_records_at_stop=stop_index.get('lag_records'),
                  index_complete_to_durable_at_stop=stop_index.get('complete_to_durable'),
                  recovery_error=item.get('recover_error'),
                  original_valid_run=item.get('valid_run'),
                  policy_threshold_configured=1000000,
                  policy_threshold_violation=(health.get('quarantine_enter_total', 0) > 0 and
                                              health.get('peak_critical_rate', 0) < 1000000))
    result['critical_recall_basis'] = 'aggregate exact-path durable counts, CRC/schema checked; no per-syscall nonce or bijection'
    result['stage_counters_scope'] = 'global run/cgroup aggregates include unrelated events; cannot assign individual missing syscall causes'
    result['kernel_cpu_and_event_to_durable_latency'] = 'NOT_MEASURED'
    result['valid_workload_and_raw'] = (item.get('valid_run') and
                                        result['critical_durable_all_lanes'] <= truth['expected_results'][1] and
                                        raw_counts['normal'] <= truth['expected_results'][2] and
                                        raw_counts['bulk'] <= truth['expected_results'][0])
    return result


def main():
    rows = [summarize_one(path) for path in sorted((HERE / 'runs').glob('*.json'))
            if not path.name.endswith('-error.json')]
    grouped = defaultdict(list)
    for row in rows:
        grouped[row['condition']].append(row)
    aggregate = {}
    for case in CASES:
        cases = grouped[case]
        aggregate[case] = dict(repeats=len(cases),
            requested_eps=cases[0]['requested_eps'] if cases else None,
            actual_eps_median=median(c['actual_eps'] for c in cases) if cases else None,
            critical_truth_total=sum(c['truth_counts']['critical'] for c in cases),
            critical_durable_total=sum(c['critical_durable_all_lanes'] for c in cases),
            normal_truth_total=sum(c['truth_counts']['normal'] for c in cases),
            normal_durable_total=sum(c['normal_durable_all_lanes'] for c in cases),
            bulk_truth_total=sum(c['truth_counts']['bulk'] for c in cases),
            bulk_durable_total=sum(c['bulk_durable_all_lanes'] for c in cases),
            quarantine_seen_global_total=sum(c['quarantine_seen_global'] for c in cases),
            quarantine_summary_total=sum(c['quarantine_summary_global'] for c in cases),
            policy_bulk_suppression_global_total=sum(c['policy_bulk_suppression_global'] for c in cases),
            ring_failed_global_total=sum(c['ring_failed_global'] for c in cases),
            queue_overflow_global_total=sum(c['queue_overflow_global'] for c in cases),
            openat_p95_us_median=median(c['openat_p95_us'] for c in cases) if cases else None,
            openat_p99_us_median=median(c['openat_p99_us'] for c in cases) if cases else None,
            collector_cpu_seconds_median=median(c['collector_cpu_seconds'] for c in cases) if cases else None,
            collector_rss_kib_median=median(c['collector_max_rss_kib'] for c in cases) if cases else None,
            raw_durable_bytes_median=median(c['raw_durable_bytes'] for c in cases) if cases else None,
            all_recovery_invalid=all(c['recovery_error'] for c in cases))
    report = dict(original_head='eb9c888bbf1e60a6c58a0c2082a1d639bc7b6607',
                  correction='Original critical_durable_count counted critical.raw only; this derived file sums all CRC/schema-checked durable lanes. Original JSON files are unchanged.',
                  caveat='P0 policy misapplication caused Q transitions under configured 1,000,000 EPS; ledger recover INVALID due duplicate config_sha256. These are defect-reproduction measurements, not final corrected-code performance.',
                  observed_runs=rows, per_condition=aggregate)
    target = HERE / 'corrected_summary-eb9c888.json'
    with target.open('w', encoding='utf-8') as file:
        json.dump(report, file, ensure_ascii=False, indent=2, sort_keys=True)
        file.write('\n')
    lines = ['# eb9c888 성능 실험 원본 보존 및 집계 정정', '',
             '원본 `runs/*.json`의 `critical_durable_count`는 `critical.raw`만 세었습니다. 이 파생 보고서는 각 원본 SHA-256을 남기고 CRC·schema 검증된 durable 경계의 모든 lane을 합산합니다. 원본 JSON과 raw 파일은 변경하지 않았습니다.',
             '', '## 조건별 3회 결과', '',
             '| 조건 | 중앙 실제 EPS | Critical 독립 truth | Critical durable 전체 lane | p95 / p99 µs 중앙 | 수집기 CPU 초 중앙 | Q 요약 총합 | 복구 원장 |',
             '|---|---:|---:|---:|---:|---:|---:|---|']
    for case in CASES:
        a = aggregate[case]
        lines.append(f'| {case} | {a["actual_eps_median"]:,.1f} | {a["critical_truth_total"]:,} | {a["critical_durable_total"]:,} | {a["openat_p95_us_median"]:.2f} / {a["openat_p99_us_median"]:.2f} | {a["collector_cpu_seconds_median"]:.3f} | {a["quarantine_summary_total"]} | INVALID |')
    lines += ['', '| 조건 | NORMAL truth / durable | BULK truth / durable | Q 대표 raw 전체 | BULK 정책 억제 전체 | ring 실패 전체 | queue overflow 전체 | raw durable 중앙 MiB | RSS 중앙 KiB |',
              '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for case in CASES:
        a = aggregate[case]
        lines.append(f'| {case} | {a["normal_truth_total"]:,} / {a["normal_durable_total"]:,} | {a["bulk_truth_total"]:,} / {a["bulk_durable_total"]:,} | {a["quarantine_seen_global_total"]:,} | {a["policy_bulk_suppression_global_total"]:,} | {a["ring_failed_global_total"]:,} | {a["queue_overflow_global_total"]:,} | {a["raw_durable_bytes_median"] / 1024**2:.2f} | {a["collector_rss_kib_median"]:,.0f} |')
    lines += ['', '## 결함과 해석', '',
              '- 설정한 Critical 진입 임계치는 1,000,000 EPS였으나 health는 약 100 EPS에서 Quarantine 진입을 기록했습니다. 정책 비교와 최종 성능 판정에는 이 코드 버전을 사용할 수 없습니다.',
              '- 각 500건은 동일한 고유 decoy 경로를 사용했습니다. 500/500은 경로별 **집계 대응**이며 개별 syscall의 일대일 대응을 증명하지 않습니다. Quarantine 대표 raw와 정책 요약을 구분해 `corrected_summary-eb9c888.json`에 보존했습니다.',
              '- `manage.py recover`는 `duplicate JSON key: config_sha256`으로 INVALID였습니다. raw CRC·index 완료와 원장 검증을 혼동하지 않습니다.',
              '- BPF `faults[2]`는 `sys_exit_openat`에서 대응되는 `pending` 항목을 찾지 못한 **run 전체 집계**입니다(`sensor.bpf.c`의 `open_exit`). baseline-r1은 13회였고 12개 run에서는 2~306회였습니다. 어떤 독립 truth 호출이 이 항목에 해당하는지는 확인할 수 없어 특정 누락 원인을 배정하지 않습니다.',
              '- syscall p95/p99는 직접 `SYS_openat` 전후의 monotonic wall clock으로 측정했으며 스케줄링 시간을 포함합니다. BPF 단독 지연, 커널 CPU/메모리, event-to-durable 지연은 미측정입니다.',
              '- 과거 15k/80k/150k 실험과 워크로드·커널·하드웨어·코드가 같지 않아 수치를 직접 비교하지 않습니다.',
              '- 재현 명령은 `run_benchmark.py`에 고정했고 무센서 pilot은 `pilot-15k.json`, source/build 해시는 `environment.json`에 있습니다. 각 원본 run의 raw 3개, evidence.meta, commit fence, manifest, health, index SHA-256은 `artifact-hashes-eb9c888.json`에 보존했습니다.', '']
    (HERE / 'CORRECTION-eb9c888.md').write_text('\n'.join(lines), encoding='utf-8')


if __name__ == '__main__':
    main()
