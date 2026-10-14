# eb9c888 성능 실험 원본 보존 및 집계 정정

원본 `runs/*.json`의 `critical_durable_count`는 `critical.raw`만 세었습니다. 이 파생 보고서는 각 원본 SHA-256을 남기고 CRC·schema 검증된 durable 경계의 모든 lane을 합산합니다. 원본 JSON과 raw 파일은 변경하지 않았습니다.

`baseline`은 0규칙이 아닙니다. 원래 설정에 규칙 키가 없어 `manage.py`가 legacy `openat` Critical 규칙 1개를 자동 생성했습니다. `rule1`은 별도의 `event_rules` 1규칙 형식입니다.

## 조건별 3회 결과

| 조건 | 중앙 실제 EPS | Critical 독립 truth | Critical durable 전체 lane | p95 / p99 µs 중앙 | 수집기 CPU 초 중앙 | Q 요약 총합 | 복구 원장 |
|---|---:|---:|---:|---:|---:|---:|---|
| baseline | 15,350.2 | 1,500 | 1,500 | 50.43 / 84.89 | 1.070 | 0 | INVALID |
| rule1 | 15,350.3 | 1,500 | 1,500 | 49.59 / 78.83 | 1.067 | 0 | INVALID |
| rule4 | 15,350.2 | 1,500 | 1,500 | 52.35 / 84.79 | 3.761 | 0 | INVALID |
| rule8 | 15,350.1 | 1,500 | 1,500 | 52.03 / 85.21 | 3.726 | 0 | INVALID |

| 조건 | NORMAL truth / durable | BULK truth / durable | Q 대표 raw 전체 | BULK 정책 억제 전체 | ring 실패 전체 | queue overflow 전체 | raw durable 중앙 MiB | RSS 중앙 KiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 3,750 / 3,750 | 225,000 / 225,000 | 771 | 0 | 0 | 0 | 17.78 | 22,528 |
| rule1 | 3,750 / 3,750 | 225,000 / 225,000 | 693 | 0 | 0 | 0 | 17.78 | 22,528 |
| rule4 | 3,750 / 3,750 | 225,000 / 225,000 | 755 | 0 | 0 | 0 | 17.72 | 22,528 |
| rule8 | 3,750 / 3,750 | 225,000 / 225,000 | 722 | 0 | 0 | 0 | 17.77 | 22,528 |

## 결함과 해석

- 설정한 Critical 진입 임계치는 1,000,000 EPS였으나 health는 약 100 EPS에서 Quarantine 진입을 기록했습니다. 정책 비교와 최종 성능 판정에는 이 코드 버전을 사용할 수 없습니다.
- 각 500건은 동일한 고유 decoy 경로를 사용했습니다. 500/500은 경로별 **집계 대응**이며 개별 syscall의 일대일 대응을 증명하지 않습니다. Quarantine 대표 raw와 정책 요약을 구분해 `corrected_summary-eb9c888.json`에 보존했습니다.
- `manage.py recover`는 `duplicate JSON key: config_sha256`으로 INVALID였습니다. raw CRC·index 완료와 원장 검증을 혼동하지 않습니다.
- BPF `faults[2]`는 `sys_exit_openat`에서 대응되는 `pending` 항목을 찾지 못한 **run 전체 집계**입니다(`sensor.bpf.c`의 `open_exit`). baseline-r1은 13회였고 12개 run에서는 2~306회였습니다. 어떤 독립 truth 호출이 이 항목에 해당하는지는 확인할 수 없어 특정 누락 원인을 배정하지 않습니다.
- syscall p95/p99는 직접 `SYS_openat` 전후의 monotonic wall clock으로 측정했으며 스케줄링 시간을 포함합니다. BPF 단독 지연, 커널 CPU/메모리, event-to-durable 지연은 미측정입니다.
- 과거 15k/80k/150k 실험과 워크로드·커널·하드웨어·코드가 같지 않아 수치를 직접 비교하지 않습니다.
- 재현 명령은 `run_benchmark.py`에 고정했고 무센서 pilot은 `pilot-15k.json`, source/build 해시는 `environment.json`에 있습니다. 각 원본 run의 raw 3개, evidence.meta, commit fence, manifest, health, index SHA-256은 `artifact-hashes-eb9c888.json`에 보존했습니다.
