# Critical Quarantine / Priority Abuse Protection — v0.3

## 기존 구조

`event.h`가 BULK=0, NORMAL=1, CRITICAL=2를 정의한다. `sensor.bpf.c`는 openat entry/exit를 연결하고, 성공 exec과 openat을 수집한다. 기존 critical 조건은 `protected_path`의 정확한 절대 경로 문자열이다. BPF → critical/general ring → 전용 drain → 고정 큐 → lane writer → CRC raw → 파생 SQLite가 기본 경로다. `collector.c`의 별도 metadata writer는 checkpoint·userspace loss·seal을 저장하며 `ledger.py`가 committed fence까지만 복구한다. `health.json`이 기존 외부 상태·metrics 인터페이스다.

이 기능은 이전 v0.2의 **critical cgroup rate cap·shared rate cap·보호 cgroup 전용 공간·tenant round robin을 제거**한다. 원래부터 있던 bulk 예산, critical/general 분리, 전체 raw 상한, critical/general 사이 저장 예산, 읽기 전용 원장은 유지한다.

## 변경한 구조

quarantine 판단을 **BPF의 ring reserve 앞**에 넣었다. collector에서만 거르면 이미 critical ring을 점유한 뒤이므로 다른 critical을 보호하기 어렵기 때문이다. stream key는 `(cgroup_id, rule_id, event_kind)`다. tenant 전체를 바꾸지 않는다.

`critical_rules`는 최대 8개의 정확한 경로 규칙을 지원한다. 현재 관찰 가능한 종류는 `openat`과 성공 `exec`이다. 같은 종류·경로의 중복 규칙과 중복 ID는 거부한다. 규칙마다 `protected=true`를 지정할 수 있다. 이는 해당 규칙의 quarantine 면제이며 cgroup 예약이나 새 탐지 엔진을 뜻하지 않는다. credential 변경·kernel integrity·collector tampering을 새로 탐지한 것으로 해석하지 않는다.

priority 값은 계속 CRITICAL이다. 232바이트 이벤트와 240바이트 CRC record 크기는 그대로이며 schema 2의 quality에 rule ID·effective policy·sample 종류를 담는다. capture 오류는 하위 2비트로 별도 검사한다. schema 1의 과거 원본도 reader와 indexer가 지원한다. 이전 reader는 schema 2를 사용하기 전에 업데이트해야 한다.

격리되지 않은 critical과 Protected Critical은 기존 critical ring·FIFO·writer로 간다. 격리된 초기 원본과 주기적 샘플은 별도 quarantine ring·512건 FIFO·writer·`quarantine.raw`로 간다. NORMAL로 덮어쓰거나 general.raw에 섞지 않는다. 큐마다 writer가 자신의 파일을 동기화하며 disk I/O는 ring callback에서 수행하지 않는다.

## 동작 흐름

```text
kernel event → classify rule → original_priority=CRITICAL
  → stream fixed-window rate check
  ├ protected rule → PROTECTED_CRITICAL → critical.raw
  ├ threshold duration 미충족 → CRITICAL → critical.raw
  └ threshold duration 충족 → QUARANTINE
       ├ 초기 N건 → INITIAL_FULL → quarantine.raw
       ├ 주기적 대표 원본 → PERIODIC_SAMPLE → quarantine.raw
       └ 나머지 → CRITICAL_QUARANTINE aggregate summary

enter/exit control + stream counters + actual raw durable counts
  → bounded metadata queue → evidence.meta → synced commit fence
  → recover / analysis diagnostics
```

1초 완료 창의 EPS가 진입 임계치 이상으로 설정 시간 동안 이어지면 진입한다. 최초의 불완전한 창은 지속 시간에 포함하지 않아 최대1초의 추가 지연이 생길 수 있다. 순간 초과만으로 진입하지 않는다. 낮은 완료 창이 복구 임계치 이하로 cooldown 동안 이어지면 해제한다. idle 구간의 해제 판단은 다음 이벤트가 올 때 수행한다. 타이머가 정확한 wall-clock 시점에 정책을 바꾸는 구조는 아니다.

샘플 방식은 **초기 일부 원본 + 시간 간격당 대표 원본 + 전체 발생 카운터**다. 1/N 방식보다 sample 간격과 초기 비용을 설정으로 직접 제한하기 쉽다. INITIAL_FULL과 PERIODIC_SAMPLE은 모두 동일한 완전한 raw payload이며, 통계에서 보존 목적만 구분한다.

## 설정값

| 키 | 기본값 | 의미 |
|---|---:|---|
| critical_rate_threshold | 10000 | 진입 EPS, 이상 비교 |
| critical_rate_duration_seconds | 3 | 지속해야 하는 높은 rate 기간 |
| critical_recovery_threshold | 2000 | 복구 EPS, 이하 비교; 진입보다 작아야 함 |
| critical_recovery_duration_seconds | 10 | 낮은 rate cooldown 기간 |
| quarantine_initial_full_events | 8 | episode 초기 전체 원본 보존 대상 수 |
| quarantine_sample_interval_ms | 100 | 이후 대표 원본 간격 |
| quarantine_max_mib | 16 | quarantine.raw 한도; 전체 raw 상한 안에 포함 |
| metadata_max_mib | 16 | metadata 원장 한도; 신규 설정은 8..64 MiB |
| critical_rules | decoy openat, id=1 | 최대8개, id·event_type·path·protected |

예시는 기존 관찰 종류를 쓰는 정책 예시이며 파일을 만들거나 접근하지 않는다.

```json
"critical_rules": [
  {"id": 1, "event_type": "openat", "path": "/tmp/repeated-critical", "protected": false},
  {"id": 2, "event_type": "exec", "path": "/usr/bin/sensitive-helper", "protected": false},
  {"id": 3, "event_type": "openat", "path": "/etc/shadow", "protected": true}
]
```

설정은 다음 시작에 적용된다. 실행 중 policy transaction은 구현하지 않는다. 이전 cgroup guard 키와 `--protected-cgroup`은 제거했다. 과거 run의 설정 snapshot은 변경하지 않는다. 기존 7키 설정에서 새 run을 시작하면 quarantine 기본값과 protected_path의 기본 규칙을 보완한다.

## Loss / Evidence Ledger와 통계

진입·해제 metadata는 stream key, original_priority=CRITICAL, effective_policy=QUARANTINE, episode ID, 시작·종료 시각과 event ID, 임계치, 관찰 EPS·기간, 원인, episode 카운터를 기록한다. snapshot에는 stream 누적 통계와 current/last episode를 남긴다. cgroup sequence는 여러 CPU가 policy lock 전에 부여하므로 chronological first/last ID가 수치상 증가한다고 가정하지 않는다. episode의 실제 저장 표본은 동일 stream의 policy 시각 범위로 매칭한다.

의도적으로 원본을 줄인 양은 `CRITICAL_QUARANTINE` 요약이며, queue·storage 거절은 별도의 정확한 event ID tombstone이다. 서로 다른 규칙이 cgroup sequence를 공유하므로 한 episode의 첫·끝 sequence 사이 모든 gap을 quarantine 때문이라고 판정하지 않는다. BPF counter를 truth 누락 이벤트의 이유에 임의로 배분하지 않는다.

구분할 카운터:

- 발생: 전체 critical, quarantined seen, protected seen, peak/current EPS, window·burst 상태.
- 정책 선택: 초기 full 대상, periodic sample 대상, summarized.
- 수집·저장: ring submitted/failed, userspace admitted/rejected, appended, durable full/sample.
- 전환: active streams, enter/exit, 전환 ring 실패, tracking failure와 incomplete coverage.
- episode: first/last event ID·시각·PID·UID, 기간·평균/최고 rate, PID/UID bitmap cardinality lower bound.

정상 종료에서 tracking이 완전하면 `seen = full_selected + sample_selected + summarized`, `selected = submitted + ring_failed`가 맞아야 한다. 실제 저장은 fdatasync 완료 원본을 기준으로 `full_saved + sampled`를 센다. `seen - durable_saved`는 최종 not-stored 합계다. 수집 중의 차이는 queue/in-flight·미동기화도 포함하므로 전부 영구 손실로 부르지 않는다.

quarantine.raw와 general.raw는 기존 noncritical 저장 예산을 공유한다. quarantine 자체 한도 도달 시 해당 lane만 거절·집계하고 다른 critical 처리를 계속한다. 전체 raw 한도나 실제 디스크 오류 시 기존 FAILED 정책은 유지한다. 메타 frame은 최대4 MiB이며 마지막 seal 공간을 예약한다. 원장·control ring이 포화되면 coverage 저하를 표시한다. 원본과 미commit tail은 수정·승격하지 않는다.

## 변경된 파일

| 파일 | 변경 |
|---|---|
| event.h / tenant.h | schema2 정책·rule 표식, 이전 cgroup guard 통계 제거 |
| quarantine.h | 설정·규칙·stream·episode·전환 계약 |
| sensor.bpf.c | 규칙 분류, pre-ring rate·hysteresis·sample·telemetry |
| collector.c | 기존 critical FIFO 복원, quarantine lane·writer·quota·원장·metrics |
| manage.py / config.json | 설정 검증·CLI 전달, 새 raw index·query 의미 |
| ledger.py | 2/3-lane 호환, 전환·episode·durable 증거 복구 |
| test_quarantine.c / test_writer.c | 요청한 정책·sampling·저장·metadata fixture |
| test_manage.py / test_ledger.py | 설정·schema·원장 호환 및 손상 fixture |
| Makefile | 신규 fixture 컴파일 및 명시적 test target |
| README.md / LEDGER.md | 현재 동작·한계·손실 원장 계약 |

## 테스트와 사용자 실행

요청한 8개 시나리오를 synthetic fixture로 작성했다: 낮은 rate, 순간 초과, 지속 초과, A/rule1만 격리, Protected Critical 면제, cooldown 복구, sampling 합계, 사후 metadata. fixture는 가상 monotonic 시각을 쓰며 live BPF나 실제 workload를 시작하지 않는다. BPF object 컴파일·skeleton 생성과 collector·두 C fixture의 `-Wall -Wextra -Werror` 컴파일을 완료했고 수정한 Python·PowerShell 파일도 구문 검사를 통과했다. fixture 실행 결과는 아직 없다.

사용자가 실행할 명령:

```bash
make                         # 컴파일만
make test                    # 명시적으로 synthetic tests 실행
sudo python3 manage.py start # 여기서부터 실제 BPF 수집
sudo python3 manage.py stop
python3 manage.py recover --run <UUID> --out /tmp/recovery-<UUID>.json
```

실제 부하 생성기와 분석기는 이 저장소에 포함하지 않는다. 본 문서의 정책 시험 절차는 수집기 synthetic fixture에 한정한다. 제작 당시의 컴파일·구문 검사는 실제 부하에서의 성능이나 손실률을 보장하지 않는다.

## 아직 남은 문제

- path 문자열 기반 규칙이며 inode·mount namespace·상대 경로를 해석하지 않는다.
- 지속 시간 조건이 충족되기 전에는 폭주가 critical ring을 점유할 수 있다. quarantine이 소급하여 이미 유실된 원본을 복구하지 않는다.
- 최대1024 stream이며 자동 LRU 축출하지 않는다. tracking 용량·동시성 실패는 별도 untracked quarantine 표식과 bounded sample·telemetry로 처리하고 정확한 개별 episode coverage를 주장하지 않는다.
- PID/UID bitmap 수치는 충돌이 가능한 lower bound이며 정확한 distinct count가 아니다.
- Protected Critical은 quarantine 면제이나 queue·raw·CPU·disk는 여전히 유한하다. 다른 이벤트의 무손실을 보장하지 않는다.
- 이벤트가 없는 동안 release는 다음 이벤트까지 지연된다. 실제 임계치·recall·성능·BPF verifier load는 사용자 실험으로 확인해야 한다.
- CRC/hash는 손상 검사이며 서명이나 root 공격자에 대한 불변 저장 보장이 아니다.
