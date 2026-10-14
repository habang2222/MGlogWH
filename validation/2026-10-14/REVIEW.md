# MGlogWH v0.4.0 코드·원장·성능 검증 기록 (2026-10-14)

## 판정과 증거 범위

**최종 상태: WSL 재검증 완료, 독립 Ubuntu 서버 검증 필요.** 이번 검토에서 P0 결함 두 개와 P1 결함 세 개를 수정했다. WSL 파일시스템 복구 후 현재 코드의 Linux 빌드·전체 시험, 새 12회 규칙별 부하, 16개 경로 규칙 사례, 실제 systemd 수집기와 Control Room API 연동을 재검증했다. 새 12개 run은 모두 `recover=RECOVERED`이고 독립 Critical 호출 6,000건과 같은 경로의 durable raw 6,000건이 집계상 일치했다. 사전 시퀀스 진단 fault가 155건 있어 커널 관측·손실 0을 주장하지 않는다. 일반 Ubuntu 서버, 다른 커널, 장시간 고부하와 브라우저에서의 인증 후 전체 조작은 미검증이다. 이전 실패 실험 원본은 수정하지 않았다.

최초 결함 진단 기준은 수집기 [eb9c888](https://github.com/habang2222/MGlogWH/commit/eb9c888bbf1e60a6c58a0c2082a1d639bc7b6607), Control Room [dcd244c](https://github.com/habang2222/MGlogWH-ControlRoom/commit/dcd244ccd3dd7212978df689e3f567f5c58e19a0)이다. 수정 후 재검증 소스는 수집기 `f9bd477`이며 `32f31ce` 이후 수집기/BPF 실행 코드는 같고 벤치 기준 표기·검증기가 개선됐다. 수집기 수정은 `363ab82`(불완전 규칙 통계), `769ce82`(BPF 정책 설정), `7e62eae`(원장 JSON), `0e24c0d`(참조 평가기 경계)에 커밋했다. Control Room은 `fbc8c97`에서 적용 성공 표시 결함을 수정했다. [10월 9일 보고서](https://www.notion.so/3f40e129ee9b8144ae55eb4219d7fdb0)는 이전 코드·프로토콜의 결과로만 인용한다.

실행 환경은 Ubuntu 24.04 WSL2, kernel `6.6.87.2-microsoft-standard-WSL2+`, x86_64, Python 3.12.3이다. 최초 실험 전 가용 메모리 6,913,664 KiB, WSL 파일시스템 가용 1,003,855,515,648 B, 논리 CPU 16개였다. WSL 파일시스템 오류를 복구해 보존 run을 다시 읽을 수 있다. 별도 Ubuntu 서버 접근은 확인되지 않았다. 실제 Control Room 연동 시험에서 MGlogWH 서비스를 시작·재시작했고 종료 후 MGlogWH·Control Room 서비스를 비활성·중지, 설정을 원본과 바이트 단위로 대조했다. 이전 G:의 보존 실험 원본은 현재 호스트에서 접근할 수 없어 소급 재분석하지 않았다.

## v0.3에서 v0.4로 바뀐 계약

`event_rules`는 최대 8개 규칙, 한 규칙 최대 24개 토큰·논리 중첩 4단계, 3값 논리, precedence→priority→policy→ID 충돌 선택을 제공한다. `critical_rules`도 계속 읽는다. raw는 240바이트를 유지하며 새 규칙 ID·정책 비트를 schema 3에 싣는다. 설정·`rules.bin` 해시와 규칙·정책 버전을 manifest에 기록하고, 규칙별 커널 집계와 collector 저장 집계를 checkpoint에 둔다. schema 1·2 reader 호환 fixture는 유지한다. 코드 구현과 실제 동작 검증은 아래에서 구분한다.

## 발견 결함과 수정

| 중요도 | 위치 | 수정 전 증거와 영향 | 수정 | 수정 후 증거·잔여 한계 |
|---|---|---|---|---|
| P0 | `sensor.bpf.c`, `quarantine.h` | `const volatile` 규칙 설정을 비휘발성 포인터로 바꿔 Clang이 초기값 0을 상수화했다. disassembly에서 임계치 비교가 사라졌고 설정 1,000,000 EPS인데 실제 약 100 EPS에서 Q 진입, health `threshold_eps=0`이었다. | volatile 한정을 정책 함수까지 유지 | 수정 BPF 실제 로드. 500회·약 96.5 EPS·임계치 1,000,000 설정에서는 Q 진입 0, raw 500/500. 임계치 50 설정에서는 Q 진입 1, episode threshold 50·initial full 8, raw 366 + 정책 요약 134 = 500. 이 이전 smoke 원본은 새 12회 재검증 표본에 포함하지 않았다. |
| P0 | `collector.c` | `meta_write` prefix와 checkpoint/seal 본문이 `config_sha256`를 중복 기록. 수정 전 12개 새 run의 `recover` 모두 `INVALID: duplicate JSON key: config_sha256`; 커밋된 원장을 판독할 수 없었다. | checkpoint/seal에서는 본문 값 하나만 기록, loss/control은 prefix 유지 | 새 C 회귀와 Linux 빌드 통과. 수정본 12/12 실제 새 run의 `recover=RECOVERED`, raw CRC·schema 유효, index durable 경계 완료. 이전 12개 원장은 고치거나 신뢰 대상으로 승격하지 않는다. |
| P1 | `rules.h` | 사용자 공간 문자열 참조 평가기가 실제 NUL 이후까지 읽었다. 2바이트 경로 `/`와 긴 규칙 `/123456`의 격리 ASAN 재현에서 heap-buffer-overflow 발생. 실제 BPF는 LPM trie를 사용하므로 이 재현은 사용자 공간 참조 평가기 문제다. | NUL에서 즉시 FALSE 반환, 짧은 할당 문자열 회귀 추가 | Windows GCC 최적화 빌드와 Linux `make test` 통과. Linux GCC ASAN·leak 검사로 `test_rules`를 다시 실행해 오류 없이 통과. |
| P1 | `ledger.py` | 정상적인 BPF map 조회 실패가 `stats_available=false`·null 커널 통계로 기록되면 reader가 raw까지 `INVALID`로 버렸다. | 불완전 커널 통계는 경고와 `complete_to_durable=false`를 유지하면서 committed raw·collector 집계 복구. 모순된 완전 선언은 거부 | 회귀 수정 전 실패, 수정 후 Python `test_ledger` 47개 통과(WSL 및 Windows). 저장 증거 schema 변경 없음. |
| P1 | Control Room `controlroom/backend.py` | `systemctl restart` 반환 코드 0만으로 규칙 적용 성공 표시 가능 | 10초 안에 새 run ID·정규화 설정 SHA-256·`RUNNING`을 확인해야 성공 | WSL 단위 시험 15/15와 실제 설치 서비스 API 흐름 통과. 규칙 저장·적용 대기·systemd 재시작·새 run ID/해시/상태·이벤트·파일 목록을 확인했다. 인증 후 브라우저 UI 조작은 미실행. |

## 규칙·BPF·원장 시험

- 사용자 공간 `test_rules.c`는 비교 연산, `all/any/not` 3값 논리, UNKNOWN의 부정 처리, 여러 규칙 선택을 다룬다. Windows GCC `-O2 -Wall -Wextra -Werror`로 수정 후 실행해 통과했다. `test_quarantine.c` 9개 가상 시간 케이스도 Windows GCC에서 통과했다.
- 수정된 BPF는 WSL에서 컴파일·verifier 통과·실제 로드되었다. 위 두 임계치 smoke로 정책값의 실제 반영을 관찰했다. 모든 다른 커널의 verifier 통과를 의미하지 않는다.
- `test_ledger.py` 47개는 committed fence, CRC, raw schema 1·2·3, 불완전 snapshot, UNKNOWN 범위를 검사했다. 수정 후 WSL 47/47, Windows 47/47이다. 복구된 WSL에서 현재 소스의 전체 `make`, `make test`를 재실행해 C writer/quarantine/rules 시험, Python 관리 50개·원장 47개·벤치 설정 3개가 통과했다. `python3 -m unittest -q test_manage test_ledger`는 총 97개 중 96개 통과·1개 환경 조건 스킵이다.
- `test_writer.c`의 프레임 검사와 collector 빌드는 수정 후 WSL에서 통과했다. 현재 코드의 12개 실제 run에서 raw CRC·schema, committed ledger와 `recover=RECOVERED`를 확인했다. Linux GCC ASAN으로 사용자 공간 규칙 평가기도 재실행했다.

## 규칙 수별 성능: 수정 전 결함 진단 자료

무센서 pilot은 15,350 requested EPS에 15,350.065 actual EPS, 5초 동안 실패 `openat` Bulk 75,000 + 성공 Critical 500 + 성공 Normal 1,250건의 독립 호출 결과가 모두 기대값이었다. 이어서 **수정 전 eb9c888** 고정 archive에서 legacy 기본 1규칙(`baseline`)과 `event_rules` 1·4·8규칙을 각 3회, 총 12회 실행했다. 기존 `baseline` 설정에는 규칙 키가 없지만 `manage.py`가 `protected_path`의 legacy 규칙 1개를 자동 생성한다. 따라서 이 실험에는 **0규칙 조건이 없으며**, `baseline`과 `rule1`은 규칙 수가 같은 서로 다른 형식의 비교다. 각 실행은 5초, raw 128 MiB·index 64 MiB·metadata 8 MiB 한도, 20초 watchdog, 시작 전 메모리 1 GiB·디스크 2 GiB 하한을 적용했다. 순서를 교차 배치하고 유리한 결과가 나올 때까지 재실행하지 않았다. 설정·빌드 해시는 `environment.json`, `configs/`, 개별 결과는 `runs/`, 원본 SHA-256은 `artifact-hashes-eb9c888.json`에 있다.

| 수정 전 조건 | actual EPS 중앙값 | 독립 Critical truth / CRC 통과 durable 전체 lane | Bulk truth/durable 합계 | Normal truth/durable 합계 | syscall p95/p99 중앙 µs | collector CPU 초 중앙 | RSS 중앙 KiB | raw byte 중앙 | 원장 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| legacy 기본 1규칙 (`baseline`) | 15,350.213 | 1,500 / 1,500 | 225,000 / 225,000 | 3,750 / 3,750 | 50.431 / 84.892 | 1.070 | 22,528 | 18,645,600 | 3/3 INVALID |
| `event_rules` 1규칙 | 15,350.347 | 1,500 / 1,500 | 225,000 / 225,000 | 3,750 / 3,750 | 49.595 / 78.828 | 1.067 | 22,528 | 18,648,000 | 3/3 INVALID |
| `event_rules` 4규칙 | 15,350.161 | 1,500 / 1,500 | 225,000 / 225,000 | 3,750 / 3,750 | 52.350 / 84.790 | 3.761 | 22,528 | 18,583,200 | 3/3 INVALID |
| `event_rules` 8규칙 | 15,350.098 | 1,500 / 1,500 | 225,000 / 225,000 | 3,750 / 3,750 | 52.030 / 85.210 | 3.726 | 22,528 | 18,630,480 | 3/3 INVALID |

이 표의 Critical 500/500은 **같은 경로의 호출·raw 건수 집계 대응**이다. 개별 syscall 식별자가 없어 1:1 recall을 입증하지 않는다. 초기에 `critical.raw`만 세어 과소 보고한 값을 원본 JSON에는 남겨 두고, 세 raw lane 합계와 원본 해시를 `corrected_summary-eb9c888.json`·`CORRECTION-eb9c888.md`에 별도 정정했다. 네 조건 모두 정책 Bulk suppression·Q summary·ring failure·queue overflow의 집계는 0이지만, 설정이 잘못 적용되어 Q 대표 raw는 발생했다. `fault[2]` pending map miss도 실행별 2~306건의 **run 전체 집계**라 대상 호출에 귀속할 수 없다. CPU는 collector 프로세스의 user+system 시간이고 RSS는 그 프로세스 최대치다. 커널 BPF 비용·event-to-durable 지연은 미측정이다. p95/p99는 `SYS_openat` 전후 wall clock이며 스케줄링과 부하 생성기 시간을 포함한다. 따라서 8규칙의 최종 성능 영향이나 과거 5,000회 smoke·15k/80k/150k 실험과의 우열을 여기서 판정하지 않는다.

## 수정 후 코드의 WSL 규칙별 실측

수집기 `f9bd477`를 고정한 별도 소스 복사본과 새 빌드에서 같은 15,350 requested EPS·5초 workload를 다시 실행했다. `legacy1`은 **명시적 legacy 규칙 1개**이고 나머지는 `event_rules` 1·4·8개다. 제품은 0규칙 설정을 허용하지 않으므로 0규칙 측정값은 없다. 4·8규칙의 추가 규칙은 평가되지만 이 workload 경로에는 일치하지 않는다. 각 조건을 3회 교차 순서로 실행했고 12/12가 workload, raw CRC·schema, `STOPPED`, index 완료, `recover=RECOVERED`와 watchdog 미발동 기준을 통과했다.

| 수정 후 조건 | actual EPS 중앙값 | syscall p95/p99 중앙 µs | collector CPU 초 중앙 | RSS 중앙 KiB | Critical durable / truth | 원장 |
|---|---:|---:|---:|---:|---:|---|
| legacy 1규칙 | 15,350.260 | 57.213 / 90.804 | 1.273 | 22,784 | 1,500 / 1,500 | 3/3 RECOVERED |
| `event_rules` 1규칙 | 15,350.271 | 54.153 / 84.280 | 1.112 | 22,784 | 1,500 / 1,500 | 3/3 RECOVERED |
| `event_rules` 4규칙 | 15,350.196 | 56.858 / 89.392 | 3.772 | 22,656 | 1,500 / 1,500 | 3/3 RECOVERED |
| `event_rules` 8규칙 | 15,350.291 | 56.623 / 89.431 | 4.309 | 22,784 | 1,500 / 1,500 | 3/3 RECOVERED |

12회 target 경로 raw는 독립 workload의 Bulk 900,000·Critical 6,000·Normal 15,000건과 각각 집계상 일치했다. 전체 raw 936,848건에는 그 외 주변 이벤트 15,848건이 섞여 있다. 각 run의 인덱스는 raw 레코드 수와 일치하고 durable 경계까지 완료됐으며 정확한 **사용자 공간** 손실 기록은 0이다. 반면 사전 시퀀스 `pending_lookup_missing` 진단은 실행별 2~21건, 합계 155건이다. 개별 syscall과 연결할 수 없어 커널 손실 0이나 모든 Critical 호출의 개별 보존을 증명하지 않는다. 4·8규칙에서 collector CPU 시간이 늘었지만 5초씩 3회는 최대 처리량·장시간 안정성을 보여주지 않는다. p95/p99는 스케줄링을 포함한 syscall wall clock이고 이벤트가 디스크나 화면에 도착하는 지연은 측정하지 않았다. [수정 후 분석](current-code-benchmark.md), 원본에서 복사한 `final-f9bd477/`의 설정·환경·12개 결과 JSON, WSL `/root/mglogwh-v040-f9bd477-data/runs/`의 raw가 증거다.

## Critical 보존과 손실 원장의 설명 범위

수정 전 15.35k EPS 집단에서 대상 Critical의 독립 truth와 경로별 durable 건수 차이는 12회 모두 집계상 0이었다. 한 실행의 `critical.raw` 211 + `quarantine.raw` 289 = 500처럼 lane을 합쳐야 한다. 모든 run의 raw는 240바이트 CRC·schema를 검사했고 health는 `STOPPED`, index는 durable 경계까지 완료 상태였다. 그러나 원장 checkpoint는 중복 키 때문에 12/12 `INVALID`였다. 이 옛 집단을 복구 성공으로 바꾸지 않는다. 수정 후 새 집단은 12/12 `RECOVERED`이고 같은 경로의 Critical truth/raw가 합계 6,000/6,000이다. 이는 개별 호출 식별을 통한 무손실 증명이 아니다.

경계별로 독립 truth는 syscall **요청·반환**까지만, raw/health는 BPF 관측 뒤의 **집계·저장**까지 관찰한다. BPF가 전혀 보지 못한 syscall, 규칙 평가 전 실패, ring 제출 전 정책 요약, 다른 이벤트와 섞인 전역 fault는 개별 truth 호출에 연결하지 않는다. 수정 전 원장의 commit fence는 존재했으나 reader가 frame을 0개 검증했으므로 loss tombstone·sequence gap·UNKNOWN 원인을 검증할 수 없었다. 수정본 원장은 실제 종료된 새 run 12개와 Control Room 통합 run 1개를 `RECOVERED`로 판독했다. 정확한 사용자 공간 손실 0과 진단 fault 155를 구분한다. `QUARANTINE_EXEMPT`는 물리적 자원 예약이나 무손실 약속이 아니다. 과거 150k EPS의 quiet 469/500과 별도 14건 누락은 당시 기록에 남으며, 현재 코드나 새 원장으로 그 개별 원인을 소급 확정하지 않는다.

## 경로 규칙의 관측 경계

새 격리 시험에서 14종 `openat`, 성공 `exec`, 실패 `execve` 총 16개 truth를 만들고 대상 15개 raw 후보를 각각 하나씩 대응했다. 각 raw의 CRC·schema, 경로·규칙 ID·우선순위, index 완료와 `recover=RECOVERED`를 확인했다. 실패 `execve`는 설계대로 raw 후보 0개였다. 성공 증거는 `path-matrix-288b454fc769/result.json`·`truth.csv`, WSL 원본은 `/root/mglogwh-v040-matrix-288b454fc769/`에 있다. 첫 새 시도 `path-matrix-7c1ccb849a3f/`는 WSL guest PID와 BPF host PID를 직접 비교한 **검증기 오류**로 1/16을 보고했다. 원본을 보존하고 고유 probe 실행 경로·서로 겹치지 않는 시간 구간으로 host PID를 결합해 재시험했다. 이전 구버전 run `37b9d5c0-9403-4027-b80b-8e9cd981cba1`의 truth CSV는 사라져 최종 판정에 쓰지 않았다.

코드와 새 실측에서 경로 규칙은 캡처된 `openat` 인수 문자열만 본다. 상대 경로와 다른 dirfd는 최종 절대 경로로 합치지 않으므로 경로 조건이 `UNKNOWN`이다. symlink는 가리키는 최종 inode/경로를 확인하지 않는다. 긴 경로나 캡처 실패도 `UNKNOWN`이며 `not`/`ne`가 TRUE로 바꾸지 않는다. `O_PATH`의 access mode는 `UNKNOWN`; `O_RDONLY`/`O_WRONLY`/`O_RDWR`는 전달된 flag를 분류한다. `O_CREAT`/`O_TRUNC`는 flag의 존재만 뜻하고 실제 생성·잘림을 증명하지 않는다. 권한 실패·파일 부재는 `openat` 결과와 함께 관측 대상이지만 이후 inode의 정체성을 보증하지 않는다. 성공한 `exec`만 관측하며 실패한 `execve`는 지원하지 않는다. 상대 경로·symlink·`O_PATH`가 같은 dev/inode를 가리키는 사례에서도 raw 규칙 판정은 전달된 문자열·flags를 따랐다.

## Control Room, Ubuntu, 배포

Control Room은 저장/적용을 구분하고 `manage.py` 검증기와 연동한다. 인증·CSRF·revision 충돌·legacy/schema 조회·다운로드 allowlist·Demo 구분 단위 시험은 WSL에서 15/15 통과했다. 실제 WSL의 v0.4 수집기와 Control Room 서비스를 설치하고 로컬 인증 API로 `critical_rules`→`event_rules` 저장, `pending_apply=true`, 적용 버튼과 같은 `/api/apply` 요청, systemd 재시작, 새 run ID·정규화 설정 SHA-256·`RUNNING`, 고유 경로의 규칙 ID 248 Critical 이벤트, `/api/files`의 실제 저장 경로를 확인했다. 테스트 후 원래 설정으로 다시 재시작하고 바이트 단위 복원을 확인했다. 종료된 테스트 run에서 raw·index가 312/312건, 해당 경로 4/4건 동일 payload, `recover=RECOVERED`였다. [통합 raw 대조](controlroom-live-evidence.json)와 Control Room 저장소의 `scripts/live-integration-smoke.py`가 재현 절차다. 브라우저에서 실제 로그인 후 모든 버튼을 눌러 보는 시각적 끝단 시험은 하지 않았다. Windows 네이티브 단위 시험은 POSIX 권한·SQLite 파일 핸들 차이로 지원 대상 판정에 사용하지 않는다.

Ubuntu 설치 스크립트는 Linux x86_64·Python 3.12·root 소유/권한을 검사하고, systemd unit은 localhost 기반 Control Room과 별개로 collector 실행을 관리한다. `bash -n install-ubuntu.sh` 및 `systemd-analyze verify packaging/mglogwh.service`는 WSL에서 통과했고, 현재 WSL에 v0.4 수집기·Control Room을 설치해 systemd 시작·재시작·중지와 실제 BPF 로드를 확인했다. 두 서비스는 시험 후 중지·비활성 상태이며 Control Room 앱은 설치돼 있다. 독립 Ubuntu 서버의 설치·systemd 동작과 다른 커널 호환성은 미검증이다. Makefile의 `BOOTSTRAP`·`BUILD` 경로에 공백이 있으면 대상 분리가 재현되어 README에 제한을 명시했다. 최상위 `LICENSE`는 없으며 임의로 선택하지 않았다. 외부 소스 고정 revision과 고지는 `THIRD_PARTY.md`·`licenses/`에 유지하고 당시 Falco·빌드 경로 서술을 역사 기록으로 구분했다.

## 이전 문제에 대한 답과 최종 평가

1. 과거 31건·14건 누락의 최신 재현 여부: 수정본 15.35k EPS 12회에서 대상 Critical truth/raw 차이는 **집계상** 0이지만 150k EPS 조건이나 개별 원인은 재현·규명하지 못했다.
2. 손실 발생 단계: 새 12회에서 정확한 사용자 공간 손실은 0이다. 사전 시퀀스 진단 155건은 개별 이벤트에 귀속할 수 없어 커널 관측 공백이나 Critical 누락 0을 주장할 수 없다.
3. 원장 설명력: 실제 새 12개 run과 Control Room 통합 run은 `RECOVERED`; raw CRC·index 경계가 맞는다. 과거 중복 키 원장 12개는 여전히 `INVALID`다.
4. 8규칙 영향: 같은 짧은 workload에서 collector CPU 중앙값은 `event_rules` 1개 1.112초, 8개 4.309초였다. 최대 EPS나 장시간 용량은 미측정이다.
5. 관측하지 못하는 경로·이벤트: 상대·dirfd·symlink 최종 inode, 잘린 경로, 실패 exec; 자세한 한계는 위 절을 따른다.
6. Control Room: 실제 WSL 서비스의 인증 API→규칙 저장→적용 대기→systemd 재시작→새 run/규칙 이벤트→raw·index·파일 경로 대조를 통과했다. 인증 후 브라우저 UI 전 과정을 누르는 시험은 미완료다.
7. 일반 Ubuntu 서버: 미검증이다. WSL 24.04에서 설치·systemd·실제 BPF 로드를 확인했다.
8. LTTng 차이: [10월 9일 이전 집단](https://www.notion.so/3f40e129ee9b8144ae55eb4219d7fdb0)의 조건부 결과만 있다. v0.4에서 같은 조건의 새 LTTng 짝 실험은 없으므로 우월성은 주장하지 않는다.
9. 남은 기술적 한계: pre-BPF 관측 공백, 개별 identity/원인 연결, 경로 문자열과 실제 inode 차이, 자원 예약 없는 Critical 보존, root 위변조 방지 없음, 운영 서버 미검증이다.

코드 품질은 결함 다섯 건의 회귀 수정과 Linux 전체 시험·ASAN 재시험으로 개선됐다. 수집 정확성은 제한된 WSL·부하에서 target raw 집계와 경로 규칙 16/16을 확인했으나 개별 Critical 보존을 일반화할 수 없다. 원장은 수정본의 실제 새 run에서 복구됐고 정확한 사용자 공간 손실 0을 보고했으나 사전 시퀀스 fault는 남는다. 성능은 15.35k EPS·5초 조건별 차이만 측정했다. Control Room은 실제 WSL 서비스 API 연동을 통과했지만 일반 Ubuntu 서버 운영과 인증 후 브라우저 UI는 남았다. 재현성을 위해 성공·실패 양쪽 결과 JSON, 설정·빌드 해시, WSL raw 원본 위치를 보존했다. 연구적 기여는 보존된 원본·정책 요약·설명 불가능한 손실을 구분하는 계약과 측정 절차에 있으며 LTTng 대비 일반 우위를 입증한 것은 아니다.

## 증거와 재현

- 수정 전 고정 소스: `source-eb9c888.tar`, SHA-256 `f58ac4a69875c9cb365e4b40e5d6784101654d2f9a92f5c4364e23c85bbc5e77`; `environment.json`에 BPF/collector/workload 해시가 있다.
- 독립 pilot `pilot-15k.json`; 수정 전 12개 원본 `runs/*.json`; 정정 근거 `CORRECTION-eb9c888.md`, `corrected_summary-eb9c888.json`; 파일별 해시 `artifact-hashes-eb9c888.json`. WSL의 수정 전 raw 원본은 보존돼 있다. 중복 키가 있는 과거 원장은 변경하지 않았다.
- 수정본 `run_benchmark_portable.py`의 12회 출력은 `final-f9bd477/`에 복사했고, 분석은 `current-code-benchmark.md`에 있다. WSL 원본은 `/root/mglogwh-v040-f9bd477-output/`과 `/root/mglogwh-v040-f9bd477-data/runs/`에 있다.
- 경로 규칙 재현 코드는 `run_path_matrix.py`, `path_matrix_probe.c`; 성공 16/16 증거는 `path-matrix-288b454fc769/`, 검증기 PID namespace 오류의 첫 실행과 정정 이유는 `path-matrix-7c1ccb849a3f/`에 보존했다.
- 실제 Control Room API 연동 재현은 별도 저장소 `scripts/live-integration-smoke.py`, 종료된 테스트 run의 raw·index·원장 대조는 `verify_controlroom_run.py`와 `controlroom-live-evidence.json`이다. 설치 전 설정 백업은 WSL `/root/mglogwh-pre-v040-20261014/`에 남았다.
- 남은 검증: 독립 Ubuntu 서버에서 설치·다른 커널 verifier·systemd 장시간 운영, 150k EPS 등 고부하 Critical 누락 재현, 브라우저 인증 후 화면 전체 흐름. 결과가 실패하면 그대로 기록한다.
