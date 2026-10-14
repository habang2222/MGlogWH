# MGlogWH v0.4.0 코드·원장·성능 검증 기록 (2026-10-14)

## 판정과 증거 범위

**최종 상태: 추가 검증 필요.** 이번 검토에서 실제 P0 결함 두 개와 P1 결함 세 개를 수정했다. 수정 전 12회 성능 실행은 결함을 재현하고 원본 보존량을 관찰한 자료이지, 수정 후 제품의 성능 검증 결과가 아니다. 수정본의 0·1·4·8규칙 3회 반복, 실제 새 run의 `recover=RECOVERED`, 전체 `make test` 재실행, 일반 Ubuntu 서버 설치는 미완료다. WSL Ubuntu가 작업 후 `/etc/passwd` 읽기 단계에서 `I/O error`를 반환해 후속 Linux 명령을 실행할 수 없었다. 기존 run이나 과거 실험 원본을 수정하지 않았다.

검토 기준은 수집기 [eb9c888](https://github.com/habang2222/MGlogWH/commit/eb9c888bbf1e60a6c58a0c2082a1d639bc7b6607), Control Room [dcd244c](https://github.com/habang2222/MGlogWH-ControlRoom/commit/dcd244ccd3dd7212978df689e3f567f5c58e19a0)이다. 수집기 변경은 `363ab82`(불완전 규칙 통계), `769ce82`(BPF 정책 설정), `7e62eae`(원장 JSON), `0e24c0d`(참조 평가기 경계)에 각각 커밋했다. Control Room은 `fbc8c97`에서 적용 성공 표시 결함을 수정했다. [10월 9일 보고서](https://www.notion.so/3f40e129ee9b8144ae55eb4219d7fdb0)는 이전 코드·프로토콜의 결과로만 인용한다.

실행 환경은 Ubuntu 24.04 WSL2, kernel `6.6.87.2-microsoft-standard-WSL2+`, x86_64, Python 3.12.3이다. 실험 전 가용 메모리 6,913,664 KiB, WSL 파일시스템 가용 1,003,855,515,648 B, 논리 CPU 16개였다. 별도 Ubuntu 서버 접근은 확인되지 않았다. MGlogWH·LTTng·Control Room 서비스는 시험 전에 inactive였고 운영 서비스를 재시작하지 않았다. 이전 G:의 보존 실험 원본은 현재 호스트에서 접근할 수 없어 소급 재분석하지 않았다.

## v0.3에서 v0.4로 바뀐 계약

`event_rules`는 최대 8개 규칙, 한 규칙 최대 24개 토큰·논리 중첩 4단계, 3값 논리, precedence→priority→policy→ID 충돌 선택을 제공한다. `critical_rules`도 계속 읽는다. raw는 240바이트를 유지하며 새 규칙 ID·정책 비트를 schema 3에 싣는다. 설정·`rules.bin` 해시와 규칙·정책 버전을 manifest에 기록하고, 규칙별 커널 집계와 collector 저장 집계를 checkpoint에 둔다. schema 1·2 reader 호환 fixture는 유지한다. 코드 구현과 실제 동작 검증은 아래에서 구분한다.

## 발견 결함과 수정

| 중요도 | 위치 | 수정 전 증거와 영향 | 수정 | 수정 후 증거·잔여 한계 |
|---|---|---|---|---|
| P0 | `sensor.bpf.c`, `quarantine.h` | `const volatile` 규칙 설정을 비휘발성 포인터로 바꿔 Clang이 초기값 0을 상수화했다. disassembly에서 임계치 비교가 사라졌고 설정 1,000,000 EPS인데 실제 약 100 EPS에서 Q 진입, health `threshold_eps=0`이었다. | volatile 한정을 정책 함수까지 유지 | 수정 BPF 실제 로드. 500회·약 96.5 EPS·임계치 1,000,000 설정에서는 Q 진입 0, raw 500/500. 임계치 50 설정에서는 Q 진입 1, episode threshold 50·initial full 8, raw 366 + 정책 요약 134 = 500. 격리 run은 WSL에 있으나 환경 I/O 오류 뒤 재열람 불가. |
| P0 | `collector.c` | `meta_write` prefix와 checkpoint/seal 본문이 `config_sha256`를 중복 기록. 수정 전 12개 새 run의 `recover` 모두 `INVALID: duplicate JSON key: config_sha256`; 커밋된 원장을 판독할 수 없었다. | checkpoint/seal에서는 본문 값 하나만 기록, loss/control은 prefix 유지 | 새 C 회귀가 수정 전 실패·수정 후 통과했고 collector 빌드도 통과. 수정본 실제 새 run의 `recover=RECOVERED`는 WSL 장애 때문에 미확인. 이전 12개 원장은 고치거나 신뢰 대상으로 승격하지 않는다. |
| P1 | `rules.h` | 사용자 공간 문자열 참조 평가기가 실제 NUL 이후까지 읽었다. 2바이트 경로 `/`와 긴 규칙 `/123456`의 격리 ASAN 재현에서 heap-buffer-overflow 발생. 실제 BPF는 LPM trie를 사용하므로 이 재현은 사용자 공간 참조 평가기 문제다. | NUL에서 즉시 FALSE 반환, 짧은 할당 문자열 회귀 추가 | Windows GCC 최적화 빌드에서 `test_rules` 통과. 수정 후 ASAN은 Windows 도구에 `libasan`이 없어 미실행, Linux 재시험도 WSL I/O 오류로 미완료. |
| P1 | `ledger.py` | 정상적인 BPF map 조회 실패가 `stats_available=false`·null 커널 통계로 기록되면 reader가 raw까지 `INVALID`로 버렸다. | 불완전 커널 통계는 경고와 `complete_to_durable=false`를 유지하면서 committed raw·collector 집계 복구. 모순된 완전 선언은 거부 | 회귀 수정 전 실패, 수정 후 Python `test_ledger` 47개 통과(WSL 및 Windows). 저장 증거 schema 변경 없음. |
| P1 | Control Room `controlroom/backend.py` | `systemctl restart` 반환 코드 0만으로 규칙 적용 성공 표시 가능 | 10초 안에 새 run ID·정규화 설정 SHA-256·`RUNNING`을 확인해야 성공 | 회귀 수정 전 실패, WSL에서 실제 `manage.py` 연동 15/15 및 가짜 매니저 15/15. 실제 systemd 재시작·브라우저 끝단 흐름은 미실행. |

## 규칙·BPF·원장 시험

- 사용자 공간 `test_rules.c`는 비교 연산, `all/any/not` 3값 논리, UNKNOWN의 부정 처리, 여러 규칙 선택을 다룬다. Windows GCC `-O2 -Wall -Wextra -Werror`로 수정 후 실행해 통과했다. `test_quarantine.c` 9개 가상 시간 케이스도 Windows GCC에서 통과했다.
- 수정된 BPF는 WSL에서 컴파일·verifier 통과·실제 로드되었다. 위 두 임계치 smoke로 정책값의 실제 반영을 관찰했다. 모든 다른 커널의 verifier 통과를 의미하지 않는다.
- `test_ledger.py` 47개는 committed fence, CRC, raw schema 1·2·3, 불완전 snapshot, UNKNOWN 범위를 검사했다. 수정 후 WSL 47/47, Windows 47/47이다. 최종 수집기 전체 `make`, `make test`, `python3 -m unittest -v`는 WSL 장애로 끝까지 재실행하지 못했다.
- `test_writer.c`의 신규 프레임 검사와 collector 빌드는 수정 후 WSL에서 통과했다. 수정본 end-to-end recover는 미완료이므로 원장 결함의 완전 해결을 아직 확정하지 않는다.

## 규칙 수별 성능: 수정 전 결함 진단 자료

무센서 pilot은 15,350 requested EPS에 15,350.065 actual EPS, 5초 동안 실패 `openat` Bulk 75,000 + 성공 Critical 500 + 성공 Normal 1,250건의 독립 호출 결과가 모두 기대값이었다. 이어서 **수정 전 eb9c888** 고정 archive에서 0·1·4·8규칙을 각 3회, 총 12회 실행했다. 각 실행은 5초, raw 128 MiB·index 64 MiB·metadata 8 MiB 한도, 20초 watchdog, 시작 전 메모리 1 GiB·디스크 2 GiB 하한을 적용했다. 순서를 교차 배치하고 유리한 결과가 나올 때까지 재실행하지 않았다. 설정·빌드 해시는 `environment.json`, `configs/`, 개별 결과는 `runs/`, 원본 SHA-256은 `artifact-hashes-eb9c888.json`에 있다.

| 수정 전 조건 | actual EPS 중앙값 | 독립 Critical truth / CRC 통과 durable 전체 lane | Bulk truth/durable 합계 | Normal truth/durable 합계 | syscall p95/p99 중앙 µs | collector CPU 초 중앙 | RSS 중앙 KiB | raw byte 중앙 | 원장 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 0규칙 | 15,350.213 | 1,500 / 1,500 | 225,000 / 225,000 | 3,750 / 3,750 | 50.431 / 84.892 | 1.070 | 22,528 | 18,645,600 | 3/3 INVALID |
| 1규칙 | 15,350.347 | 1,500 / 1,500 | 225,000 / 225,000 | 3,750 / 3,750 | 49.595 / 78.828 | 1.067 | 22,528 | 18,648,000 | 3/3 INVALID |
| 4규칙 | 15,350.161 | 1,500 / 1,500 | 225,000 / 225,000 | 3,750 / 3,750 | 52.350 / 84.790 | 3.761 | 22,528 | 18,583,200 | 3/3 INVALID |
| 8규칙 | 15,350.098 | 1,500 / 1,500 | 225,000 / 225,000 | 3,750 / 3,750 | 52.030 / 85.210 | 3.726 | 22,528 | 18,630,480 | 3/3 INVALID |

이 표의 Critical 500/500은 **같은 경로의 호출·raw 건수 집계 대응**이다. 개별 syscall 식별자가 없어 1:1 recall을 입증하지 않는다. 초기에 `critical.raw`만 세어 과소 보고한 값을 원본 JSON에는 남겨 두고, 세 raw lane 합계와 원본 해시를 `corrected_summary-eb9c888.json`·`CORRECTION-eb9c888.md`에 별도 정정했다. 네 조건 모두 정책 Bulk suppression·Q summary·ring failure·queue overflow의 집계는 0이지만, 설정이 잘못 적용되어 Q 대표 raw는 발생했다. `fault[2]` pending map miss도 실행별 2~306건의 **run 전체 집계**라 대상 호출에 귀속할 수 없다. CPU는 collector 프로세스의 user+system 시간이고 RSS는 그 프로세스 최대치다. 커널 BPF 비용·event-to-durable 지연은 미측정이다. p95/p99는 `SYS_openat` 전후 wall clock이며 스케줄링과 부하 생성기 시간을 포함한다. 따라서 8규칙의 최종 성능 영향이나 과거 5,000회 smoke·15k/80k/150k 실험과의 우열을 여기서 판정하지 않는다.

## Critical 보존과 손실 원장의 설명 범위

수정 전 15.35k EPS 집단에서 대상 Critical의 독립 truth와 경로별 durable 건수 차이는 12회 모두 집계상 0이었다. 한 실행의 `critical.raw` 211 + `quarantine.raw` 289 = 500처럼 lane을 합쳐야 한다. 모든 run의 raw는 240바이트 CRC·schema를 검사했고 health는 `STOPPED`, index는 durable 경계까지 완료 상태였다. 그러나 원장 checkpoint는 중복 키 때문에 12/12 `INVALID`였다. 그러므로 이 집단은 개별 누락 0건이나 원장의 원인 설명 성공을 입증하지 않는다. 수정 후 고임계치 smoke에서는 Critical 500/500이 `critical.raw`에 남았지만, 그 원본의 독립 재검증은 현재 WSL 장애로 막혀 있다.

경계별로 독립 truth는 syscall **요청·반환**까지만, raw/health는 BPF 관측 뒤의 **집계·저장**까지 관찰한다. BPF가 전혀 보지 못한 syscall, 규칙 평가 전 실패, ring 제출 전 정책 요약, 다른 이벤트와 섞인 전역 fault는 개별 truth 호출에 연결하지 않는다. 수정 전 원장의 commit fence는 존재했으나 reader가 frame을 0개 검증했으므로 loss tombstone·sequence gap·UNKNOWN 원인을 검증할 수 없었다. 수정본은 실제 end-to-end 복구를 다시 실행해야 한다. `QUARANTINE_EXEMPT`는 물리적 자원 예약이나 무손실 약속이 아니다. 과거 150k EPS의 quiet 469/500과 별도 14건 누락은 당시 기록에 남으며, 현재 코드나 새 원장으로 그 개별 원인을 소급 확정하지 않는다.

## 경로 규칙의 관측 경계

격리 테스트 디렉터리의 가짜 파일로 14종 `openat`와 성공 `exec` 한 건의 직접 syscall truth를 만들었고, 시험 당시 raw에서 대상 15건과 probe 시작 시의 추가 성공 exec 1건을 관찰했다. 테스트 스크립트는 Desktop의 `mglogwh-rule-matrix-*.py`/`.c`, 당시 run ID는 `37b9d5c0-9403-4027-b80b-8e9cd981cba1`이다. 세부 case별 raw·규칙 ID 대조 JSON은 WSL I/O 오류 전에 Windows로 반출되지 않아 **이 요약을 최종 differential pass로 판정하지 않는다**.

코드상 경로 규칙은 캡처된 `openat` 인수 문자열만 본다. 상대 경로와 다른 dirfd는 최종 절대 경로로 합치지 않으므로 경로 조건이 `UNKNOWN`이다. symlink는 가리키는 최종 inode/경로를 확인하지 않는다. 긴 경로나 캡처 실패도 `UNKNOWN`이며 `not`/`ne`가 TRUE로 바꾸지 않는다. `O_PATH`의 access mode는 `UNKNOWN`; `O_RDONLY`/`O_WRONLY`/`O_RDWR`는 전달된 flag를 분류한다. `O_CREAT`/`O_TRUNC`는 flag의 존재만 뜻하고 실제 생성·잘림을 증명하지 않는다. 권한 실패·파일 부재는 `openat` 결과와 함께 관측 대상이지만 이후 inode의 정체성을 보증하지 않는다. 성공한 `exec`만 관측하며 실패한 `execve`는 지원하지 않는다. 이 범위를 실제 원본과 각 케이스별로 대조하는 재시험이 필요하다.

## Control Room, Ubuntu, 배포

Control Room은 저장/적용을 구분하고 `manage.py` 검증기와 연동한다. 인증·CSRF·revision 충돌·legacy/schema 조회·다운로드 allowlist·Demo 구분 회귀는 WSL에서 실제 관리자 연동 15/15, 가짜 관리자 15/15로 통과했다. 새 `apply()`는 새 run ID, manifest 설정 해시, `RUNNING`을 확인한 뒤에만 성공을 응답한다. 이 시험은 systemctl과 상태를 격리 모의 처리했으며, 실제 브라우저→서비스 재시작→새 규칙 이벤트→raw/index/health의 완전한 15단계 흐름은 실행하지 않았다. Windows 네이티브 단위 시험은 POSIX 권한·SQLite 파일 핸들 차이로 15건 모두 실패해 지원 대상 판정에 사용하지 않았다.

Ubuntu 설치 스크립트는 Linux x86_64·Python 3.12·root 소유/권한을 검사하고, systemd unit은 localhost 기반 Control Room과 별개로 collector 실행을 관리한다. `bash -n install-ubuntu.sh` 및 `systemd-analyze verify packaging/mglogwh.service`는 WSL에서 통과했고, 기존 WSL에서 BTF/CO-RE·tracepoint·BPF map·`bpf_loop`를 사용하는 실제 BPF 로드가 확인됐다. 독립 Ubuntu 서버의 설치·systemd 시작/중지/재시작과 다른 커널 호환성은 미검증이다. Makefile의 `BOOTSTRAP`·`BUILD` 경로에 공백이 있으면 대상 분리가 재현되어 README에 제한을 명시했다. 최상위 `LICENSE`는 없으며 임의로 선택하지 않았다. 외부 소스 고정 revision과 고지는 `THIRD_PARTY.md`·`licenses/`에 유지하고 당시 Falco·빌드 경로 서술을 역사 기록으로 구분했다.

## 이전 문제에 대한 답과 최종 평가

1. 과거 31건·14건 누락의 최신 재현 여부: 이번 15.35k EPS의 **집계**에서는 Critical truth/raw 차이가 0이지만 150k EPS 조건 재현이나 개별 원인 규명은 하지 못했다.
2. 손실 발생 단계: 이번 대상 Critical에 대해 확인된 개별 누락은 없다. 원장이 INVALID였으므로 누락 원인 분류 능력은 최종 검증되지 않았다.
3. 원장 설명력: 코드와 합성 fixture는 commit fence, exact userspace tombstone, UNKNOWN을 구분한다. 실제 새 run 복구는 다시 확인해야 한다.
4. 8규칙 영향: 수정 전 결함 진단 자료의 collector CPU 시간 증가는 보이나 수정본 성능 결론은 미측정이다.
5. 관측하지 못하는 경로·이벤트: 상대·dirfd·symlink 최종 inode, 잘린 경로, 실패 exec; 자세한 한계는 위 절을 따른다.
6. Control Room: 관리자 연동 단위 시험은 통과, 실제 서비스 끝단 통합은 미검증이다.
7. 일반 Ubuntu 서버: 미검증이다. WSL 24.04만 실제 BPF 로드 확인했다.
8. LTTng 차이: [10월 9일 이전 집단](https://www.notion.so/3f40e129ee9b8144ae55eb4219d7fdb0)의 조건부 결과만 있다. v0.4에서 같은 조건의 새 LTTng 짝 실험은 없으므로 우월성은 주장하지 않는다.
9. 남은 기술적 한계: pre-BPF 관측 공백, 개별 identity/원인 연결, 경로 문자열과 실제 inode 차이, 자원 예약 없는 Critical 보존, root 위변조 방지 없음, 운영 서버 미검증이다.

코드 품질은 재현 가능한 결함 네 건과 회귀 수정으로 개선됐지만 전체 Linux 재시험이 남았다. 수집 정확성은 제한된 WSL·부하에서 raw 집계 대응만 보였고 개별 보존을 일반화할 수 없다. Critical 보존 능력은 이번 낮은 부하의 집계 500/500과 과거 고부하 누락을 함께 제시한다. 원장 신뢰성은 기존 코드에서 실제 실패했고 수정본 end-to-end 검증 전까지 보류한다. 성능은 수정 전 진단 자료만 있으며 최종 판정 보류다. 운영 안정성은 Control Room apply 오표시를 개선했으나 실제 서버 운영은 미확인이다. 재현성은 고정 소스·설정·명령·원본 SHA-256과 실패 자료를 남겼지만 WSL 원본 접근 장애가 남는다. 연구적 기여는 보존된 원본·정책 요약·설명 불가능한 손실을 구분하는 계약과 측정 절차에 있으며 LTTng 대비 일반 우위를 입증한 것은 아니다.

## 증거와 재현

- 수정 전 고정 소스: `source-eb9c888.tar`, SHA-256 `f58ac4a69875c9cb365e4b40e5d6784101654d2f9a92f5c4364e23c85bbc5e77`; `environment.json`에 BPF/collector/workload 해시가 있다.
- 독립 pilot `pilot-15k.json`; 12개 원본 `runs/*.json`; 정정 근거 `CORRECTION-eb9c888.md`, `corrected_summary-eb9c888.json`; 파일별 해시 `artifact-hashes-eb9c888.json`. WSL raw 원본 경로는 각 결과의 `source_run_dir`이며 현재 WSL I/O 오류로 재열람이 막혀 있다.
- 수정본 재실행 준비용 `run_benchmark_portable.py`는 `MGLOGWH_BENCH_SOURCE`, `MGLOGWH_BENCH_BUILD`, `MGLOGWH_BENCH_DATA`, `MGLOGWH_BENCH_DECOY`, `MGLOGWH_BENCH_HEAD`를 요구한다. `bench_workload.c`를 먼저 컴파일하고 유효한 소스·BPF 빌드와 가짜 파일을 준비한다. 새 출력에는 `MGLOGWH_BENCH_OUTPUT`을 지정하며 기존 출력 파일은 덮어쓰지 않는다. 이 스크립트는 수정본에서 **아직 실행하지 않았다**.
- 복구 확인: `python3 manage.py recover --run-dir <새 run 경로>`에서 `status=RECOVERED`, 원본 CRC, 마지막 committed fence, 규칙 통계 완전성, index 범위를 각각 확인해야 한다. 기존 `INVALID` run을 고쳐 읽는 절차로 취급하지 않는다.
- 후속 완료 조건: WSL 파일시스템 I/O 장애 해결 및 기존 원본 상태 확인 → 새 격리 run의 원장 복구 → 수정본 0·1·4·8규칙 동일 조건 3회 → path matrix raw·규칙 ID 대조 결과 반출 → 전체 `make`, `make test`, Python 시험 → 독립 Ubuntu 서버와 Control Room 실제 서비스 흐름 확인. 결과가 실패하면 그대로 기록한다.
