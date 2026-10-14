# MGlogWH 수집기 v0.4.0

MGlogWH는 Linux eBPF 기반 `openat` 및 성공한 프로세스 실행 이벤트 수집기입니다. 이벤트를 우선순위별 raw 파일에 기록하고, 저장 경계·손실 계수·손실 원장을 남깁니다.

## 주요 파일

| 파일 | 역할 |
|---|---|
| `sensor.bpf.c`, `event.h`, `tenant.h`, `quarantine.h`, `rules.h` | 커널 이벤트 수집·규칙 판정·quarantine 정책과 데이터 형식 |
| `collector.c` | BPF ring 수신, bounded queue, raw·metadata·health 저장 |
| `manage.py`, `ledger.py` | 실행·중지·검색용 인덱스와 읽기 전용 손실 원장 복구 |
| `config.json`, `Makefile`, `examples/` | 기본 설정·빌드 및 검증 가능한 규칙 예제 |
| `install-ubuntu.sh`, `packaging/` | Ubuntu 설치, systemd 서비스, 진단 로그 순환 |
| `test_*.py`, `test_*.c` | 수집기 전용 synthetic·live 검증 코드 |
| `RULES.md`, `LEDGER.md`, `QUARANTINE.md`, `THIRD_PARTY.md`, `licenses/` | 규칙·데이터 계약·정책, 외부 코드 출처·라이선스 |

## Ubuntu 서버 설치

대상은 Linux x86_64, `/usr/bin/python3` 3.12 이상, BTF·필요한 tracepoint·`bpf_loop` helper와 BPF LPM trie를 지원하는 커널입니다. `bpf_loop`는 [upstream Linux 5.17](https://github.com/torvalds/linux/blob/v5.17/include/uapi/linux/bpf.h)부터 제공되며 배포판 backport도 사용할 수 있습니다. [LPM trie](https://docs.kernel.org/bpf/map_lpm_trie.html)는 Linux 4.11부터 제공되고 `BPF_F_NO_PREALLOC` 플래그가 필요합니다. 아래 절차는 Ubuntu 24.04의 새 서버에서 저장소와 고정 revision의 `libbpf-bootstrap`을 홈 디렉터리 아래 나란히 복제합니다. 계정 이름과 무관하게 동작하며 여러 서버에서 같은 절차를 반복할 수 있습니다.

```bash
sudo apt update
sudo apt install -y git build-essential clang libelf-dev zlib1g-dev pkg-config python3 logrotate util-linux
cd "$HOME"
git clone https://github.com/habang2222/MGlogWH.git
git clone https://github.com/libbpf/libbpf-bootstrap.git
git -C libbpf-bootstrap checkout d5f36b8ff051c78035696da31e673602c266d93c
git -C libbpf-bootstrap submodule update --init --recursive
make -C libbpf-bootstrap/examples/c bootstrap
make -C MGlogWH
make -C MGlogWH test
sudo bash MGlogWH/install-ubuntu.sh
```

빌드는 일반 사용자로 실행합니다. `Makefile`은 기본적으로 저장소 옆의 `libbpf-bootstrap`과 저장소 안의 `build/`를 사용합니다. 다른 위치에 두었다면 `make -C MGlogWH BOOTSTRAP=/absolute/path/to/libbpf-bootstrap BUILD=/absolute/path/to/build`로 지정하세요. 빌드 위치를 바꾼 경우 설치에도 `sudo env MGLOGWH_BUILD_DIR=/absolute/path/to/build bash MGlogWH/install-ubuntu.sh`를 사용합니다.

GNU Make의 현재 대상 경로 처리상 `MGlogWH`, `libbpf-bootstrap`, `BOOTSTRAP`, `BUILD` 경로에는 공백을 넣지 마세요. 공백이 있는 절대 경로는 빌드 대상으로 분리되어 지원되지 않습니다.

설치 스크립트는 빌드한 수집기와 대응 소스를 root 소유의 `/opt/mglogwh`에 복사합니다. 최초 설치 시 설정은 `/etc/mglogwh/config.json`, 수집 데이터는 `/var/lib/mglogwh`에 둡니다. 기존 설정과 run은 덮어쓰거나 삭제하지 않습니다. 설정을 검토한 뒤 시작합니다.

```bash
sudo /usr/bin/python3 /opt/mglogwh/manage.py validate --config /etc/mglogwh/config.json
sudo /usr/bin/python3 /opt/mglogwh/manage.py capability
sudo systemctl enable --now mglogwh
sudo systemctl status mglogwh
sudo /usr/bin/python3 /opt/mglogwh/manage.py status
```

중지는 `sudo systemctl stop mglogwh`입니다. 업데이트할 때는 서비스를 중지하고, 새 소스를 일반 사용자로 빌드·테스트한 다음 설치 스크립트를 다시 실행합니다. 정상 종료는 인덱서의 마지막 원본 반영을 기다릴 수 있습니다. 기동에 실패하면 `sudo journalctl -u mglogwh -n 100 --no-pager`와 `sudo systemctl status mglogwh`로 확인하세요. 서비스는 10분 안에 3회 실패하면 재시도를 멈춥니다. 원인을 해결한 다음 `sudo systemctl reset-failed mglogwh`와 `sudo systemctl start mglogwh`를 실행합니다.

systemd가 없는 환경에서는 설치 후 `sudo /usr/bin/python3 /opt/mglogwh/manage.py start --config /etc/mglogwh/config.json`으로 시작하고, 같은 설치본의 `status`와 `stop`을 사용합니다. `MGLOGWH_DATA_DIR`과 `MGLOGWH_BUILD_DIR`은 필요할 때 설정할 수 있으며, 데이터 디렉터리는 실행 계정 소유의 `0700` 권한이어야 합니다. 상대 경로 환경변수는 `manage.py`가 있는 디렉터리를 기준으로 해석합니다.

## 설정·데이터·검증 범위

설정은 `/etc/mglogwh/config.json`에서 변경하고 `validate`로 검사한 뒤 새 run을 시작합니다. 새 `event_rules`는 이벤트 종류·결과·경로·UID·PID·프로세스 이름·cgroup·openat 플래그를 `all`/`any`/`not`으로 조합하며 Priority와 폭주 대응 정책, 규칙별 Quarantine 임계치를 지정합니다. [RULES.md](RULES.md)에 조건·연산자·충돌 우선순위·제한과 검증 가능한 예제 A~D를 정리했습니다. 이전 `critical_rules`도 계속 읽으며 `protected=true`는 격리 면제에 해당합니다. 면제는 저장 실패까지 막는다는 뜻이 아닙니다. [QUARANTINE.md](QUARANTINE.md)와 [LEDGER.md](LEDGER.md)에 수집 범위·raw 형식·손실 해석을 기록했습니다.

조건 비교는 `eq`, `ne`, `in`, `not_in`, `prefix`, `gt`, `ge`, `lt`, `le`를 지원합니다. 중요도 `BULK`·`NORMAL`·`CRITICAL`과 폭주 정책 `NORMAL_COLLECTION`·`QUARANTINE`·`QUARANTINE_EXEMPT`를 따로 지정합니다. 여러 규칙이 일치하면 큰 `precedence`가 먼저 적용되고, 같은 값이면 중요도·정책·규칙 ID 순으로 결정합니다. 규칙은 최대 8개, 한 규칙의 실행 토큰은 최대 24개, 논리 중첩은 최대 4단계입니다. 실패한 `exec`, 최종 inode 경로, 심볼릭 링크 해석은 관찰하지 않습니다. 상대 경로나 잘린 경로는 경로 조건에서 보수적으로 처리하며 세부 사항은 [RULES.md](RULES.md)를 따릅니다.

규칙을 바꾼 뒤에는 `sudo /usr/bin/python3 /opt/mglogwh/manage.py validate --config /etc/mglogwh/config.json`로 검사하고 새 run을 시작하세요. [MGlogWH Control Room](https://github.com/habang2222/MGlogWH-ControlRoom)의 규칙 화면도 같은 검증기를 사용합니다. 실행 중인 수집기의 규칙은 자동으로 교체되지 않습니다. 서비스 재시작은 새 run을 만들므로 운영자가 현재 수집 상태를 확인한 뒤 적용합니다.

수집기는 시스템 전체 tracepoint에서 모든 UID의 대상 이벤트를 수집합니다. raw 파일에는 경로와 프로세스 정보가 담기므로 설치 데이터 디렉터리 접근을 root로 제한합니다. 진단용 `.log`에는 logrotate 설정을 설치하지만 raw·원장·기존 run은 자동 삭제하지 않습니다. 운영자가 전체 디스크 사용량과 증거 보존 기간을 관리해야 합니다. CRC는 우발 손상 검사이며 root 공격자에 대한 위변조 방지 서명은 아닙니다.

기존 run을 변경하지 않고 복구 보고서를 만들려면 수집을 중지한 뒤 실행합니다.

```bash
sudo /usr/bin/python3 /opt/mglogwh/manage.py recover \
  --run-dir /var/lib/mglogwh/runs/REPLACE_WITH_RUN_UUID --out /path/to/report.json
```

초기 v0.4.0 `eb9c888`에서 Ubuntu 24.04 WSL의 BPF object·skeleton·collector 빌드, C·Python 시험과 8규칙 BPF 실제 로드·이벤트 수집을 확인했습니다. 독립된 run에서 `/etc/shadow` 읽기 이벤트 3건이 `critical.raw`에 기록됐습니다. 당시 5,000회 `openat` 부하의 세 번 반복 중앙값은 1규칙 56.36ms, 8규칙 58.07ms였으며 Python 호출·syscall·수집기 전체 시간입니다. 이후 [2026-10-14 검증](validation/2026-10-14/REVIEW.md)에서 이 버전의 Quarantine 설정 미적용과 원장 checkpoint 중복 키 결함을 발견해 수정했습니다. 당시 시간과 새 수정 전 12회 성능 실험을 수정본의 성능 결론으로 사용하지 않습니다. 수정본의 전체 반복 부하·원장 end-to-end 복구, 실제 Ubuntu 서버 설치와 다른 커널 BPF 로드는 별도 확인이 필요합니다.

수집기 전체에 적용할 최상위 `LICENSE`는 아직 없습니다. 외부 배포 조건은 프로젝트 소유자가 결정해야 합니다. 파일별 라이선스와 외부 코드 고지는 [THIRD_PARTY.md](THIRD_PARTY.md) 및 [licenses/](licenses/)를 확인하세요.
