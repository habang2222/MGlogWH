# MGlogWH 수집기

MGlogWH는 Linux eBPF 기반 `openat` 및 성공한 프로세스 실행 이벤트 수집기입니다. 이벤트를 우선순위별 raw 파일에 기록하고, 저장 경계·손실 계수·손실 원장을 남깁니다.

## 주요 파일

| 파일 | 역할 |
|---|---|
| `sensor.bpf.c`, `event.h`, `tenant.h`, `quarantine.h` | 커널 이벤트 수집·분류·quarantine 정책과 데이터 형식 |
| `collector.c` | BPF ring 수신, bounded queue, raw·metadata·health 저장 |
| `manage.py`, `ledger.py` | 실행·중지·검색용 인덱스와 읽기 전용 손실 원장 복구 |
| `config.json`, `Makefile` | 기본 설정과 빌드 |
| `test_*.py`, `test_*.c` | 수집기 전용 synthetic·live 검증 코드 |
| `LEDGER.md`, `QUARANTINE.md`, `THIRD_PARTY.md`, `licenses/` | 데이터 계약, 정책 설명, 외부 코드 출처·라이선스 |

## 빌드와 실행

대상은 Python 3.12 이상을 사용하는 Linux x86_64 또는 WSL Ubuntu입니다. 빌드는 libbpf-bootstrap의 BPF 도구·헤더·정적 라이브러리를 사용합니다. `Makefile`의 기본 checkout 위치는 `/home/ljw/libbpf-bootstrap`, 출력 위치는 `/home/ljw/mglogwh-build`입니다. `manage.py`는 현재 이 출력 위치의 `collector`와 `sensor.bpf.o`를 사용하며, 원본 run은 `/home/ljw/mglogwh-data`에 저장합니다.

```bash
make
make test                         # synthetic 검증; 실제 BPF 수집은 시작하지 않음
sudo python3 manage.py validate
sudo python3 manage.py start
sudo python3 manage.py status
sudo python3 manage.py stop
```

설정을 바꾸려면 `config.json`을 수정하고 `validate`로 검사한 뒤 새 run을 시작합니다. `critical_rules`의 `protected=true`는 해당 규칙의 quarantine 면제이며 저장 공간 예약은 아닙니다. 수집 범위·raw 형식·손실의 해석과 한계는 [QUARANTINE.md](QUARANTINE.md)와 [LEDGER.md](LEDGER.md)에 기록돼 있습니다.

기존 run을 변경하지 않고 복구 보고서를 만들려면 수집이 중지된 뒤 다음 명령을 사용합니다.

```bash
python3 manage.py recover --run-dir /path/to/runs/<run-uuid> --out /path/to/report.json
```

외부 코드의 출처와 라이선스는 [THIRD_PARTY.md](THIRD_PARTY.md)와 [licenses/](licenses/)를 확인하세요.
