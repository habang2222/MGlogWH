# 사용자 정의 보안 이벤트 규칙

`config.json`의 `event_rules`에 규칙을 넣고 `python3 manage.py validate --config config.json`으로 검사합니다. 규칙은 수집기를 **새로 시작할 때** 해당 run에 고정됩니다. 실행 중 파일을 고쳐도 기존 run의 정책은 바뀌지 않습니다. 실제 운영 설정을 교체하거나 서비스를 재시작하기 전에 현재 수집 상태를 확인하세요.

## 형식

```json
{
  "event_rules": [
    {
      "id": 7,
      "enabled": true,
      "precedence": 10,
      "priority": "CRITICAL",
      "overload_policy": "QUARANTINE",
      "when": {
        "all": [
          {"field": "event_type", "op": "eq", "value": "openat"},
          {"field": "path", "op": "prefix", "value": "/etc/"},
          {"field": "uid", "op": "ne", "value": 0},
          {"field": "write_access", "op": "eq", "value": true},
          {"field": "success", "op": "eq", "value": true}
        ]
      },
      "quarantine": {
        "critical_rate_threshold": 5000,
        "critical_rate_duration_seconds": 2,
        "critical_recovery_threshold": 1000,
        "critical_recovery_duration_seconds": 5,
        "quarantine_initial_full_events": 16,
        "quarantine_sample_interval_ms": 200
      }
    }
  ]
}
```

위 내용은 전체 설정의 규칙 부분입니다. 즉시 검증할 수 있는 전체 설정은 [예제 A](examples/A-nonroot-etc-write.json), [B](examples/B-cgroup-shell-exec.json), [C](examples/C-shadow-exempt.json), [D](examples/D-uid-specific-file.json)에 있습니다. 기존 저장 공간·bulk·전역 Quarantine 값은 예제에서 바꾸지 않았습니다. `quarantine`의 생략한 값은 같은 이름의 전역 설정에서 가져옵니다.

| 필드 | 관찰 가능한 값 | 의미와 제약 |
|---|---|---|
| `event_type` | `openat`, `exec` | `exec`는 성공 이벤트만 수집됩니다. 실패한 `exec` 조건은 설정 검증에서 거부합니다. |
| `success` | boolean | `openat`는 반환값이 0 이상이면 성공입니다. 수집된 `exec`는 성공입니다. |
| `result` | 정수 | `openat`의 syscall 반환값입니다. 성공 `exec`는 0입니다. |
| `access_mode` | `read`, `write`, `read_write` | `openat`의 `O_ACCMODE` 플래그입니다. |
| `write_access`, `create`, `truncate` | boolean | `openat`의 쓰기 모드, `O_CREAT`, `O_TRUNC` 플래그입니다. |
| `path` | 절대 경로 문자열 | 캡처된 경로 **문자열**을 비교합니다. 파일의 실제 inode나 정규화된 최종 경로가 아닙니다. |
| `uid`, `root` | 정수, boolean | 센서가 본 UID 및 `uid == 0` 여부입니다. |
| `pid` | 정수 | 관찰 시점의 프로세스 ID입니다. |
| `comm` | 문자열 | 커널의 프로세스 이름(`comm`, 최대 15바이트)입니다. |
| `cgroup_id` | 정수 | 센서가 본 cgroup ID입니다. 서버별로 실제 ID를 확인해 사용합니다. |

비교 연산자 `eq`, `ne`, `in`, `not_in`, `prefix`, `gt`, `ge`, `lt`, `le`를 제공합니다. `in`/`not_in`의 `value`는 목록이며 `path`의 복수 경로나 제외 경로, UID/PID/cgroup의 포함·제외 목록도 이 방식으로 작성합니다. `prefix`는 문자열에만 사용합니다. 수치 대소 비교는 수치 필드에만 사용합니다. 형식과 지원되지 않는 조합은 `validate`가 거부합니다.

`when`은 단일 비교 또는 `{"all":[...]}`(AND), `{"any":[...]}`(OR), `{"not":{...}}`(NOT) 중 하나입니다. `bash` 또는 `python3`는 `comm in ["bash", "python3"]` 혹은 `any`로 표현할 수 있습니다. 규칙은 최대 8개, 한 규칙의 postfix 조건·논리 토큰은 최대 24개, 중첩은 최대 4단계입니다. 각 `in` 목록은 최대 4개입니다. 규칙별 문자열 풀은 최대 1,024바이트, 전체 설정 파일은 최대 64 KiB입니다. `id`는 중복 없는 1..255, `precedence`는 0..1000 정수입니다. 경로는 최대 126바이트, `comm`은 최대 15바이트입니다. 너무 큰 규칙은 조용히 잘라내지 않고 거부합니다.

## 중요도와 폭주 정책

| Priority | 허용 Overload Policy | 저장 경로 |
|---|---|---|
| `BULK` | `NORMAL_COLLECTION` | 일반 lane, 기존 bulk 입장 제어 적용 |
| `NORMAL` | `NORMAL_COLLECTION` | 일반 lane |
| `CRITICAL` | `NORMAL_COLLECTION` | critical lane, Quarantine 미적용 |
| `CRITICAL` | `QUARANTINE` | critical lane; 임계치 충족 시 표본을 quarantine lane에 보존하고 나머지는 집계 |
| `CRITICAL` | `QUARANTINE_EXEMPT` | critical lane, Quarantine 면제 |

`QUARANTINE_EXEMPT`는 격리 샘플링을 피한다는 뜻입니다. ring·queue·디스크·센서 추적에는 한도가 있으므로 원본 무손실을 보장하지 않습니다. 규칙이 없으면 기존 기본 분류가 적용됩니다. 기존 `critical_rules`는 그대로 유효하며 `protected=true`를 `CRITICAL + QUARANTINE_EXEMPT`로 해석합니다. `critical_rules`와 `event_rules`를 동시에 명시할 수 없습니다.

여러 규칙이 일치하면 `precedence`가 큰 규칙을 고릅니다. 같으면 `CRITICAL > NORMAL > BULK`, 이어서 `QUARANTINE > QUARANTINE_EXEMPT > NORMAL_COLLECTION`, 마지막으로 작은 `id`가 이깁니다. 설정 배열 순서는 영향을 주지 않습니다. 최종 규칙 ID와 원래 Priority·적용 정책은 새 Raw 이벤트와 조회 응답에 남깁니다.

## 관측 범위와 원장

규칙 조건은 bounded 커널 평가로 ring buffer 예약 전에 적용됩니다. 경로 캡처가 잘리거나 실패했을 때, 혹은 상대 경로일 때 경로 조건은 `UNKNOWN`으로 처리합니다. `not`이나 `ne` 조건도 이 불확실성을 참으로 바꾸지 않습니다. `O_PATH`는 읽기 접근으로 잘못 분류하지 않도록 접근 모드를 `UNKNOWN`으로 처리합니다. `create`·`truncate`는 해당 flag 비트의 존재만 뜻하며 실제 파일 생성·잘림을 증명하지 않습니다. 심볼릭 링크의 최종 경로·파일 inode·디렉터리 FD와 합쳐진 실제 경로는 확인하지 않습니다. PID는 재사용되고 `comm`은 짧아서 다른 프로세스와 같을 수 있습니다. UID·PID·cgroup ID는 센서가 관찰한 호스트 커널 값이며 컨테이너 안의 표시 값과 다를 수 있습니다. 이 정보만으로 공격 또는 파일 정체성을 확정하지 마세요.

각 run의 설정 해시와 규칙·정책 버전을 manifest에 보존합니다. 새 원본은 같은 240바이트 레코드의 schema 3으로 구분하며 기존 schema 1·2 reader 호환을 유지합니다. 저장된 원본은 실제 `fdatasync` 경계, 원장은 committed fence까지만 복구합니다. 규칙별 발생·선택·제출·요약·저장 수는 각 증거의 관측 범위와 함께 표시합니다. 정책에 따른 의도적 요약과 ring·queue·저장소 실패를 분리합니다. 규칙 판정 전 실패나 불완전한 snapshot은 특정 규칙에 임의로 귀속하지 않고 `UNKNOWN`/불완전 범위로 남깁니다. 자세한 정의는 [LEDGER.md](LEDGER.md)와 [QUARANTINE.md](QUARANTINE.md)를 따릅니다.

초기 v0.4.0 `eb9c888`에서는 BPF 컴파일러가 규칙별 Quarantine 설정의 0 초기값을 고정해 실제 설정 임계치를 무시하는 결함이 있었다. 이후 수정본은 `volatile` 속성을 정책 함수까지 유지한다. 과거 WSL 격리 검증에서 설정 임계치에 따른 Q 진입 여부를 확인했지만, 전체 부하 조건과 다른 커널에서의 재검증이 필요하다.

커널은 규칙마다 최대 24개 토큰을 평가하고, 문자열 비교에는 규칙별 키를 올린 BPF LPM trie를 사용합니다. 규칙 수와 조건 수가 늘면 이벤트당 CPU 비용도 증가할 수 있습니다. `bpf_loop` helper가 있는 커널과 BTF·필요한 tracepoint가 필요합니다. 과거 Ubuntu 24.04 WSL 커널 6.6에서는 8규칙 BPF 로드·실제 이벤트 매칭을 확인했습니다. 운영 서버의 커널·권한·부하가 다를 수 있으므로 적용 전에 `make`와 BPF 로딩·관찰 범위·성능을 환경별로 확인하세요.
