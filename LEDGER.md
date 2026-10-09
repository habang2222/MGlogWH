# 재시작 뒤 메타 장부 확인

`ledger.py`는 이미 저장된 run을 읽는 독립 복구 도구입니다. 수집기를 시작하지 않으며 원본 raw, health, 장부를 변경하지 않습니다. 프로세스 재시작이나 다른 디렉터리로 복사한 뒤에도 run UUID 이름과 원본 manifest/config를 유지하면 읽을 수 있습니다. 이전 수집 run에 장부가 없으면 `LEGACY_UNSUPPORTED`를 반환합니다.

```bash
python3 ledger.py --run <data>/runs/<run-uuid> \
  --out <reports>/recovery-<run-uuid>.json
```

`--out`은 생략할 수 있으며 결과 JSON은 stdout에 출력합니다. 지정한다면 원본 run 바깥의 새 파일이어야 합니다. 기존 보고서를 덮어쓰지 않습니다. manager의 `recover --run <run-uuid> --out <report.json>`도 같은 읽기 전용 API를 사용합니다. 상태가 `INVALID`이면 종료 코드 2이며 정확한 손실·durable 증거 목록을 제공하지 않습니다.

시작 도중 종료되어 committed checkpoint가 없고 fence만 비어 있으면 `UNCOMMITTED`입니다. checkpoint 없이 loss frame만 커밋되어 있으면 `PARTIAL_RECOVERY`이며 loss tombstone만 정확한 정보입니다. 두 경우 모두 `raw_recovery_supported=false`이고 raw 전체를 tail로 보존합니다. checkpoint 뒤에 추가로 커밋된 loss도 `COMMITTED_JOURNAL_FENCE` 범위의 정확한 userspace 거부 기록이며 checkpoint의 raw 경계를 늘리지는 않습니다.

## 커밋 경계

`evidence.meta`는 `<uint32 payload_length, uint32 crc32>` little-endian header와 UTF-8 JSON payload로 이어집니다. 0.3 reader의 한 frame은 최대 4 MiB입니다. schema 1의 `journal_seq`는 1부터 연속으로 증가하며 `record_type`은 `loss`, `checkpoint`, `seal`, `quarantine_enter`, `quarantine_exit`입니다. collector는 journal을 sync한 뒤 `evidence.meta.commit`을 원자적으로 교체하고 디렉터리를 sync합니다.

복구 도구는 commit fence의 `offset`까지만 읽습니다. fence가 없으면 유효해 보이는 frame도 `UNCOMMITTED`이며 durable 증거로 인정하지 않습니다. fence 뒤의 잘린 frame·온전한 frame·raw tail은 별도의 byte 수로 남기며 승격하지 않습니다. 커밋된 frame의 CRC, 길이, 순번, run/boot/config/manifest hash가 맞지 않으면 `INVALID`입니다. CRC와 hash는 무결성 검사이며 서명이나 공격자에 대한 진위 증명은 아닙니다.

commit fence와 frame은 `run_id`, `boot_id`, `config_sha256`, `manifest_sha256`으로 동일 run에 연결됩니다. manifest hash는 파일 전체 byte의 SHA256이고 config hash는 JSON `sort_keys=True,separators=(',',':')`의 SHA256입니다. `checkpoint`/`seal`의 `durable_offsets`는 새 run의 `critical`·`general`·`quarantine` raw byte 경계입니다. 기존 2-lane run도 지원하며 journal 중간에 lane 집합이 바뀌면 거부합니다. health.json의 마지막 상태만으로 장부 경계를 늘리지 않습니다.

## 정확한 정보와 확인 불가 정보

- `loss`는 userspace에서 확인한 `cgroup_id`, `seq`, `lane`, `reason`, `monotonic_ns`의 tombstone입니다. 동일 ID의 동일 tombstone은 중복으로 집계하고 다른 내용이면 손상으로 거부합니다. 동일 ID가 committed raw에도 있으면 충돌입니다.
- `checkpoint`는 주기적인 durable raw 경계와 tenant sequence, aggregate counter를 남깁니다. counter를 개별 손실 ID나 원인으로 배분하지 않습니다.
- detach·ring drain·writer drain/sync 뒤의 `seal state=STOPPED`와 `sequence_snapshot_complete=true`가 있으면 각 tenant의 **sequenced ID 1..최종 sequence** 중 committed raw에 없는 ID를 `ABSENT_FROM_DURABLE_RAW`로 구분합니다. 해당 ID에 loss tombstone이 있으면 그 정확한 userspace 이유만 표시하고 나머지는 `UNKNOWN`입니다.
- seal이 없거나 `FAILED`, sequence map snapshot이 불완전하면 이후 범위는 `UNBOUNDED_UNKNOWN_TAIL`입니다. 끝 sequence와 손실 건수를 만들어 내지 않습니다. 마지막 checkpoint 직전의 queue/in-flight 이벤트도 최종 저장 여부가 확정되지 않습니다.
- sequence 부여 전의 tenant map/pending 관측 fault 0..2는 별도의 `unsequenced_faults` aggregate로 남습니다. 개별 ID, 영향 이벤트 수를 추정하지 않습니다. 기존 run의 fault 3은 sequence 뒤의 shared critical budget lookup입니다. 새 3-lane run의 fault 3은 sequence 부여 전 quarantine global lookup으로 `pre_sequence_policy_faults`에 표시하며 이후 fallback에서 sequence가 생길 수도 있으므로 부재 건수를 추정하지 않습니다. 이것이 전체 실제 syscall을 모두 관측했다는 뜻은 아닙니다.
- metadata queue/용량 overflow는 `userspace_loss_reason_coverage_complete=false`와 경고로 나타납니다. 유효한 clean seal이 있으면 sequenced 범위의 raw 부재 집합은 계산할 수 있지만 누락 이유의 완전성은 주장하지 않습니다.

대형 sequence 범위를 하나씩 나열하지 않습니다. 임시 SQLite에서 raw ID를 streaming 검증하고 연속 interval로 압축합니다. 카테고리별 출력은 최대 4,096개 interval이며 초과 시 `ranges_truncated=true`, 전체 `range_count`와 정확한 `count`를 함께 제공합니다. 임시 DB는 원본 run 밖에 생성되고 끝나면 삭제됩니다.

raw의 comm/path는 Linux byte 문자열로 검사합니다. NUL 종료와 captured byte 길이를 확인하지만 UTF-8 변환은 요구하지 않으므로 UTF-8이 아닌 파일 이름도 센서 ID 복구를 막지 않습니다.

## Critical Quarantine 장부

0.3 raw schema 2는 기존 240-byte CRC record 크기를 유지합니다. `quality`의 비트 0..1은 기존 캡처 오류, 비트 8은 QUARANTINED, 9는 INITIAL, 10은 PERIODIC, 11은 PROTECTED, 12는 UNTRACKED, 16..23은 rule ID입니다. 그 밖의 비트는 거부합니다. INITIAL/PERIODIC은 동시에 붙을 수 없습니다. quarantine.raw는 원래 priority=critical이며 QUARANTINED와 INITIAL 또는 PERIODIC을 요구합니다. protected 규칙은 critical.raw에 저장되며 PROTECTED|UNTRACKED fallback도 허용합니다. legacy raw schema 1의 quality 의미는 바꾸지 않습니다.

보고서의 `critical_quarantine`은 실제 committed raw를 세어 INITIAL의 `full_saved_total`과 PERIODIC의 `sampled_total`을 제공합니다. 격리 전 일반 critical 원본은 이 두 지표에 넣지 않습니다. 두 경우 모두 원본 payload를 저장하며 우선순위를 바꾸지 않습니다.

`streams`는 `(cgroup_id, rule_id, kind)`별 lifetime의 seen, selected, submitted, ring_failed, summarized와 실제 durable INITIAL/PERIODIC 수를 비교합니다. `episodes`는 `current`, `last`, 이전 `closed_history`를 구별하고 다음 정보를 유지합니다.

`declared_metric_aliases`에는 active_quarantined_streams, critical_events_total, quarantined_events_total, peak_critical_rate를 보존합니다. peak_critical_rate의 단위는 `MAX_TRACKED_STREAM_ONE_SECOND_EPS`이며 전체 stream을 합한 peak가 아닙니다. `quarantine_by_reason`의 CRITICAL_RATE_EXCEEDED/CRITICAL_RATE_RECOVERED는 `TRANSITIONS` 단위의 진입·해제 건수입니다. 버린 event 건수와 섞거나 개별 event 원인으로 배분하지 않습니다. scope·정수 범위를 검사합니다.

전환 기록의 original_priority는 CRITICAL이고 effective_policy는 진입 시 QUARANTINE, 해제 시 CRITICAL입니다. trigger_reason은 각각 CRITICAL_RATE_EXCEEDED/CRITICAL_RATE_RECOVERED이며 기존 HIGH_RATE/LOW_RATE reason과 threshold·episode 정보도 유지합니다. 새 필드가 있으면 해당 전환과 일치하는지 검사하고, 없는 기존 기록은 그대로 읽습니다.

- 진입·해제의 threshold/observed rate, 적용 지속시간, 사유 HIGH_RATE/LOW_RATE, monotonic 시각과 sequence.
- burst 시작, episode 시작·마지막 이벤트·해제 시각, 현재/최대 rate, 평균 rate의 계산 정의.
- 최초·마지막 PID/UID, bitmap으로 얻은 고유 PID/UID 수의 **하한**. 정확한 distinct 수로 표기하지 않습니다.
- owned episode의 seen·초기 full 선택·주기 sample 선택·summary·ring 실패·제출 수, 실제 durable 기록 수.
- control 존재 여부, tracking 완전성, stream/storage snapshot 완전성. control이 누락되면 episode별 actual durable/loss 값은 null로 둡니다.

episode ID는 최초 격리 cgroup sequence이며 first/last sequence는 그 이벤트의 ID입니다. sequence는 BPF stream lock 이전에 부여되어 CPU 처리 순서에 따라 last가 first보다 작을 수 있으므로 ordering 경계로 사용하지 않습니다. episode의 실제 durable 원본은 같은 cgroup/rule/kind, Q·non-UNTRACKED 표시와 `start_ns <= monotonic_ns < end_ns`로 찾습니다. 아직 해제되지 않은 current episode는 마지막 이벤트 시각을 inclusive로 사용합니다. sequence 구간을 CRITICAL_QUARANTINE의 개별 손실 ID라고 주장하지 않습니다. `CRITICAL_QUARANTINE`은 scope가 명시된 `AGGREGATE_ONLY` summary reason입니다. 실제 userspace의 Q_QUEUE_FULL/Q_STORAGE_LIMIT tombstone만 해당 ID의 정확한 이유로 사용합니다.

clean STOPPED 및 완전한 stream/storage/tracking snapshot에서 전체 Q seen과 durable INITIAL/PERIODIC의 차이를 `quarantine_not_stored_total`로 표시합니다. RUNNING/FAILED/불완전 상태에서는 null이며 현재 차이는 `quarantine_pending_or_not_stored_total`, 선택 원본의 대기량은 `selected_pending_total`로 구분합니다. contention·map full의 UNTRACKED fallback은 owned episode와 별도로 세고, global의 명시적인 critical/protected/quarantined event counter를 사용해 중복 합산을 피합니다. 원본 부재 집합은 세 raw lane의 합집합을 사용합니다.

센서의 `(cgroup_id, seq)`와 외부 부하 생성기의 순번은 별도 ID입니다. 원장의 진단 결과는 기존 health durable boundary를 바꾸지 않습니다. 센서 tombstone을 외부 ground truth 동작의 원인으로 연결하지 않습니다.

## 검증 상태

모듈과 synthetic fixture의 Python 구문 검사를 수행했습니다. 사용자 요청에 따라 이 제작 작업에서 센서·워크로드·실험·fixture 테스트는 실행하지 않았습니다. 실행자가 필요할 때 아래 검증을 수행합니다.

```bash
python3 -m py_compile ledger.py test_ledger.py
python3 -m unittest -v test_ledger.py
```

작성한 fixture는 fence 부재·잘린 uncommitted suffix·committed CRC/순번/lineage 오류·raw 경계·crash tail·clean/failed seal·aggregate 원인 배분 금지·metadata overflow·uint64 상한·tombstone 중복/충돌·원본 보존·출력 덮어쓰기 거부를 다룹니다.
