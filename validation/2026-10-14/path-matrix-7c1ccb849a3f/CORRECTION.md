# 첫 경로 행렬 결과의 판정 오류

이 디렉터리의 `result.json`은 원본 그대로 보존한다(SHA-256:
`43818a527516d6e275c86ffe48618a8730ea77d32a37329547b23c3760985981`).
당시 분석기는 probe의 `getpid()`를 raw의 BPF PID와 직접 비교했다. WSL 배포판의
PID namespace 때문에 truth의 probe PID는 1073이었고 raw에는 host-initial PID
15407이 기록되어, 후보 15건을 0건으로 잘못 판정했다. 원본 자체의 raw CRC/schema,
index 완료, 원장 `RECOVERED`는 정상으로 기록되었다.

검증기는 고유 probe 실행 파일의 시작/자식 exec 경로와 분리된 monotonic 시간창으로
guest PID와 host PID를 엄격히 묶도록 수정했다. 수정 후 **새 격리 run**의
`../path-matrix-288b454fc769/result.json`에서 16/16 case가 각 1개 후보로
대조되고, raw CRC/schema·index·원장 복구가 모두 통과했다. 첫 `result.json`을
수정본의 성공 근거로 사용하지 않는다.
