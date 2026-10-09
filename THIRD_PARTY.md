# GitHub 활용 기록

작성일 2026-09-17. 무관한 프로젝트 전체를 실행하거나 자동 설치하지 않고 필요한 수집 구조와 이미 설치된 라이브러리를 사용했다.

## 실제 활용

| upstream | 고정 revision | 사용 범위 | 라이선스 |
|---|---|---|---|
| [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) | d5f36b8ff051c78035696da31e673602c266d93c | bootstrap.bpf.c의 exec tracepoint/CO-RE/ring 구조; bootstrap.c의 skeleton lifecycle | kernel scaffold GPL-2.0 OR BSD-3-Clause; userspace LGPL-2.1 OR BSD-2-Clause |
| [libbpf](https://github.com/libbpf/libbpf) | dcaac95035044ff7e59bcaa2da4b9ae7f0a78a97 | 설치된 `.output/libbpf.a`를 실제 링크; BPF map·ring 관리 | LGPL-2.1 OR BSD-2-Clause, BSD 선택 |
| [BCC opensnoop.bpf.c](https://github.com/iovisor/bcc/blob/ab8e0616e88b9e1ba92520c6d041ae9214b10cf6/libbpf-tools/opensnoop.bpf.c) | ab8e0616e88b9e1ba92520c6d041ae9214b10cf6 | openat entry/exit를 map으로 연결하는 구조와 tracepoint 접근 패턴 | GPL-2.0, Copyright 2019 Facebook / 2020 Netflix |
| [bpftool](https://github.com/libbpf/bpftool) | 8485b9fba9b3bb3bd311b00632d2d22c0eee2e13 | 기존 설치 도구로 skeleton 생성. 실행 시 별도 데몬 없음 | upstream 라이선스 유지 |
| [vmlinux.h](https://github.com/libbpf/vmlinux.h) | 991dd4b8dfd8c9d62ce8999521b24f61d9b7fc52 | 기존 x86 CO-RE 타입 헤더 사용 | 원본 checkout의 고지 유지 |

기존 `/home/ljw/libbpf-bootstrap` checkout 자체는 수정하지 않았다. 결과물은 `/home/ljw/mglogwh-build`에 빌드한다. BCC 전체를 설치하거나 opensnoop 프로그램 전체를 복사하지 않았다. pathname pointer를 exit에서 다시 읽는 원본 방식과 달리 여기서는 entry에서 최대 128바이트를 복사해 보관한다. full-path 해석/stack 수집/openat2 등 원본의 다른 기능은 가져오지 않았다.

`sensor.bpf.c`는 GPL-2.0으로 고지하고 원본 copyright를 유지했다. `collector.c`에는 bootstrap userspace의 BSD-2-Clause 선택과 Facebook copyright를 유지했다. 로컬 변경: 중요도 분류, 두 ring, cgroup GCRA, sequence/loss counter, bounded 문자열, namespace-aware 자체 이벤트 제외. raw framing·내구성 checkpoint·Python 관리기·SQLite indexer·Sensor Console 연결·tests는 이 프로젝트를 위해 작성했다. GPL BPF가 포함된 수집기 배포 시 대응 소스와 고지 파일을 함께 제공한다.

라이선스 전문: `licenses/GPL-2.0.txt`, `licenses/libbpf-BSD-2-Clause.txt`, `licenses/bootstrap-BSD-3-Clause.txt`. bootstrap.c 유래 부분에는 아래 BSD-2 고지도 적용된다.

Copyright (c) 2020 Facebook

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## 검토만 한 프로젝트

- [Cilium Tetragon](https://github.com/cilium/tetragon): 커널 기반 process/context 추적 구조 검토. 데몬·정책 엔진·Kubernetes 의존성은 이번 범위에 가져오지 않음.
- [Falco libs](https://github.com/falcosecurity/libs): 수집 엔진 참고. 기존 Falco는 그대로 유지하며 libs 엔진을 MGlogWH에 통합하지 않음.

외부 코드 활용을 기능 완성으로 혼동하지 않는다. 새 코드는 이 로컬 환경에서 검증한 연구 구현이며 upstream 제품의 기능·보증·지원 범위를 승계하지 않는다.

## 2026-09-28 v0.2

critical cgroup·shared 예산, 보호 ring, tenant 공정 큐, metadata 원장과 읽기 전용 recovery는 이 프로젝트를 위해 작성했다. raw ABI는 유지한다. 지원하는 Linux x86_64에서 cgroup inode와 BPF cgroup ID의 관계는 Linux v6.6의 [kernfs inode 정의](https://raw.githubusercontent.com/torvalds/linux/v6.6/include/linux/kernfs.h), [cgroup ID 정의](https://raw.githubusercontent.com/torvalds/linux/v6.6/include/linux/cgroup.h), [BPF helper](https://raw.githubusercontent.com/torvalds/linux/v6.6/kernel/bpf/helpers.c)를 읽어 확인했다. 해당 파일의 코드를 새로 복사하지 않았다. 파일 inode를 해석하여 critical을 분류하는 기능은 별개의 미구현 목표다. 이번 버전에서는 컴파일·구문 검사만 수행했으며 신규 동작·성능 실험을 실행하지 않았다.

## 2026-09-28 v0.3

사용자 요청으로 이전 critical cgroup 예산·보호 cgroup 예약·tenant 공정 큐를 제거했다. Critical Quarantine의 fixed-window 상태, hysteresis, representative sampling, 정책·episode 원장과 fixture는 이 프로젝트를 위해 새로 작성했다. raw record 크기는240바이트이며 policy·rule 표시를 위해 schema2를 사용한다. 기존schema1 reader 호환을 작성한다. 외부 코드를 추가로 복사하지 않았으며 기존 BPF/userspace 출처·라이선스 고지는 유지한다. 신규 fixture 실행·실수집·부하·성능 시험은 수행하지 않는다.
