# Current-code WSL benchmark evidence (2026-10-14)

Source commit: `f9bd477fbb18987a1b8cb2adb1d073010b555108`. The source, build,
configuration, workload, and BPF object hashes are recorded in
`final-f9bd477/environment.json`. The 12 individual run reports, configs,
and summary were exported unchanged to `final-f9bd477/`. The original reports
remain under `/root/mglogwh-v040-f9bd477-output/`; raw runs remain under
`/root/mglogwh-v040-f9bd477-data/runs/`. Those originals were not modified
while preparing this note.

The host was WSL2 with kernel `6.6.87.2-microsoft-standard-WSL2+` and 16
reported CPUs. Each run requested five seconds of 15,000 failed `openat`
bulk calls, 100 protected Critical calls, and 250 normal calls per second
(15,350 calls/s total). Four conditions were each repeated three times.
`legacy1` used **one explicit legacy Critical rule**; it is **not a zero-rule
baseline**. The other conditions used 1, 4, or 8 `event_rules`. In the 4- and
8-rule conditions, only rule ID 1 matched the workload; the extra path rules
were configured and evaluated but deliberately did not match.

| Condition | Runs | Median actual calls/s | Median p95 / p99 `openat` µs | Median collector CPU seconds | Median collector peak RSS KiB | Raw Critical / expected |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `legacy1` | 3 | 15,350.260 | 57.213 / 90.804 | 1.273087 | 22,784 | 1,500 / 1,500 |
| `rule1` | 3 | 15,350.271 | 54.153 / 84.280 | 1.111542 | 22,784 | 1,500 / 1,500 |
| `rule4` | 3 | 15,350.196 | 56.858 / 89.392 | 3.772182 | 22,656 | 1,500 / 1,500 |
| `rule8` | 3 | 15,350.291 | 56.623 / 89.431 | 4.309165 | 22,784 | 1,500 / 1,500 |

All 12 run reports have `valid_run=true`, valid workload truth, a clean
`STOPPED` health state, valid raw CRC and schema, `RECOVERED` ledger status,
no recovery errors or warnings, and no watchdog trigger. All three workload
paths have their exact requested raw counts in every run: 75,000 bulk,
500 Critical, and 1,250 normal. Across 12 runs, the protected Critical path
had **6,000 / 6,000** durable raw records. The raw files contain 936,848
records in total, including 15,848 events outside the 921,000 generated
workload calls. Every index reported `INDEX_COMPLETE`, zero byte and record
lag, and an indexed count equal to that run's raw record count. Every
recovery report recorded zero exact userspace losses. Each rule ID 1 matched
500 times per run; additional configured rules matched zero times.

Limits of the measurement:

- The p95/p99 values measure direct syscall wall time, including scheduling.
  They are not event-to-durable-record or dashboard display latency.
- This is a fixed offered load near 15,350 calls/s for five seconds, not a
  maximum throughput or sustained capacity result. Collector CPU use rose
  in the four- and eight-rule conditions, but three short repetitions do not
  establish a production capacity limit.
- Every run reported `pending_lookup_missing` in the pre-sequence fault
  counters: 2–21 per run, 155 in aggregate. The other three fault counters
  were zero. These aggregate diagnostics have no event identities and must
  not be presented as exact lost-event counts or as proof of zero kernel
  loss. The exact **userspace** loss count was zero.
- This is a WSL2 result. It does not substitute for a separate Ubuntu server
  run. The requested zero-rule condition was not tested because the current
  configuration requires at least one Critical rule.
