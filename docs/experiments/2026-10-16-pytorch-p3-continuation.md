# P3 continuation safety and bounded delay experiment

> Historical Replicant Mesh experiment, recorded before the project rename.
> Original image names, source paths and measurements are retained as evidence;
> use the [migration guide](../RENAMING.md) for current commands and names.

Date: 2026-10-16. This work extends P3 on the same laptop. Separate-device
performance, the full performance envelope and pooled-GPU capacity remain
unproven. P4–P8 gates are unchanged.

## Protocol frozen before measurement

The selected pipeline subset is LAN and 10 ms added egress delay, each at 128
input / 64 output tokens, concurrency three and three repetitions. Every
repetition targets 100 completed requests within 200 attempts, retaining failed
attempts and any in-flight completions beyond 100. The runner balances the order
across repetitions. Numerical/lifecycle validation must pass before measurement;
each case and the final cleanup must verify `noqueue` on every target.

The historical LAN repetitions took about 41 seconds each. Extrapolating the
earlier 8-output-token delay10 smoke throughput to the new 64-output-token
workload suggested roughly 11 minutes of delayed generation across three
repetitions, plus LAN, validation, probes and resets: approximately 15 minutes
overall. This was a rough planning estimate from different images/workloads,
not a measurement or a guaranteed bound. The strict duration estimator does
not treat those observations as compatible samples for the new image.

The complete-model control is separately frozen to three LAN repetitions of the
same workload and stopping policy. Four complete-model replicas each have two
CPU quota units and 3 GiB RAM; together they match the pipeline's eight CPU units
and 12 GiB, including its coordinator. Both use the same one-CPU / 1 GiB thin
driver. Pipeline services are stopped during control measurements, and replicas
are stopped during pipeline measurements. Control runtime was initially unknown.

The model/tokenizer revision, float32 eager CPU stack, fixed greedy output and
public fixture are unchanged from the [M5 report](2026-10-16-pytorch-m5.md).
The client uses one monotonic clock, includes admission and prefill, and excludes
tokenization, loading and warm-up. Throughput counts completed output only.
Control requests use the same remote benchmark implementation and arrival policy.
All replicas are warmed. Replica selection uses current client request counts,
rotating ties; requests remain on one replica through completion.

## Evidence integrity

Continuation creates new records with parent plan/evidence hashes and original
case references. Frozen source, Compose and image checks reject incompatible
continuation. Historical plans without the new provenance are preserved but not
retrofitted. Failed repetitions remain in the parent even when attempted again.
The auditor cross-checks request and attempt limits and keeps image identities
separate. See the [analysis guide](../PYTORCH_EXPERIMENT_ANALYSIS.md).

The replica implementation adds bounded streams, execution slots, deadlines and
safe cancellation drain. A wedged cancelled compute thread terminates its replica
process after the drain bound; this is a private lab control, not recovery by
replay. Its numerical gate compares forced continuations on all four replicas,
then checks concurrent requests and cancellation cleanup.

## Verification

The delay subset used image
`sha256:346b3aad9e7fd0aca1c7570ff542d668daa901a2483e80e4057e4ecd3fda8119`.
Its full runtime/tooling suite passed **255 tests, zero skipped, in 69.193 seconds**.
The replica preflight gate passed **256 forced-logit comparisons** at the fixed
`atol=1e-3, rtol=0` tolerance and checked concurrent sessions and cancellation
cleanup. The pipeline gate passed **144 comparisons** and its lifecycle checks
before the first measured repetition. The preceding M5 evidence stays separate
under its recorded image identities.

One initial test run found a missing `asyncio` import in the new cancellation
regression; it was fixed. A later validation process was interrupted before its
log completed, so it was not counted as passing. Detached jobs with separate
stdout/stderr and exit markers were then used for validation and measurement.
An intermediate full suite passed 255 tests; the final suite above additionally
covers repeated cancellation while compute still owns a session.

After the control CLI repair below, image
`sha256:82b0ba0935bd706180c8578f65a21b96976bb8756ce1f51fdb0c1ea7672dccc6`
passed **256 tests, zero skipped, in 68.505 seconds**. A separate 128-input /
8-output-token CLI smoke completed **6/6 requests**; this short check validates the
entry point and is not a performance repetition. The corrected image also passed
the 256-comparison replica gate before the fresh matched comparison.
The final replica comparisons had maximum absolute logit error **0.0**, with all
greedy choices agreeing. Both pipeline gates observed maximum absolute error
**3.814697265625e-6**, below the fixed `1e-3` absolute tolerance.

Commands executed included:

```powershell
docker compose -f compose.pytorch.yaml build prepare
docker compose -f compose.pytorch.yaml run --rm tests
docker compose -f compose.pytorch.yaml exec -T pipeline-benchmark python -m lab.benchmark bench --backend matched --prompt-tokens 128 --new-tokens 8 --concurrency 3 --requests 6 --output /results/p3-control-cli-smoke.json
docker compose -f compose.pytorch.yaml run --rm --no-deps service-check python -m lab.matched_control check --output /results/p3-controlfix-gate.json
pwsh -NoProfile -File tests/test_network_reset.ps1
```

The pipeline and control runners invoked the per-run numerical gates, probes,
benchmarks and reset commands. Their frozen plans and source/image identities
are named below. The [lab guide](../PYTORCH_LAB.md) and
[continuation guide](../PYTORCH_EXPERIMENT_ANALYSIS.md) describe those entry points.

## Pipeline measurements

The frozen parent is `m5-20261016T212514595Z-35f976dc`, its immutable continuation
plan is `p3-delay10-frozen-continuation`, and the execution directory is
`m5-20261016T212532066Z-66bfda4d`, all under `.lab/pytorch-results/`. The original
plans remain unchanged. The [compact summary](2026-10-16-pytorch-p3-summary.json)
retains report hashes, per-run metrics, resource observations and probe summaries.

All **612/612 requests** completed, producing **39,168 output tokens** with zero
failed attempts or retries. Every case and the final cleanup verified `noqueue`
on all four inference services. The final audit reports six of six planned cases,
no issues, no completion/attempt-policy misses and a verified final reset.

| Profile | Rep. | Completed | Output tokens/s | TTFT p50 / p95 ms | Inter-token p50 / p95 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| LAN | 1 | 102 | 158.28 | 39.50 / 51.80 | 17.63 / 23.78 |
| LAN | 2 | 102 | 157.63 | 39.47 / 55.82 | 17.76 / 23.73 |
| LAN | 3 | 102 | 156.98 | 39.63 / 49.73 | 17.83 / 24.32 |
| Delay 10 ms | 1 | 102 | 37.27 | 226.22 / 233.25 | 77.31 / 82.47 |
| Delay 10 ms | 2 | 102 | 37.30 | 227.67 / 237.14 | 77.27 / 82.37 |
| Delay 10 ms | 3 | 102 | 37.29 | 226.94 / 238.34 | 77.26 / 82.78 |

TTFT percentiles use request samples within each repetition. The inter-token
columns pool received-token intervals **within that repetition only**. The compact
summary additionally records the median per-session inter-token p50/p95 and the
95th percentile of per-session p95 values. No mean of run percentiles is presented
as a pooled percentile. The actual order was LAN1, delay1, delay2, LAN2, delay3,
LAN3; results are grouped above only for reading.

This subset shows repeatable additional-delay sensitivity for one tiny-model
workload. It does not establish the full P3 operating envelope. After collection,
the same-image/source duration estimator can use these six observations to
estimate **649.4 seconds of benchmark time** for a repeat of this subset, with an
observed sample range of 648.7–650.2 seconds. That is a post-run estimate for future
work, not the estimate used before launch; setup, gates, probes and resets remain
outside it.

## Matched complete-model comparison

The corrected image above is shared by fresh LAN pipeline execution
`m5-20261016T214719497Z-40eb40cb` and control execution
`matched-20261016T215146484Z-d822a13a`. The former references frozen parent
`m5-20261016T214621895Z-52704e16` through `p3-matched-lan-frozen-continuation`.
Both completed **306/306 requests** and **19,584 output tokens**, with zero failed
requests or retries. Earlier-image repetitions are not pooled into this comparison.

| Topology | Rep. | Completed | Output tokens/s | TTFT p50 / p95 ms | Inter-token p50 / p95 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Pipeline | 1 | 102 | 158.02 | 38.03 / 54.68 | 17.69 / 23.75 |
| Pipeline | 2 | 102 | 157.22 | 37.17 / 46.75 | 17.82 / 23.55 |
| Pipeline | 3 | 102 | 158.66 | 37.97 / 45.57 | 17.72 / 23.21 |
| Complete-model replicas | 1 | 102 | 717.98 | 11.38 / 13.94 | 4.06 / 5.09 |
| Complete-model replicas | 2 | 102 | 710.54 | 11.21 / 13.28 | 4.09 / 5.18 |
| Complete-model replicas | 3 | 102 | 716.30 | 11.25 / 13.18 | 4.09 / 5.14 |

The same within-run percentile definitions apply. Under these matched configured
budgets, the complete-model replicas delivered higher completed-output throughput
and lower client latency for this model, which fits easily in one container.
There is **no demonstrated pipeline efficiency benefit** here. This does not test
the project's larger-model pooled-memory hypothesis. Four full weight copies,
direct request routing, different service health checks and the absence of stage
activation transfers distinguish the control. Topologies ran sequentially rather
than in randomized interleaved order; thermal drift and other laptop contention
were not measured.

All three control case resets and the final reset were verified. The pipeline
services were restored healthy afterwards, with replicas stopped. The fresh LAN
audit also reports complete three-case coverage, no issues and verified cleanup.

## Network and resource observations

The delay-only probes measured median TCP echo RTTs of **20.480–20.586 ms** across
the three repetitions, rather than treating the configured 10 ms as total RTT.
Upload goodput ranged from **298.95–330.26 Mbit/s**, and download from
**300.13–331.28 Mbit/s**. This was delay-only shaping; those rates are observed TCP
behavior, not a configured bandwidth cap. Fresh LAN pipeline probe medians were
0.133–0.142 ms; direct client-to-replica medians were 0.140–0.175 ms.

| Corrected-image topology | Inference CPU seconds observed per repetition | Driver CPU seconds | Sum of sampled inference memory after case (MiB) |
| --- | ---: | ---: | ---: |
| Pipeline | 246.14–247.44 | 4.57–4.60 | 1,261.67–1,265.02 |
| Complete-model replicas | 58.46–58.95 | 3.86–3.94 | 1,313.78–1,316.77 |

These counter windows include warm-up/command/health-check overhead, and the
control window additionally includes reset. They are not isolated inference CPU
cost or an energy-efficiency ratio. Per-service usage, throttling counters and
memory samples are retained in the compact summary. Individual pipeline cgroup
peaks were 440.42 / 441.93 / 444.16 MiB for workers and 385.18 MiB for the
coordinator; replica peaks ranged from 361.55–364.09 MiB. These lifetime peaks do
not constitute one simultaneous aggregate peak or a per-repetition peak. The
driver peak was 37.56 MiB.
The complete-model reference gate records 18,485,504 parameter bytes, counting
tied parameters once. Four replicas therefore retain 73,942,016 logical weight
bytes in total, before caches and allocator overhead. This is weight replication
accounting, not a GPU-memory fit demonstration.

Per-user interval variability is also retained: the median of each request's
inter-token p95 was 20.90–21.61 ms across fresh LAN repetitions, versus
4.89–4.99 ms for replicas. In the separately identified delay-image runs it was
82.10–82.65 ms. These summaries are explicitly across per-session statistics,
not pooled interval percentiles.

## Retained control setup failures

`matched-20261016T214039273Z-6c6e778a` passed its 256-comparison numerical gate but
all three cases stopped before benchmark invocation: the TCP probe's default
port 50053 collided with the replica gRPC listener. The rejected probe replies,
cleanup errors and case outcomes remain saved. **No benchmark requests started**
in this attempt. All case resets and the final reset verified the four replica
queues. The control runner now explicitly uses probe port 50054. The replacement
run has a new plan and directory; the failed run is not overwritten or treated as
a repetition with zero request failures. The runtime image itself did not change.

`matched-20261016T214259193Z-6d85bfb4` then saved working network probes and another
passing numerical gate, but its benchmark CLI failed before measurement. It had
constructed asynchronous gRPC clients before entering the measurement event loop.
All three failed benchmark reports and resets remain retained; these are
pre-measurement client failures, not successful repetitions. Client construction
now occurs inside the running measurement loop, with a regression that checks
loop ownership. This requires a new image. The final resource-matched comparison
therefore uses fresh LAN pipeline repetitions on that same corrected image;
the earlier LAN/delay subset remains separately identified above.

## Interpretation limits

All services share the laptop CPU, physical RAM, Docker VM and kernel. CPU quotas
are ceilings, not reserved cores. Replica memory contains four full weight copies;
the pipeline partitions transformer weights and retains input/output weights in
the coordinator. Cache placement also differs. Equal resource ceilings do not
establish equal energy use, thermal behavior or an efficiency benefit.

Shaping applies to worker and coordinator egress. Every stage exchange goes
through the coordinator, whose egress also carries streamed tokens to the client.
Configured 10 ms is therefore neither total RTT nor a single delay per token.
TCP probes record observed link RTT/goodput separately. Replica LAN probes use
the direct driver-to-replica route.

CPU counter differences bracket the benchmark command, including warm-up and
command overhead; the control's after-snapshot additionally follows its network
reset. These are not CPU measurements isolated to the client's timed interval,
and their ratios are not an efficiency comparison. Current memory is sampled,
and cgroup peaks cover container lifetime.
Energy and thermal state are unmeasured. Reported per-run percentiles and their
run-to-run ranges must not be interpreted as pooled percentiles.

The full 128/1,024-token and concurrency 1/3/8 sweep, other delay/rate profiles,
real links, heterogeneous devices, energy measurements and GPU execution remain
untested here. The new replica control's hard process-exit path for a wedged
thread was not fault-injected; cancellation/drain regressions and the live
cancellation gate passed. P4 still needs actual participating GPUs, a model that
cannot fit on each device alone, loading/cache headroom measurements and successful
distributed execution. Synthetic capacity arithmetic is not that evidence.

Final checks passed: PowerShell syntax for the changed runners/shaper, mocked
per-target network-reset regressions, local documentation links across 20 files,
and `git diff --check`. A final status-only inspection after service restoration
recorded root `noqueue` on all four pipeline services. Raw runs, failed attempts,
probe data, test logs and detached-job exit markers remain under ignored `.lab/`.
