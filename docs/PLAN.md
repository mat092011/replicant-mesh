# Multiphase research and implementation plan

## Objective and current status

Test whether internet-connected consumer devices can pool memory and compute to
serve useful LLM inference, then test whether reciprocal credits can sustain that
network. Contributors would earn credits for accepted work and spend them on
their own requests.

**Status, 2026-10-13:** a prototype private Petals container lab, complete-model
reference, correctness checks, and benchmark runner have been added. The first
laptop inventory and launch protocol are in [LOCAL_LAB.md](LOCAL_LAB.md). The
[first smoke experiment](experiments/2026-10-13-local-lab.md) passed numerical
checks and completed 58 benchmark requests across local and simulated networks.
The broader phase gates below remain incomplete; no credit system exists.
Usability targets remain proposals, not claims established by this tiny model.

**Runtime status, 2026-10-16:** [PYTORCH_PIPELINE_PLAN.md](PYTORCH_PIPELINE_PLAN.md) defines
the replacement runtime in six gated milestones: contracts, in-process partition
parity, session protocol, worker services, coordinator scheduling, and Docker
comparisons. All six runtime milestones (M0–M5) are implemented within P0–P3;
Petals stays an optional baseline. The [M5 lab gate and selected measurements](experiments/2026-10-16-pytorch-m5.md)
pass. The full performance sweep, separate devices and broader research gates
remain incomplete.

**Research tooling, 2026-10-16:** the [experiment auditor](PYTORCH_EXPERIMENT_ANALYSIS.md)
checks saved run coverage, repetitions, failures and resets. The
[capacity preparation tool](PYTORCH_CAPACITY.md) records local hardware observations
and checks explicit component budgets without claiming execution fit. See the
[tooling validation record](experiments/2026-10-16-research-tooling.md). The laptop
and a separate ZimaBlade CPU host are available; no supported GPU has been
validated. Pooled-GPU evidence remains pending.

**P3 follow-up, 2026-10-16:** [bounded delay and matched-control measurements](experiments/2026-10-16-pytorch-p3-continuation.md)
add immutable continuation provenance, strict image/source/configuration checks,
duration estimates and complete-model replicas with matched aggregate CPU quotas.
The LAN/delay10 subset completed 612/612 requests; a corrected-image LAN pipeline
and replica comparison each completed 306/306. All final resets were verified.
Two failed control setup/client runs remain retained separately. Replicas were
faster for this locally fitting tiny model; no pipeline efficiency or pooled-memory
benefit is established. Full P3 coverage and separate-device links remain pending.

The first intended deployment uses invited GPU-equipped desktops and one fixed
model. Device count, GPU types, available memory, and internet connections still
need to be inventoried. CPU processes can establish correctness; hardware support
beyond the initial cohort should follow measured results.

**Release preparation, 2026-10-17:** the maintainer selected Apache-2.0 for project
code/documentation; see [LICENSE](../LICENSE) and the
[third-party review](THIRD_PARTY.md). The [README](../README.md),
[contribution guidance](../CONTRIBUTING.md), [release readiness review](OPEN_SOURCE_RELEASE.md)
and [development roadmap](ROADMAP.md) now distinguish the source-preview work from
research completion. The [release validation](experiments/2026-10-17-release-readiness.md)
records maintainer ownership confirmation, installed license/OS inventories,
tokenizer provenance, pinned secret scanning, CI definitions and clean local-clone
runtime reproduction. The subsequent maintainer-authorized
[source publication](experiments/2026-10-17-publication.md) records the public
repository, hosted CI and verified GitHub private reporting without email.
The new correctness/smoke checks do not extend the performance envelope;
all P0–P8 research statuses remain unchanged.

**Participant-network planning, 2026-10-17:**
[PARTICIPANT_NETWORK_PLAN.md](PARTICIPANT_NETWORK_PLAN.md) proposes the next
connector and network work: consumer/host/orchestrator roles, secure admission,
participant resource controls, real-device GPU experiments, measured placement,
recovery, reciprocal credits and eventual federation. Its C0–C9 work packages
map to the existing research gates; they are proposed work, not implementation
or new experimental evidence. The derived
[multiphase execution plan](PARTICIPANT_NETWORK_PHASES.md) adds task checklists,
local versus real-device sub-gates, dependencies, deliverables and evidence
requirements for C0–C9. The [C0 contract gate](experiments/2026-10-17-participant-c0.md)
passed after reviewed identity/permission/resource/failure contracts, closed-type
configuration validation, rebuilt Docker checks and the unchanged CPU controls.
C1 is in progress and unaccepted. Actual split-host baseline attempt 6 passed
four requests with 27 last-position vectors and maximum absolute error
`3.445148468017578e-05`. A later `c1b-happy-v1` attempt passed seven requests
with 36 vectors, including unequal 5/11-token concurrency and the 1,151+1
context boundary; its nine extension vectors had maximum absolute error
`9.5367431640625e-06`. Local preflight denied the 1,152+1 request before tensor
allocation or coordinator submission. The earlier failed `c1b-happy-v1` attempt
remains retained and unexplained. The happy-profile run recorded no remote
overlap and did not collect an ordered-interleave trace. The later physical
interleave observation is recorded below and in the parity report. The remaining
C1a/C1b lifecycle gates are open, so these bounded results are not C1 or P2
acceptance. C2–C9 and P0–P8 remain at their prior
statuses. C0 implements
declarations, not authentication or a connector. The
[lock portability follow-up](experiments/2026-10-17-participant-c0-portability.md)
records a corrected cross-platform identity and Git-source validation after
hosted CI exposed a CRLF/LF mismatch. All P0–P8 statuses remain unchanged.

**Local secure implementation, 2026-10-17 (unfinished C1a):** the
[local evidence record](experiments/2026-10-17-participant-c1a-local.md) records an
actual authenticated consumer/three-worker CPU matrix: 27 last-position logit
comparisons for patterned prompts 1/128/1024 with eight forced continuations,
plus bounded shutdown regressions. An earlier retained full security attempt ran
289 tests with zero skips and one error: a backward-clock rejection with
unconfirmed cleanup before a reply-loss injection. This is a historical failure,
not the latest full-suite result. A separate
[bounded clock diagnostic](experiments/2026-10-17-participant-c1a-clock.md)
measured a supplied wall-clock rollback; its underlying environment cause remains
unknown. C1a is unaccepted and saved privately. An earlier hardware-stop
instruction paused work before C1b; the later availability of the second CPU host
and authorization to resume are recorded below. This does not claim all local work
is exhausted. C1–C9 and P0–P8 completion statuses are unchanged. These unfinished
changes remain isolated from the C0-only publishing branch.

**Physical-host preparation, 2026-10-18 (unfinished C1):** the maintainer made a
second CPU host available and authorized implementation to resume. Its pinned
runtime and all eight existing in-process numerical controls passed, with finite
logits, greedy agreement, maximum absolute error zero, and reclaimed session/cache
owners. The
[two-device parity report](experiments/2026-10-18-participant-two-device-parity.md)
records split-host results and retained failures. Local and ZimaBlade each passed
a full 391-test suite without skips;
these are independent host-local controls. Actual split-host baseline attempt 6
passed four requests with 27 finite wire-logit vectors, confirmed local/remote
cleanup, and had maximum absolute error `3.445148468017578e-05`. A fresh
`c1b-happy-v1` run passed seven requests and 36 vectors, including unequal 5/11-
token correctness and the 1,151+1 boundary; local preflight denied the 1,152+1
request. Its extension maximum absolute error was `9.5367431640625e-06`. The
[two-device parity report](experiments/2026-10-18-participant-two-device-parity.md)
records both runs. The earlier expanded-profile failure remains unexplained and
retained. The fresh run observed no remote overlap and supports no ordered
interleaving claim. Trial 14's full-suite failure is retained in the parity
report. A later focused suite passed the corrected completion cases, but the
trial-14 backward-clock lifecycle failure remains unexplained. C1a acceptance
and remaining C1b numerical/lifecycle cases remain open, so neither C1 nor P2
is accepted.
The original 313-test physical run's expiry-attribution failure and earlier WSL
`CLOCK_UNSAFE` event remain retained; the latter is unexplained. The laptop's
AMD 890M integrated GPU is physically present, but its supported GPU backend is
unvalidated. No GPU execution, pooled-memory benefit, WAN performance, or later
research gate is established.

**C1a cold-transition components, 2026-10-18:** trial 19 passed 22 focused
Linux tests with zero skips, including protected final approval and actual
owned-process/group retirement. Its explicit containment assumption is trusted
operator code staying in its process group. The
[component evidence](experiments/2026-10-18-participant-c1a-followup.md)
pins the 260-file source and image and identifies later untested changes.
At the Trial 19 point, durable activation/high-water persistence and actual
service startup/root cutover remained incomplete; C1a, C1b and C1 remain
unaccepted.

**C1a focused follow-up, 2026-10-18:** the
[focused evidence report](experiments/2026-10-18-participant-c1a-followup.md)
records trial 17's 11 focused tests passing with zero skips, including three
completion/lifecycle cases and eight whole-cohort private issuance cases. The
source and image were pinned and all 250 baked source files matched. This is
test-suite runtime, not inference performance. At Trial 17, the private issuance
candidate had been tested, while policy approval, integration, publication,
activation, durable high-water state, and physical root cutover were incomplete.
Trial 23 later added a strict-v2 private high-water component; runtime adoption
and activation remain incomplete. Trial 17's complete 471-test, zero-skip security regression
also passed in 134.858 seconds of unittest runtime (not inference performance),
with both secure-pipeline and capture-backpressure opt-ins. Its log SHA-256 is
`b717ec4b3b39484807543cd34cb78ec9b2228ade369b058d572bef80d719781c`. Trials
13–16 remain retained with their failures; trial 17 does not supersede them or
establish their causes. Trial 18 added two focused local TLS-disconnect tests
with zero skips in 37.413 seconds of unittest runtime (not inference performance),
using 252 pinned source files and image
`sha256:7dcbf728a7d207e6db839161fd2c23d17fec578e0becb4ab6d1ec2af23811928`;
see the [C1a follow-up report](experiments/2026-10-18-participant-c1a-followup.md).
At that earlier point no additional physical split-host run had occurred. Trial 23 later added a tested
private strict-v2 policy high-water persistence component, but supported runtime
adoption, root activation/startup, actual boot/restart integration, and physical
C1b lifecycle requirements remain open. C1a, C1b, C1, and P2 remain unaccepted;
later phase statuses are unchanged.

**C1a cold-transition storage follow-up, 2026-10-18:** trial 20's three
fault-sweep errors are retained; the production store rejected ambiguous
leftover selector temporary files, while the test harness expected construction
to succeed. Trial 21 fixed that assertion and passed 51 focused Linux tests with
zero skips in 2.238 seconds of unittest runtime (not performance), using 263
source files, image `sha256:1f4a899566b2b4150a7bf674f5ded560d230ec53b6d99b4293f7e52624735d2e`,
and a matching baked-source proof. The cold-selection storage primitive and
snapshot durable-commit seam do not establish actual high-water persistence,
bootstrap, approval, activation, or readiness. The full Trial 21 regression
passed 524 tests with zero skips in 176.694 seconds of unittest runtime (not
performance), exit 0, on the same frozen source/image; its log SHA-256 is
`12ace22e8165f2bf45d86d991578391bae045211c0b5cf17a38683830c2a030f`. The full
discovery count is reported as observed, not as a sum of focused suites. C1a,
C1b, C1, and P2 remain unaccepted.

**C1a launch claims and strict-v2 policy high-water, 2026-10-18:** Trial 22's
earlier launch-claim component run passed 16 tests with zero skips in 0.037
seconds of unittest runtime; it preceded later test-strength/process-split
changes. Trial 23 then passed 84 focused checks with zero skips in 2.714 seconds
and the full security discovery passed 557 tests with zero skips in 176.686
seconds, all unittest runtime rather than inference performance. Its 266-file
source identity, Linux image, and complete baked-source proof are recorded in
the [C1a follow-up evidence](experiments/2026-10-18-participant-c1a-followup.md).
The strict-v2 store keeps immutable baseline artifacts and separately pinned
active-policy blobs under one selector lock/head; tested cases include signed
policy high-water updates, cold-verifier floor enforcement, idempotent equal
policy re-signatures, rollback/equivocation rejection, exact pending refresh
recovery, eligible cold-transition versus refresh contention, and the final
wall/monotonic check after selector-temp fsync. Trial 21's v1 storage work was a
private predecessor, not a published API.

The persistence mechanism remains a private component. Supported runtime
adoption and root startup do not yet consume active policy or launch claims;
activation composition, end-to-end READY/death validation, TLS root cutover,
and physical C1b lifecycle are still incomplete. These results do not accept
C1a, C1b, C1, or P2 and do not close any later-phase gate.

**C1a activation composition, 2026-10-18:** trial 24 passed 90 focused tests
with zero skips in 3.764 seconds of unittest runtime, using a verified
268-file image. Protected whole-cohort approval, actual owned-process
retirement, and cold selection now compose in a tested component. The
[evidence report](experiments/2026-10-18-participant-c1a-followup.md) records
the exact source/image and final grant-deadline validation. Actual service
startup from that selection, single-use launch-claim consumption, TLS root
cutover, and physical C1b lifecycle remain incomplete. C1a/C1b/C1 and the
research gates remain unaccepted.

**C1a durable runtime and worker-adoption follow-up, 2026-10-18:** trials 27
and 28 retained focused failures in test fixture setup/order; trial 28's
separate real worker-adoption diagnostic passed one test. Trial 29 passed 172
focused tests with zero skips, including the corrected real adoption fixture.
Its full security discovery ran 596 tests with zero skips but failed one
inherited secure-pipeline case (`Worker step failed`, coordinator close was not
confirmed, and one capture remained pending). The exact cause is unknown; this
is not a clean full-suite result. A bounded diagnostic later observed a
`CLOCK_UNSAFE` negative wall sample followed by fencing, but a separate observer
batch did not reproduce it and does not establish the original failure's cause.
Trials 30 and 32 added process-startup component evidence; Trial 31's 76-test
run remains a harness-threshold failure. The [follow-up report](experiments/2026-10-18-participant-c1a-followup.md)
records retained history, source/image identities, logs, and commands.

A later physical split-host interleave run passed six requests and 35 vectors,
including the bounded worker-3 sequence A0/B0/A1/B1, with the stage-1 barrier
and remote all-owners-global-zero check confirmed. It establishes this bounded
correctness/interleave observation, not performance or all-step overlap. Root
startup still lacks end-to-end claim consumption, process ownership, actual
root-worker CLI/TLS/model cutover, and launch/admission epoch composition.
Physical fault/restart/drain requirements remain open. C1a, C1b, C1, and P2
remain unaccepted.

Trial 40 passed 85 focused component tests with zero skips in 8.782 seconds of
unittest runtime (not inference performance), covering the fixed worker-process
and root-runtime components plus cancellation-profile validators and fixtures.
That component invocation did not run the physical two-host profile. The later
physical cancellation/disposal pass is recorded at the end of this plan and
in the separate-device report. The
[trial-40 record](experiments/2026-10-18-participant-c1a-followup.md) preserves
the frozen source/image identities and exact test command. No C1 or P2 gate is
closed by this component result.

## Questions to answer

1. Can partitioning preserve the model's computation and session state?
2. Under which network conditions does pooling memory produce a useful result?
3. How does concurrency change per-user latency and aggregate throughput?
4. Does the benefit survive heterogeneous hardware, failures, and verification?
5. Can useful contributions be accounted for without creating unearned credits?
6. Which control services can be decentralized while preserving those benefits?

The project does not assume that adding internet-connected devices accelerates a
single answer, lowers total energy use, or creates more compute than participants
contribute. These are separate measurements. Exchange can still be useful by
sharing idle capacity across time and enabling larger models.

## Initial architecture

Use a fixed pipeline of contiguous transformer blocks. Weights remain loaded on
workers; activations cross stage boundaries. Each stage maintains the KV cache for
its layers and active sessions. The selected token must feed back to the beginning
before the next ordinary decode step for that session can start.

Different sessions can occupy different stages simultaneously. Prefill processes
the prompt; decode produces subsequent output tokens. Measure these separately.
Record where embeddings, final normalization, output projection, and sampling
execute: their placement changes memory use and the actual communication route.

Start with a trusted control service and fixed assignments in the private Docker
lab. The first Petals baseline has been reproduced. The next implementation uses
owned PyTorch workers so protocol, cache lifecycle, scheduling and measurement are
under project control; see the linked implementation plan for the scope and gates.
Authenticated worker admission is required before expanding beyond the trusted
local lab. Verify runtime/model compatibility and pin the tested stack.

The first owned-runtime slice (M0/M1) now passes in-process numerical and session
checks on the locked PyTorch stack, including full 1,024-position prefill logits.
See [the runtime guide](PYTORCH_RUNTIME.md) and
[M1 evidence](experiments/2026-10-14-pytorch-m1.md). The subsequent
[M2 protocol/lifecycle gate](experiments/2026-10-14-pytorch-m2.md) also passes
binary transport, bounded validation and cancellation/expiry checks, including
loopback gRPC. [M3](experiments/2026-10-15-pytorch-m3.md) adds three supervised
worker containers, bounded queues, process-fault checks and remote logit parity.
[M4](experiments/2026-10-15-pytorch-m4.md) validates bounded scheduling, cancellation,
concurrent output parity and actual compute overlap across these containers.
[M5](experiments/2026-10-16-pytorch-m5.md) adds the standalone service, thin client,
controlled network profiles, measured RTT/goodput and verified network reset.
Same-host correctness and overlap do not complete the separate-device or performance
research gates below.

## Phase overview

| Phase | Outcome | Dependency | Status |
| --- | --- | --- | --- |
| P0 | Fixed protocol, hardware inventory, and acceptance targets | None | Local CPU protocol and runtime validated; GPU cohort and final acceptance targets pending |
| P1 | Reproducible complete-model reference | P0 | Petals smoke baseline and owned PyTorch full-logit reference validated; detailed timing/peak memory incomplete |
| P2 | Correct fixed pipeline across processes and devices | P1 | PyTorch M4 and one bounded split-host baseline passed; required C1a/C1b lifecycle coverage and full P2 gate remain pending |
| P3 | Measured LAN and WAN performance envelope | P2 | Selected LAN/delay10 repetitions and matched-budget replica controls measured; full sweeps and real links pending |
| P4 | Demonstrated pooled-memory benefit | P3 | Local inventory and explicit memory-fit planner implemented; GPU capacities, suitable model and demonstration pending |
| P5 | Scheduling and recovery under changing availability | P4 | Pending |
| P6 | Auditable reciprocal credits | P5 | Pending |
| P7 | Evidence from an invited community pilot | P6 | Pending |
| P8 | Incremental decentralization | P7 | Pending |

### P0: Fix the experimental protocol

**Work**

- Inventory GPU/CPU models, usable VRAM/RAM, operating systems, power limits,
  network upload/download rates, direct versus relayed connectivity, and measured
  round-trip latency. Confirm access to the proposed test machines.
- Select a small supported dense model and a candidate model requiring pooled
  memory. Record model/tokenizer revisions and distribution requirements.
- Pin compatible runtime and dependency versions. Use a reproducible environment;
  for the current Windows workstation, assess WSL2 or Linux containers as needed.
- Define workload fixtures, timing boundaries, numerical tolerances, repetitions,
  failure scenarios, and the comparisons below before measuring performance.

**Deliverable:** a versioned experiment manifest and documented launch procedure.

**Gate:** another developer can identify the exact hardware, model, software, and
workload required. Unknown hardware-dependent choices remain explicit.

### P1: Establish the reference

**Work**

- Run the complete small model locally with fixed prompts and greedy decoding.
  The laptop lab starts with the eight-block `Maykeye/TinyLLama-v0` to test
  mechanics; `bigscience/bloom-560m`, with 24 blocks, is a larger follow-up.
- Begin without weight quantization or lossy activation compression. Record dtype,
  attention implementation, logits, generated token IDs, timing, and peak memory.
- Warm up before measuring. Report model loading and cold-start overhead separately.
- Establish the numerical tolerance using the chosen runtime/precision and control
  runs. Record near-tied logits when they can change greedy token selection.

**Deliverable:** reference runner, fixtures, and a compact baseline report.

**Gate:** the reference is reproducible within the declared tolerance and its
measurements distinguish prefill, decode, and startup.

### P2: Validate a fixed pipeline

**Work**

- For the eight-block checkpoint, start with ranges `[0, 3)`, `[3, 6)`, `[6, 8)`.
  For the 24-block candidate, use `[0, 8)`, `[8, 16)`, `[16, 24)`.
  Include the separately placed input/output components in the resource budget.
- Start on one machine, then place stages on separate devices. For a custom
  implementation, validate an in-process split before adding network transport.
- Keep stage weights resident. Index caches by session and layer. Track token
  position, sequence number, masks, tensor shape/dtype, and model revision.
- Compare full-model and pipeline logits for prefill and decode while feeding both
  the same continuation tokens. Also compare greedy outputs and inspect any
  divergence; do not let diverging contexts invalidate the numerical comparison.
- Test interleaved sessions, different context lengths, cancellation, cache
  cleanup, and rejected out-of-order or incompatible messages.
- Trace independent sessions to demonstrate overlapping useful work on workers.

**Deliverable:** fixed three-stage runner and meaningful correctness tests.

**Gate:** logits meet the declared tolerance; session state remains isolated;
memory measurements match the intended partition; a trace demonstrates overlap.
Three processes sharing one GPU demonstrate mechanics only.

### P3: Measure LAN and WAN behavior

**Work**

- Use the workload and metrics defined below. Run a local network baseline before
  separate home connections. Record the actual client and stage traffic route.
- Sweep added network delay and bandwidth independently before combining them.
  Distinguish configured additional delay from measured total round-trip latency.
- Record compute, queue, serialization, transfer, and client-side processing time.
  Use traces to identify pipeline idle periods and slow stages.
- Compare one session with several sessions. Keep all other variables fixed.
- Inspect long-prompt prefill separately from short decode messages. Include actual
  relay overhead where NAT traversal requires it.

**Deliverable:** reproducible benchmark harness, sanitized traces, and charts of
per-user latency versus aggregate throughput under each network condition.

**Gate:** results establish a repeatable operating envelope, including failure
cases. If networking dominates, test fewer stages, nearby peers, or a different
workload and document the revised hypothesis before expanding the system.

### P4: Test pooled memory on a larger model

**Work**

- Select a fixed model/precision configuration that cannot remain GPU-resident on
  any single participating device but fits across the group with cache headroom.
- Repeat correctness checks when changing the model, quantization, or compression.
- Compare with the same model using local CPU/RAM offloading where feasible. Keep
  runtime differences explicit. A smaller local model is a separate quality and
  user-experience comparison, not a like-for-like speed baseline.
- Measure peak memory, per-user responsiveness, successful throughput, total
  transferred bytes, and energy where a credible measurement is available.
- Include client-side memory, loading, and recovery costs. Report any paid relay
  or infrastructure usage if incurred; do not infer lower cost from idle hardware.

**Deliverable:** a capacity demonstration and comparison report.

**Gate:** pooled memory enables the selected configuration and the report states
whether it meets the frozen usability and resource-cost criteria. A model merely
starting successfully is insufficient evidence of useful inference.

### P5: Add placement, scheduling, and recovery

**Work**

- Add worker registration, heartbeats, measured capacity, memory budgets, bounded
  queues, request deadlines, cancellation, and admission control.
- Prefer warm stages and nearby links. Keep sessions on their current workers
  where possible. Balance measured stage time rather than only layer counts.
- Replicate necessary stages and test worker loss during prefill and decoding.
  Replication requires additional memory beyond the minimum complete pipeline.
- Implement a documented recovery method, such as replaying cached inputs or
  rebuilding state from the accepted token history. Measure its actual cost.
- Identify requests and decode steps so retries do not append duplicate cache
  entries or stream duplicate tokens. Release resources on termination.
- Sample computations against a trusted reference and record audit overhead.

**Deliverable:** worker lifecycle, scheduler, and fault-injection tests/report.

**Gate:** failures cause explicit errors or bounded recovery, preserve the accepted
output prefix, and do not corrupt other sessions. All recovery limits and audit
coverage are stated. Spot checks do not establish permissionless correctness.

### P6: Introduce reciprocal credits

**Work**

- Use a central ledger and one model initially. Publish a versioned tariff for
  accepted work, distinguishing prefill/decode, context length, and layer share.
- Use measured reference work to normalize contributions. Do not reward unused
  advertised capacity, self-reported GPU time, or arbitrary output length.
- Reserve a bounded request budget, settle accepted work, and release unused
  reservations. Use unique job/step IDs for idempotent debit and reward records.
- Specify the rules for cancellation, retries, failures, audit work, and recovery.
  Charges cannot exceed reserved budgets; retries cannot create duplicate rewards.
- Keep ledger transfers balanced. Any initial grants, fees, subsidy, or credit
  retirement must have explicit entries and limits. Self-dealing must not mint
  net new credits.
- Exercise replayed receipts, forged work reports, colluding client/worker claims,
  and repeated account creation. State which attacks still require trusted peers.

**Deliverable:** ledger, tariff, contribution receipts, and accounting/abuse tests.

**Gate:** every issued, spent, transferred, and retired credit reconciles; replay
and retry tests pass; contributors can inspect their accepted work. Receipts show
attribution, not proof of correct execution. Claimed benefits include audit costs.

### P7: Run an invited community pilot

**Work**

- Expand toward 10-20 invited participants, subject to available hardware. Let
  contributors set memory/power limits, availability windows, and stop controls.
- Test mixed devices, busy periods, sparse demand, disappearing peers, repeated
  requests, and unequal contribution/consumption across time.
- Use public or synthetic workloads initially. Measure installation burden,
  reliability, credit usefulness, user responsiveness, and resource consumption.
- Compare useful completed work against the baselines after verification,
  scheduling, relay, and recovery overhead. Report unsuccessful requests too.

**Deliverable:** pilot report and a documented continue, revise, or stop decision.

**Gate:** evidence shows whether participants receive a useful benefit and whether
the chosen workload can be supported reliably. No automatic expansion is assumed.

### P8: Decentralize control services incrementally

**Work**

- Replace centralized discovery first, then assess distributed placement and
  scheduling. Keep protocol identity, versioning, and admission limits explicit.
- Test discovery poisoning, stale availability, network partitions, and malicious
  resource advertisements under a stated threat model.
- Treat decentralized accounting as a separate design problem: agreement on
  balances, double spending, identities, collusion, and compute verification.
- Evaluate whether federation or trusted communities provide the intended benefit
  before claiming fully permissionless operation.
- Re-run the same benchmark and accounting checks after each architectural change.

**Deliverable:** architecture decisions, adversarial tests, and updated benchmarks.

**Gate:** name every remaining trusted component. Claim decentralization only for
functions actually distributed and validated. Full decentralization is conditional
on preserving a useful and accountable service.

## Benchmark protocol

Initial proposed workload:

| Dimension | Values |
| --- | --- |
| Transformer pipeline | Three fixed stages; later compare fewer stages |
| Prompt lengths | 128 and 1,024 tokens |
| Output length | 64 generated tokens per controlled request |
| Active sessions | 1, 3, and 8 |
| Added one-way link delay | 0, 10, 25, and 50 ms |
| Bandwidth caps | 20, 100, and 1,000 Mbit/s, within physical link capability |
| Environments | Local processes, distinct LAN devices, distinct internet sites |
| Repetitions | At least 100 completed requests per configuration, with failures also recorded |

Define early-EOS behavior consistently when fixing output length. Fix and disclose
batching policy, queue limits, warm-up, request arrival pattern, seeds, and prompt
fixtures. The initial concurrency sweep is a closed-loop test with a fixed number
of active sessions; add an arrival-rate sweep later to expose saturation and queue
growth. Do not silently omit timeouts to reach the completed-request target.

Delay settings refer to each shaped direction; applying a delay to both directions
changes round-trip latency accordingly. Application sleeps model waiting time
only. Use packet/network shaping for bandwidth, jitter, and loss, then verify on
real links. Configure shaping within the test environment and record its removal.

Report:

- Client-observed time to first output token, including queuing and prefill.
- Per-session median and 95th-percentile time between output tokens; report
  per-session generation rate separately from whole-request elapsed time.
- Aggregate output throughput over one shared measurement interval. Count each
  accepted output token once and state whether prefill is inside the interval.
- Request completion, rejection, cancellation, timeout, and retry counts.
- Memory per worker and client, stage compute time, queue time, bytes per link,
  recovery time, and measured energy when available.
- Run-to-run variation and achieved network conditions. Device-side GPU timings
  require CUDA events or appropriate synchronization, not enqueue time alone.

Compare against complete-model local execution and complete-model replicas on the
same available GPUs when they fit. Use the same model, precision, workload, and
aggregate resource inventory wherever possible. Keep hardware/runtime differences
visible. For large models, use same-model offloading as the relevant local control.

**Provisional usability target:** for the selected larger model with a 1,024-token
prompt, 64-token output, and one active session, test for median decode throughput
of at least 5 output tokens/second and 95th-percentile time to first token of at
most 5 seconds. Freeze or revise these targets in P0 before collecting results;
they are not expected measurements or universal requirements. Define a separate
concurrency target after selecting the hardware, also before the relevant run.

## Repository outputs

Current prototype:

- `compose.yaml` and `docker/`: private CPU lab topology and image dependencies.
- `lab/`: container entry points, reference/pipeline runner, and reporting helpers.
- `tests/`: dependency-free checks for configuration and metric calculations.
- `scripts/`: container network shaping.
- `.lab/results/`: ignored local output directory for run reports.
- [LOCAL_LAB.md](LOCAL_LAB.md): setup, first machine inventory, and validation limits.
- `docs/experiments/`: measured smoke report, compact run summaries, and package inventory.
- `docs/decisions/`: CPU runtime, private topology, and wrapper decisions.

Create these additional areas as the later experiments require them:

- `src/`: worker, client, protocol, and scheduling code added for the experiments.
- `tests/`: extend coverage for failure handling and accounting as they are added.
- `benchmarks/`: expanded workload fixtures, traces, and metric collection if they
  outgrow the initial `lab/` runner.

Extend the reports and decisions with later evidence on real devices, trust,
recovery, and credits.

Each completed phase should link its deliverables and evidence from the phase
table. Keep raw private data, model weights, caches, and large traces out of Git.

**C1a fixed worker-process follow-up, 2026-10-18:** trial 38 passed seven
Linux tests with zero skips, including the real protected Python CLI, loaded
model, native TLS listener, authenticated Describe and confirmed graceful
cleanup. The [follow-up report](experiments/2026-10-18-participant-c1a-followup.md)
retains the earlier fixture failures and exact source/image/log identities.
This component result does not establish whole-cohort root-cutover Generate
or close C1a, C1b, C1 or P2. The consolidated full regression failed one inherited valid-baseline case
out of 630 tests with zero skips; its cause remains unknown.

**Worker Open outcome component, 2026-10-18:** trial 46 passed one Linux
native-TLS test with zero skips. It confirms raw receive-cap exhaustion after
real OpenSession admission remains an unknown charged coordinator owner, with
no Step/retry and eventual worker lease/cache retirement while the coordinator
fence remains. This admission-only test does not run model generation or claim
a safely delivered native protobuf capacity rejection. See the
[trial-46 record](experiments/2026-10-18-participant-c1a-followup.md#trial-46-worker-open-outcome-regression-passes).
The physical partial-admission profile, root cutover, consolidated regression,
and C1/P2 acceptance remain open.

**Physical C1b Step reply-loss, 2026-10-18:** the narrow `c1b-step-reply-loss-v1`
profile passed after the four-request, 27-vector baseline. It discarded a real,
validated worker-3 first-prefill Step reply at the caller boundary only after a
fresh remote status confirmed the committed session; this is a controlled
unknown-outcome test, not evidence of packet loss. The three workers each saw
one OpenSession, Step and CancelSession, with no retry or emitted token. Remote
session/cache ownership was later confirmed empty. Local request, stream,
capture and worker owners were reclaimed while the coordinator truthfully
remained failed and unready; the intermediate snapshot still showed 15 static
transport connection reservations and zero pending reservations. The parent
measured 6.844 seconds from its same-host arm to independently confirmed local
process exit, within the 40-second bound. Both operators exited 0, owned
containers and remote private job files were removed, and the result reported
no pending transport operations. This narrow physical result does not complete
partial admission, cold root cutover, the failed consolidated regression, C1b,
C1 or P2; see the [parity report](experiments/2026-10-18-participant-two-device-parity.md#physical-step-reply-loss-run-1).

**C1a cold-cutover attempt, 2026-10-18:** Trial 47's single opted-in Linux
test failed during fixture construction because its old credential was outside
the 300-second renewal window. No cohort process started, so it provides no
cutover or inference evidence; the failure is retained in the
[C1a follow-up report](experiments/2026-10-18-participant-c1a-followup.md#trial-47-retained-cold-cutover-fixture-failure).
The physical Step-reply-loss result above does not change this C1a gap or the
failed consolidated regression.

**C1a cold-cutover follow-up, 2026-10-18:** Trials 48 and 49 retained fixture
errors during final proof and selected-root validation; the exact declaration
membership and trusted read callback are corrected. Trial 50 passed 56
capacity-profile component tests with zero skips, but its separate opted-in
cold-cutover run failed after old-cohort startup, Generate and retirement:
final status for old worker 3 was incomplete, with the specific resource field
still undiagnosed. No new-root activation or successful cutover is established.
The [C1a follow-up report](experiments/2026-10-18-participant-c1a-followup.md#trials-48-and-49-retained-cold-cutover-fixture-and-api-errors)
records these attempts and source pins. The physical capacity profile has not
run; C1a, C1b, C1 and P2 remain unaccepted.

## Primary references

- [Petals implementation](https://github.com/bigscience-workshop/petals) and
  [private swarm guide](https://github.com/bigscience-workshop/petals/wiki/Launch-your-own-swarm).
- [Distributed Inference and Fine-tuning of Large Language Models Over the Internet](https://arxiv.org/abs/2312.08361):
  prior research on heterogeneous WAN inference and recovery; its offloading
  comparison is not evidence of beating a model that fits on one GPU.
- [PyTorch pipeline parallelism](https://docs.pytorch.org/docs/stable/distributed.pipelining.html).
- [Hugging Face KV cache explanation](https://huggingface.co/docs/transformers/main/cache_explanation).
- [BLOOM-560m configuration](https://huggingface.co/bigscience/bloom-560m/blob/main/config.json).
- [Petals security and privacy limitations](https://github.com/bigscience-workshop/petals/wiki/Security,-privacy,-and-AI-safety).

References were consulted during planning on 2026-10-13. Pin tested versions when
implementing; documentation URLs and project defaults may change.


**Physical cancellation, 2026-10-18 (C1 still open):** the two-host
`c1b-cancel-v1` run passed baseline parity and cancellation after remote prefill
and held local decode KV mutation. No additional output or Step retry occurred;
sessions, caches and authorization owners were reclaimed. Both actual processes
exited 0 and their scoped resources were removed. The parent observed a
6.922-second conservative arm-to-disposal bound against the frozen 40-second
limit. See the [physical cancellation record](experiments/2026-10-18-participant-two-device-parity.md#physical-cancellation-after-remote-prefill).
Other physical admission/reply-loss/restart/drain/revocation cases, local cold
root cutover, the current consolidated regression and C1/P2 acceptance remain
open. No additional hardware is needed for these current checks.


**Real root-coordinator process component, 2026-10-18:** trial 42 passed the
required Linux process test with zero skips: the actual fixed coordinator child
served one authenticated forced-feedback request through three real native TLS
worker services, with nine finite vectors matching the complete-model reference
within the frozen tolerance. Graceful exit 0, process-group retirement, final
status, worker cleanup and zero transport reservations were confirmed. Its
initial selected root was test-provisioned; operator approval, whole launch
claims and local cold root cutover remain open. See the
[trial-42 evidence](experiments/2026-10-18-participant-c1a-followup.md#trial-42-real-fixed-coordinator-process-and-three-tls-workers).
C1/P2 acceptance and the latest failed consolidated regression remain open.

The frozen Trial 50 diagnostic subsequently identified the final-status
assertion: normal worker-bridge shutdown deliberately leaves restart-required
and unavailable flags set after complete resource release. The test now checks
that stopped state truthfully while retaining strict live readiness and every
resource/process-exit check. A successful cold-cutover rerun is still pending;
see the [C1a follow-up](experiments/2026-10-18-participant-c1a-followup.md#trial-50-capacity-components-pass-cold-cutover-cleanup-remains-unresolved).

**Cold root cutover and remaining C1 checks, 2026-10-18:** Trial 51 passed four
Linux tests with zero skips, including an actual five-role cold transition,
approved 13-artifact activation, new-root inference, a stale-leaf wire denial,
and confirmed process/resource retirement. This is one-host evidence, with
explicit trusted-bootstrap and observation limits; see the
[Trial 51 record](experiments/2026-10-18-participant-c1a-followup.md#trial-51-actual-local-cold-root-cutover).
Trial 52 passed 65 focused Linux tests with zero skips for capacity synchronization
and boot-authority components. The physical capacity runs still failed before
their fault arm, and partial-admission run 3 failed result/disposal validation;
the [retained failures](experiments/2026-10-18-participant-two-device-parity.md#retained-capacity-and-partial-admission-failures)
distinguish measured exits from absent timing evidence. Actual worker restart,
remaining physical lifecycle checks and a clean consolidated regression remain
open. The earlier Trial 38 consolidated failure is unexplained. C1a, C1b, C1
and P2 remain unaccepted; no additional hardware is needed for these current checks.

**Physical partial admission and capacity, 2026-10-18:** after Trial 53's 73-test
focused Linux gate passed with zero skips, the two-device partial-admission run 4
and capacity run 3 passed on matching source-proven images. Partial Open loss
retained the unknown logical owner truthfully until actual exit 0 in 14.672
seconds; capacity exercised eight captured requests, pre-submit ninth refusal and
confirmed cleanup, with actual exit 0 in 7.672 seconds. Both bounds were measured
on the parent monotonic clock against 40 seconds. See the
[partial result](experiments/2026-10-18-participant-two-device-parity.md#physical-partial-admission-run-4)
and [capacity result](experiments/2026-10-18-participant-two-device-parity.md#physical-capacity-run-3).
Physical restart, owner drain and signed identity removal/revocation, plus the
current consolidated regression, remain open; C1a, C1b, C1 and P2 remain unaccepted.

**Restart and owner-control follow-up, 2026-10-18:** Trial 55 passed 89 focused
Linux tests without skips. Physical restart run 2 reached new-worker READY, then
failed before the next observation; its original failing branch is unattributed.
A separate frozen diagnostic reproduced an old-connection timeout without native
authentication rejection. Both failures remain retained. Trial 56 passed all 122
selected tests without skips, but its required harness failed because its count
floor was incorrectly set to 123. These component results do not complete actual
restart, drain, signed removal or the consolidated regression. See the
[follow-up evidence](experiments/2026-10-18-participant-c1a-followup.md#trials-55-and-56-restart-and-owner-control-component-gates)
and [physical restart record](experiments/2026-10-18-participant-two-device-parity.md#physical-restart-run-2-ready-reached-failure-unattributed).
C1a, C1b, C1 and P2 remain unaccepted; current checks need no additional hardware.

**Focused helpers and consolidated regression, 2026-10-18:** Trial 60 passed
201 Linux tests with zero skips. Trial 61 failed before test spawn at the Windows
command-line limit; its replacement used a read-only frozen gate file with the
same required cases and pass criteria. Trial 62 ran 783 tests with zero skips,
five failures and one error. Trial 63 passed all 41 tests in the two corrected
fixture modules with zero skips, preserving strict production validation. This
is not a clean consolidated gate or a diagnosis of the historical Trial 38
failure. See the [retained Trial 60–63 evidence](experiments/2026-10-18-participant-c1a-followup.md#trials-60-to-63-helper-gate-and-retained-consolidated-failure).
Restart, physical drain/removal and current full acceptance remain open; C1a,
C1b, C1 and P2 remain unaccepted. No additional hardware is needed for these checks.

**Owner-control and restart follow-up, 2026-10-18:** Trials 57 and 58 retained
two fixture/import errors; Trial 59 passed its 187-test Linux gate with zero
skips and verified signed two-policy component behavior. Its bridge/status
fixtures do not establish physical drain, removal or TLS denial. Physical
restart run 3 reached new-worker READY and Describe, then failed before the
first authenticated old-session refusal; its native cause remains unrecorded,
and the local operator exited 143. See the [C1a follow-up](experiments/2026-10-18-participant-c1a-followup.md#trials-57-to-59-owner-adapter-fixture-repair-and-linux-gate) and [physical restart record](experiments/2026-10-18-participant-two-device-parity.md#physical-restart-run-3-stale-control-check-failed). Actual restart, owner drain/removal, the current full regression and C1/P2 acceptance remain open.


**Restart fixture and physical run 4, 2026-10-18:** Trial 64 ran 248 required
tests with zero skips but retained one error: its genuine Step authorization
fixture omitted the bounded tensor envelope and the production validator
correctly rejected it. Trial 65 passed all 248 required Linux tests with zero
skips after correcting only that fixture. Physical restart run 4 reached the
new worker's READY acknowledgement, then failed generation-two listener setup
because its private Unix socket directory exceeded the acceptor path bound;
the remote processes exited 0 and resources were removed, while the local
operator exited 143. No restarted inference, native old-binding rejection,
physical removal, clean consolidated regression, or C1/P2 acceptance is
established. See [Trials 64 to 65](experiments/2026-10-18-participant-c1a-followup.md#trials-64-and-65-native-binding-component-fixture-and-rerun)
and [restart run 4](experiments/2026-10-18-participant-two-device-parity.md#physical-restart-run-4-generation-two-listener-setup-failed).

**Native restart-owner component rerun, 2026-10-18:** Trial 66 retained one
failure and five fixture errors in its 311-test required Linux gate; Trial 67
passed all 311 required IDs with zero skips. The corrected fixtures preserve
strict production validation. Trial 68 then passed 311 required tests with zero
skips in 35.658 seconds of unittest runtime, with 298 pinned source files and a
matching ZimaBlade overlay. These are component results, not a physical Remove
profile or accepted restart. See the [component evidence](experiments/2026-10-18-participant-c1a-followup.md#trial-68-current-required-component-gate).

The frozen Trial 67 `RST5-diag1` command at 19:44 UTC was an actual on-host
diagnostic and observed the secondary `cohort_result:restart_binding`
rejection at `secure_cohort_supervisor.py:2411` (diagnostic result SHA-256
`6d0e578c5e26ca25599b8b04d1718879c9daa6633444f4b7524ef41fd9b0d797`, log
SHA-256 `d79351b8728371fea15f43cf350b7f5eac65ab7601a86cb9a3c713cb52e5733a`).
A separate offline copy-only analysis later identified the upstream mismatch:
a 20-field held-status observation versus the strict 11-field result projection.
It does not explain the original RST5 failure. Physical RST6 then failed during the
old cohort's first baseline with `RemoteError`, before the held-status
projection or generation-two startup; its version-1 record had no error code.
The old remote exited 0 and its job was removed, while the local operator exited
143. No clock cause is inferred. See the [RST5/RST6 evidence](experiments/2026-10-18-participant-two-device-parity.md#trial-67-on-host-diagnostic-and-separate-offline-analysis). Physical restart, drain/removal, current full regression, and C1a/C1b/C1/P2 acceptance remain open.

**Consolidated Trial 69, 2026-10-18:** The required Linux gate completed 825
tests with zero skips and one failure in 367.458 seconds of unittest runtime,
exit 1, with both required opt-ins enabled. The sole failure was the fenced
cancellation child: it exited 1 on `CLOCK_UNSAFE: clock moved backwards`
during baseline generation, before the cancellation hook; teardown was
unconfirmed and one capture reservation remained. The environment cause is
unknown, and this does not diagnose RST6 or earlier full-gate failures. The run
used the 298-file Trial 68 pre-owner source and its recorded image; the final
integrated owner-profile full regression remains required. See the [Trial 69
record](experiments/2026-10-18-participant-c1a-followup.md#trial-69-consolidated-required-linux-gate)
for exact identities. Restart, owner drain/removal, and C1a/C1b/C1/P2 acceptance
remain open.

**Trial 70 owner-flow gate, 2026-10-18:** 357 required tests ran with zero skips,
one failure and one error in 36.306 seconds, exit 1. The full-Remove controller
fixture used a loopback endpoint which actual `run_supervisor` refused before
READY; a separate producer final-STOP fixture had `listener_slots=0` below its
configured minimum of one. Parent corrected both test fixtures without
production changes. Trial 71 then reached a successful controlled Remove
result but its final assertion errored on dictionary material records; the
negative variants did not run. Trial 72 passed 357 required tests with zero
skips after the test fix. The controlled flows use mocked I/O and synthetic
baseline vectors, so they add no physical or numerical evidence. The matching
Trial 72 overlay then verified all 300 source files, preserved the 14-layer
base, and left runtime and dependencies unchanged; it exited 0 with no cleanup
errors. Physical RST7 has since passed its bounded restart checks: both old and
new baselines completed four requests/27 vectors, stale bindings were rejected,
and all local/remote processes exited 0 with confirmed cleanup. Drain run 1 then
failed before remote launch because the frozen local launcher lacked the source
`src` import path; the supervisor reported `ModuleNotFoundError`, while the
operator exited 143 and its container was removed. This is a harness setup
failure, not drain lifecycle evidence. Drain 2 and Remove 2 were not yet
prepared or run. See [Trials 70 to 72 and RST7/Drain1](experiments/2026-10-18-participant-c1a-followup.md#physical-restart-run-7-and-drain-run-1)
for the retained records. Physical drain/removal, the integrated qualifying
gate, and C1a/C1b/C1/P2 acceptance remain open.

**Physical Drain 2, 2026-10-18:** the corrected host launcher reached the remote
worker, but the run failed validation of its first owner-action response. A
protected read-only check of the retained command and ACK confirmed the worker
accepted Drain; the supervisor had published 281 bytes including a trailing
newline, while the command identity and response validator required the 280-byte
canonical document. The file hash matched canonical bytes plus that newline.
This identifies a command-publication defect; the failed run supplies no accepted
drain result. See the [retained Drain 2 evidence](experiments/2026-10-18-participant-two-device-parity.md#physical-drain-run-2-canonical-command-publication-failure).
Physical drain/removal and final integrated validation remain required. The
maintainer requested stopping after C1; subsequent phases will remain pending.

**Trial 73 and physical Drain 3, 2026-10-18:** the canonical-command publication
fix passed 358 required Linux tests with zero skips, including a regression that
derives receipts from actual publisher bytes. Its matching physical-host image
verified all 300 source files. Drain 3 passed command 1 publication/response but
failed the fresh OpenSession native-refusal check; its original native status
was not recorded. A separate real TLS regression on the unchanged old runtime
reproduced PERMISSION_DENIED where the frozen profile requires UNAUTHENTICATED.
The narrow drain-admission mapping correction still requires fresh validation.
See the [Trial 73 and Drain 3 record](experiments/2026-10-18-participant-c1a-followup.md#trial-73-and-retained-physical-drain-3).
Physical drain/removal, final-source CPU controls, full security discovery, and
C1 acceptance remain open. Work will stop after C1 at the maintainer's request.

**C1 final status, 2026-10-18:** C1 remains unaccepted pending a clean full
security regression. Physical RST7, Drain4 and Remove4 passed their bounded
checks and were independently reviewed. The final-source M1/M2 controls and
focused 359-case gate passed. Laptop Trial 76 failed with one failure in 873
required cases; its cause is unknown. Native ZimaBlade run 3 also failed: 873
required cases, zero skips, three root-process errors and 870 passes,
including partial-Open reply loss. No hardware cause is established. Trial 77
failed its mandatory 873-case regression with one baseline-generation error before its interleaving hook
in 372.851 seconds; the generic RPC outcome and unconfirmed teardown leave its
cause unknown. Full-history DIAG3 also failed its 873-case gate: one
cold-cutover READY timeout in 309.379 seconds. The prior Trial 77 target
passed with all seven observer hooks restored and no error events;
this does not explain either full-run failure. One focused baseline case and
five fresh repetitions passed, but do not explain or qualify the full runs.
C1a and C1b, including every C1 checklist item, remain open pending a clean
full regression and review. See the [C1 final validation
record](experiments/2026-10-18-participant-c1.md) for exact evidence,
limitations and retained failures. C2–C9 remain at their prior statuses;
research P0–P8 statuses are unchanged. Work stops after C1 as requested.

**C1 accepted, 2026-10-19:** The parent accepted C1 validation and exit criteria
following Trial 78's rebuilt-candidate software regression: 878 unique required
cases, all passed, zero skips/failures/errors in 367.862 seconds. The laptop
image was `593d1e79b98f85947e5ad759c1aa108a0288cdd045afaa1c97d40f86dee31305`
with frozen 302-file source digest
`ef3b8222941bd6a233a47fae2e0c70dfa0f37cc7a6bdf98dfcbec8e439426d52`. The
bounded physical RST7, Drain4 and Remove4 evidence, M1/M2 controls and focused
359-case gate are recorded with their separate source/image identities in the
[C1 final validation record](experiments/2026-10-18-participant-c1.md). Trial
76, Native ZimaBlade run 3, Trial 77 and full-history DIAG3 failures remain
preserved with unknown causes; Trial 78 does not explain them, and no hardware
cause is established. The full run was on the laptop; it does not replace or
change the separately frozen split-host evidence. C2–C9 and research P0–P8
statuses remain unchanged at that C1 acceptance point. The stop-after-C1
instruction was subsequently superseded when C2 work resumed on 2026-10-19.

**C2 resumed, 2026-10-19:** the maintainer authorized further implementation
after the completed C1 stop point. C1 remains accepted and published at `89ea4b1`.
The [C2 component record](experiments/2026-10-19-participant-c2-components.md)
records component 27's latest complete Docker inventory: 562 unique tests
passed with zero skips/failures/errors in 36.336 seconds, from 415 frozen source
files and a rebuilt image. It supersedes the historical 474-case component-26
inventory. Selected native-9 egress checks passed 42 cases (RPC 8, protobuf
guard 8, SDK 12, egress 14); independent main reviews accepted the bounded RPC
and SDK changes, and component 27 has bounded passing native signed-C1
`WorkerHandler` evidence. This does not establish deployed gateway integration.
Capture-native1 passed seven parser controls with native RSS measured only for
malformed input; valid-data and control high-water deltas were unmeasured. The
selected-cohort validator source review passed and inherited-main native-2
passed 12 tests, but the validator remains inert without local identities,
claims or startup. Earlier
selected probes also include the assigned-artifact pin child handoff and
watchdog-publication fixture reproduction. RPC/SDK/transport integration and
aggregate root-group startup remain incomplete or under review. A separate bounded
ZimaBlade OS probe measured kernel CPU throttling and a role memory-limit OOM
kill, with task cleanup. These are component results, not phase acceptance.
C2.1–C2.6 and its exit gate remain open pending actual daemon/resource
integration, whole-cohort claims and root loading, fixed-role backend and
enrollment integration, the actual dual-listener gateway, shared physical
resource accounting, and the CT-11/CT-13 split-host outbound numerical/lifecycle
gate. C2 is unpublished;
C3 and research gate statuses are unchanged. Work uses the laptop and ZimaBlade;
no additional hardware requirement has been established.

**C2 component update, 2026-10-19:** component 29 rebuilt the bounded full
Docker inventory after the foreign-owner fixture-only correction: 705 unique
tests passed, with zero skips, failures or errors, in 38.605 seconds. The frozen
source snapshot is 432 files (`b35138503cd218d43f37ae024b8c05e82910e64da10ecb6cc06ee74c4503b685`,
head `1b221ff`); the pinned image is
`sha256:44301c3d0a5f06a5ef41e3518bc273486a9c18a47c0b118fc211ef3219722f7b`.
The record retains component 28's two missing-fixture failures and the
fixture-only resolution. Fresh bounded native runs then passed local launch
claim (12), global launch claim (15), coordinator (9), route (14), and startup
seam (57) tests. These are component controls: claim receipts remain inert,
host/coordinator binding does not establish READY, the route ledger is not
physical resource integration, and the startup seam uses fake cgroup limits.
The root-runtime final-lock control also changed from one failure in the old
implementation to one pass in the new implementation. All artifacts remain
private and unpublished. The full details, source snapshots, limitations, and
retained invalid/failed attempts are in the [component record](experiments/2026-10-19-participant-c2-components.md).

C2.1–C2.6 and its exit gate remain open: actual fixed-role enrollment and local
startup, gateway integration, shared physical CPU/RAM/disk/traffic accounting,
and CT-11/CT-13 laptop-to-ZimaBlade routed session/lifecycle validation remain
unproven. No hardware blocker or GPU/performance result is established.
