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
[tooling validation record](experiments/2026-10-16-research-tooling.md). Only this
laptop is currently available; pooled-GPU and separate-device evidence remains pending.

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

**Project rename, 2026-10-24:** the source project is now **Replicant Mesh**,
with repository `mat092011/replicant-mesh`, Python package `replicant_mesh`,
environment prefix `REPLICANT_MESH_` and RPC namespace `replicant.mesh.v1`.
The [migration guide](RENAMING.md) covers coordinated upgrades and fresh Compose
volumes. Historical experiment identities remain preserved. Research phase
statuses and measured performance claims are unchanged by the rename.
The maintainer completed the hosting rename; the new repository name was verified
against stable GitHub repository ID `1416538470`. The follow-up
[CI repair record](experiments/2026-10-24-ci-secret-scan.md) explains the exact
synthetic-marker exceptions needed when scanning all branch histories.

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
| P2 | Correct fixed pipeline across processes and devices | P1 | PyTorch M4 concurrent remote parity, lifecycle and same-host compute-overlap traces passed; separate devices pending |
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
