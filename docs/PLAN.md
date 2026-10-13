# Multiphase research and implementation plan

## Objective and current status

Test whether internet-connected consumer devices can pool memory and compute to
serve useful LLM inference, then test whether reciprocal credits can sustain that
network. Contributors would earn credits for accepted work and spend them on
their own requests.

**Status, 2026-10-13:** planning documents exist. No inference implementation,
hardware inventory, benchmark results, or credit system exists yet. All technical
phases below are pending. Targets are proposals, not measured performance.

The first intended deployment uses invited GPU-equipped desktops and one fixed
model. Device count, GPU types, available memory, and internet connections still
need to be inventoried. CPU processes can establish correctness; hardware support
beyond the initial cohort should follow measured results.

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

Start with a trusted control service, fixed assignments, and authenticated worker
connections. Prefer an existing private Petals deployment as the first baseline.
Confirm its runtime/model compatibility before fixing the stack. Introduce a
custom worker implementation only for a documented experimental need or learning
objective. Do not assume that any pretrained model works with every runtime.

## Phase overview

| Phase | Outcome | Dependency | Status |
| --- | --- | --- | --- |
| P0 | Fixed protocol, hardware inventory, and acceptance targets | None | Pending |
| P1 | Reproducible complete-model reference | P0 | Pending |
| P2 | Correct fixed pipeline across processes and devices | P1 | Pending |
| P3 | Measured LAN and WAN performance envelope | P2 | Pending |
| P4 | Demonstrated pooled-memory benefit | P3 | Pending |
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
  `bigscience/bloom-560m`, with 24 transformer blocks, is an initial candidate.
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

- For the 24-block candidate, start with ranges `[0, 8)`, `[8, 16)`, `[16, 24)`.
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

Create these areas as implementation requires them; only this plan and the root
documentation exist today:

- `src/`: worker, client, protocol, and scheduling code added for the experiments.
- `tests/`: correctness, session isolation, failure handling, and accounting tests.
- `benchmarks/`: launch manifests, workload fixtures, runners, and metric collection.
- `docs/experiments/`: dated reports with configuration, results, limitations, and
  reproduction commands.
- `docs/decisions/`: decisions about runtime, topology, trust, recovery, and credits.

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
