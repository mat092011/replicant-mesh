# Multiphase execution plan: participant network

Prepared 2026-10-17 from [PARTICIPANT_NETWORK_PLAN.md](PARTICIPANT_NETWORK_PLAN.md).
**C0 passed on 2026-10-17; C1 validation and exit criteria were accepted on
2026-10-19; C2 implementation is in progress and unaccepted; C3–C9 remain
planned.** See the [C1 final validation
record](experiments/2026-10-18-participant-c1.md) and [C0 validation
record](experiments/2026-10-17-participant-c0.md). Trial 78 passed all 878
unique required software-regression cases with zero skips, failures or errors
in 367.862 seconds on the laptop. Physical RST7, Drain4 and Remove4 passed
bounded checks; Trial 75 M1/M2 controls and focused 359-case validation
also passed. Trial 76, Native ZimaBlade run 3, Trial 77 and full-history DIAG3
failures remain recorded with unknown causes; Trial 78 does not explain them,
and no hardware cause is established. Separate-device evidence retains its own
frozen source and image identities. The AMD 890M GPU backend remains
unvalidated. Work stops after C1 as requested.

This document owns the C0–C9 execution sequence, task checklists and engineering
exit criteria. The [architecture plan](PARTICIPANT_NETWORK_PLAN.md) explains the
design; [PLAN.md](PLAN.md) owns research acceptance and evidence for P0–P8.
[PYTORCH_PIPELINE_PLAN.md](PYTORCH_PIPELINE_PLAN.md) records the implemented M0–M5
runtime. These identifiers are separate: completing a connector phase does not
automatically complete a research phase.

The intended progression is a secure fixed cohort, an installable connector,
measured GPU pipelines, useful pooled memory, recovery, credits and an invited
pilot, followed by conditional federation. Participants can consume inference,
host contiguous model components, or operate an authorized coordinator. Global
membership supplies many suitable routes and replicas; each request uses a
bounded subset of compatible machines.

## Phase overview

C0 is **Passed**; C1 is **Passed**; C2 is **In progress**; C3–C9 are **Planned**. The hardware column describes an exit requirement,
not a reason to stop independent preparation. Responsibility labels are proposed
roles, not assigned people or staffing commitments.

| Phase | Outcome | Completion dependencies | Hardware / external requirement | Lead responsibility | Supports research |
| --- | --- | --- | --- | --- | --- |
| C0 | Agreed contracts and experiment boundaries | Existing baseline reviewed | Hardware access may remain an explicit open dependency | Maintainer / architecture | P0 |
| C1 | Secure fixed cohort with real-device parity | C0; C1a and C1b below | At least two physical devices and an authenticated route | Network / security | P0–P2 |
| C2 | Headless consumer/host/personal-orchestrator connector | C0, C1a; real-route validation | Test participant machine and outbound gateway/route | Connector / platform | P0–P2, groundwork for P5 |
| C3 | One verified GPU backend | C0; C1 for remote gate | Actual supported GPU and remote test access | Runtime / GPU | P1–P3 |
| C4 | Flexible placement and measured real-link envelope | C1–C3; supported topology gates | Separate LAN and internet sites; measured route types | Runtime / research | P2–P3 |
| C5 | Measured useful pooled-memory configuration | C3, C4 | Suitable accelerator cohort, model and local controls | Research / runtime | P4 |
| C6 | Bounded recovery and availability scheduling | C4; C5 continue decision for expansion | Replacement capacity and fault-injection access | Runtime / reliability | P5 |
| C7 | Auditable credits and operator controls | C5, C6 | Trusted ledger/verification operator and resource budget | Accounting / security | P6 |
| C8 | Supported desktop distribution and invited pilot | C2; C5–C7 for pilot | Recruited participants and support ownership | Connector / operations | P7 |
| C9 | Evaluated federation and open-network options | C8 continue decision and adversarial review | Multiple actual trust domains/operators | Architecture / security | P8 |

## Dependencies and parallel work

Use local sub-gates to avoid coupling all engineering work to hardware arrival:

- **C1a** is authenticated transport/admission implementation and local tests;
  **C1b** is its evidence on physically separate devices. Both complete C1.
- **C2a** is local daemon/consumer/lifecycle work after C0; **C2b** adds enrollment
  and outbound serving after C1a. C2 completes only with the real-route checks.
- **C3a** is a local GPU reference and worker gate on confirmed hardware after C0;
  **C3b** is remote numerical/lifecycle validation after C1. Both complete C3.
- **C4a** is explicit manifest/stage generalization, initially testable on CPU;
  **C4b** is measured placement and real-network evaluation after C1–C3.

```mermaid
flowchart TD
    C0[C0: contracts] --> C1a[C1a: local secure transport]
    C1a --> C1b[C1b: separate-device parity]
    C0 --> C2a[C2a: local connector]
    C1a --> C2b[C2b: outbound connector]
    C2a --> C2b
    C0 --> C3a[C3a: local GPU gate]
    C1b --> C3b[C3b: remote GPU gate]
    C3a --> C3b
    C0 --> C4a[C4a: explicit partitions]
    C1b --> C4b[C4b: placement and real links]
    C2b --> C4b
    C3b --> C4b
    C4a --> C4b
    C4b --> C5[C5: useful pooled memory]
    C5 --> C6[C6: measured recovery]
    C6 --> C7[C7: credits]
    C7 --> C8[C8: invited pilot]
    C8 --> C9[C9: conditional federation]
```

The graph shows the principal completion path. C6 protocol/fault-fixture work
may begin after C4, while its expansion gate waits for the C5 decision. C8 UI work
may begin after C2, while the pilot waits for C5–C7. Recruitment, selected existing
CPU experiments and reproducibility work can proceed alongside these tracks.
Direct peer links are an optional measured C4 extension; they are not required
to develop the secure gateway path.

## C0 — Freeze contracts and acceptance boundaries

**Outcome:** implementers know which roles, operations, platforms and evidence the
first connector supports. **Entry:** review the current CPU baseline and the
architecture plan; do not treat existing design prose as an approved contract.

**Tasks**

- [x] **C0.1** Record an architecture decision for consumer, host and orchestrator
  permissions; trusted registry/coordinator/catalog boundaries; and personal
  versus community operator mode. Keep public enrollment and credits out of the
  first runtime slice.
- [x] **C0.2** Specify account, device, boot, request, session, route and operation
  identities; model/runtime/placement compatibility; credential rotation and
  revocation; and a versioned control/inference protocol boundary.
- [x] **C0.3** Specify resource policy and shared local reservations for memory,
  disk, bandwidth, queues, concurrency and deadlines. Define drain, immediate
  stop, removal, unavailable telemetry and unsupported-platform behavior.
- [x] **C0.4** Choose the initial supported platform and secure route approach.
  Record hardware recruitment, gateway ownership and operating budgets as open
  dependencies where unconfirmed; assign responsibility before remote trials.
- [x] **C0.5** Prepare the first fixed-cohort experiment manifest, numerical
  criteria, fault cases and evidence schema. Define fields for later hardware
  values; freeze those values before their associated experiment starts.

**Deliverables:** versioned schemas/configuration examples, architecture decision,
threat model, test matrix and an explicit dependency register. New runnable
commands must be documented only when implemented.

**Exit gate:** review confirms unambiguous permissions, limits and failure
semantics; no unresolved choice prevents local C1a/C2a work. Unconfirmed hardware
and later usability targets remain named dependencies, not assumed facts. The
existing CPU/Petals paths remain the controls.

**Evidence / next:** the [reviewed decision](decisions/0001-participant-contracts.md),
[normative contract and dependency register](PARTICIPANT_CONTRACTS.md),
[versioned declarations](../config/participant/README.md) and
[Docker validation record](experiments/2026-10-17-participant-c0.md) complete C0.
Start isolated C1a and C2a, and CPU C4a preparation. C3a execution awaits supported
GPU access. No security implementation, physical-route, GPU or research gate is
completed by C0; external operator/hardware dependencies remain open.

## C1 — Secure a fixed invited cohort

**Outcome:** the existing fixed pipeline can run across authenticated participants.
**Entry:** C0; at least two real devices are required for C1b, not for C1a.

**Tasks**

- [x] **C1.1 / C1a** Add an explicit TLS peer-authenticated transport profile to
  worker and coordinator services/clients. Preserve isolated insecure-lab
  configuration; never make the private-network flag authorize internet access.
- [x] **C1.2 / C1a** Implement invited enrollment, protected device credentials,
  scoped coordinator permissions, expiry/revocation and identity-bound sessions.
  Session IDs alone must not grant access.
- [x] **C1.3 / C1a** Bound connections, handshakes, admission and malformed payloads.
  Test wrong roots/identities/roles, expired or revoked credentials, stolen session
  IDs, reconnect and loss after possible cache mutation. Retain no automatic
  ambiguous-step retries.
- [x] **C1.4 / C1b** Inventory two or more physical devices and their actual route.
  Freeze model/runtime, public fixtures, resource ceilings and test bounds. The
  fixed three stages may share devices; record exactly where they execute.
- [x] **C1.5 / C1b** Run same-input prefill/forced-decode comparisons, interleaved
  sessions, cancellation, partial admission, restart/boot-ID invalidation and
  bounded cleanup across those devices.

**Deliverables:** secure configuration, enrollment/revocation procedure, local
negative tests and a sanitized separate-device correctness/lifecycle report.

**Exit gate:** C1a rejects every invalid admission case within declared resource
bounds and preserves valid session semantics. C1b passes the frozen numerical and
lifecycle checks on actual separate machines. If hardware is missing, record C1a
independently and leave C1b pending; containers cannot substitute for this gate.

**Evidence / next:** the [C1 final validation record](experiments/2026-10-18-participant-c1.md) records the accepted software regression and bounded physical evidence. C1 is complete; work stops here as requested. C2–C9 remain planned. The AMD 890M backend remains unvalidated.

## C2 — Deliver the headless participant connector

**Outcome:** a participant can consume inference, contribute a supported shard,
and explicitly enable personal orchestration using one controlled application.
**Entry:** C0 for C2a, C1a for secure integration; real routing for final acceptance.

**Tasks**

- [ ] **C2.1 / C2a** Add a CLI/daemon and authenticated local management interface.
  Reuse worker/coordinator supervision. Keep the consumer SDK free of PyTorch and
  model downloads; enable each execution role separately.
- [ ] **C2.2 / C2a** Implement diagnostics, policy, status, start, drain, immediate
  stop and removal. Reserve shared resources across all local roles; report
  unsupported limits and insufficient capacity instead of silently overcommitting.
- [ ] **C2.3 / C2a** Install only approved assigned artifacts; verify identities
  before loading offline. Test corrupt/interrupted downloads, disk exhaustion,
  incompatible versions, hung compute and bounded log/cache growth.
- [ ] **C2.4 / C2b** Connect enrollment, expiring readiness, heartbeat and one
  bounded outbound work stream or tunnel. Define multiplexing, backpressure,
  cancellation and reconnect behavior; registration alone is not a work channel.
- [ ] **C2.5 / C2b** Add consumer submission/stream/cancel and personal coordinator
  startup, with input/output component budgets, worker permission and complete
  route checks. Preserve explicit failure after ambiguous mutation.
- [ ] **C2.6 / C2b** Exercise enrollment through first completed inference on a
  separate supported participant machine, including an outbound-only tested
  route without manual router-port changes. Capture install and stop behavior.

**Deliverables:** proposed `src/steamboat_connector/`, focused connector tests,
supported-platform guide and reproducible install/start/leave procedure. Source
installation can support the first trial; verify binary distribution before
shipping installers in C8.

**Exit gate:** consumer-only mode needs no model runtime; authorized roles work
together without double reservations. Readiness requires checked loaded weights,
healthy compute and available resources. Owner stop controls remain responsive
under hung inference; the real-route lifecycle and numerical checks pass. Secrets
and prompts do not appear in default logs.

**Evidence / next:** record tested OS/runtime/route and unsupported platforms.
Begin C4 integration and optional C8 UI scaffolding; no community pilot yet.

**Implementation resumed, 2026-10-19:** the maintainer authorized continuing C2
after completed C1 publication. The [component record](experiments/2026-10-19-participant-c2-components.md)
records the latest complete 474-case, skip-free Docker inventory, followed by
selected source and native probes. The pinned-artifact child handoff and watchdog
publication fixture passed their bounded probes. RPC ownership, SDK, transport
and aggregate root-group integration remain incomplete or under review; these
follow-ups do not change the full-inventory result. A separate ZimaBlade OS probe
verified task-scoped CPU/RAM enforcement. Actual combined daemon enforcement,
both authenticated gateway hops and the outbound split-host route remain
incomplete; every C2 checkbox remains open and C3 has not advanced.
The [connector design](PARTICIPANT_CONNECTOR_DESIGN.md) freezes the required gates.

## C3 — Validate one GPU execution path

**Outcome:** one explicitly supported GPU/backend/precision combination preserves
the model and session contract. **Entry:** C0 and actual supported GPU access for
C3a; complete C1 for C3b. Do not infer GPU support from inventory alone.

**Tasks**

- [ ] **C3.1 / C3a** Select the cohort/backend and isolate its image/dependency
  lock from CPU and Petals. Pin drivers/runtime compatibility, precision and
  attention implementation; keep architecture/model support narrow.
- [ ] **C3.2 / C3a** Make weight, activation and per-layer KV placement explicit.
  Budget loading peaks, temporary buffers, allocator use and local shared roles.
- [ ] **C3.3 / C3a** Build the complete-model reference on the same GPU stack.
  Establish numerical tolerance from repeated controls before the partition gate;
  test full prefill/forced decode, boundaries, interleaving and cancellation.
- [ ] **C3.4 / C3a** Measure loading/execution peak memory and synchronized GPU
  compute durations. Test changing free memory, OOM rejection and supervisor
  recovery without attributing enqueue time to completed computation.
- [ ] **C3.5 / C3b** Repeat parity/lifecycle checks over the secure physical route
  for the supported configuration. Record device layout and CPU/GPU transfers.

**Deliverables:** isolated GPU environment, supported device/precision contract,
same-stack reference and local/remote numerical and resource reports.

**Exit gate:** finite logits meet the frozen justified tolerance, cache/session
isolation and cleanup pass, and actual memory/timing observations are available.
C3b requires real remote evidence. No speedup or support for other vendors follows
from this gate; multiple processes on one GPU remain one physical resource pool.

**Evidence / next:** attach hardware/backend-specific evidence and proceed to C4.
If no GPU is available, prepare interfaces and fixtures without marking C3 passed.

## C4 — Generalize placement and measure real links

**Outcome:** the system selects complete supported routes from measured capacity
and has a repeatable performance envelope. **Entry:** C0 for CPU C4a design/tests;
complete C1–C3 for C4b integration and GPU real-link evaluation.

**Tasks**

- [ ] **C4.1 / C4a** Separate model/artifact, runtime-compatibility and placement
  identities. Remove fixed three-worker assumptions behind explicit supported
  manifests; validate 1/2/3-stage cases, exact layer coverage and component owners.
  Propagate supported shape, dtype, vocabulary and context contracts into clients
  and wire validation. Replace tiny-model constants only through versioned limits;
  define bounded messages or validated streaming/chunking before larger payloads.
- [ ] **C4.2 / C4a** Preserve an in-process/full-model reference for every supported
  partition. Keep embeddings/head and tied-weight accounting explicit; retain
  the current coordinator placement as a comparison when moving components.
- [ ] **C4.3 / C4b** Add expiring candidate registrations, bounded probes of actual
  route endpoints, measured stage/cache budgets and warm-stage preference. Reserve
  every stage before execution; enforce shared quotas across coordinators.
- [ ] **C4.4 / C4b** Freeze per-tenant queues, active limits and the bounded owner
  share. Test mixed prompt lengths and competing coordinators under saturation.
  Preserve the known non-preemptible-prefill limitation unless chunking passes
  its own numerical/lifecycle gate.
- [ ] **C4.5 / C4b** Execute selected same-host, separate-LAN and real-internet
  comparisons with matching workload/resources. Record direct/relayed reachability,
  route bytes, token feedback, RTT/goodput, failures and actual infrastructure cost.
  Record useful compute overlap separately from overlapping RPCs, with bounded
  cross-host clock uncertainty whenever comparing absolute worker spans.
- [ ] **C4.6 / C4b** Compare supported direct and relayed routes; introduce direct
  worker forwarding only if justified and validated as a distinct topology.
  If a route type cannot be tested, retain that coverage gap and narrow claims.

**Deliverables:** generalized contracts/scheduler, real-route measurement support,
frozen experiment manifests and a report showing latency/capacity tradeoffs.

**Exit gate:** supported partitions and maximum accepted prefill/logit payloads
pass parity; oversized or incompatible messages are rejected before tensor allocation.
Stale/incompatible advertisements are rejected, and concurrent admission cannot
exceed declared shared reservations. Unexpected memory pressure, inaccurate
capacity claims and OOM cause bounded rejection or failure. The preregistered
LAN/internet cases retain successes, failures, fair-service results and resource
measurements. Optional direct forwarding is not required to declare a tested
relayed envelope; incomplete topology coverage remains explicit.

**Evidence / next:** publish continue/revise/stop guidance for the selected model
and routes. A bounded C4 study does not silently close all outstanding P3 coverage.
Select a C5 cohort/model only from the measured feasible region.

## C5 — Demonstrate useful pooled memory

**Outcome:** multiple participant machines enable useful inference for a fixed
configuration unavailable accelerator-resident on any one of them. **Entry:** C3,
C4, a suitable measured cohort and a supported model with reviewed artifact terms.

**Tasks**

- [ ] **C5.1** Select one pinned larger model/precision and implement only its
  necessary adapter/manifest/preparation and client/wire changes. Verify its
  maximum payloads against the C4 contract; the current tiny-model transport
  ceiling cannot be assumed sufficient. Re-run reference and partition correctness,
  including any new chunking/compression, before performance claims.
- [ ] **C5.2** Measure all physical memory pools and loading/execution peaks:
  layers, embeddings/head, tied weights, caches, communication and temporary state.
  Validate assigned fit; do not use synthetic arithmetic as execution evidence.
- [ ] **C5.3** Establish that no participating machine can execute the complete
  configuration accelerator-resident, including supported local multi-GPU
  controls. Record same-model CPU/RAM offloading and its practical limits; when
  a control is infeasible, document why and limit comparative claims.
- [ ] **C5.4** Freeze usability, concurrency, success and resource-cost criteria
  before collecting runs. Retain the provisional research target only if adopted
  explicitly for the actual cohort.
- [ ] **C5.5** Run the selected repeated experiment and controls, retaining failed
  attempts. Account for coordinator, client, relay, verification and standby costs.

**Deliverables:** supported model configuration, measured placement budgets,
correctness report, repeated control comparisons and a research decision.

**Exit gate:** correct completed requests demonstrate cross-machine capacity and
are evaluated against the frozen usability/resource criteria. Loading a model is
insufficient. Report a negative outcome if targets fail; that finishes the study
but does not pass the useful-service gate or authorize automatic expansion.

**Evidence / next:** update P4 only from actual results. Continue into C6 service
expansion after a supported continue decision; otherwise revise model/topology
under a new manifest or stop the current service hypothesis.

## C6 — Handle availability changes and bounded recovery

**Outcome:** worker loss produces a correct bounded recovery or explicit failure.
**Entry:** C4 for protocol/fault work; C5 continue decision for service expansion.

**Tasks**

- [ ] **C6.1** Implement stale-worker removal, bounded drain, replica selection
  and shared admission using measured capacity. Pin healthy sessions to their
  current workers and budget replacement weights/cache reconstruction separately.
- [ ] **C6.2** Define logical request/step identity, attempts, payload identity,
  route epoch, accepted prefix, sampler state and output-event acknowledgement
  before implementing retries. Fence stale results and old coordinator owners.
- [ ] **C6.3** Reconstruct fresh sessions from the prompt and accepted forced
  token history; avoid re-emitting past tokens. Bound attempts, retained history,
  time, bytes and work. Keep fail-and-cleanup as the measured control.
- [ ] **C6.4** Implement indexed client resume with a bounded event buffer and
  explicit resume-unavailable behavior after eviction. Distinguish state
  committed in a worker, output accepted by the coordinator and client delivery.
- [ ] **C6.5** Inject failures before/after admission, cache mutation, replies and
  token delivery; include cancellation, coordinator/relay loss, sleep, OOM,
  revocation, expired replay history and upgrade interruption.
- [ ] **C6.6** Measure recovery tails, spare memory, replay/verification work and
  traffic against the frozen limits. Attempt selective stage/KV reconstruction
  only as a separately justified and validated optimization.

**Deliverables:** versioned recovery semantics, fault fixtures, bounded resume
implementation and a cost/reliability report.

**Exit gate:** the accepted prefix is preserved; no replay advances the same live
cache twice, duplicates logical output or escapes resource/deadline limits.
Unrecoverable cases terminate explicitly and release resources within bounds.
Until durable coordinator ownership/history is implemented, coordinator loss
must fail the request; this phase does not imply transparent coordinator failover.

**Evidence / next:** record covered faults and remaining failure modes. Start C7
only after both useful-service and bounded-recovery gates support continuation.

## C7 — Introduce credits and community operator controls

**Outcome:** accepted normalized work can be exchanged without duplicate charges
or rewards. **Entry:** C5 and C6, plus named trusted accounting/verification roles.

**Tasks**

- [ ] **C7.1** Define calibrated versioned tariffs for supported model components,
  prefill/decode and context; specify verification coverage and its cost.
  Worker-reported time, hardware and token count alone must not authorize rewards.
- [ ] **C7.2** Implement a central balanced ledger with request reservation,
  idempotent acceptance/settlement, unused-budget release and inspectable events.
  Keep normal logical-work keys separate from execution attempts.
- [ ] **C7.3** Specify cancellation, partial failure, accepted upstream work,
  refunds and recovery policies. Record grants, subsidies, verification, fees and
  retirement explicitly; no charge exceeds its authorized reservation.
- [ ] **C7.4** Add approved community coordinator roles, consumer quotas,
  secure ingress, operator diagnostics and dispute/revocation procedures.
  Personal coordinators cannot self-authorize public rewards.
- [ ] **C7.5** Test receipt replay, crash between acceptance and settlement,
  concurrent spending/refunds, collusion, forged work and repeated-account grants.
  Budget stateful trusted recomputation; signatures prove attribution only.

**Deliverables:** proposed ledger module, tariff/policy specification, accounting
invariant tests and trusted operator procedures.

**Exit gate:** all issued/transferred/retired balances reconcile; retries/crashes
cannot duplicate normal rewards or charges; self-dealing cannot create net
credits. Residual malicious-worker/coordinator and identity assumptions are
documented. Measure accounting/audit overhead with the same service controls.

**Evidence / next:** update P6 from accounting and abuse-test evidence, then enable
credits only in the explicitly supported invited pilot scope.

## C8 — Package the desktop experience and run an invited pilot

**Outcome:** recruited people can install, control and benefit from the service.
**Entry:** C2 for UI work; C5–C7 for the pilot, with support and operating budgets.

**Tasks**

- [ ] **C8.1** Build a thin UI over the daemon: role selection, resource policy,
  enrollment, download/readiness progress, current work, traffic, accepted credits
  and clear unavailable/paused states. Keep consumer installation lightweight.
- [ ] **C8.2** Verify signed distribution/update metadata, artifact integrity,
  compatibility, upgrade draining, safe rollback and complete removal. Review
  code/image/model distribution separately on each supported platform.
- [ ] **C8.3** Freeze pilot enrollment, success/latency/recovery, fairness,
  owner-disruption and cost targets; state trust/privacy limits and support routes.
  Use public/synthetic workloads and bounded diagnostics retention.
- [ ] **C8.4** Recruit toward 10–20 invited participants, subject to actual
  availability. Measure clean-install burden, readiness, mixed devices, owner
  requests, sparse demand, busy periods, unavailable peers and credit consumption.
- [ ] **C8.5** Publish completed-work benefit and all material infrastructure,
  verification/recovery and measured energy costs, including failures and
  withdrawals. Record a continue, revise or stop decision.

**Deliverables:** supported installers/UI, update and operator runbooks, declared
pilot protocol, sanitized observations and a participant-benefit report.

**Exit gate:** the recruited cohort and duration are explicit, participant limits
and emergency controls work, and frozen service/resource criteria are evaluated.
A small trial is labeled as such; device registrations or an attractive UI alone
do not pass P7. Expansion requires a supported continue decision.

**Evidence / next:** resolve support, economics and participant-friction findings
before evaluating C9. Keep unsuccessful pilot results and revised hypotheses.

## C9 — Evaluate federation and open-network participation

**Outcome:** determine which control functions can be distributed while retaining
useful, accountable service. **Entry:** C8 continue decision, multiple real
operators/trust domains and an adversarial review.

**Tasks**

- [ ] **C9.1** Define federation trust roots, model identity, quotas, session
  ownership, data retention and cross-domain settlement. Start with bounded
  trusted communities and keep the central ledger if it serves the experiment.
- [ ] **C9.2** Evaluate discovery independently: bounded candidate lists,
  authenticated expiring advertisements, stale/poisoned entries and partitions.
  Re-run the service controls before changing scheduling authority.
- [ ] **C9.3** Evaluate multi-domain scheduling and operator failover only with
  ownership/fencing, capacity and recovery invariants preserved. Report trust
  and costs for gateways, directories, coordinators and ledger separately.
- [ ] **C9.4** Test malicious computation, collusion, identity farming, grant abuse,
  resource exhaustion and compromised coordinators. Quantify verification cost
  and unresolved guarantees before considering unrestricted admission.
- [ ] **C9.5** Publish a separate decision for decentralized discovery, scheduling
  and accounting, with repeatable comparisons and an operating model.

**Deliverables:** federation protocol/decisions, adversarial fixtures, measured
cross-domain report and a named list of remaining trusted services.

**Exit gate:** claims match the functions actually distributed and tested;
performance and accounting remain within the frozen criteria. A valid outcome is
to retain federation/invited admission. This phase never implies automatic proof
of correct permissionless compute, private activations or decentralized credits.

**Evidence / next:** update only the supported P8 findings. Any wider enrollment
is a new explicit deployment decision with its own scope and acceptance record.

## Evidence and phase completion rules

Each phase must retain a compact completion record containing:

| Field | Required content |
| --- | --- |
| Status | Planned, in progress, awaiting dependency, passed, or study concluded with revise/stop decision |
| Scope | Phase/sub-gate, task IDs, supported configurations and deferred work |
| Identity | Commit/image, runtime/dependency lock, model/tokenizer revision, precision, attention and compression |
| Environment | Actual physical device layout, unique memory pools, resource ceilings, route and trust roles |
| Protocol | Frozen workload, numerical tolerances, targets, repetitions, fault cases and timing boundaries |
| Execution | Exact commands actually run, outcomes, failures/skips and links to sanitized reports |
| Decision | Passed criteria, failed/missing criteria, continue/revise/stop rationale and prerequisites unlocked |
| Ownership | Responsible implementer/reviewer and unresolved external dependencies |

Use `docs/decisions/` for approved designs and `docs/experiments/` for executed
evidence, without creating placeholder reports that resemble measured outcomes.
Update task checkboxes when their work is verified. Update phase status here and
the relevant evidence links in [PLAN.md](PLAN.md) only when supported; all earlier
partial research coverage remains visible.

For performance studies, preserve three repetitions targeting at least 100
completions within 200 attempts per repetition, with failed/underfilled runs
retained. Freeze any changed protocol before execution. Use same-stack
complete-model/replica controls when the model fits and same-model offloading
when it does not. Report client p50/p95 first-token and inter-token latency,
aggregate completed-output throughput, failures/retries, peak memory, bytes,
startup, prefill, decode, recovery and verification separately. Count generated
output once. Use monotonic client timing and synchronized GPU timing; cross-host
timestamp subtraction requires measured synchronization uncertainty.

The inherited larger-model usability target remains **provisional**: 1,024 prompt
tokens, 64 output tokens, one active session, median decode rate at least 5 output
tokens/s and p95 first-token latency at most 5 seconds. Adopt or revise it before
C5 measurement. Set concurrency, reliability, recovery and cost targets before
their respective experiments; documentation does not turn these into guarantees.

## Immediate implementation queue

This queue proposes reviewable changes; it does not create issues or start their
implementation. Each item should land with its relevant checks and documentation.

| Order | Change | Dependency | Completion evidence |
| --- | --- | --- | --- |
| 1 | C0 contracts: identities, roles, policy, trust boundaries and local test matrix | Current baseline | Reviewed decision/schema and explicit dependency register |
| 2A | C1a secure worker/coordinator transport and admission | C0 | Negative auth tests, bounded valid lifecycle and unchanged private-lab control |
| 2B | C2a local daemon, consumer client, resource policy and stop controls | C0; can run beside 2A | Local supervision/limits/IPC tests with real and fake workers |
| 2C | C3a GPU reference and C4a explicit-stage design | C0; confirmed GPU for GPU execution | Separate scoped changes; actual GPU evidence or clearly labeled CPU contract results |
| 3 | C2b enrollment and outbound work channel | C1a, C2a | Flow-control, disconnect, revocation and end-to-end route evidence |
| 4 | C1b/C3b fixed-device parity and GPU remote validation | Respective local gates plus real hardware | Sanitized device inventory, numerical/lifecycle results and coverage limits |
| 5 | C4b bounded placement/real-link comparison | C1–C3, C4a | Frozen selected cases, controls, audit and continue/revise/stop recommendation |

The required full software regression passed on the laptop, and bounded C1b lifecycle checks passed on the laptop and separate ZimaBlade CPU host. C1 was accepted on 2026-10-19; see the [final validation record](experiments/2026-10-18-participant-c1.md). The AMD 890M is physically present, but its supported backend remains unvalidated. Identify additional
hardware and a supported GPU cohort alongside items
1–3. While those later resources are unavailable, implement local contracts,
TLS/admission, connector lifecycle, fake-worker faults and bounded existing CPU
experiments. Leave device gates pending. Do not require completion of every
historical tiny-model sweep to start the connector, or mistake local scaffolding
for a completed public network.
