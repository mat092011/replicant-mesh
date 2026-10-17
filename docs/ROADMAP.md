# Development roadmap

Prepared 2026-10-17. This is a proposed execution order, not completed work or a
calendar commitment. [PLAN.md](PLAN.md) remains the authority for P0–P8 research
acceptance criteria; [PYTORCH_PIPELINE_PLAN.md](PYTORCH_PIPELINE_PLAN.md) records
the implemented M0–M5 runtime. Do not rename those milestones or advance phase
status without measured evidence.

For the detailed participant application and worldwide network design, see
[PARTICIPANT_NETWORK_PLAN.md](PARTICIPANT_NETWORK_PLAN.md). It specifies consumer,
shard-host and orchestrator roles, secure connectivity, resource policy, protocol
changes, placement, recovery, credits and reviewable implementation packages.
The [multiphase execution plan](PARTICIPANT_NETWORK_PHASES.md) expands C0–C9 into
task checklists, dependencies, local/device sub-gates and completion evidence.
Those phases supplement this work order and do not advance research status.

## Starting point and constraints

- M0–M5, selected P3 repetitions and matched complete-model controls are recorded.
  Replicas were faster for the tiny model under matched configured resource
  ceilings. No pooled-memory or pipeline efficiency benefit is established.
- Only the maintainer's laptop is available. Current inference is CPU float32;
  hardware inventory does not establish usable GPU capacity. Access to other
  devices and an independent reproducer are open dependencies.
- The runtime supports one pinned tiny Llama model, fixed assignments, trusted
  private RPC and bounded failure termination. GPUs, authenticated peers, replay
  recovery, credits and public operation need new implementation and evidence.

## 1. Prepare the source preview

**Deliverables:** finish the [release checklist](OPEN_SOURCE_RELEASE.md), including
ownership/third-party review, secret/history review, clean reproduction, CI and
an actual private security-reporting route. Apache-2.0 is selected for project
code/docs; third-party terms remain separate.

**Acceptance:** the reviewed commit passes documented checks, contains no model
weights/caches/private traces, and has a compact clean-start evidence record.
README commands work in that recorded environment. Source publication requires
maintainer authorization and does not authorize a hosted inference service or
binary/model distribution.

**Implementation update, 2026-10-17:** source/manual-runtime CI definitions,
pinned secret scanning, installed license/OS inventories, tokenizer provenance,
ownership attestation and a clean local-clone runtime reproduction are recorded
in the [release validation report](experiments/2026-10-17-release-readiness.md).
The subsequent [publication record](experiments/2026-10-17-publication.md) tracks
the maintainer-authorized public source repository, hosted CI and enabled/verified
GitHub private reporting. No public inference service or versioned release tag
is part of this source preview. Keep each change reviewable.

## 2. Strengthen reproducibility and the CPU baseline (P0–P3)

**Deliverables:** obtain an independent reproduction if a collaborator is
available; expand selected CPU measurements toward the existing frozen matrix.
Use the duration estimator and auditor to choose a bounded subset before running
it. Measure prompt lengths 128/1,024, 64 output tokens, concurrency 1/3/8,
independent delay/rate cases and selected combinations as resources permit.
Retain complete-model local and matched-replica controls where the model fits.

**Acceptance:** numerical/lifecycle gates pass first; each selected configuration
has three repetitions targeting at least 100 completions within 200 attempts,
with failures/underfilled runs retained. Record actual RTT/goodput, runtime/image
identity, resource ceilings, run order and verified final network reset. Report
per-user TTFT/inter-token distributions and aggregate completed-output throughput.
Keep the uncollected matrix explicit; a selected subset does not complete P3.

**Decision:** use the measured bottlenecks to select the next experiment. If
networking dominates, preregister fewer stages, different placement or a revised
workload as a new comparison. Do not silently change topology mid-series.

## 3. Enable trusted separate-device experiments (P0–P2)

**Dependency:** obtain actual participating devices and permission to use their
resources. Complete model/precision/workload selection and acceptance targets
before measurement. CPU tests can validate device separation before GPU support.

**Deliverables:** transport authentication and encryption, authenticated worker
admission, pinned compatibility identities, bounded connection/admission behavior,
and explicit deployment/configuration for a fixed invited cohort. Keep the
trusted coordinator. Test rejection of unknown workers and identity mismatches,
disconnects, restarted boot IDs, timeouts and cleanup over the real route.
Document direct/relayed connectivity without exposing current insecure listeners.

**Acceptance:** run identical-token prefill/forced-decode comparisons and
interleaved session/cancellation checks across physically separate devices.
Publish a sanitized device/network inventory and trust model. Do not compare
worker clocks without bounded alignment uncertainty. Worker owners can observe
computation even when links are encrypted; use public/synthetic inputs.

**Availability fallback:** if no second device is available, continue CPU
reproducibility and offline transport tests. Mark the separate-device gate
blocked by hardware access; never substitute containers as completion evidence.

## 4. Add one GPU execution path and measure real links (P1–P3)

**Deliverables:** select a supported hardware/backend cohort from inventory;
create an isolated GPU dependency lock and same-stack complete-model reference.
Add explicit device placement for weights, activations and per-layer KV caches.
Validate the pinned tiny model before extending model/precision support. Preserve
the CPU and historical Petals controls as separate recorded configurations.

**Acceptance:** repeated finite-logit comparisons justify the frozen numerical
tolerance on the selected precision/backend; caches remain isolated and cleanup
is bounded. Measure loading and execution peaks, synchronized GPU compute time,
client TTFT/inter-token latency and output throughput. Re-run lifecycle faults.
Test distinct devices on LAN, then real internet links with known relay costs.
Keep measured real links separate from shaped-network simulations.

**Decision:** proceed toward a larger model only after the report establishes a
repeatable operating envelope for the selected device/link configuration.
Do not infer speedup from multiple processes sharing a GPU or higher concurrency.

## 5. Demonstrate useful pooled memory (P4)

**Dependency:** measured participating GPU capacities, a compatible larger model,
and a supported execution path. Changing the model may require manifest,
preparation and adapter work; the arithmetic planner alone does not enable it.

**Deliverables:** choose a pinned model/precision that cannot remain GPU-resident
on any one participant but fits across the group. Budget embeddings/head/tied
weights, stage weights, caches, temporary buffers, loading peaks and token
feedback. Freeze usability/resource criteria, then compare the same model with
CPU/RAM offloading where feasible. A smaller model is a separate quality control.

**Acceptance:** distributed execution passes correctness and produces useful
completed requests within the frozen criteria. Report per-user responsiveness,
memory peaks, bytes transferred, failures, recovery/infrastructure costs and
energy only when actually measured. Starting the model or passing budget
arithmetic does not complete P4.

**Decision:** continue, revise or stop the pooled-memory hypothesis from the
measured outcome. A negative result is publishable research evidence.

## 6. Adapt to availability and implement bounded recovery (P5)

**Deliverables:** placement from measured stage time, free memory and network
performance; warm-stage preference, explicit replication budgets and a chosen
recovery method. Define job/step identity and payload checks before adding any
retry or replay behavior. Record scheduler/topology changes as new variables.

**Acceptance:** injected failures during prefill/decode preserve the accepted
output prefix, never duplicate emitted tokens/cache advancement, and produce
bounded errors or measured recovery. Include cache reconstruction, extra memory,
verification and recovery time in comparisons. Current fail-and-cleanup semantics
remain the control until this gate passes.

## 7. Test credits, an invited pilot, then decentralization (P6–P8)

**Deliverables:** first a trusted central ledger for accepted normalized work,
with versioned tariffs, budget reservation, idempotent settlement and explicit
grants/fees/recovery costs. Then, subject to recruited hardware, an invited pilot
with participant resource limits and stop controls. Assess decentralized
discovery, scheduling and accounting as distinct later changes.

**Acceptance:** replay/retry cannot duplicate rewards or charges; ledger entries
reconcile and abuse tests state remaining trust assumptions. The pilot measures
reliability, user benefit, installation burden and resource cost after verification
and relay overhead. Expand only from a documented continue/revise/stop decision.
Spot checks and signed receipts are limited checks, not proof against collusion.

## Immediate planning board

| Priority | Work item | Completion evidence |
| --- | --- | --- |
| Now | Review the local release evidence and remaining distribution boundaries | Inventories, ownership attestation, secret scan and reproduction report |
| Publication follow-up | Review hosted CI, private reporting and retained test intermittency | [Publication evidence](experiments/2026-10-17-publication.md) and verified repository setting |
| Next | Specify connector identities, roles, resource policy and secure fixed-cohort transport | [Connector C0–C2 phases](PARTICIPANT_NETWORK_PHASES.md) and local admission/lifecycle checks; device evidence remains a separate gate |
| Next | Select a bounded remaining CPU experiment subset | Frozen plan, duration estimate, audit and report |
| Next | Recruit/inventory a second device and choose an initial GPU cohort | Confirmed access and measured hardware/network inventory |
| After access | Secure transport/admission and separate-device parity | Negative admission tests and numerical/lifecycle report |
| After parity | GPU reference/worker support, real-link measurements, P4 candidate | Frozen configurations and measured execution evidence |

Assign owners and dates only when collaborators and hardware are confirmed.
Keep progress/evidence links in [PLAN.md](PLAN.md); this roadmap sets work order
without treating an implementation task as a completed research result.
