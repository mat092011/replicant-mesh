# C0 decision: participant contracts for the first secure slice

Date: 2026-10-17. Scope: C0 design only. Contract revision: 1.

This records the parent-selected final v1 engineering choices implementers must
follow for C1a and C2a, reconciled before any trial or phase acceptance. No new
human design approval is required. It does not record security implementation,
appointment of deployment operators, executed acceptance tests, or a phase
passing. C1b and all real-route, GPU, recovery, credit and pilot gates remain
separate. The parent/maintainer owns integration, acceptance and status in
[the C0–C9 phases](../PARTICIPANT_NETWORK_PHASES.md) and
[the P0–P8 research plan](../PLAN.md); neither is changed here. M0–M5 identify the
existing owned-runtime milestones, not participant-network completion.

## Context

Read [the participant architecture](../PARTICIPANT_NETWORK_PLAN.md),
[the runtime plan](../PYTORCH_PIPELINE_PLAN.md),
[the CPU runtime](../PYTORCH_RUNTIME.md),
[the worker protocol](../PYTORCH_PROTOCOL.md),
[the worker services](../PYTORCH_WORKERS.md),
[the coordinator](../PYTORCH_COORDINATOR.md), and
[the private lab](../PYTORCH_LAB.md) together. They establish a bounded CPU
correctness baseline, not authenticated internet service. The existing gRPC lab
is plaintext and unauthenticated; its private-network opt-in is not admission.
It must remain isolated, with no public ports or untrusted-network exposure.

The first connector needs exact permissions, ownership, limits and failure
semantics before transport or daemon work starts. Reconnection must not silently
turn the current fail-and-cleanup runtime into a retry/recovery system. Only the
local laptop is confirmed. People, second machines, GPU access, real routes and
operating budgets cannot be assumed from design prose.

## Decision

The normative details, constants and acceptance matrix are in
[PARTICIPANT_CONTRACTS.md](../PARTICIPANT_CONTRACTS.md). The following choices are
fixed for revision 1, rather than alternatives left to C1a/C2a implementers.

| Area | Selected contract |
| --- | --- |
| Roles | Consumer, host and personal coordinator are independently opt-in; all are off on install and after removal. Consumer-only, host-only and coordinator-only declarations are valid; a consumer need not share a daemon with its coordinator. Local host/coordinator declarations match the daemon's stable account/device, never its boot. Personal coordination serves only the same account and explicitly authorizing workers. Community operation, public enrollment and ledger privileges are denied. |
| Trust | A trusted admission/registry authority admits accounts/devices and grants bounded scopes. A separately pinned trusted catalog authority approves artifact manifests. Coordinators are trusted with prompts, output order and route ownership; host owners can inspect computation. Operators are named human responsibilities, not a remotely invocable superuser role. |
| First execution target | Linux amd64, the existing pinned CPython/PyTorch CPU environment, float32/eager, unpadded batch one, no lossy compression/quantization, and the exact tiny-model/tokenizer revision. Native Windows, AMD GPU, CUDA, Apple Silicon and other backends are unsupported. The Windows workstation's verified execution route is its Linux CPU container path; WSL CPU use requires that same tested environment, not an inference of native or GPU support. |
| Fixed transport | gRPC mTLS, TLS 1.2 or newer. The client offline-verifies the configured expected leaf against the pinned cohort CA, expected SAN/EKU/role/device/hash/validity, then uses that exact leaf as trust on the actual channel while retaining hostname validation. No target override or separate TOCTOU probe. Both endpoints authorize each operation. Rotation drains before replacing the pin/channel. C1a must test pin rejection/enforcement; a parent feasibility probe is not a security gate. |
| Credential lifetime | Separate role keys/certificates; maximum 900-second leaves, renewal 300 seconds before expiry, no expiry grace. Snapshot maximum lifetime, refresh and expiry check are distinct 300/30/5-second settings. Rotation drains old bindings, advances the affected role credential/admission epoch and uses fresh IDs. Every fresh request/route/session has `route_epoch=1`; no session survives rotation. |
| Identity | Typed IDs `acct_`, `dev_`, `req_`, `ses_`, `route_`, `op_` and `asg_` plus 32 random lowercase hex characters; process boots are distinct raw 32-character lowercase hex IDs compatible with worker UUID.hex. Attempt is always 1. `route_epoch=1` is immutable per request; credential/admission epoch is separate. IDs/leases alone confer no authority. |
| Protocol separation | Participant contract, control, inference payload and authenticated binding have separate version checks. Keep inference payload version 1; secure binding version 1 uses the normative `steamboat-binding-bin` carrier with a per-stage `assignment_id`. A synthetic `SessionOperation` declaration is not that wire envelope or proof of authorization. |
| Transport bounds | TLS listener maximum 16 total connections including pending handshakes, two per admitted peer, four pending handshakes and five-second handshake timeout; Unix management sockets are excluded. RPCs/streams have their separate existing ceilings. C1a must test installed C-core enforcement, not infer it from configured argument names. |
| Local management | C2a uses Linux AF_UNIX, same UID plus a per-daemon-boot secret, private directory/socket and at most four management connections, never loopback TCP. This narrows the architecture's proposed management API; no browser or remote management listener is added. |
| Local resources | One daemon accounts for every local role/process in each physical resource pool. Explicit owner budgets and enforceable mechanisms are required before enabling execution. An enabled policy requiring unavailable/stale telemetry fails closed for the affected execution roles. No GPU isolation, temperature, power or idle detection is invented. |
| Logit capture | Wire capture is last-position only, with maximum JSON event budget `vocabulary * 32 + 4096` bytes under the unchanged 1 MiB ceiling. Coordinator reservations include worst-case capture buffering across active sessions, output queues and in-flight representations. Full-prefill logits remain in-process controls, never a wire-capture payload. |
| Lifecycle | Drain rejects new work and completes existing work only until a bounded deadline; Stop now invalidates queued/live work immediately but retains unsafe memory until compute exits or is killed. Remove first disables local roles, then revokes the device and offers bounded artifact deletion. Lost mutating replies fail the request; no transparent reconnect, replay or coordinator failover. |
| Outbound route | C2b will use a bounded worker-initiated bidirectional work stream through a trusted transport-terminating gateway. Each hop uses mTLS; the gateway can read traffic and must enforce delegated identities. This is not opaque end-to-end relay encryption and is not implemented by registration or C0. |

### Scope boundaries and invariants

- Keep the fixed `[0,3)`, `[3,6)`, `[6,8)` stages and coordinator-owned
  tokenizer/embedding/norm/head/greedy sampler. Workers retain resident weights
  and their own per-session, per-layer KV state. Token feedback precedes the next
  ordinary decode step. Overlap is between independent requests, not independent
  generation of successive tokens of one answer.
- Preserve the existing 1,152-position, eight-session, 1 MiB payload and bounded
  queue/deadline contracts; lower effective owner/tenant quotas may reject work.
  C0 does not silently generalize model layout, payload size or layer placement.
- A real two-device experiment must execute route stages/coordinator across at
  least two inventoried physical hosts. Listing an unused second host, or moving
  only the thin consumer to it, does not establish that execution gate.
- Attempt is 1 and each v1 request's `route_epoch` is 1. Credential rotation
  drains the affected old bindings and advances the role credential/admission
  epoch; subsequent work has fresh request/route/session IDs, again with
  `route_epoch=1`. Live-route replacement, retries and reconstruction remain C6.
- No automatic mutating RPC retries. A response lost after cache mutation is
  ambiguous, even over authenticated TLS. Cleanup acknowledgement and client
  delivery are different facts. Unknown leases expire; late outputs are fenced.
- Public/synthetic workloads only. Transport encryption does not hide activations,
  tokens or caches from trusted coordinators, gateways or worker owners. Artifact
  hashes, finite tensors, readiness challenges and signatures do not prove
  honest computation or protect against collusion.
- Credits, settlement, recovery, signed installers/updates and federation remain
  later work. A personal coordinator cannot authorize its own public reward.
  Same-host CPU parity and capacity arithmetic do not establish pooled GPU fit,
  useful WAN latency, speedup, energy savings or separate-device performance.

## Considered and rejected for this slice

| Alternative | Reason not selected |
| --- | --- |
| Expose the existing private lab or treat RFC1918/overlay membership as identity | Neither authenticates or authorizes a peer; this would bypass the required secure profile. |
| Bearer session IDs or one shared cohort secret | No device/role attribution, revocation isolation or owner binding. Existing leases remain additional cache-ownership checks, not credentials. |
| Public registration, community coordinators or permissionless execution | No implemented abuse response, audited accounting or malicious-compute guarantees. |
| Pick a hole-punching/opaque relay stack now | Not needed for fixed-peer C1a; would add unverified dependencies and a different trust/traffic model. The first outbound gateway is explicitly trusted. |
| Browser-accessible loopback HTTP management | C2a has no browser requirement; Unix peer credentials and filesystem permissions make the local boundary narrower and testable. |
| Resume/retry after status inspection | Status cannot reconstruct a lost activation or prove client delivery; reconstruction and indexed resume require C6. |
| Equal per-process quotas without a shared physical controller | Multiple roles or workers could reserve the same RAM/accelerator capacity. |
| Implicit support for Windows/AMD/GPU from local CPU tests | Requires different locks, device/backend telemetry and numerical/resource evidence. |

## Consequences and handoff

C1a can implement fixed-peer mTLS, local test admission authority fixtures,
operation authorization/binding, short-lived credentials and negative security
tests without a second machine or public registry. C2a can implement protected
local IPC, a thin consumer, diagnostics, shared policy accounting, supervision and
stop controls with fake workers and the existing CPU interface. Production
enrollment and the outbound gateway are C2b integration, not prerequisites for
local fake authority/worker tests. Secure execution must stay unavailable until
its checks exist; a configuration validator is not enforcement.

The independent configuration/schema contribution is intended under
`config/participant/`, with a standard-library validator. This decision does not
assert that those files or commands already exist. Parent-owned reconciliation
of field spelling, version discriminators, examples and links is in progress.
These parent-selected v1 choices are the integration target, not a request for
another human design approval. The parent will cross-check the independent
schema/code contribution before merging. No new runnable command is defined here.

The [specification's dependency register](../PARTICIPANT_CONTRACTS.md#dependency-register)
names responsible roles and exact access still needed. Real operator/hardware
owners remain unassigned where availability is unknown; DEP-01 is parent-owned
engineering reconciliation in progress. External dependencies can stay pending
without leaving local C1a/C2a design open, but must be resolved before their
associated real-device experiment. Only the parent/maintainer updates phase
evidence and checkboxes after review and actual execution.

## Verification obligations

Implement the [test matrix](../PARTICIPANT_CONTRACTS.md#acceptance-test-matrix)
before claiming the corresponding sub-gate. Retain exact executed commands,
source/image/model pins, successful and failed cases, cleanup observations,
errors/skips and limitations. Keep generated/private records under `.lab/`; only
compact sanitized public/synthetic evidence belongs in committed reports.
Documentation/link/whitespace checks establish document consistency only. This
decision contains no executed security or real-device acceptance result.
