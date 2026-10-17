# Participant contracts, revision 1

Date: 2026-10-17. **Normative C0 specification, not implemented security or a
passed phase.** “Must” specifies future C1a/C2a behavior unless a later phase is
explicitly named. See [the decision](decisions/0001-participant-contracts.md),
[architecture](PARTICIPANT_NETWORK_PLAN.md), and
[execution phases](PARTICIPANT_NETWORK_PHASES.md). [PLAN.md](PLAN.md) owns P0–P8
research evidence; [PYTORCH_PIPELINE_PLAN.md](PYTORCH_PIPELINE_PLAN.md) owns M0–M5
runtime milestones. C0–C9 are different engineering gates. Nothing here changes
their status or completes C1 or later work.

The parent selected the final v1 engineering choices below before any trial or
phase acceptance. Parent-owned schema/code reconciliation is in progress; it
does not require new human design approval. Actual hardware access, operator
appointments and deployment budgets remain unresolved dependencies.

## Baseline and supported envelope

The existing [runtime](PYTORCH_RUNTIME.md), [protocol](PYTORCH_PROTOCOL.md),
[worker](PYTORCH_WORKERS.md), [coordinator](PYTORCH_COORDINATOR.md), and
[lab](PYTORCH_LAB.md) guides describe implemented behavior. Their insecure gRPC
path stays a private, isolated comparison with no public ports. The
private-network flag, container DNS and private IP addresses grant no identity,
authorization or permission to expose the lab to untrusted networks. A secure
profile must be explicit and must never fall back to this path.

| Field | Frozen first-slice value |
| --- | --- |
| Execution platform | Linux amd64, CPython 3.12 in the existing pinned CPU environment |
| Model and tokenizer | `Maykeye/TinyLLama-v0`, revision `298338802ab94432b917bcce11382aa151aee50f` for both |
| Runtime | PyTorch `2.14.1+cpu`, Transformers `5.19.0`, gRPC `1.84.0`, Protobuf `7.36.2`; use the full [CPU hash lock and base-image pin](../docker/pytorch/README.md), not these four versions alone |
| Numerics | CPU float32, eager attention, batch one, no padding, quantization or lossy compression |
| Placement | Three workers own global layers `[0,3)`, `[3,6)`, `[6,8)`; coordinator owns tokenizer, embedding, final norm, output head and greedy sampling |
| Activation contract | Dense contiguous little-endian float32, `[1,T,64]`, layout `batch_sequence_hidden`; exact payload `T * 64 * 4` bytes |
| Artifact verification | Existing preparation hashes, safetensors slices and manifest fingerprint; read-only offline inference, no peer-supplied Python, remote model code, pickle or arbitrary operators |
| Correctness criterion | Finite same-input logits, `atol=1e-3, rtol=0`, against the complete model on the identical locked stack; greedy output checked separately |

Native Windows, AMD/ROCm, CUDA/GPU, Apple Silicon, browser hosting and phones are
unsupported. On the Windows workstation, only execution in the verified Linux CPU
container environment is established. WSL2/container use must preserve and verify
that environment; this is not a claim that bare WSL, native Windows, Windows GPU
passthrough or every container platform was validated. Unsupported backends fail
before artifact installation or role readiness. Consumer-only operation requires
no Torch or weights, but does not expand the verified platform support list.

Weights stay resident and KV state stays with the worker owning each layer.
Communication includes coordinator-relayed activations and token feedback. The
tiny checkpoint puts about 89% of parameters in coordinator input/output
components; host-only budgets cannot stand in for coordinator budgets. Multiple
local processes are not multiple physical memory pools. The complete-model test
reference is additional validation memory/compute, not production capacity.

## Roles and trust boundaries

All three role-enable flags default to false. Enrollment, installation, a daemon
restart, a worker restart or a failed start must not implicitly enable a role.
Explicit owner consent and successful checks are required; an owner may persist
opt-in policy, but restart must recheck credentials, policy, resources and readiness
before advertising. Removal clears that opt-in. Simultaneous roles use one local
resource controller. A remote role never implies permission to change local policy.

| Principal/role | Allowed scope | Explicitly denied |
| --- | --- | --- |
| Consumer | Describe an admitted coordinator's public capabilities; tokenize/submit its own bounded public/synthetic requests; stream/cancel its own requests and see redacted own usage | Worker operations, another account's sessions, capacity advertisements, local host management, coordinator grants, catalog edits or credits |
| Host | Advertise only its device/boot's checked assignment and capacity; execute supported operations authorized for that assignment; report own bounded status | Choose consumer routes, mutate another host's assignment, submit arbitrary code, change owner policy, grant privileges or settle work |
| Personal coordinator | Serve only consumers with the same account ID; inspect authorized fixed workers; reserve all stages; open/renew/step/status/close/cancel only sessions bound to its own coordinator boot and authorized tenant/route | Serve other accounts, use arbitrary peers/URLs, borrow another coordinator's leases, exceed host policy, approve artifacts or public rewards |
| Local owner | Same-UID protected management IPC: inspect own daemon, explicitly enable/disable roles, set policy, drain/stop/remove, approve bounded artifact storage | No remote worker shell or policy bypass on another device; local root is outside this protection boundary |

“Orchestrator” in the architecture means coordinator. Its initial enabled mode is
only **personal**. Community-operator mode is rejected, not a hidden default or
an alias for personal mode. C7 will define its consumer quotas, secure ingress,
incident responsibility and accounting permissions separately.

Validate each role independently. Consumer-only declarations require consumer
credentials and an admitted coordinator target, not local host assignments,
execution artifacts or an enabled local coordinator. Host-only declarations
require their own host credentials, approved assignment and local resource
policy, not local consumer/coordinator roles. Coordinator-only declarations
require coordinator credentials, input/output resources and an authorized
complete route, not a co-enabled consumer/host. Local host and coordinator
processes match the daemon's stable account/device identity only; their process
boots must be distinct from the daemon's boot. Referenced remote peers are not
implicitly enabled local roles.

A consumer need not share a daemon with its coordinator. Its device may differ;
the personal coordinator authorizes the consumer by the same stable account,
never by equality with the daemon or coordinator boot. Consumer ingress defaults
to `127.0.0.1`; a separately configured consumer device needs an explicit approved
fixed-peer mTLS route. Every such listener still enforces mTLS and same-account
scope, not community/public ingress. Host/coordinator worker traffic uses only
the approved fixed route. These inference listeners are distinct from management,
which is always AF_UNIX and never TCP.

| Trusted component/responsibility | Authority and exposure | Limit |
| --- | --- | --- |
| Admission/registry authority | Invites accounts/devices, signs scoped credentials/authorization snapshots, revokes identities, returns fresh admitted candidates | A candidate is not proof of available memory or correct computation; no arbitrary executable assignments or owner-policy override |
| Artifact catalog authority | Approves signed immutable manifests containing revisions, hashes, runtime/tensor compatibility and allowed components | Separate pinned signing root from the admission CA; never accepts an unsigned “latest” replacement or peer-selected download URL |
| Coordinator owner | Trusted with prompts/token IDs, embeddings/head, route reservations, accepted output order and cleanup | Personal scope only; no public settlement authority or durable failover claim |
| Host operator | Controls physical execution, memory and local policy; can inspect weights, activations and KV state | mTLS does not make host computation private or honest |
| Gateway operator, C2b | Terminates both secure hops and sees forwarded payloads/metadata; enforces delegated identities and route limits | Trusted intermediary, not an opaque relay; no permission to originate work outside a delegation |
| Security/operations operator | Holds protected authority keys, maintains revocation and handles incidents within an approved deployment | A human responsibility, not a network-wide remote-admin role; registry/catalog/gateway responsibilities stay distinct even if one person fills them |

Only invited trusted participants and public/synthetic fixtures are permitted.
Consumers must be told that coordinators, worker owners and future terminating
gateways can inspect computations. Activations or local tokenization are not a
privacy guarantee. Signatures establish attribution, not correctness or freedom
from collusion. No ledger, credit balance, reward or permissionless security is
provided by this contract.

## Identity and compatibility

Typed IDs consist of their exact prefix followed by 32 lowercase hex characters
encoding 128 independently cryptographically random bits. Do not substitute
hyphenated UUID text, timestamps, counters or hashes of prompts. Boot IDs are
specifically **raw 32 lowercase hex characters, with no prefix**, compatible with
the existing worker's UUID.hex encoding. Every daemon, worker and coordinator
process generates a distinct fresh boot at start, even on the same device.
The existing session grammar remains 1–64 ASCII letters/digits/underscore/hyphen;
the generated `ses_` IDs fit within it. IDs are opaque, not addresses, secrets or
proof of ownership. Existing random lease-token encoding remains unchanged.

| Identity | Lifetime and binding |
| --- | --- |
| Account ID | `acct_` plus 32 hex; stable admission-authority-issued invited owner/tenant identity, not an email or credential |
| Device ID | `dev_` plus 32 hex; stable enrolled installation bound to one account and protected role keys; re-enrollment after removal creates a new ID |
| Boot ID | Raw 32 lowercase hex; bind worker RPCs to the worker boot and sessions to the exact coordinator boot. Never compare either to the daemon boot to establish personal-mode ownership or adopt a preceding boot's sessions. |
| Credential identity/epoch | Verified certificate serial, role key and positive `credential_epoch`, initially 1; serial/key/epoch rotation invalidates old session bindings after bounded drain and advances the epoch without changing account/device or granting another role |
| Request ID | `req_` plus 32 hex; fresh per consumer submission, owned by authenticated account/device; caller-supplied IDs never establish authorization |
| Session ID and lease | `ses_` plus 32 hex; fresh per request, with the same ID permitted on different workers as in the baseline. Each reservation is namespaced by target worker device/boot, both endpoints' credential identities/epochs, tenant, coordinator device/boot, assignment and route. Each worker lease is an additional secret check. |
| Assignment ID | `asg_` plus 32 hex; authority-approved fixed worker/component mapping, model/manifest and limits; not a grant to load arbitrary artifacts |
| Route ID/epoch | `route_` plus 32 hex; fresh per request and enumerates coordinator boot, worker devices/boots, stage assignment IDs, ranges and component owners. The v1 schema's `route_epoch` const remains 1 for every request/route, including all new routes after rotation; it is immutable and never increments across requests. Credential/admission epoch is separate. No live-route replacement, retry or reconstruction; C6 owns those semantics. |
| Operation ID | `op_` plus 32 hex; fresh per RPC and echoed in its response. Step also checks session/lease, sequence and absolute position. Close/cancel repetition uses a fresh operation ID for the same terminal intent. |

Request attempt is exactly **1**, the only allowed attempt; there are no retries.
An ambiguous operation terminates the request;
a later explicit consumer submission gets a new request/route/session identity
and is a new request, not automatic recovery. C6 must version attempts, payload
identity, accepted-prefix history and output replay before changing this rule.
An operation ID is correlation, not a cached-response/exactly-once facility.

Keep three compatibility identities distinct:

- **Model/artifact identity:** pinned model/tokenizer revisions, configuration and
  verified file hashes; no placement changes may weaken these checks.
- **Runtime compatibility:** full dependency/image lock, adapter, CPU float32/eager,
  layout, shape/context/vocabulary and inference version. Compatibility is exact
  allowlist matching in the first slice, not “similar model” negotiation.
- **Placement identity:** assignment/route IDs and exact component owners. The
  current runtime manifest fingerprint also includes resource/placement data;
  retain its exact checks as an additional binding. C4a, not C0, generalizes it.

All eight layers must be covered exactly once in order. Input/output component
capacity and any tied-weight copies are included in the route budget. Fixed
peers and local validated assignments suffice for C1a; registry discovery is not
required to test the security boundary locally.

## Versioned protocol and authenticated binding

Revision 1 fixes four separate discriminators: participant contract version 1,
control protocol version 1, inference payload protocol version 1, and secure
binding version 1. Never infer one from another. Missing, unknown or unsupported
versions/fields are rejected before allocation/admission; there is no automatic
downgrade or mixed-version session. Existing sessions keep their original
versions. Upgrade drains/stops them and rechecks readiness before new admission.

| Plane | Permitted contents | Boundary |
| --- | --- | --- |
| Control | Enrollment/renewal, signed authorization/revocation, checked advertisements/assignments, readiness/heartbeat, drain/status notices | Separate control service namespace and credential scopes; no tensors, arbitrary commands or remote local-policy edits |
| Inference | Existing worker Protobuf methods and bounded coordinator Describe/Tokenize/Generate streams, with secure binding | Keeps strict existing payload parsing; no control message interpreted as Step or a management command |
| Local management | Enumerated status/policy/role/lifecycle/artifact-approval actions | Protected Unix IPC only; no inference credential grants management authority |

C1a must add a mandatory per-RPC secure envelope without claiming that the
current [worker schema](../src/steamboat_runtime/protocol/worker.proto) contains it.
Freeze its transport carrier as the single binary gRPC metadata key
`steamboat-binding-bin`: UTF-8 JSON bytes, at most 4,096 bytes, duplicate/unknown
keys and nonfinite values rejected, no nesting beyond one object. Serialized
outgoing keys are sorted, with no optional whitespace. Total metadata is at most
8 KiB per call, including the binding; it does not enlarge the 1 MiB message cap.
The receiver constructs trusted call context from validated TLS identity and
local authorization, not from untrusted JSON claims. Response initial metadata
echoes the validated binding; token/result bodies retain existing event indices.

The schema's synthetic `SessionOperation` declaration is a static test/config
description, **not** the actual wire envelope, an alternate transport, or an
authorization token. The implementation must construct the following
method-specific carrier from authenticated context and the selected route;
passing declaration validation alone neither emits nor authenticates a call.

| Operation scope | Required semantic binding fields |
| --- | --- |
| Every secure call | `binding_version`, `operation_id`, `account_id`, `device_id`, `role`, `credential_epoch`, `target_device_id`; binding version is 1, actor fields/epoch match the authenticated role certificate and current grant, and target equals the configured peer |
| Consumer Generate | Above plus `request_id`; personal coordinator sets tenant to authenticated account and binds the running coordinator boot/route internally before any worker reservation |
| Worker Describe | Common fields plus expected `worker_boot_id` and `assignment_id` when already known; only this discovery call may omit the boot/assignment before preflight |
| Worker Open | Common fields plus `coordinator_boot_id`, `tenant_account_id`, `request_id`, `session_id`, `route_id`, `route_epoch`, `attempt`, `assignment_id`, `worker_boot_id` |
| Worker session operations | Same complete Open binding, matching the stored owner tuple and existing payload session/boot/lease; Step sequence/start/count remain mandatory payload checks |

| Declaration/route meaning | Explicit mapping into `steamboat-binding-bin` |
| --- | --- |
| Binding version | Always emit integer `binding_version: 1`; neither participant/control version nor inference payload version substitutes for it |
| Actor and operation | Map the declared account/device/role and operation identity to `account_id`, `device_id`, `role`, `operation_id`; match authenticated context, not merely declaration text; emit its verified `credential_epoch` |
| Request/session/route | Worker session calls emit fresh `request_id`, `session_id` and `route_id`, `route_epoch: 1` and `attempt: 1`; every explicit new request after rotation gets new request/route/session IDs and still starts at route epoch 1. Consumer Generate emits its request ID in addition to common fields; Describe has no request/session/route fields. |
| Per-stage assignment IDs | For each worker session call select that stage's `asg_` ID as singular `assignment_id`; validate it against target device/boot and exact component/range. Describe may omit it only during initial discovery as specified above. Do not copy the route's assignment list into the carrier or omit assignment because it existed in a declaration. |
| Process boots | Worker session calls map the coordinator process boot to `coordinator_boot_id` and selected worker boot to `worker_boot_id`, never the daemon boot; Describe uses only its listed known-worker fields; target device maps to `target_device_id` |
| Payload/session consistency | Carrier session/worker boot equal the existing Protobuf fields; lease/sequence/start/count stay in the payload and must also match stored session state |

Method-specific keys not listed for that scope are invalid. All version, epoch
and attempt fields are integers, role is exactly `consumer`, `host` or
`personal_coordinator`, and identifier fields use their exact typed/raw-boot
grammars above. Attempt is 1 and epochs are positive integers. Both endpoints'
certificate serials, role keys and epochs also form the immutable session owner
binding through validated TLS/grant context; peer identity/epoch is not trusted
from a forwarded header. In worker calls the actor must be
`personal_coordinator`; `tenant_account_id` must equal its account in this slice.
The authority grant must allow the exact actor, target, assignment, model and
method. Store that owner tuple at Open and compare it on **every** subsequent
operation, including status/cancel/close. Guessing a session ID and lease is not
sufficient. Never use caller-supplied account/role metadata to impersonate a peer.

Worker Describe needs an admitted scoped peer; it is not an anonymous inventory
endpoint. Consumer Describe/Tokenize have only common binding; they do not grant
worker access. Generate disconnect or deadline can prevent terminal delivery;
that is explicit client failure, not permission to resume the stream. A result
with mismatched actor/target/operation/route/boot/sequence is discarded and fails
the affected request. Sensitive leases and bindings are not echoed to logs.

Unauthenticated/expired peers receive transport `UNAUTHENTICATED`; authenticated
but unauthorized operations receive `PERMISSION_DENIED`. Bound/redact diagnostics
so these errors do not reveal whether another tenant's session exists. Existing
runtime validation/capacity/order errors remain distinct after authorization.
No arbitrary URI, URL, shell command, executable object or model operator is an
accepted peer instruction.

### Last-position logit capture and communication reservations

Wire logit capture is an explicit validation-only option and contains exactly
one vocabulary vector for the last input position of each prefill/decode step.
Do not return full-prefill logits over the coordinator wire API, including for
the maximum accepted prompt. Full-prefill comparisons remain same-stack
in-process controls; wire validation compares last-position vectors and forced
continuations. This does not remove the existing full-prefill numerical controls.

Let `V` be the pinned vocabulary size. Reserve **32 bytes per finite float32
value**, including its JSON representation/separator, plus **4,096 bytes for the
token-event envelope**: `L = V * 32 + 4096`. Require `L <= 1,048,576` before
admitting capture, and still check the actual serialized message against that
unchanged 1 MiB ceiling. The tiny model's `V = 32000` gives `L = 1,028,096` bytes.
Reject oversized/nonfinite output explicitly; do not silently truncate vectors,
enlarge the ceiling or reinterpret the budget as four binary bytes per value.

Coordinator communication reservations must include all active capture sessions
and their full output queues, not one vector or one request. With `A` active
capture sessions and `Q` output slots per session, reserve at least `A * Q * L`
for queued capture events: eight sessions and 16 slots require 131,596,288 bytes
of serialized-event budget alone. Bound producer/write work to at most two
additional event slots per active session and include them: `A * (Q + 2) * L`
is 148,045,824 bytes at those maxima. Add explicit headroom for simultaneously
retained raw float32 tensors, Python objects, encoding copies and transport
buffers; serialized-event arithmetic is not a measured Python/RSS bound. Retain
these reservations until all referenced buffers are reclaimed, even after a
disconnect. If the implementation cannot bound its representations or reserve
the resulting shared physical budget, reject capture admission. No extra queue
or active session is authorized by this reservation calculation.

## Fixed-peer transport and credential lifecycle

### C1a selected transport

Use gRPC mTLS, TLS 1.2 or newer, private cohort CA roots pinned by the owner,
ECDSA P-256/SHA-256 authority and leaf certificates, and a distinct protected
private key per device role. Workers present host certificates; personal
coordinators present personal-coordinator certificates; consumers present
consumer certificates. Each leaf has client/server EKU only as needed for its
enabled listener/caller duties. An unauthorized EKU or role is rejected.

Each certificate carries exactly one identity URI SAN of the form
`urn:steamboat:participant:v1:<account_id>:<device_id>:<role>`; DNS/IP server SANs
additionally match the fixed target. Check chain, validity, SAN, EKU, enrolled key,
credential serial and current grant; do not trust CN, IP origin or a client
metadata header as identity. Connect only to owner-configured allowlisted
endpoints and expected device IDs. DNS resolution must remain within that
endpoint's configured address allowlist. No arbitrary peer-supplied redirects,
probe destinations, `skip_verify`, target-name override or insecure fallback.

For the fixed cohort, the client loads the owner-approved expected server leaf
certificate and SHA-256 pin from the signed/pinned catalog. Offline, before
opening any channel, it verifies that exact leaf against the pinned cohort CA,
validity, expected DNS/IP SAN, role/device URI SAN, EKU, enrolled key and serial,
and the configured leaf hash. It then supplies only that expected leaf as
`ssl_channel_credentials(root_certificates=expected_server_leaf_pem, ...)` on
the actual gRPC channel. Ordinary hostname validation remains enabled; there is
no target-name override, CA-wide interchangeable server trust, or separate
preflight TLS connection that could introduce a TOCTOU gap. Server-side admission
still checks the actual TLS client certificate against current scoped grants.
Rotation drains affected sessions before replacing the leaf pin/channel and
credential epoch. C1a must verify the installed locked-runtime behavior and
negative cases, including a different leaf signed by the same CA for the same
DNS/IP SAN, changed role/device/EKU/serial/hash, expired/not-yet-valid leaves,
wrong CA, and attempted certificates signed by an enrolled leaf key. The local
feasibility probe supports this client choice only; it is not a security gate or
evidence that C1a has been implemented or passed.

At each TLS listener cap total transport connections at 16, including pending
handshakes, with at most four incomplete handshakes and a five-second handshake
timeout. Cap established connections per admitted peer at two. These budgets
exclude local AF_UNIX management sockets, which have their own four-connection
limit. Streams/RPCs are separate from transport connections: multiple streams
may share one HTTP/2 connection. Worker concurrent RPC ceiling remains 32;
coordinator RPC ceiling is 52, of which at most 40 are Generate streams.

Enforce these at the transport boundary, not merely in the tensor handler.
C-core offers `grpc.max_allowed_incoming_connections` and server handshake
timeout controls, including `grpc.server_handshake_timeout_ms`; C1a must test
their actual enforcement in the installed locked runtime, together with pending
handshake and per-peer limits. Merely passing named arguments is not evidence
that a cap is supported/enforced. A missing/unverified mechanism blocks secure
readiness rather than claiming the limits work. Reject excess without an
unbounded wait queue. One admitted peer cannot bypass smaller tenant/owner
queues. Connection probes may make at most three attempts with one- then
two-second backoff within a ten-second total budget; these are Describe/connect
probes only, never mutation retries.

### Enrollment, expiry, revocation and rotation

1. The admission operator explicitly approves account, device public keys and
   role/method/target/assignment scopes. Bootstrap uses pinned authority roots
   and a single-use invitation valid at most ten minutes, bound to that account
   and allowed roles. Secrets enter through protected local IPC/file input, not
   arguments, shell history, environment variables or default logs. C1a may use
   local synthetic authority fixtures; a deployed enrollment service is C2b.
   C1a bootstrap is operator-mediated offline, not an unauthenticated network
   enrollment RPC: the operator allocates the account/device identity, the
   device generates its role keys/CSRs locally, and the operator verifies the
   invitation and public keys before returning signed leaves and an initial
   authorization snapshot through owner-protected files. The daemon verifies
   the pinned roots, identity, scopes and matching local public keys before
   accepting them. C1a renewal uses the same operator/fixture publisher and
   protected-file boundary; C2b may transport that authenticated lifecycle,
   but must not create an anonymous bootstrap exception on inference listeners.
2. Leaf credentials last at most 900 seconds. Begin renewal 300 seconds before
   expiry using possession of the existing device key and a still-valid grant.
   A renewed serial is a credential rotation and follows the drain/fresh-session
   rule in item 7, even when the key is unchanged. Old/new credential material
   may coexist only to prepare the transition before the old `notAfter`, not
   to preserve or overlap live session bindings across rotation. Roles/scope
   cannot expand through renewal; a removed/revoked key cannot renew.
3. Use a separately pinned ECDSA P-256/SHA-256 authorization signing key. Signed
   snapshots carry increasing revision, issue/expiry, revoked serials/device
   IDs, enrolled role keys/credential epochs and exact scoped grants. Snapshot
   maximum lifetime is 300 seconds, refresh interval is 30 seconds, and expiry
   check interval is at most five seconds, additionally checked on each RPC/
   admission. Configuration/schema must distinguish these three timings; none
   substitutes for another. Routine snapshot refresh with unchanged credential
   identity/grants is not credential rotation. C1a's local fixture publisher
   obeys the same signature/expiry rules, not an indefinite policy cache.
4. Reject rollback, bad signatures and freshness outside the bound. Wall time
   determines certificate/snapshot validity; require clock uncertainty at most
   30 seconds and reject uncertain/rolled-back time, with no expiry grace.
   Convert accepted remaining validity to a local monotonic upper bound; sleep,
   resume or clock anomalies require revalidation before readiness. Request and
   lease durations still use local monotonic clocks, never remote timestamps.
5. Revocation stops admission and invalidates affected sessions within five
   seconds of receipt, discarding late results and initiating bounded cleanup.
   With a healthy refresh route this is at most 35 seconds after publication.
   On authority loss, existing permissions last no longer than the last signed
   snapshot expiry (at most 300 seconds after its issue), plus the five-second
   check interval; then affected sessions terminate. A heartbeat cannot extend
   this or a certificate expiry. Compute cleanup may add its 15-second grace.
6. Check permission/credential expiry on established channels, not just during
   handshake. No Open/Step/Renew, response acceptance or stream emission after
   its authorization expires. Bound an in-flight operation by the earlier
   request/session/credential/grant deadline. Expiry terminates affected work;
   it does not silently reuse an already authenticated channel indefinitely.
7. Rotate leaf keys through a new CSR authorized by the current key and operator
   approval; a lost/compromised key requires out-of-band re-enrollment and old-key
   revocation. Any serial/key/credential-epoch change at either endpoint first
   stops affected admission and drains old bindings within the owner drain
   deadline clipped to credential/grant/request expiry; unfinished work is
   cancelled with the existing cleanup grace. Prevalidation of replacement
   credentials/channels is preparation only, not new inference admission.
   After old bindings are terminal, advance the affected role's credential/
   admission epoch and use fresh request, route, session and operation IDs for
   subsequent work. Every new route has `route_epoch: 1`; route epoch is scoped
   to one request and never advances across requests. Late old-credential work
   is rejected; no cache/session survives rotation, no old/new live-binding
   overlap is allowed, and no partial request is retried or reconstructed.
   Stable account/device and unchanged permissions do not create an exception.
   A process need not restart, but its boot never changes the rotation rule.
   CA/catalog/signing-root rotation also
   requires an explicit owner-approved overlap bundle and drain/revalidation;
   never fetch a replacement root from an unauthenticated peer.

On Linux protect credential directories with mode 0700 and private files with
0600, owned by the daemon UID; reject symlinks, wrong ownership and broad modes.
Do not place authority private keys in participant deployments. Runtime workers
receive only their scoped keys and read-only verified artifacts, never the Docker
socket or authority keys. Root/host administrators can still extract local keys.

### C2b outbound gateway boundary, not yet implemented

The selected next route is one worker-initiated persistent bidirectional work
stream to an explicitly admitted **trusted terminating gateway**. The coordinator
uses a separately authenticated mTLS hop to that gateway. Both hops validate
certificates and delegated grants; the gateway must bind the original tenant,
coordinator device/boot and route to its authenticated upstream and the selected
worker stream. Workers accept forwarded identities only from that specific
authorized gateway and within the signed delegation, never from arbitrary
forwarded headers. The gateway can read/change traffic within this trust model;
do not advertise end-to-end coordinator/worker encryption or prompt privacy.

The C2b stream must preserve the identities, message caps, deadlines, no-retry
rule and worker queues above. Bound it to one stream per worker boot, eight
pending work frames plus one active call per stage, and a separately serviced
control/cancel lane of at most eight frames; full queues reject work, not buffer
without limit. Heartbeat every 30 seconds, mark the stream unavailable after
60 seconds without a valid heartbeat, and reconnect only for new work after
fresh authentication/readiness. Its loss fails affected requests and invalidates
old stream bindings; it never resumes live cache mutation. Registration alone
is not a work channel. Flow-control/gateway-loss tests and exact byte/egress
budgets are required before deploying it; operators/routes/budgets are still
awaiting dependency. An opaque relay/direct peer path is a different future
decision and experiment, not an interchangeable configuration of this one.

## Local management and resource policy

### C2a management boundary

Use Linux AF_UNIX IPC in an owner-only runtime directory (0700), socket mode
0600, same UID verified through kernel peer credentials on each connection,
and a random 256-bit per-daemon-boot management token in a 0600 owner-only file.
Both UID and token are required; rotate the token on every daemon restart.
Refuse insecure directories, symlinks or unsafe stale sockets. No TCP listener,
cross-user access, browser/CORS bridge, inherited public socket or remote
management credential is allowed. Same-UID malicious code and local root remain
trusted/out of scope; the token does not protect against the owner account being
compromised. Tokens are not CLI arguments or URLs.

Management accepts only enumerated policy, status, role enable/disable,
artifact-approval, drain, stop and removal actions, bounded to 64 KiB per message,
four simultaneous management connections and five seconds per operation. These
Unix sockets do not consume the separate TLS listener connection allowance.
Long work returns an operation ID/status, not a blocked control loop. Drain/stop/
remove must acknowledge local intent within one second even if inference hangs;
that acknowledgement is **not** proof of reclamation or remote revocation.
C2a uses unprivileged existing process entry points in the pinned Linux runtime;
it does not add a general shell, arbitrary executable configuration, privileged
network agent or worker-accessible container-engine API. A launcher needing
resource-control privilege remains a separate trusted local operator boundary.

### One physical resource controller

Consumer-only mode does not install execution dependencies. Before host or
personal coordinator enablement, require explicit owner ceilings and an available
enforcement mechanism. No guessed hardware-derived budget auto-enables a role.
Configuration must name each physical RAM/accelerator pool; local processes,
containers and devices sharing/unifying memory cannot advertise it repeatedly.

Only one resource controller may authorize a physical pool. C2a must take an
exclusive local controller lock before execution enablement and refuse a second
daemon for the same device/pool. A trusted launcher/operator must allocate any
separate users' or containers' ceilings from one physical host budget; a private
per-container lock is not proof of host exclusivity. If that shared accounting
cannot be established, do not advertise independently additive capacity.

For each physical pool atomically enforce:

`resident weights + reserved KV + loading/execution/allocator headroom + communication buffers + all other local role reservations <= owner usable ceiling`.

| Policy | Required enforcement/failure behavior |
| --- | --- |
| RAM and CPU | Explicit bytes and CPU quota units across all local roles, with protected owner headroom; enforce Linux cgroup/process ceilings, not diagnostic RSS alone. Missing delegation/enforcement blocks execution readiness. |
| KV/session/queues | Reserve maximum context before Open and share counters across coordinators/processes. Release partial route reservations; no second independent reservation of the same physical budget. Runtime maxima below remain upper bounds. |
| Capture communication | Include `V * 32 + 4096` bytes per maximum last-position JSON event across all active capture sessions, their full queues and bounded producer/write slots, plus representation/copy/transport headroom. Hold reservations through reclamation; full-prefill logits are in-process only. |
| Disk/artifacts/logs | Explicit artifact, staging, diagnostic and total disk-byte ceilings; reserve staging plus final footprint before download, verify hashes/signatures before atomic installation, and never evict in-use weights. Interrupted/corrupt downloads stay unready; disk exhaustion fails explicitly. |
| Bandwidth/data | Explicit aggregate send/receive bytes-per-second and cumulative byte allowance across all roles; count artifact/control/activation/token/relay traffic. Stop new data work before allowance is exhausted, retaining a separately reserved bounded cleanup/control allowance. Unsupported metering/enforcement blocks the enabled cap, not silent unlimited service. |
| Availability/owner share | Explicit allowed windows and reserved owner share from the same pool; first slice uses FIFO at whole-stage-call boundaries, no preemption. Per-account active/queued ceilings are explicit, no greater than global limits; unused owner share does not create capacity twice. |
| Battery/thermal/idle/power | Optional only when the required sensor and enforcement are reliable. If an owner enables idle-only, temperature, battery or power policy and its required telemetry is unsupported, invalid or stale for over five seconds, mark affected execution roles unavailable, stop admission and cancel active work using Stop now. Do not substitute zero, “probably idle” or unknown-as-safe. |
| Policy reduction/external pressure | Stop admission immediately if new ceilings cannot cover reservations. Never reclaim referenced cache early or lie about free memory. If active work cannot remain within the new policy/headroom, cancel it with bounded supervision; report allocator-retained RSS separately. |

Owner bytes/rates/CPU/availability values must be present and validated before
execution; they are deployment dependencies, not performance targets supplied
by this document. C1a/C2a unit tests use explicitly labeled synthetic budgets and
fake telemetry. Physical quotas require real enforcement tests before claiming
them. Unsupported optional policies can be disabled only by explicit owner
action, not automatic fallback. Sensor failure does not disable consumer-only
mode unless its own enabled policy requires that sensor.

## Runtime bounds and lifecycle semantics

Execution readiness follows `unenrolled -> enrolled -> probing -> loading ->
ready`, with roles still independently disabled until owner opt-in. A host is
ready only with fresh credentials/grants, verified loaded assignment, healthy
executor, valid required telemetry and shared reservations available. A personal
coordinator additionally needs checked input/output resources and the complete
authorized worker route. A control heartbeat alone is never readiness.
Consumer-only mode skips execution probing/loading and never advertises host
capacity. Transient connection/resource/sensor failure makes execution
`unavailable`; corrupt artifacts or incompatible identities make it
`quarantined`. Neither state automatically relaxes policy. Reentry requires all
relevant checks, and quarantine requires an explicit owner-approved correction.
Drain ends `paused`; owner pause/stop prevents automatic restart into `ready`.

These retain the implemented M2–M5 maxima. Effective limits are the minimum of
runtime ceilings, local owner policy, authority/assignment grant, tenant quota,
remaining request budget and credential freshness. Increasing an existing
manifest-bound limit requires new validation/evidence, not a secure-profile flag.

| Bound | First-slice maximum/default |
| --- | --- |
| Request/session context | 1,152 combined prompt/output positions; no truncation or chunking |
| Worker sessions/reservations | Eight sessions; 12,288 reserved positions and 16 MiB KV tensor budget per stage |
| Existing lab process ceilings | Each worker and standalone coordinator: two CPU quota units and 3 GiB RAM; these are baseline configured ceilings, not dedicated cores or independently available host capacity |
| Compute/stage queue | One active compute and at most eight queued calls per stage; one active/queued Step per session; normal eight-session case leaves at most seven other sessions waiting |
| Coordinator admission | Eight active requests, 32 waiting admissions, 30 seconds from submission including reservations |
| Output buffering | 16 tokens/request; full queue or transport write stalled 30 seconds cancels the request |
| Wire logit capture | Last-position only; `V * 32 + 4096` event budget under 1 MiB, with all-session/full-queue/in-flight communication reservations; no full-prefill wire capture |
| Request and RPC | Request at most 300 seconds from submission including admission; each RPC at most 30 seconds and clipped to remaining lifetime |
| Text/tokenization | At most 64 KiB UTF-8 text, 1,152 tokens, no silent truncation; optional Tokenize RPC is separately bounded to 30 seconds and remains outside the submission clock |
| Worker idle/hard lease | Idle at most 120 seconds, check interval at most five seconds; renewal every 30 seconds; lifetime at most 300 seconds from Open, clipped to request remainder; never extended by renewal |
| Payload/replay metadata | 1 MiB per inference message before parsing; 30-second terminal tombstones, 4,096 active-plus-terminal records; reject admission rather than evict protected tombstones |
| Compute cancellation | Invalidate work immediately; retain unsafe ownership for at most 15 seconds before independent supervisor termination/restart |
| Cleanup/shutdown | Coordinator polls worker cleanup up to 20 seconds; standalone coordinator shutdown ceiling 40 seconds; neither is extra generation time |
| Startup/watchdog | Startup at most 60 seconds, missed child heartbeat detected after two seconds; at most three restarts within 60 seconds, then unavailable |

Worker cache bytes count live tensors, not all RSS, loading peaks, temporary
buffers or allocator retention. Reservations are admission accounting, not
preallocated physical memory. Report `reclaimed=false`/`cleanup_complete=false`
when ownership cannot be proven released. Missing acknowledgements are not
success. A process restart invalidates all sessions on that process, including
other requests; do not promise per-session isolation from a process kill.

### Owner actions

| Action | Immediate transition | Completion, deadline and retained facts |
| --- | --- | --- |
| Drain | `ready -> draining`; withdraw readiness, reject new host Open/consumer submissions/queued admissions for affected roles, retain already admitted reservations | Existing sessions may Step/Renew within their original lifetime and authorization. Owner drain deadline defaults to 30 seconds, configurable 1–300 seconds, never extended by progress/heartbeats or later Drain. At deadline use Stop now. Successful drain ends paused, no auto-resume. |
| Stop now | Disable affected roles' admission, discard queued work, mark sessions terminal, suppress late results and stop renewals | Acknowledge intent within one second. Send known-lease cancellation best effort; never wait for a peer before local stop. In-flight compute keeps ownership until completion or supervisor kill within its 15-second grace. Local coordinator teardown has the 40-second outer ceiling; report unconfirmed remote cleanup, not an instant memory-free claim. Explicit owner start plus all checks is needed to reenter readiness. |
| Remove device | Persist all roles off, a signed device-revocation intent and a removal/revocation-pending marker before network calls; perform Stop now, submit revocation best effort and delete local role credentials | Operator revokes device and all serials/grants; if disconnected, remote revocation is pending, not confirmed. Retain only the protected signed removal intent for delivery through the admission operator, not active role keys or a work reconnect loop. Authority freshness/lease bounds still apply. Offer deletion of daemon-owned artifacts/staging/logs only after local compute exits; do not delete shared owner files or promise secure erasure/backups removal. Rejoin requires new invitation/device identity. |

Stopping hosting does not implicitly stop an unrelated consumer-only connection;
if its route uses that host, it fails normally. Device removal stops all roles.
Disabling personal coordination fails its requests and cancels its worker
reservations. Local pause/drain/stop persists across restart and overrides any
saved enable flag. Local lifecycle controls cannot renew credentials or bypass
owner budgets to keep a request alive.

### Deadline, disconnect and stale-result rules

- Only local monotonic durations are used for admission, RPC, lease, cleanup and
  drain clocks. Every hop passes a remaining duration clipped to the origin's
  budget; clocks never restart at retries, forwarding, queue exit or heartbeat.
  Generation stops at its deadline even if cleanup/terminal delivery continues.
- An Open timeout may mean a reservation exists. Cancel every known lease and
  rely on worker expiry for an unknown lease; no second route/request is
  silently started. An unrenewed Open with no subsequent work expires within
  120 seconds plus the five-second expiry check, or its earlier hard deadline.
- A lost Step reply, response validation failure, worker/stream disconnect,
  coordinator loss, sleep or boot change fails the affected request. Cancel
  all reachable known leases and stop renewal. Do not retry the Step, infer
  success from SessionStatus, reuse a new boot, or resume output delivery.
  Status is diagnostic and cannot recover a missing activation.
- After invalidation, queued work is removed; executing results are discarded.
  The existing sequence/position check prevents applying a duplicate Step to
  live KV state but does not recover its missing response. Close/cancel is
  idempotent within its owner binding; duplicate Open is allowed only for the
  same owner and identical bounds, never as an automatic lost-reply retry.
- If cancellation cannot reach a worker, its unrenewable maximum session
  lifetime gives an outer bound of 300 seconds from Open plus five seconds to
  detect expiry and 15 seconds for compute termination. Usually the shorter
  idle lease applies. This 320-second worst-case orphan bound is not a promise
  that the coordinator confirms remote cleanup within its 20-second poll.
- Credential revocation/expiry and stale authorization terminate affected work
  under the earlier bounds above. A broken client stream may never receive a
  terminal event; report failure and the delivered partial prefix, not success
  or exactly-once delivery. Coordinator-enqueued output can exceed delivered
  output. There is no indexed replay buffer, transparent failover, request
  reconstruction or duplicate-output recovery until C6.

## Threat model

| Threat/boundary | Required first-slice defense/test | Residual risk/non-goal |
| --- | --- | --- |
| Unknown/expired/revoked peer, stolen session/lease, forged role | Mutual certificate checks, current scoped grants, every-operation owner binding, boot/route fencing, bounded freshness | Compromised admitted key can act within its grant until revocation is observed/bounds expire |
| MITM, endpoint substitution, downgrade, registry/catalog rollback | Pinned roots, DNS/IP and identity SANs, fixed address allowlist, signed increasing policy/catalog versions, no insecure fallback | Trusted CA, registry/catalog operator, local clock and root protection remain required |
| Hostile tensors/metadata, arbitrary execution, memory/connection exhaustion | Strict preallocation validation, finite tensors, supported methods only, transport/message/queue/shared quotas and independent watchdog | No hard isolation from local root; bugs or physical pressure can still terminate a process |
| Cross-user/browser management, unsafe files, peer policy override | Same-UID Unix IPC plus boot token, private modes, bounded enum actions, no remote management shell | Same-UID malware/root can inspect keys/policy; this is not a hostile-local-owner sandbox |
| Malicious host/coordinator/gateway, false capacity/collusion | Invited trust, artifact checks, frozen reference parity/readiness challenges and explicit operator responsibility | TLS/signatures/spot checks do not prove correct computation, capacity, privacy or honest accounting |
| Lost responses, cancellation, restart, stale output | Fail-and-cleanup, retain unsafe caches, hard leases, tombstones, no mutation retries or session adoption | Temporary orphan reservations and failed partial output are permitted and reported |
| Privacy/log/artifact leakage | Public/synthetic inputs only, offline approved artifacts, default no prompts/tokens/activations/leases/credentials/digests in logs; bounded access-controlled diagnostics | Worker/gateway/coordinator owners see computation; no confidential execution or secure deletion guarantee |
| Deceptive resource readings, missing telemetry, duplicate pools | Fail-closed enabled policy, one physical controller, measured ceilings and pressure tests | No GPU/power/thermal guarantee without a supported measured backend; advertisements alone are untrusted |

Default diagnostics contain only bounded status/error/counter/timing/version
data, not user payloads or secret/prompt/activation hashes. Owner-enabled debug
capture requires explicit scope, byte/retention limits and access control; it is
not permitted for private real prompts in this initial slice. Generated keys,
certificates, captures and raw logs stay ignored under `.lab/`, never in fixtures
or committed reports. Test fixtures must be public/synthetic with nonproduction
credentials. Human incident escalation and key compromise response require an
assigned operator before any remote trial.

## Acceptance test matrix

**Required tests, not executed results.** Local fake-worker/authority/sensor tests
are valid for their bounded contracts, not substitutes for numerical execution,
real enforcement or physical routes. Each row retains positive and negative
cases, exact bounds/configuration, outcome, cleanup counts and errors/skips.

| ID / gate / responsible role | Cases to implement and evidence required |
| --- | --- |
| CT-01 C0 / architecture + config reviewer | All roles off; consumer-only/host-only/coordinator-only declarations independently valid with only their role's required fields; remote consumer need not share coordinator daemon/device; local execution roles match stable account/device, never daemon boot. Check typed 128-bit hex IDs, distinct raw-hex boots, attempt 1, route_epoch 1 per request, separate credential/admission epochs, binding version 1 and per-stage assignment mapping; reject wrong types/versions/roles/backends/missing execution budgets. Synthetic SessionOperation validation is not wire/auth evidence. |
| CT-02 C1a / network-security | Valid fixed-peer mTLS with offline expected-leaf verification against pinned cohort CA and exact-leaf trust on the actual gRPC channel, retaining hostname checks; wrong CA/SAN/EKU/device/key/role/hash, a different same-CA/same-hostname leaf, missing cert/binding, expired/not-yet-valid/revoked leaf, disabled TLS or downgrade all rejected before admission; no TOCTOU probe or session/target enumeration leak |
| CT-03 C1a / network-security | Consumer cannot call worker; host cannot coordinate; personal coordinator cannot serve other accounts. Wrong credential epoch, stolen session/lease, changed tenant/target/stage assignment/route/boot, duplicate binding keys or unsupported versions rejected without mutation; validate the actual steamboat-binding-bin carrier, not only a synthetic declaration. |
| CT-04 C1a / identity-security | 900-second certificate limit, renewal 300 seconds before expiry and role restrictions; serial/key/credential-epoch rotation drains old bindings then creates fresh request/route/session IDs with credential/admission epoch advanced and route_epoch 1 on every request, with no preserved/replayed request or overlapping live binding. Test separate 300/30/5-second snapshot lifetime/refresh/expiry checks, signed revision rollback, authority loss, revocation within five seconds of receipt, existing-channel expiry, clock rollback/sleep and root rotation using controlled clocks. |
| CT-05 C1a / transport-runtime | Oversized/malformed tensor/metadata rejected before tensor allocation; exact byte/context bounds, nonfinite data and unknown methods. Exercise installed C-core listener total 16/per-peer 2/pending handshake 4/five-second timeout limits; streams/RPCs remain separately bounded and Unix management sockets excluded. Test maximum finite float32 last-position JSON at V*32+4096 under 1 MiB, reject full-prefill wire capture and over-budget output; configured arguments alone are not enforcement evidence. |
| CT-06 C1a / runtime-reliability | Lost Open/Step/reply after mutation, reordered/duplicate sequence, changed boot, partial admission, cancellation during queue/compute, tombstone saturation and expiry; no automatic Step replay or stale output; known cleanup plus unknown-lease expiry bounded |
| CT-07 C2a / connector-platform | Wrong UID/token, insecure/symlinked socket/key directories, stale boot token, browser/TCP path, malformed/oversized IPC; at most four AF_UNIX management connections independently of TLS counts. Stop intent acknowledged within one second under hung fake compute; missing resource delegation leaves execution unavailable. |
| CT-08 C2a / connector-resource | Simultaneous host/coordinator/local workers sharing one physical pool, atomic conflicting reservations, owner/tenant ceilings, policy reduction, disk full/corrupt/interrupted artifacts, bounded logs/staging and aggregate network allowance. Include maximum capture buffering over eight active sessions/16 queued outputs plus bounded producer/write slots and live representation headroom, slow/disconnected consumers and reclamation; no double-counted capacity or early release. |
| CT-09 C2a / connector-platform | Enabled battery/thermal/idle/power policy with missing/stale/fake-invalid telemetry fails closed within five seconds, cancels work with grace, explicit owner disable required to relax; unaffected consumer-only mode remains lightweight |
| CT-10 C2a / connector-reliability | Drain's admission cutoff and 30-second default/300-second max; deadline cannot slide; Stop now removes queues, preserves referenced caches then kills hung child within grace; Remove persists roles off/revocation pending offline, protected deletion/rejoin; no automatic restart into ready after owner pause |
| CT-11 C1a CPU integration / runtime-research | Preserve in-process every-prefill-position comparisons for 1/128/1,024-token prompts; secure coordinator wire capture compares only last-position vocabulary logits for prefill plus eight identical forced tokens against the same-stack full model. Greedy separately, unequal interleaving, 1,152 boundary, eight sessions/ninth rejection, finite logits and `atol=1e-3, rtol=0`; zero live sessions/cache/queues after bounded cleanup. Maximum full-prefill logits never use wire capture. |
| CT-12 C2b / connector-network | Real bidirectional work stream, delegated actor/target binding, data/control backpressure and reserved cleanup lane, heartbeat expiry, gateway/worker/coordinator loss, revocation and reconnect only for new work; exact bytes and trusted termination recorded |
| CT-13 C1b/C2b / research-operations | Actual executing route stages/coordinator span at least two inventoried physical hosts, with exact component placement recorded; a registered unused host or a separate thin consumer alone does not qualify. Real route enrollment/readiness/inference/cancel/drain/remove; repeat CT-11 with last-position wire capture/full-prefill in-process controls and remote lifecycle cases; outbound-only route without manual router changes for C2b; no same-host substitute. |
| CT-14 later C3/C4/C5 / GPU-runtime + research | Separate GPU lock/tolerance, memory/loading peaks, actual LAN/internet paths and matched controls; pooled capacity/usefulness only from the actual cohort. Missing hardware/topology is a skip/dependency, not a passed CPU proxy. |

No row is marked passed by this specification. C1a local acceptance and C2a local
acceptance do not complete C1b/C2b or change research P gates. The parent owns
serialization of Docker/model/GPU/network-shaping/performance validation.

## Experiment manifest and evidence handoff

Before the first fixed-cohort run, freeze: contract/control/inference/binding
versions; source commit and immutable image digest; full dependency lock; model/
tokenizer/artifact fingerprints; precision/attention/compression; synthetic token
fixtures and forced continuations; EOS/greedy policy; the exact component route,
device/boot/physical-pool mapping and trust roles; credential/grant validity
without secrets and their epochs/rotation boundaries; per-stage assignment IDs;
owner/tenant quotas, capture communication reservations and all timeout values;
hardware/OS/driver inventory; direct or gateway legs;
workload/concurrency/warm-up/arrival policy;
fault injection points; timing boundaries, numerical tolerance and cleanup limits.
No execution may use placeholder hardware, operator, route or budget fields.
For a real two-device gate, the executing route stages and coordinator placement
must span at least two of those inventoried physical hosts. An unused registered
host or a second host running only the thin consumer does not satisfy the
execution requirement.

Retain exact executed commands and exit status, environment/config identities,
all success/failure/skip cases, logit errors, token comparisons, cleanup/restart
observations, unconfirmed leases and exclusions. Include per-user monotonic
TTFT/inter-token latency, completed-output throughput, failures/retries, stage
queue/compute spans, bytes, memory/loading/startup and recovery/verification cost
when measuring performance. Prompt tokens are not generated output. Cross-host
timestamp subtraction needs measured synchronization uncertainty; same-host
overlap is not multi-device speedup. Keep raw/private material under `.lab/` and
publish only compact sanitized summaries of actual execution.

Numerical/lifecycle acceptance uses CT-11, not the provisional P4 usability target.
A future performance study must predeclare selected cases and three repetitions
targeting 100 completions within 200 attempts each, with failures retained and
same-stack whole-model/replica controls when it fits or same-model offloading
when it does not. The inherited 1,024-input/64-output, one-session, median
5-output-token/s and p95 five-second TTFT target remains provisional until an
actual larger-model cohort explicitly adopts/revises it. C0 supplies no speed,
resource-cost, energy or user-experience result.

## Dependency register

Responsible roles are concrete functions, **not staffing commitments**. DEP-01
is parent-owned engineering reconciliation, completed at the
[C0 gate](experiments/2026-10-17-participant-c0.md); the parent is authorized
to accept these choices under the user's goal, without another human design
approval. Real operator/hardware owners in DEP-02–DEP-10 remain **unassigned**
because availability is unconfirmed. “Awaiting dependency” describes actual
external access/operating authorization still needed, not a phase status change.
Resolve those owners and authorization before using external access.

| ID | Responsible role / owner | State and exact access or decision needed | Blocks |
| --- | --- | --- | --- |
| DEP-01 | Architecture/integration reviewer / parent coordinator | Complete for C0: parent reconciled the decision, declarations/validator, identity/binding mappings and timing fields; independent review and Docker controls passed. Later executable security/connector work has its own gates. | No remaining C0 design blocker for local C1a/C2a; deployment dependencies below remain open |
| DEP-02 | Network-security implementer + admission operator / unassigned | Awaiting dependency: operator-authorized cohort CA and separate authorization signing key custody, invitation/account/device scope list, revocation publication endpoint, clock source/uncertainty and key compromise contact; local nonproduction fixtures may proceed | Deployed C1/C2 enrollment and security operation |
| DEP-03 | Artifact catalog/release operator / unassigned | Awaiting dependency: approved catalog signing key and distribution location, verified model/image manifests and hashes, download access/terms, revocation/rollback procedure; preserve existing CPU lock and offline artifacts as controls | Participant artifact distribution; not fake corruption tests |
| DEP-04 | Hardware/cohort recruiter + device owner / unassigned | Awaiting dependency: written invited access to at least a second physical machine, CPU/RAM/disk/OS inventory, approved Linux amd64 runtime execution, scoped operator login, container/cgroup delegation and permission for bounded restart/fault/cleanup tests. Executing stages/coordinator must actually span two inventoried hosts, not leave the new host unused; only local laptop presently confirmed. | C1b and physical C2 acceptance |
| DEP-05 | Network/route operator / unassigned | Awaiting dependency: endpoint/DNS/IP SAN ownership, approved firewall/private mTLS reachability at both real sites, endpoint address allowlists, measured RTT/goodput and route/relay disclosure; explicit permission for bounded probes/faults, no insecure lab exposure | Real fixed-peer route and LAN/internet claims |
| DEP-06 | Gateway service operator + security reviewer / unassigned | Awaiting dependency: Linux gateway hosting/admin access, TLS termination/delegation approval, protected keys, inbound coordinator/outbound worker reachability, connection/egress controls, incident contact and retention policy; no assumed public relay | C2b outbound-only route |
| DEP-07 | Resource/budget owner + participating device owners / unassigned | Awaiting dependency: written RAM/CPU/disk/headroom/session/rate/data/window ceilings, reserved cleanup allowance, available enforcement/telemetry; explicit spend limits/payer for hosting, downloads, egress and probes and authorization for machine disruption | Any real participant execution or paid infrastructure; synthetic local policy tests independent |
| DEP-08 | GPU-runtime lead + accelerator owner / unassigned | Awaiting dependency: actual supported GPU/VRAM inventory, Linux driver/runtime installation and device access, telemetry/synchronized timing permission and GPU test windows; no vendor/backend assumed | C3a/C3b and pooled-GPU claims |
| DEP-09 | Research/experiment lead / unassigned | Awaiting dependency: actual cohort/route/budget manifest, frozen workload/fault cases, approved test windows and complete-model controls; later suitable larger model, terms, local offload/multi-GPU controls and usability/resource targets | Real-device reports, C4b/C5; not C1a/C2a fake tests |
| DEP-10 | Operations/support + accounting/security operator / unassigned | Awaiting dependency: human incident/revocation/support ownership before remote use; later approved community ingress, verification/ledger funding, tariff/dispute policy and recruited pilot support | Remote operations; credits/community/pilot remain C7/C8, federation C9 |

## Run the C0 checks

The [versioned declarations and examples](../config/participant/README.md) have
a standard-library checker. They are not deployed security configuration.
The [C0 Compose file](../compose.participant-contracts.yaml) separates declaration
and document checks from the unchanged CPU model tests and smoke control:

```powershell
docker compose -p steamboat-c0 -f compose.participant-contracts.yaml build contracts model-tests
docker compose -p steamboat-c0 -f compose.participant-contracts.yaml run --rm contracts
docker compose -p steamboat-c0 -f compose.participant-contracts.yaml run --rm documents
docker compose -p steamboat-c0 -f compose.participant-contracts.yaml run --rm model-tests
docker compose -p steamboat-c0 -f compose.participant-contracts.yaml run --rm runtime-tests
docker compose -p steamboat-c0 -f compose.participant-contracts.yaml run --rm smoke
```

Run the services serially. Contracts/documents use the digest-pinned Python
3.12.15 image with no installed packages, one CPU quota unit and 256 MiB RAM.
The model checks use the existing hash-locked runtime, two CPU quota units and
6 GiB RAM. All services have no external network, no published ports, dropped
capabilities and a read-only source filesystem with bounded temporary storage.
Rebuild after source changes; neither validation image replaces the historical
CPU/Petals image tags.

The full `runtime-tests` service enables the existing offline model, protocol,
process, coordinator and service gates, including the new declaration tests.
The runtime image includes their configuration fixtures and carries an unchanged
copy of `requirements.lock` at `/app/docker/pytorch/requirements.lock`, the path
used by contract discovery as a reproducibility identity. Dependency installation
still reads the original lock with `pip --require-hashes` during the image build.

Existing audit tests create temporary directories under `/app`, while the baked
runtime image is read-only. For full discovery, only `runtime-tests` receives a
128 MiB `/test-app` tmpfs. Its Python bootstrap copies the baked `/app` tree into
that bounded scratch mount at launch, then runs the suite from `/test-app` with
`PYTHONPATH=/test-app/src:/test-app`. It mounts no host source. The service keeps
`read_only: true`, `network_mode: none`, its existing read-only artifact/cache
volumes, dropped capabilities, no-new-privileges setting, and CPU/memory/process
limits. `/tmp` retains its existing bounded tmpfs. `model-tests` and `smoke` do
not use the scratch copy, and their source/control settings are unchanged. This
is a test-only writable snapshot of the image's baked source, not a production
filesystem or security relaxation.

The source CI fast suite also runs declaration tests without loading model
dependencies.

Model validation requires the existing verified `steamboat-pytorch-m1` artifact
and cache volumes from [the runtime setup](PYTORCH_RUNTIME.md). Validation mounts
them read-only; it does not prepare, download or overwrite artifacts. Missing or
incompatible artifacts fail the model checks. Results are written to ignored
`.lab/participant-network/c0-results/` with unique report names. The declaration
container needs no model artifacts. Static validation, model correctness and
actual security/device gates remain distinct evidence.
