# C2 connector implementation design

Status: implementation in progress; no C2 exit gate has passed. This design
extends the published C1 baseline `89ea4b1`. The older C2a local report is
historical evidence for isolated components, not this integrated application.
The normative scope remains [C2.1–C2.6](PARTICIPANT_NETWORK_PHASES.md)
and [the participant contracts](PARTICIPANT_CONTRACTS.md).

## Execution ownership

The unprivileged Linux daemon launches fixed Python entrypoints. It does not
accept arbitrary programs or commands and has no Docker API or socket. The
operator provisions a delegated cgroup and allocates one physical host budget.
A shared physical-pool lock, actual cgroup enforcement, and daemon reservations
must all hold before execution enablement. A container-private lock alone does
not establish host exclusivity.

A standard-library bootstrap waits on an inherited private gate before importing
execution dependencies. The parent owns the child before attaching it to its
bounded cgroup and releasing that gate. Loaded, verified runtime readiness is a
separate condition from successful process creation. Stop admission and local
intent acknowledgments do not wait on inference. Termination, reaping, and an
empty owned cgroup must be confirmed within the existing 15-second compute
grace; uncertain ownership retains all associated reservations and artifacts.

One host role may own up to three fixed component handlers in the same process
and aggregate cgroup. Each component retains its signed assignment and worker
boot. Its installer has one catalog high-water mark, one inventory and disk
budget, and three bounded active host slots. Legacy singleton state requires
explicit guarded migration. A group lifetime pin must cover all resident
assignments; opening several independent artifact roots is not the selected
solution. Component KV, queue, capture and execution limits must either share
one admission budget or be disjoint allocations whose sums fit the role budget.
This arrangement permits three stages across the available two physical hosts.

## Channel credentials

C1 direct participant credential validation is unchanged. C2 adds a separate
purpose-specific channel certificate profile under the pinned cohort CA:

- `worker_stream` has client authentication only and binds the existing host
  account, device, C1 credential serial and credential epoch.
- `gateway` has client and server authentication and binds an operator-selected
  service identity. It is a transport service, not a fourth participant role.

Both profiles use P-256, SHA-256, exact key-usage/extension/SAN constraints and a
maximum 900-second lifetime. Gateway clients retain fixed DNS/IP verification.
A valid channel certificate alone confers no enrollment, readiness, revocation
status, work permission or delegation authority. Explicit operator policy must
pin its identity and certificate and authorize its purpose. C1 leaves cannot
substitute for channel leaves or vice versa.

The worker-side TLS owner loads its private key and certificate into a private
TLS 1.2/1.3 client context, verifies the configured gateway CA and fixed endpoint,
and keeps the SSLObject private. It proves only that the configured credential
was loaded into its client context; the client cannot prove that the server
requested or verified it. The gateway server must separately require client
certificates and validate the worker profile and policy before accepting a
channel. It accepts bounded MemoryBIO input and output chunks (16 KiB), bounds
each pending BIO to 64 KiB, and limits handshake traffic
to 128 KiB and ten monotonic seconds. Credential files are created in a 0700
temporary directory with 0600 files and removed after OpenSSL loads them. Failed
cleanup leaves a faulted owner with an explicit uncertain status and retained
directory path; it never reports those credentials as removed. The completed
owner exposes the actual peer certificate and the configured worker leaf loaded
into its own context. Gateway ingress accepts this owner and does not accept a
caller-supplied SSLObject plus a claimed local certificate. This transport
primitive does not provide sockets, wire framing, aggregate traffic quotas, or
channel readiness. POSIX file mode checks remain platform-specific.

## Trusted terminating gateway

The selected gateway terminates two independently authenticated mTLS hops. A
worker initiates and maintains its outbound channel; the coordinator makes an
authenticated upstream connection to the gateway. The gateway can see and alter
the traffic. Its signed attestation that a coordinator authenticated upstream is
trusted within an explicit operator-authorized delegation scope. It is not
end-to-end coordinator proof of possession at the worker.

The operator channel policy uses a separate signature domain, canonical payload,
strict size limits, revision antirollback/equivocation protection and a lifetime
of at most 300 seconds. It authorizes gateway certificate/key identity, worker
channel and existing C1 credential/boot identity, and allowed coordinator/tenant,
worker, model, assignment and methods. The gateway holds no CA or policy signing
key.

Each gateway delegation signs its own purpose domain and the exact C1 canonical
binding, service, method and bounded request digest. It also binds policy identity,
gateway leaf, original coordinator leaf/serial/epoch, selected host boot, unique
stream generation and monotonic per-stream frame sequence. The actual upstream
TLS peer and selected authenticated worker channel must match those fields.
Policy, certificate, C1 snapshot/grant, readiness and request deadlines clip its
authority. Queueing or refresh cannot extend an existing request or session.

Direct `Authorizer.authorize` continues to derive its actor from the direct TLS
peer. An explicit gateway entry verifies the actual transport-established
gateway context and signed delegation before entering the same private
verified-actor admission implementation. It does not feed forwarded certificate
metadata into the direct-peer API. The concrete core `Authorizer` and runtime
bridge retain existing payload, grant, replay, session, capture and cleanup
checks.

The outbound side also needs an explicit delegated transport path. A gateway
certificate is the actual upstream TLS server identity; the logical host leaf
comes from current enrollment and the operator-authorized worker-channel map.
That logical host certificate must never be presented to the existing direct
outbound API as if it were the TLS peer. A separate gateway entry must verify
the real gateway connection and selected route, then reuse C1's private scope,
trusted-context, payload, response and cleanup logic. This preserves the stated
trusted-gateway boundary without claiming end-to-end host key possession.

Gateway policy and stream-generation liveness must participate in every
authorization live check, deadline monitor and completion, rather than only
initial admission. Open captures an immutable ingress identity in the session;
all subsequent operations must match it. Stream loss invalidates its sessions
and affected requests, reaches actual runtime owners, and retains uncertain
cleanup. A fresh authenticated/readied generation permits new work only. A
delayed old-stream close cannot invalidate or adopt its replacement. Mutations
with ambiguous outcomes are never retried.

One channel per worker boot admits at most eight pending data frames and one
active stage call, with a separately serviced eight-frame control/cancel lane.
Heartbeat is every 30 seconds and availability expires after 60 seconds without
a valid heartbeat. All wire and certificate/envelope overhead must fit explicit
aggregate byte, rate and cleanup allowances. No channel is ready before actual
metering, independent control and reconnect bounds are implemented and tested.

## Acceptance frozen before new measurements

1. Owner-only Linux management IPC, bounded CLI/daemon operations, independent
   opt-in roles, and a consumer path with no Torch or model installation.
2. Real owned execution children, one physical-pool controller, enforced shared
   CPU/RAM, disk/staging/log and traffic budgets, and fail-closed enabled sensors.
3. Signed assigned-only installation and offline loading in the actual services;
   corruption, interruption, disk exhaustion, compatibility and retained-artifact
   ownership tests. The executing path uses C1's conservative `Clock`.
4. Actual two-hop authenticated outbound work channel, delegated scope and
   payload checks, replay fencing, independent cancellation, bounded queues,
   expiry/revocation, loss and fresh-generation behavior.
5. Actual same-account consumer streaming/cancellation and complete authorized
   personal-coordinator route with shared input/output and capture accounting.
   Stop/drain/remove intent acknowledgment remains below one second under hung
   compute; reclamation evidence is separate and bounded.
6. Clean installation, enrollment, assignment, loaded readiness and first real
   inference through that outbound channel on the separate ZimaBlade CPU host.
   Actual executing stages and their coordinator span at least two physical
   hosts; a remote thin consumer alone cannot satisfy this gate. Repeat the
   exact CT-11 numerical matrix and CT-13 lifecycle/failure requirements in
   [the normative acceptance table](PARTICIPANT_CONTRACTS.md).
   Record exact sources, dependencies, placement, enforcement and cleanup.

All six gates, appropriate Docker regression checks and independent acceptance
review are required before C2 publication. Preserve failed runs. LAN results
will be labelled LAN; they cannot establish WAN/NAT universality or GPU pooling.
The available laptop and ZimaBlade suffice to attempt this scope. Stop if actual
progress requires additional hardware; no C3 or GPU gate is implied here.
