# Participant secure transport

This module provides an explicit mTLS transport profile for the C1a participant
runtime. The existing `protocol.transport` worker lab keeps its isolated
plaintext profile. Shared service cleanup/writer changes preserve its default
behavior; callers must select the secure factories directly. There is no
insecure fallback.

C1 validation passed on 2026-10-19 after Trial 78 ran all 878 required
software-regression cases with zero skips, failures or errors in 367.862
seconds. The original 600-second watchdog and declared resource limits
were retained. Bounded split-host, RST7, Drain4, Remove4 and numerical
checks retain their separately frozen source and image identities. See
the [C1 final validation record](experiments/2026-10-18-participant-c1.md).

Earlier failed runs remain recorded with unknown causes; Trial 78 does
not explain them or establish a hardware cause. C2–C9 and broader research
statuses are unchanged.

## Fixed numeric peers and pinned certificates

The current implementation accepts canonical, owner-allowlisted IPv4 literals
such as `192.168.1.12:50051`. Outbound peers may use a public address only when
that exact literal is explicitly allowlisted. Listener binds must use an
allowlisted private or loopback interface. DNS names and IPv6 are rejected as
unsupported. A one-time DNS lookup would not constrain gRPC's later resolution
to the checked address. The server certificate must contain the matching IP
SAN, and gRPC's ordinary IP hostname verification remains enabled. There is no
target-name override or broad-CA fallback, and this code does not launch a
public listener.

Before constructing an outbound channel, `create_secure_worker_client` invokes
the required C0 verifier on the configured expected leaf. The transport's hook
is intentionally not a direct drop-in for the identity-core function: the C0
primitive takes `(ca_pem, leaf_pem)` and keyword-only expected identity fields.
`C0ExpectedServerLeafAdapter` maps the values and normalizes serial and
SHA-256 pins to lowercase hexadecimal text. It returns the approved non-CA
server leaf, which is the only gRPC `root_certificates` value. Host leaves
require the server EKU; personal coordinator leaves require both client and
server EKUs. The channel keeps ordinary IP SAN verification enabled.

The adapter does not duplicate CA, SAN, EKU, serial, key, digest, grant or
session validation. It requires the real C0 verifier. The actual-core test
uses synthetic CA and leaf certificates and covers host and personal
coordinator EKUs, plus wrong leaf, serial, hash and EKU failures.

## Secure RPC authorization

Each call carries exactly one canonical UTF-8 JSON `steamboat-binding-bin`
metadata item, at most 4 KiB. Duplicate keys, noncanonical encodings,
non-finite values, nested values and duplicate binding items fail closed. The
application parser caps all call metadata at 8 KiB; gRPC receives both the
soft and absolute 8 KiB metadata limits. Send and receive message limits stay
at 1 MiB, retries are disabled, and responses echo the exact binding bytes.

The worker service and operation names are `steamboat.v1.Worker` and
`Describe`, `OpenSession`, `RenewSession`, `Step`, `CloseSession`,
`CancelSession` and `SessionStatus`. The coordinator uses
`remote_client.SERVICE` (`steamboat.v1.Coordinator`) with `Describe`,
`Tokenize` and `Generate`.

The server gets the client certificate only from gRPC's actual TLS
`auth_context`, parses the worker `Request` Protobuf, and calls
`Authorizer.authorize(service, method, payload, metadata,
peer_certificate_pem)` before handler work. The authenticated request binding
must match the authorization's canonical `binding_bytes`. Before each response
or stream event, the adapter calls `assert_live()` and echoes those exact bytes
in initial metadata. The only accepted successful `assert_live()` results are
exact `None` (assertion style) and exact `True` (boolean style), including when
the result is awaited. `False` and every other result fail closed.

Every operation requires an explicit revocation and expiry watcher. The C0
adapter must observe revocation within five seconds; the transport cancels
active work when it signals invalidation and clips waits to the authorization
deadline. A dropped or ambiguous mutation reply is reported as an explicit
failure and is never retried. Any unfinished gRPC call is cancelled on an
unsuccessful exit, and ambiguous calls fence the channel before it can be
reused.

`OpenSession` ownership is claimed during authorization before a handler can
disclose a lease. The successful response is passed to
`Authorization.complete(response)` before the transport emits it so the core
can seal the owner record. The transport does not reproduce the core's
tombstone or grant logic.

## Bound pre-admission rejection marker

The server and client implement a request-scoped marker to distinguish a
validated pre-admission capacity denial from transport-generated
`RESOURCE_EXHAUSTED`, such as an oversized first reply. A bare gRPC status or
empty stream is not sufficient evidence that no work was admitted.

For a known pre-admission Generate capacity denial, the server must first
validate the request and its actual authorization, verify current liveness,
and echo the matching initial `steamboat-binding-bin`. It then sets one binary
trailer, `steamboat-capacity-rejection-bin`, whose 37-byte value is ASCII `SNCR`,
byte `0x01`, and the 32-byte SHA-256 digest of those exact canonical binding
bytes. This is a closed, versioned C1 application marker under the existing
8 KiB metadata bound. It does not change the initial binding parser or its
4 KiB limit. Both ends must use this secure-profile revision.

The client may preserve the shared channel only when that marker is exact and
unique, the initial binding matches, authorization remains live, no response
frame has arrived, and the RPC ends with `RESOURCE_EXHAUSTED`. The rejected RPC
still fails; no work is counted as accepted and no automatic retry occurs.
Missing, malformed, duplicate, wrong-version or wrong-binding markers and
transport-only exhaustion remain ambiguous and retain the fencing behavior.

Only confirmed pre-admission limits may emit the marker: capture admission,
the canonical coordinator queue, and the bounded Generate stream limit.
Post-admission or unknown submission failures must use an execution failure or
failed terminal result without this marker. Rejection must not create a model
reservation or tensor merely to report a full stream limit. The marker relies
on the trusted coordinator and authenticated TLS stream; it is not independent
proof against a Byzantine or malicious authenticated coordinator. It is not a
bare-status exception and does not authorize retry. The marker implementation
is present in both endpoints, but combined Linux validation of the matching
trailer, client channel-preservation decision, and shared-stream behavior is
still pending. Until that gate passes, treat unmarked or otherwise ambiguous
`RESOURCE_EXHAUSTED` as uncertain and retain the existing fencing behavior.

## Trusted coordinator request context

Secure coordinator `Generate` requires a validated in-process
`TrustedRequestContext`, produced by a trusted adapter after it authorizes the
actual consumer request. It is not network JSON, and valid ID shapes alone do
not prove authority. Its API is:

```python
from steamboat_runtime.participant_context import TrustedRequestContext

context = TrustedRequestContext(
    tenant_account_id=tenant_account_id,       # acct_ + 32 lowercase hex
    request_id=request_id,                     # req_ + 32 lowercase hex
    session_id=session_id,                     # ses_ + 32 lowercase hex
    route_id=route_id,                         # route_ + 32 lowercase hex
    coordinator_boot_id=coordinator_boot_id,   # 32 lowercase hex
    route_epoch=1,
    attempt=1,
    authorization=consumer_authorization,
    hard_monotonic_deadline=deadline,
)
handle = coordinator.submit(tokens, new_tokens,
                            trusted_request_context=context)
```

The consumer authorization exposes synchronous `assert_live()` and
`remaining_seconds()` methods. The capability validates ID types and shapes,
the fixed v1 route epoch and attempt, the authorization interface and a finite
future monotonic deadline. It is single-use; its typed `ses_` ID becomes the
coordinator request/session key. Coordinator admission rejects an already
active session ID before inserting request state and clips admission and the
request deadline to the capability's remaining lifetime.

Secure coordinator `Generate` accepts only that typed `ses_` plus 32 lowercase
hexadecimal session ID on every stream event and requires the ID to stay stable
through the terminal result. The legacy `remote_client.py` stream contract keeps
its existing raw 32-hexadecimal ID shape.

Request-specific worker `Describe`, `OpenSession`, `Step` and `RenewSession`
calls receive the exact context. `CancelSession`, `CloseSession` and
`SessionStatus` retain it for bounded cleanup after consumer expiry; the
outbound adapter must still verify its coordinator role and exact existing
worker owner. Cleanup does not restore permission for data operations. The
cleanup deadline is at most 20 seconds and no later than the original request
deadline plus 20 seconds. Startup `Describe`, which has no consumer context,
requires a separate outbound bootstrap policy.

With `trusted_request_context=None`, legacy coordinator calls use the original
three-positional-argument `_execute(index, method, request)` path without added
keywords. Legacy worker clients likewise receive no new keyword. A non-None
context is passed explicitly through every operation so concurrent stage loops
do not depend on task-local request state.

The secure coordinator service accepts only an actual `TrustedRequestContext`
from its context factory, tied to the same consumer `Authorization`. `None`,
`False`, dictionaries and unrelated objects are rejected before metadata
emission or submit. The concrete consumer factory, outbound worker authorizer, watcher and leaf
adapter are composed in the [local secure pipeline test](PARTICIPANT_SECURE_PIPELINE.md).
Selected local numerical and lifecycle paths have run; the full C1a fault,
resource and independent acceptance gate remains unfinished.

## TCP gate, private gRPC backend and limits

Each secure server binds the gRPC TLS server to a private Unix-domain socket
inside an owner-owned mode-0700 directory. A small TCP gate binds the explicit
configured numeric interface and forwards opaque TLS bytes to that socket. The
gate does not terminate TLS or change the TLS name. The client still connects
to the original numeric IP, verifies its IP SAN, and trusts only the pinned
leaf.

For each accepted TCP socket, the gate reserves a live node-wide pending token
before forwarding. It creates a unique private UDS client path ending in
`gate-client.sock`. After the actual server handler has read the TLS peer PEM
from `auth_context`, authorized the request and checked the echoed binding,
`context.peer()` is used only to find that gate connection and release its
pending token. The peer path is resource bookkeeping, not identity. A
connection with no authorized RPC, including TLS completed without an HTTP/2
preface, expires after five seconds measured from its pending reservation.
Backend UDS setup and connect time count inside that same deadline.

The gate forwards through two pumps per connection. Each pump reads at most
64 KiB per iteration. At the four-pending ceiling this is at most eight
concurrent pumps and two Python socket descriptors per proxied connection,
plus the gRPC backend socket and C-core's own descriptors. The module can hold
at most two 64 KiB payload chunks per proxied connection at once; kernel socket
buffers, TLS state and C-core buffers are outside this Python-level estimate.
The mTLS unary integration test sends and receives through both pumps.

Static capacity and live pending handshakes are separate:

| Bound | Accounting |
| --- | --- |
| Node connections | At most 16 combined static reservations across inbound listener slots and outbound channels, in one shared controller |
| Listener profile | Explicit `listener_slots=1` or `2`; C-core incoming cap and static reservation use that exact value |
| Static topology | Each inbound slot costs one; each outbound gate reserves three (one fixed-peer socket plus two private C-core/proxy socket slots). Four one-slot listeners plus four outbound gates use all 16 slots |
| Live handshakes | One runtime counter, maximum four, shared by inbound TCP gates and outbound initial setup; outbound setup is additionally capped at two |
| Outbound per peer | At most two statically reserved gates per peer |
| RPCs | 32 concurrent worker RPCs; 52 coordinator RPCs; at most 40 Generate streams |

Idle listener reservations do not consume live pending tokens. An established
inbound connection continues to consume one of its listener's static slots,
but releases its dynamic pending token after the first authorized RPC. Outbound
setup reserves one shared live token before opening its local gate or
constructing the channel. The same token stays reserved through the one CONNECT,
fixed-peer TCP connection and end-to-end TLS readiness. After readiness, the
token is released while the established connection retains its static three
slot reservation. Each connector accepts one local CONNECT only and closes its
listener immediately after that accept. Hidden C-core reconnects cannot create
another upstream socket through the retired gate. A later explicit operation
may create a fresh gate after prior teardown is confirmed.

Rejected or expired gate connections close both sockets, wait for their
forwarding pumps to exit, and then release the pending token. Authorized
connections release that token when the first RPC passes identity and grant
authorization. Cancellation cleanup is capped at five seconds; unfinished
cleanup retains its connection accounting and marks the service unavailable.
`SecureAcceptor.wait_for_idle(timeout)` is an awaitable observation point that
returns only after tracked connections and their pending tokens are retired.

### Outbound one-shot connector

`SecureConnector(endpoint, allowed_addresses, *, pending_reservation,
handshake_deadline, lifetime_seconds, on_lifetime_expired,
cleanup_grace=5.0)` binds an ephemeral
loopback CONNECT listener for one channel. It accepts one HTTP/1.0 or HTTP/1.1 CONNECT request
whose target must exactly match the configured numeric IPv4 endpoint. The
request has a 4 KiB header ceiling, bounded field count and lengths, a private
per-gate token, no duplicate or unknown fields, and no body framing. The gate
dials only the validated fixed address and forwards opaque bytes through two
64 KiB backpressured pumps. It never terminates TLS or reads inference data.
The `pending_reservation` passed at construction is the same shared token the
subchannel acquired before channel construction. The connector releases it
after TLS `READY` is confirmed, or during pre-ready teardown only after closure
is confirmed; it never allocates a second pending token.
The internal subchannel receives a preflighted monotonic `absolute_deadline`
alongside the remaining timeout. It starts the five-second setup cap before
waiting for its lock or constructing the gate/channel and never rebases the
request or authorization deadline.

The native gRPC address-proxy options are private to that channel: retries are
disabled, the local subchannel pool is enabled, the proxy address is its owned
loopback port, and the enabled address set is exactly the peer IPv4 `/32`. The
HTTP proxy environment is explicitly overridden per channel. The gRPC channel
still targets the original configured endpoint and keeps its pinned leaf as its
only root certificate, so ordinary IP SAN verification remains active. No
authority override or direct-connect fallback is configured. A closed or
consumed gate cannot forward a reconnect. Setup uses the absolute request/auth
deadline clipped to five seconds; after readiness the gate independently
invokes the owning subchannel's close callback at 300 seconds and expires the
tunnel.
Any initial channel readiness failure, including a bad pinned leaf, surfaces as
a generic `SecureTransportError` before RPC dispatch; no operation is replayed.

The connector owns its one-shot listener, accepted local socket, fixed-peer
socket and pump tasks. The subchannel first awaits gRPC channel close, then
retires the listener. For a connected tunnel it requests bidirectional socket
shutdown while retaining both descriptors and the pump readers. It waits for
the accept task and both pumps to exit, then closes the descriptors and checks
that local ownership is gone before releasing the static reservation. This
ordering matters on Linux `SelectorEventLoop`: immediate descriptor close can
leave a registered `loop.sock_recv` pending, while shutdown with the descriptor
still open wakes it with EOF. Pre-pump cleanup closes synchronously only after
the active socket operation unwinds and no pump reader owns the descriptor.
Closure evidence records observed EOF, peer reset, or completed owners and
closed descriptors; it does not claim that the remote
TCP stack has processed a FIN.
If task or descriptor closure cannot be confirmed within the bounded cleanup
grace, the client remains unavailable and retains its static reservation and
any pending token. Python cannot force-stop a stuck kernel task. A channel is
not recreated until confirmed local ownership teardown.
SecureTaskPending and SecureConnectorPending are ordinary transport failures
carrying the still-owned tasks. They are deliberately not subclasses of
asyncio.CancelledError: asyncio treats a task that raises a cancellation
subclass as cancelled, and later task/gather observation can lose the attached
child-task list. Resource-owning callers must catch these pending failures
before broad exception handlers and keep authorization, connection capacity,
and descendant task ownership until those tasks finish. CancelledError
continues to mean actual cancellation.
Coordinator stage/request loops, SecureAcceptor proxy cleanup, and secure
coordinator unary/Generate paths now have explicit pending-failure ownership
handling in the source. That ownership is local lifecycle protection, not proof
that every transport or socket fault has been validated; see the scoped Linux
evidence and remaining limits below.
This controller is process-local and does not coordinate separate daemons.
The parent Linux socket-retirement probe observed the selector result 3/3 times:
`shutdown(SHUT_RDWR)` with the descriptor retained woke `sock_recv`, while
shutdown followed by immediate close left it pending. Its script and log are
`probe-linux-socket-retirement.py` and
`linux-socket-retirement-probe-1792258745747.log` (SHA-256
`4f08e36d663992d88631171ec77ccfd7544ebcf51fe86e9c81bd89bfd7b2fd5b`). This
isolated probe establishes the shutdown ordering mechanism only. A follow-up
probe showed that tasks raising CancelledError subclasses are observed as
generic cancellation by later task inspection, losing their attached child
tasks; the parent probe and log are probe-cancelled-exception-ownership.py
and probe-cancelled-exception-ownership-1792259540605.log (SHA-256
925b8bc44549af455bac624c12edc59fba094918fb2fbb4f2f7c91adae499646). The
The recorded Linux runs are scoped, not an all-pass result. The
clock-and-identity suite passed 31 tests, and three public-client cancellation
and late-descendant tests passed separately. A 195-test combined security run
had two fixture failures; an earlier 244-test cleanup run had one retained
cleanup-verification error (`cleanup_pending_captures` remained 5). The two
195-run failures were fixture issues: the late-descendant test created its child
before its release barrier, and a fake gRPC context omitted the trailing-metadata
setter. These failed runs remain part of the evidence and must not be summarized
as passing. Two newer fault cases exercise caller-boundary
conditions rather than raw socket faults and still need Linux combined
validation. Passing component tests do not establish the paired marker behavior
or C1a acceptance.

The retained records are `clock-and-identity-required-1792269850336.log`,
`client-owner-prefixed-control-required-1792270490722.log`,
`capacity-marker-owner-identity-required-1792269969101.log` (195 tests, two
fixture failures), and `all-security-required-1792268350171.log` (244 tests, one
cleanup-verification error). The latter failure includes unreclaimed capture
reservations and remains visible; do not infer a green combined suite from the
separate positive records.

`NodeConnectionBudget` is process-local. It cannot enforce a shared bound
across separate processes; such a topology needs an external shared
controller. The C-core options are not enforcement evidence by themselves.
The pinned runtime test suite includes behavioral checks for
incomplete-handshake rejection, five-second expiry, reconnect, the aggregate
four-pending bound, and independent established TLS connections without
HTTP/2 prefaces. Those cases use independent raw sockets so HTTP/2 pooling cannot
reduce the counted connections. C-core arguments alone are not enforcement
evidence, and the recorded subset runs do not establish every bound as accepted.

## Checks and evidence status

`tests/security/test_secure_connector.py` uses local stdlib sockets to check
the strict CONNECT parser, fixed target, bounded headers, one accept, opaque
forwarding, layered half-close response flow, stalled opposite-direction
cleanup, descriptor closure evidence and the absolute readiness deadline. Two
Linux-only socketpair regressions hold `sock_recv` owners across shutdown and
check that descriptors close only after the readers finish; they are skipped
on other host platforms and cannot prove C-core behavior. The gRPC shutdown
assertions also require terminal results from both directional pumps before
they accept descriptor closure.
`tests/security/test_secure_transport.py` covers endpoint validation, the
transport-to-C0 adapter field mapping, strict authorization liveness, clipped
deadlines, cancellation, static and dynamic connection accounting, shutdown
retry, Generate admission and typed session IDs. The coordinator runtime suite
also covers the legacy `_execute` override signature and explicit context
forwarding.

`tests/security/test_secure_transport_core.py` imports the actual C0 expected
leaf verifier and has no stub or skip path. `test_secure_transport_grpc.py`
uses synthetic certificates and real loopback gRPC mTLS to check certificate
provenance, binding echo, the private UDS backend and TCP gate, wrong-leaf
rejection, incomplete-handshake limits, aggregate pending accounting, timeout
and reconnect, independent TLS sockets without HTTP/2 prefaces, and outbound
native-proxy mTLS with the proxy address distinct from the original target.
It also holds two real RPC streams concurrently and verifies that they share
one HTTP/2 tunnel, retains the static connection reservation while one actual
directional pump finalizer is held after EOF, and permits fresh-gate recovery
only after confirmed teardown.
Fixtures write temporary synthetic PEM files under ignored `.lab` storage.

The Windows host runtime lacks protobuf, gRPC and Torch, so it did not run the
Linux transport suite. The [recorded real-model TLS pipeline matrix](experiments/2026-10-17-participant-c1a-local.md)
passed one test with zero skips and compared exactly 27 last-position vectors
over prompt lengths 1, 128, and 1024; the greedy-token control was checked
separately within that test. A later standalone TLS lifecycle run also passed
one test with zero skips
(`secure-pipeline-lifecycle-required-1792270060733.log`). The 27 is a vector
count, not a test count; the matrix and lifecycle runs are separate, source-
identified subset results, not a complete gate. Three
public-client cancellation/late-descendant tests also passed in a separate Linux
run. The capacity marker's combined Linux validation, the two newer
caller-boundary fault cases, remaining source review, and a fully green combined
security suite are still required. No separate-device behavior or C1a
acceptance is established.
