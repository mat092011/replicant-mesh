# Participant Identity Core

This document describes the transport-neutral C1a identity and scoped-admission
core in `src/steamboat_security/`. The core is composed by separate runtime and
mTLS adapters documented in [PARTICIPANT_RUNTIME_SECURITY.md](PARTICIPANT_RUNTIME_SECURITY.md)
and [PARTICIPANT_SECURE_TRANSPORT.md](PARTICIPANT_SECURE_TRANSPORT.md).

C1 validation passed on 2026-10-19 after Trial 78 ran all 878 required
software-regression cases with zero skips, failures or errors in 367.862
seconds. The original 600-second watchdog and declared resource limits
were retained. Bounded split-host, RST7, Drain4, Remove4 and numerical
checks retain their separately frozen source and image identities. See
the [C1 final validation record](experiments/2026-10-18-participant-c1.md).

Earlier failed runs remain recorded with unknown causes; Trial 78 does
not explain them or establish a hardware cause. C2–C9 and broader research
statuses are unchanged.

This core guide documents one component; aggregate C1 acceptance is recorded in the final validation report. It does not establish broader research-phase completion.

## Trust material and enrollment

The core uses ECDSA P-256 keys and SHA-256 signatures. An operator creates a
self-issued cohort CA with `generate_ca()` and a separate authorization signing
key with `generate_authorization_signing_key_pem()`. The CA certificate requires
critical `BasicConstraints(ca=True, path_length=0)` and key-cert-sign/CRL-sign
usage. The authorization signing key must not reuse the CA public key. Keep both
private keys in the operator environment; neither belongs in a participant
bundle.

Role credentials are device-specific private keys and CA-signed leaves. Each
leaf is a non-CA P-256 signing certificate with a unique positive serial, critical
key usage and EKU, exact identity URI SAN
`urn:steamboat:participant:v1:<account_id>:<device_id>:<role>`, and at most eight
fixed DNS SANs and eight IP SANs. DNS SANs are canonical lowercase names with no
wildcards. The required EKUs are `client` for consumers, `server` for hosts, and
both for personal coordinators. A leaf is valid for no more than 900 seconds.
`verify_leaf()` checks the one-level chain, exact role and SAN, EKU, serial,
public-key hash, certificate hash, and validity. `verify_expected_server_leaf()`
adds the owner-pinned DNS/IP target check; it validates PEM only and does not
create a TLS channel or set channel trust.

Offline enrollment uses `create_invitation()` to issue a signed, single-use
invitation for one account/device and approved roles, valid for at most 600
seconds. `InvitationRegistry` verifies it against a pinned authorization public
key and bounds retained invitation nonces. The participant generates role keys
and CSRs locally. The operator calls `enroll_invited()` with those CSRs and the
CA private key; it returns role leaves and signed-snapshot credential records,
not the private keys. Enrollment has no network endpoint.

Renewal uses the device-side `make_renewal_proof()` helper with the current role
key and exact new CSR. The issuer's `renew_leaf()` receives the old public leaf,
the CSR proof, and a `SnapshotStore`; it does not receive the old device private
key or a caller-supplied credential record. It requires a fresh verified
snapshot, a current grant involving that credential, a nonrevoked enrolled
leaf, and the conservative 300-second renewal window. It keeps the role EKUs
and DNS/IP SAN scope, issues a new serial, and advances the credential epoch.
The operator must publish a new authorization snapshot and drain old sessions
before replacing credentials. Renewal helpers do not publish snapshots or
perform runtime draining automatically.

`publish_snapshot()` signs canonical bounded JSON with the separate
authorization key. `SnapshotStore` verifies the pinned key, exact schema,
monotonic revision, revocations, credential pins, method-specific grants and
freshness. Snapshots last at most 300 seconds; refresh target and expiry polling
are separate constants of 30 seconds and at most five seconds. `install()` is
explicit; the caller owns refresh scheduling and protected snapshot-file
replacement. Invalid signatures, duplicate/unknown fields, rollback, expired
policy, revoked identities, or invalid credential/grant pins fail closed.

## Protected credential files and clocks

`safe_read()` and `safe_write()` are Linux/POSIX-only. They require a credential
root and every nested directory to be owned by the daemon effective UID with
mode `0700`; private files must be owned by that UID, regular, and mode `0600`.
Path traversal uses directory file descriptors and no-follow opens. Reads and
writes are bounded to at most 1 MiB. Writes create a new file and never replace
an existing key. Unsupported platforms and unsafe paths raise `StorageError`.

`Clock` takes injectable wall and monotonic providers plus an explicit
uncertainty callback. Missing, nonfinite, negative, or greater-than-30-second
uncertainty fails closed. Validity checks use `wall - uncertainty` for
not-before and snapshot-issued checks, and `wall + uncertainty` for expiry.
There is no expiry grace. Monotonic deadlines are converted from the earliest
possible expiry, and unchanged snapshot/certificate/grant caps cannot extend on
refresh or after uncertainty decreases. It rejects monotonic or wall rollback,
wall/monotonic discontinuity over 30 seconds, and a changed resume token; any
anomaly remains latched until trusted-clock and policy review explicitly calls
`revalidate_after_resume(trusted_clock=True)`. A monotonic rollback requires
process restart and fresh policy installation because old monotonic deadlines
cannot be compared safely. This core does not discover or configure a trusted
system clock source.

## Binding carrier and service scopes

The carrier is one binary gRPC metadata key, `steamboat-binding-bin`, containing
canonical compact UTF-8 JSON, at most 4 KiB. Aggregate metadata is capped at
8 KiB. Duplicate metadata keys, duplicate JSON keys, noncanonical encodings,
nested values, unknown or missing binding fields, wrong types, nonfinite values,
unsupported IDs, and invalid method scopes are rejected. Binding version,
credential epoch, route epoch, and attempt are checked as exact integers; route
epoch and attempt must both be 1. The wire names are fixed:

| Service | Methods | Admitted caller and target |
| --- | --- | --- |
| `steamboat.v1.Worker` | `Describe`, `OpenSession`, `RenewSession`, `Step`, `CloseSession`, `CancelSession`, `SessionStatus` | Personal coordinator to host, using a grant for the exact actor, tenant, target, worker boot, coordinator boot where present, assignment, model, method, and both credential epochs |
| `steamboat.v1.Coordinator` | `Describe`, `Tokenize`, `Generate` | Consumer to a personal coordinator in the same account, using the exact target credential and method grant |

`steamboat.v1.Coordinator` is the current `SERVICE` constant in
`steamboat_runtime.remote_client`. No logical `Open` or `Status` alias is
accepted. Worker `Describe` may omit its expected worker boot and assignment
only for the initial discovery form; worker session operations require the full
binding. Consumer `Generate` carries a request ID. Session calls require fresh
request/session/route/operation IDs with `route_epoch=1` and `attempt=1`.

The core does not import protobuf or Torch. A worker `Authorizer` must be
constructed with `worker_request_type` set to the exact generated
`steamboat_runtime.protocol.worker_pb2.Request` class. Worker calls require
`type(payload) is worker_request_type`, the `steamboat.v1.Request` descriptor,
and a protobuf `ByteSize()` no larger than 1 MiB. The transport must enforce
its message-byte ceiling while parsing and pass the already bounded parsed
message; the core does not parse a request mapping. Coordinator calls receive
the service's bounded JSON mapping. The coordinator transport remains
responsible for its request schema and serialized message limits.

## Authorizer API

Construct a `SnapshotStore` with the pinned snapshot public key, pinned cohort
CA certificate, and one `Clock`. Install a signed snapshot before constructing
the `Authorizer`. The same `Clock` object must be passed to the store, session
table, and authorizer. For worker operations, inject the generated Request
class. The local identity binds this process's leaf certificate, process boot,
model fingerprint, and (for a host) local assignment.

```python
authorization = authorizer.authorize(
    service="steamboat.v1.Worker",
    method="OpenSession",
    payload=parsed_request,
    metadata=grpc_metadata,
    peer_certificate_pem=tls_peer_certificate,
)

timeout = min(configured_timeout_seconds, authorization.remaining_seconds())
response = await asyncio.wait_for(handler.handle("OpenSession", parsed_request), timeout)
authorization.assert_live()
authorization.complete(response)
await context.send_initial_metadata((("steamboat-binding-bin",
                                      authorization.binding_bytes),))
await context.write(response)
```

`authorize()` validates the metadata and payload type, verifies the actual peer
leaf and configured local leaf against the current snapshot, checks the exact
method grant, and returns an `Authorization`. Its `binding_bytes` are the
canonical validated bytes to echo in response initial metadata. Worker handlers
must not be entered before `authorize()` succeeds; tensor allocation remains
after the transport and existing protocol checks.

`Authorization.assert_live()` rechecks current policy and the immutable live
session owner before work or output.
`deadline_monotonic` is the earliest current snapshot, grant, actor credential,
local credential, and session authorization deadline. `remaining_seconds()`
revalidates and returns the seconds remaining to that monotonic deadline. The
transport must clip the whole RPC/handler timeout to this value and cancel
in-flight work at the deadline. A before-response check alone cannot prevent
work from continuing past expiry.

For coordinator streams, `complete(response)` does not impose event-schema
validation. The coordinator adapter owns those schemas and must call
`assert_live()` before every event emission while clipping the full stream
deadline. The adapter must echo the validated binding exactly and must not add
automatic retries.

## Two-phase session ownership and cleanup

Worker `OpenSession` payloads have no lease. Before returning authorization,
the core atomically claims an immutable owner keyed by
`(target_device_id, worker_boot_id, session_id)`. It binds all Open fields except
the fresh operation ID, both current credential identities/epochs, the
OpenSession grant, model, and reservation parameters. A duplicate Open is
admitted only for that exact owner. `Authorization.complete(response)` checks
the successful response identity and reservation, then stores only an HMAC
digest of its lease. A duplicate Open response must have the same lease digest;
the core never returns or logs plaintext leases.

Later worker operations must match that owner and lease and recheck the exact
current method grant. Ambiguous mutation failures invalidate the owner and keep
its cache reference until trusted local cleanup. Call `fail(cache_may_exist=False)`
only when the handler is known not to have allocated a cache; otherwise use the
default `cache_may_exist=True`. The keyword is required. `close()` also retains
uncertain cache references. `CloseSession` and `CancelSession` retain ownership
until the response confirms reclamation or the trusted adapter calls
`mark_reclaimed()` after actual cleanup. Only the terminal RPC that validated
the transition may complete its response; old Step/Status authorizations fail
their live-owner recheck after termination or reclamation. Reclaimed owners
remain as 30-second tombstones.

Session state is bounded to eight live/pending owners and 4,096 retained records;
there is no live-record eviction. Snapshot and session callback registrations
are each capped at 16. The operation replay table is capped at 4,096 entries
with a 300-second lifetime. Full or unhealthy bounded tables fail closed.
Snapshot refresh with unchanged credential identities and exact grant identity
keeps sessions and updates their current policy deadline, capped by the
original Open lifetime and preserved absolute expiry caps. Revocation, expiry,
rotation, or removal/change of the Open grant invalidates affected bindings
and returns bounded `SessionNotice` records. New Worker admission for a rotated
actor or target principal remains blocked until every old binding is terminal
and reclaimed. After drain, rotation requires fresh IDs; the core does not
silently transfer caches to a new credential epoch.

Reclaimed tombstones keep request and route IDs fenced for their full 30-second
retention interval. That replay fence is scoped to the fixed worker device,
boot, and assignment, so separate pipeline workers may use the same request
and route IDs without sharing owner state.

## Outbound authorization adapter

`OutboundAuthorizer` is a transport-neutral core hook for a client configured
with one immutable `OutboundTarget`. The target pins service, account, device,
role, boot, model, assignment where applicable, certificate serial, public-key
hash, certificate hash, and credential epoch. Each call re-verifies the
configured local leaf and transport-provided expected peer leaf against the
current signed snapshot, then uses the same `authorize_scope()` credential and
grant policy as incoming admission. It accepts only the exact existing wire
names: Worker `Describe`, `OpenSession`, `RenewSession`, `Step`, `CloseSession`,
`CancelSession`, `SessionStatus`; Coordinator `Describe`, `Tokenize`, `Generate`.

Worker client calls require the exact injected `TrustedRequestContext` type and
an actual core `Authorization` from an admitted consumer `Generate`. The
adapter derives tenant, request, session, route, coordinator boot, route epoch
1, and attempt 1 from that immutable context; payload identity fields must
match. Only an explicit adapter-issued `BootstrapContext` can authorize a
context-free startup `Describe`, with at most eight uses and a 300-second
lifetime. Data calls never use bootstrap context. Previously observed contexts
may authorize only `CloseSession`, `CancelSession`, or `SessionStatus` for up to
20 seconds after their current authorization deadline; records are bounded to
4,096 and do not contain leases or cache ownership. Those cleanup calls still
require the current outbound local credential, peer credential, snapshot, and
exact method grant.

Consumer clients use a separate adapter-issued `ConsumerRequestContext` with a
fresh local `req_` ID and fixed monotonic deadline. `Generate` consumes the ID
once; `Describe` and `Tokenize` carry only common binding fields. IDs are
correlation metadata, never consumer authentication. Every RPC gets a fresh
`op_` ID and the adapter does not retry. `OutboundAuthorization` exposes
`binding_bytes` and `canonical_binding_bytes`, `assert_live()`,
`deadline_monotonic`, `remaining_seconds()`, `complete(response)`,
`fail(*, cache_may_exist=True)`, and `close()`. It checks endpoint identities,
credential epochs, grants, context deadline, and current snapshot on liveness
checks; it does not create a server session owner or own a remote KV cache.

### Runtime context and worker bootstrap API

Composition contract: the incoming secure handler creates the runtime context
from the actual server-side core `Authorization`, after `authorize()` succeeds.
`SecureCoordinatorService` uses the factory's receive-time deadline API and
passes the resulting context through `Coordinator.submit()`:

```python
from steamboat_runtime.secure_context import ConsumerContextFactory

context_factory = ConsumerContextFactory(
    account_id=local_account_id,
    device_id=local_coordinator_device_id,
    coordinator_boot_id=local_boot_id,
    model_id=model_fingerprint,
)
trusted_context = context_factory.create_with_deadline(
    authorization, parsed_generate_json,
    absolute_deadline=request_deadline,
)
handle = coordinator.submit(
    input_ids, new_tokens,
    trusted_request_context=trusted_context,
)
result = await handle.result()
```

This fragment illustrates context data flow, not a complete handler. The
`SecureCoordinatorService` adapter owns authorization, context and cleanup across
success, rejection and cancellation; use that composition for runtime dispatch.

`ConsumerContextFactory` requires the exact core `Authorization` type for
Coordinator `Generate`, a current consumer-to-personal-coordinator grant, the
configured local coordinator leaf/boot/model, and payload equality with the
admitted authorization under the existing `remote_client.validate_generate()`
rules. It derives tenant and request ID from the verified actor and Generate
binding, and creates fresh `ses_` and `route_` IDs with route epoch and attempt
both fixed to one. The direct `__call__` API remains compatible. Secure server
composition uses `create_with_deadline(..., absolute_deadline=...)` to include
the already receive-based server deadline without rebasing it. The hard
monotonic deadline is the earliest of that cap, the request timeout and the
current authorization lifetime, capped at 300 seconds. Each
Authorization creates one context. The factory retains bounded live entries
without eviction; release drops its strong context reference, while one-use
fencing remains until the Authorization is terminal or deallocated. Call
`release()` only after request cleanup is confirmed. In production,
`SecureCoordinatorService` invokes the factory release hook and retains it with
the cleanup owner when work is pending; do not release merely because a wrapper
or RPC task has returned. The transport must separately enforce received-time
and whole-Generate deadlines. The
factory's optional monotonic provider must share the same process-monotonic
domain used by `TrustedRequestContext`; the default is `time.monotonic`.

For startup readiness only, wrap each actual `SecureWorkerClient` with an
adapter-minted finite Describe capability:

```python
from steamboat_runtime.secure_context import BootstrapWorkerClient

bootstrap = outbound_authorizer.create_bootstrap_context(
    lifetime_seconds=30,
    max_describes=3,
)
worker_client = BootstrapWorkerClient(secure_worker_client, bootstrap)
```

`Coordinator.start()`'s context-free Worker `Describe` calls receive this exact
capability. The wrapper injects it only for context-free `Describe`; context-free
`OpenSession`, `Step`, `RenewSession`, and cleanup calls are rejected. Explicit
non-`None` contexts are passed through unchanged, and the underlying secure
client must apply `OutboundAuthorizer` exact type, owner, grant, and deadline
checks (which reject bootstrap context on data methods). The wrapper delegates
close and async context-manager methods; it does not add TLS, permit a plaintext
legacy client, or retry requests. Starting close immediately fences new calls.
The wrapper marks itself closed only after delegated cleanup succeeds. If close
or async context exit raises or is cancelled, call `close()` again to retry the
same delegate operation; an exit retry retains the original exception
arguments. The wrapper adds no close timeout, so the secure transport remains
responsible for bounded cleanup.

`AuthorizationWatcher` is an async callable for the transport's outbound
watcher hook. Its poll interval is at most five seconds and each sleep is
clipped to the current deadline. It propagates task cancellation and parks
after completion so it cannot race a validated response into a false
revocation. Runtime session reclamation remains a separate trusted transport
obligation. The transport must use `remaining_seconds()` to clip the actual
in-flight RPC timeout; watcher polling alone cannot stop work at expiry.

## Integration limits

The identity core remains transport-neutral and does not itself call runtime
handlers. The current `SecureWorkerRuntimeBridge` polls `Authorizer.sweep()` at
most every five seconds, consumes session notices, and calls
`mark_reclaimed()` only after handler and authorization ownership are confirmed;
the secure coordinator composes the outbound context and authorization path.
Neither adapter can force-stop a worker thread, reclaim memory while compute is
live, or interrupt a long-running native operation. See the runtime and
transport guides for their separate bounds and remaining validation.

This core does not configure gRPC mTLS, TLS versions, exact-leaf channel trust,
hostname checks, connection or handshake limits, process isolation, secure
readiness, or management IPC. It has no Torch import. The identity-core tests do
not establish the combined C1a gate or C1 acceptance.

## Lightweight host tests

Run the identity-core and outbound-adapter suites with the primary runtime's
Python and cryptography installation. The test fixtures generate synthetic
P-256 keys in memory.

```powershell
python -B -m unittest tests.security.test_identity_core tests.security.test_outbound_authorization
```

Tests cover
certificate and pin rejection, signed-snapshot rollback/expiry/revocation,
conservative uncertainty and clock anomalies, strict metadata parsing, scope
and actual-certificate identity-alias rejection, duplicate Open ownership,
session theft/lease mismatch/stale completion/replay, rotation drain, bounds,
offline invitation/current-authority renewal, and protected-file operations.
Outbound tests cover both exact wire directions, fixed peer pin and target
rotation, grant/role/assignment/boot/epoch scope, real core Authorization
context injection, bounded bootstrap and cleanup contexts, fresh IDs,
method-field validation, revocation/expiry, response completion, and watcher
cancellation.
Linux runs exercise actual `safe_read()`/`safe_write()` ownership, modes,
symlinks, bounds, exclusive creation, rename/symlink races, and descriptor
cleanup. Those two Linux-only cases are expected to be skipped on Windows; the
Windows run covers portable validation helpers and unsupported-platform
failure. Run the same command on Linux before relying on filesystem evidence.

The recorded Linux run of the identity core and `test_clock_threading.py`
passed 31 tests (`clock-and-identity-required-1792269850336.log`). In the
current parent clock implementation, provider reads and acceptance/latch
updates are serialized as one sample transaction. Detected anomalies latch until explicit trusted
revalidation, while monotonic rollback requires restart. These tests cover the
implementation and injected clock cases, not the root cause or quality of a
host clock source. Production still requires an operator-approved uncertainty
provider; this evidence is not a root-cause diagnosis or C1a acceptance.
