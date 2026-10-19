# Participant Runtime Security Bridge

This note describes the explicit C1a adapter that binds the accepted C0
`Authorizer` and `SessionBindings` to the existing `WorkerHandler`. It is a
bounded implementation slice; aggregate C1 acceptance is recorded in the final
validation report and does not imply broader research-phase completion.

C1 validation passed on 2026-10-19 after Trial 78 ran all 878 required
software-regression cases with zero skips, failures or errors in 367.862
seconds. The original 600-second watchdog and declared resource limits
were retained. Bounded split-host, RST7, Drain4, Remove4 and numerical
checks retain their separately frozen source and image identities. See
the [C1 final validation record](experiments/2026-10-18-participant-c1.md).

Earlier failed runs remain recorded with unknown causes; Trial 78 does
not explain them or establish a hardware cause. C2–C9 and broader research
statuses are unchanged.

The bridge does not change the plaintext baseline when it is not selected.

## Explicit wiring

Create one bridge for one fresh `WorkerHandler` and its matching host identity.
Start it before accepting secure worker calls, then pass the wrapper pair to
the existing mTLS server. Keep the real C0 authorizer and watcher in the path:

```python
bridge = SecureWorkerRuntimeBridge(authorizer, worker_handler)
await bridge.start()
server = await create_secure_worker_server(
    handler=bridge.handler,
    listen_endpoint=listen_endpoint,
    allowed_listen_addresses=allowed_listen_addresses,
    server_identity=server_identity,
    client_ca_pem=client_ca_pem,
    authorizer=bridge.incoming_authorizer,
    authorization_watcher=bridge.authorization_watcher,
    connection_controller=connection_controller,
    listener_id=listener_id,
    listener_slots=listener_slots,
    acceptor_directory=acceptor_directory,
)
```

All arguments are required by the existing server API and must come from the
approved C0 deployment configuration; this excerpt is wiring guidance, not a
standalone launch recipe. Close the secure server first, then call
`await bridge.stop()` on the same event loop, then follow the existing
`WorkerHandler.shutdown()` lifecycle. A `False` stop result means
cleanup was not confirmed; the process must remain unavailable for its external
supervisor to terminate or restart. Do not wire the raw handler around the
bridge on a secure listener.

`SecureWorkerRuntimeBridge` accepts only the actual core `Authorizer`, its
`SessionBindings`, and the actual `WorkerHandler` type. Production transport
continues to require the generated `steamboat.v1.Request`; the dependency-free
request and handler doubles in `tests/security/test_runtime_binding.py` are
unit fixtures only. `Describe` has no session cache or session owner.

## Admission and identity binding

For every worker method, the incoming wrapper calls the unchanged core
`Authorizer.authorize` before the runtime handler, including `Describe`,
duplicate `OpenSession`, `SessionStatus`, and `CancelSession`. The adapter then
retains the exact parsed request object and actual issued core Authorization in
a bounded record before returning admission. At most 32 such records are live;
session owners remain within the core `SessionBindings` limits. It does not use
request payload identity as authority and never accepts a caller-provided
session ID or lease without the core binding and lease checks.

The record captures the core `SessionClaim` owner for a new Open, the verified
actor and local credential identities, the authenticated binding fields, model
identity, and the fixed local target device, worker boot, and assignment. Later
session operations must match that captured identity. The bridge’s private
namespace is `(target device, worker boot, assignment, session)`; C0 notices
carry target device, worker boot, and session, so the adapter supplies its one
fixed local assignment and resolves the notice only against that boot’s
captured owner. Each pending notice also carries the core owner claim and
credential/binding identity captured for that namespace; a delayed notice for
an older owner cannot invalidate a later owner that reuses the session text.
Stale target/boot notices cannot touch a new worker instance.

The wrapper checks authorization again immediately before dispatch and drains
pending notices on both sides of that final check. It checks again after the
handler returns and refuses to return a response if the authorization or owner
was invalidated. An invalidated dispatch is locally terminated even if it
returns late. The same request object must be presented to the handler; a
different object, duplicate dispatch, or dispatch after authorization closure
is rejected.

## Reclamation and failure behavior

Core invalidation is only a notice, not runtime cleanup. The bridge delivers
trusted notices to one deduplicated, bounded notice set across threads and
processes them on the handler’s owning event loop. Its capacity cannot exceed
the core session-record bound. It polls `Authorizer.sweep()` at a configured
interval in `(0, 5]` seconds (default one second). It creates no per-notice
tasks. Notice overflow, callback/scheduling failure, clock or snapshot failure,
and failed/unconfirmed handler cleanup fence new admission, set the handler’s
existing restart-required supervision state, and expose `unavailable`,
`requires_restart`, and `cleanup_confirmed` status. Overflow or a callback
failure leaves cleanup explicitly unconfirmed even if some owners were cleaned;
the bridge never auto-restarts or retries a request.

The local `WorkerHandler.invalidate_for_authorization(session_id)` method is
not a wire operation. It delegates to the existing terminal `_terminate`
path: queued work is removed, terminal state prevents a late output commit,
and cache memory remains owned while compute is in flight. A pending Open with
no handler session is not considered reclaimed while its authorization or
handler dispatch is still live; if a late dispatch creates state, completion
reasserts invalidation before ownership can be released.

Authorization closure and handler dispatch completion are tracked separately.
The bridge calls `SessionBindings.mark_reclaimed` only after all of these hold:

- No admission is being registered and no related core authorization remains
  open, including authorizations retained by `SecureTaskPending` cleanup.
- No related handler dispatch is unfinished.
- The actual handler has no live session, queued operation, active operation,
  tombstone with outstanding work, or nonzero cache ownership for that session.

If any check fails, the core owner remains reserved. This includes lost Open
replies, failed Open responses, revocation during Step, cancellation, and
rotation. A fresh credential epoch uses fresh requests, routes, sessions, and
IDs; this bridge does not preserve old sessions across rotation.

The `WorkerHandler` compute thread cannot be forcibly stopped by Python. Its
existing supervision callback/deadline remains authoritative: an in-flight
cache stays retained until the thread exits and cleanup completes. If compute
exceeds the existing grace, an external supervisor must terminate the process;
the bridge reports unavailable/restart-required and does not reclaim memory or
pretend cancellation stopped a kernel/native call.

## Coordinator context release

After `SecureCoordinatorService` creates a trusted request context, it calls
`release(context)` in a `finally` path when the factory provides that hook.
This covers validation/admission errors, normal completion, and ordinary
cancellation. The C0 `ConsumerContextFactory` provides the hook. If nested
guarded work is retained as `SecureTaskPending`, release is itself retained
until all owned tasks finish. This hook does not close Authorization, release
a Generate slot, or assert that capture buffers/resources are free.
`ConsumerContextFactory` keeps its weak one-use marker until the core
Authorization is actually closed.

## Limits and verification

The bridge composes existing C0 authorization with local runtime lifecycle; it
does not implement TLS, certificate issuance, outbound peer verification,
remote invalidation delivery, or a general session cache. The secure listener
must still be explicitly created through the existing mTLS transport. Plaintext
baseline behavior is unchanged when that adapter is not used.

Host unit coverage uses real issued core Authorizations with clearly labeled
fake Request/handler objects. The generated-Request/real-WorkerHandler test is
opt-in through the existing `STEAMBOAT_PROTOCOL_TESTS=1` gate and requires the
read-only pinned artifacts directory in `STEAMBOAT_ARTIFACT_DIR`; when enabled,
missing artifacts fail setup. This Windows host did not run model, protobuf, or
gRPC tests.

A frozen parent Linux lifecycle candidate passed 28 tests with zero skips,
including the real generated-Request/WorkerHandler/StageExecutor KV-rotation
case, terminal RPC postconditions, empty-state health, automatic maintenance,
and repeated-cancellation context cleanup. That source snapshot was 202 files
with digest
`d144461b1c83a51d660a21a9144a9a5debf7f797fa626a5605b6cfc98931ee9a`; its log
SHA-256 was
`d505baf4067a48633c463ab15e4165f4f79f290836a8cb0d78bb7d5d9cc2ad2b`. This is
candidate-specific historical evidence, not validation of later source bytes or
the complete capture-admission/backpressure path. Subsequent combined Linux
runs retained fixture/cleanup failures. At that historical source checkpoint,
C1a remained under validation and C1 and the research phases were pending; the
later aggregate C1 acceptance is recorded in the final validation report.
