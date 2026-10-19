# Secure coordinator runtime guard

`SecureCoordinatorService` and `create_secure_coordinator_server` accept an
optional synchronous `runtime_guard`. The callback is an additional liveness
condition for a future selected C2 coordinator binding; it must return exactly
`None`. It does not replace or wrap the existing C1 `Authorizer`, authorization
object, trusted request context, or authorization watcher.

The adapter checks the guard before C1 authorization, after awaited
authorization and peer tracking, around context-factory/admission work, before
stream events and results, and both before and after awaited gRPC writes and
metadata operations. A callback exception, non-`None` result, or awaitable
sticks the service in the unavailable state. Coroutine guard results are closed
when possible. The sticky event wakes active RPC watchers, which take the
existing authorization-failure and resource-cleanup paths.

The post-write check prevents the operation from being treated as successfully
completed and fences later output. It cannot recall bytes already accepted by
the gRPC context before invalidation was observed.

`request_runtime_invalidation(reason)` is the synchronous owner notification
path. It sets sticky refusal immediately and schedules acceptor pausing on the
service's owner event loop. It does not wait for coordinator cleanup or claim
that active work has been reclaimed. Existing authorization close, session
cleanup, capture accounting, and uncertain-ownership retention remain in force.
With `runtime_guard=None`, the service keeps its existing C1 behavior and
watcher task topology. `request_runtime_invalidation` is available only when a
runtime guard was configured; calling it without one raises `ValueError` before
changing service state.

The focused tests use bounded fake C1 authorizations and gRPC contexts. They
cover callback ordering, sticky invalidation, watcher wakeup, late factory and
submit returns, and the before/after write fence; they do not establish a real
TLS/C2 binding or prove end-to-end worker reclamation. Run them with:

```text
python -m unittest tests.security.test_coordinator_runtime_guard
```
