# Optional C2 runtime binding guard

`SecureWorkerRuntimeBridge` accepts an optional synchronous `runtime_guard`
callback. The default is `None`, which preserves the existing C1-only bridge
behavior. A selected C2 host binding can be supplied as
`runtime_guard=binding.assert_live`; the binding remains a narrowing condition
and does not replace the bridge's real C1 `Authorizer`, gateway ingress, or
session ownership checks.

The callback must be a synchronous callable that returns exactly `None`.
Coroutine and async-generator functions are rejected at construction. If a
callback returns an awaitable or any other value, or raises, the bridge fences
itself and fails closed. Guard calls run without bridge ownership, notice,
capture, or handler locks. The bridge checks the callback around C1 admission
and completion, before and after core authorization liveness checks, at handler
dispatch and before returning a computed response, and during startup and
maintenance.

`request_runtime_invalidation(reason)` is the synchronous, thread-safe teardown
hook for a C2 binding subscriber. It sets a sticky invalidation event before
returning, so subsequent authorization and liveness checks fail immediately.
It coalesces owner-loop fencing work and does not wait for bridge, lifecycle,
filesystem, or inference locks. The supplied reason is never retained or
logged. The actual C1 session invalidation and `WorkerHandler` cleanup run on
the bridge's owning event loop. If that loop cannot accept the callback, the
bridge remains unavailable and cleanup stays unconfirmed; callers must retain
the bridge and its owners for supervision.

The post-completion guard is intentionally fail-closed: if the C1 authorization
has already committed but the selected C2 binding expires during completion,
the bridge withholds a successful result and fences the runtime because the
outcome is ambiguous. This seam does not implement C2 host loading, selected
root composition, service startup/readiness, gateway routing, aggregate
physical-resource enforcement, or an inference acceptance gate. The guard is a
runtime validity check, not peer identity evidence or a new source of request
authority. The blocked-compute regression uses the real `WorkerHandler` and
signed C1 authorization with a deterministic lifecycle executor; it does not
measure or validate model numerics.
