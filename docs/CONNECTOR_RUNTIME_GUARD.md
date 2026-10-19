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
It makes a best-effort, nonblocking wake attempt; if the wake lock is busy, the
sticky event is still observed at the bounded maintenance cadence. The C2
invalidation is applied once on the owner loop and does not mark the C1
authorizer or handler unhealthy by itself. The supplied reason is never
retained or logged. C1 session invalidation and `WorkerHandler` cleanup run on
the bridge's owning event loop. Actual C1 cleanup errors still leave cleanup
unconfirmed.

Worker RPC cleanup attempts its one C1 authorization close even when the
reclamation observer fails. It retains the bounded request capture and fails
the stream if reclamation or post-close retirement cannot be confirmed; a
close attempt alone is not evidence that cleanup completed.

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
