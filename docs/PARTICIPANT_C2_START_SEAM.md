# C2 process start seam

`ProcessRoleBackend.spawn_owned_start` and `observe_owned_ready` separate local
process ownership from the child's READY signal. Spawn validates the selected
fixed role, policy and persisted configuration, retains the current artifact
pin, creates its cgroup, publishes one strong `Popen` owner, attaches the child,
and releases the inherited bootstrap gate. It then returns an opaque,
backend-bound `PendingRoleStart`; it does not read or infer READY. The handle
grants only one bounded observation and is not a role, claim, readiness or
execution capability.

The C2 caller can hold its selected root-store head and trusted enable snapshot
through the complete local claim and immediate ownership publication, then
release those snapshots before waiting for READY and the child's store fsync.
`before_popen_check` is an optional trusted synchronous callback executed after
configuration and pin checks immediately before `Popen`. It must return exactly
`None`; awaitables and every other return value fail closed. Callers must keep it
to a fast in-memory check and must not perform I/O there. Cancellation and the
current start-intent identity are rechecked after the callback and immediately
after publishing the process owner, before entering `Popen`.

The backend retains the start intent and strong child owner while a handle is
pending, including when the caller abandons it. Existing `request_stop`,
watchdog escalation and bounded `stop` remain independent of READY observation.
Stop reclamation invalidates the pending handle; a racing READY result cannot
restore readiness. The final process poll is followed by another Stop/Drain and
generation check before READY can be reported. Gate pipe descriptors are
consumed before close attempts so an ambiguous close error cannot cause cleanup
to close a descriptor number that has since been reused. READY observation
accepts only a current handle made by the same backend, one time, with a timeout
from zero through 30 seconds. The compatibility `start` method calls both
phases and keeps its boolean result.

This seam is local process lifecycle support. It does not connect process starts
to C2 claims or enablement, prove loaded runtime readiness, add a coordinator
adapter, or complete C2 acceptance. The focused tests use fake cgroups and
processes to cover ownership and stop races; the separate native pinned-runtime
suite must continue to exercise real `Popen`, cgroup attachment and fork
behavior.
