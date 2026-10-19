# C2 local compute startup adapter

This is a bounded composition prototype for explicitly enabled local `host`
and `coordinator` compute roles. The connector role `coordinator` maps to the
selected C2 role `personal_coordinator`. A request must name the complete
enabled compute projection. The `consumer` role is rejected before owner state
is read or its durable start epoch is advanced; consumer startup needs its own
in-process ownership contract. Remote and global cohort members are never
launch candidates.

The operator supplies immutable local launch references. Startup first loads
and checks the selected host/coordinator runtime bindings, including protected
headers, before acquiring the selected-root shared transaction lock. The
backend must already have an artifact pin and an exact closed
`c2-local-compute-v1` role configuration. That profile binds the selected root,
protected configuration root/header path, local principal, selected launch
role, boot, generation, header digest, and launch nonce. The backend's
`spawn_owned_start` additionally hashes the role config actually read after it
owns the start intent, closing the config-replacement race before Popen.

For each attempt, owner consent is durably advanced first and held through
selected raw-head validation, local single-use claim, and publication of every
immediate owned-process handle. Cancellation is checked at every backend
Popen gate. That callback is synchronous and only reads the independent event;
it performs no filesystem access or store locking. Any partial publication
failure requests bounded cleanup while ownership remains in
`ProcessRoleBackend`. Both durable-store contexts exit before READY observation.
On READY failure, cleanup is requested and the claimed boot tuple remains
consumed. A final owner/head check is performed before returning an inert
result.

The result contains plan and claim digests plus observed backend role names. It
does not prove process identity, loaded model health, or durable readiness and
must not be used as such. This adapter does not yet wire a public controller,
serve inference, or provide consumer ownership. Portable contract tests cover
pre-consent rejection and operation exclusion. Linux process/cgroup integration,
real multi-role selected fixtures, cancellation during claim fsync, lock
ordering, READY timing, and native Popen behavior remain acceptance work; fake
process/cgroup evidence must be labeled as software-only when added.
