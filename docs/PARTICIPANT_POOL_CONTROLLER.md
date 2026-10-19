# Physical pool controller lock

`PoolControllerLock` is a local fail-closed primitive for one operator-provisioned
Linux system-RAM allocation. It validates a private `allocation.json` and holds a
cross-process `flock` for the trusted controller's execution lifetime. The lock
name derives only from the supplied SHA-256 physical-host identity and
`system_ram`; policy labels, runtime paths, and per-daemon state paths cannot
create additional lock namespaces.

The allocation file must be a bounded (4 KiB), owner-only (`0600`), single-link
regular file inside an existing owner-only (`0700`) operator directory. Version
1 has exactly these fields: `version`, `physical_host_id`, `pool_kind`, `pool_id`,
`memory_ceiling_bytes`, `cpu_quota_millis`, `controller_cgroup`, and `owner_uid`.
The host identity is a 64-character lowercase SHA-256 hex digest supplied by the
trusted launcher from the physical host's machine identity. It must not be
derived from a container hostname. `pool_kind` must explicitly be
`system_ram`; ceilings must be positive and present; the policy pool label must
match and its memory and CPU limits may not exceed the allocation. No budget is
inferred or enabled by default.

The `controller_cgroup` value is validated as an absolute normalized Linux path
without traversal. This primitive does not create or configure that cgroup,
change host settings, grant privileges, or expose a container-engine API.
Resource limits still require a trusted launcher and actual Linux enforcement.
The operator directory, physical-host identity, and allocation are deployment
trust dependencies: a private directory inside each container is not evidence
of host-wide exclusivity and cannot authorize additive budgets. A trusted
launcher must bind the same operator directory and identity into every
controller instance or refuse a second controller.

Call `assert_current(policy)` before enablement and whenever the current
allocation must be revalidated. If the allocation changes or the policy exceeds
it, validation fails while the lock remains held. Trusted cleanup may call
`release()` only after the process supervisor and resource ledger independently
confirm that owned cgroups and reservations have been reclaimed. Releasing this
file lock is not evidence of reclamation and does not release resource-ledger
reservations by itself.

Tests using temporary directories establish file validation and local
cross-process lock behavior only. Production acceptance still requires testing
the trusted host mount/identity binding and real cgroup and budget enforcement.
