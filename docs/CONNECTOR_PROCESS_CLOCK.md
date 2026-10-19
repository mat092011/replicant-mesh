# C2 process Clock handoff

`ProcessRoleBackend.clock` remains the monotonic callable used for lifecycle
deadlines. C2 wall/monotonic authority is bound separately with
`bind_authority_clock(exact_clock)`. The binding is idempotent for the same
`Clock` object and cannot be changed after it is established or while a role
generation is live. `C2LocalStartup` binds its exact trusted `Clock`; its
selected artifact pin and catalog verifier must continue to use that same
object.

Only a valid, closed `c2-local-compute-v2` child configuration triggers the
handoff. A C2 profile without a bound trusted Clock fails before process
creation; legacy role configurations keep the existing path. The supervisor
creates one `OwnedClockBridge` for the captured process generation before
entering `Popen`, leases its child descriptor through `pass_fds`, and keeps the
bootstrap gate closed until the actual returned PID has been bound and the
complete `clock_handoff` metadata has been written to the private outer role
document. The inner canonical C2 configuration and its `configV2SHA` are not
changed. The inherited descriptor is only a same-host handoff; it does not
provide remote time or child readiness.

An exception from `Popen` after entry is treated as an unknown child outcome.
The bridge generation and role ownership remain retained; an empty cgroup by
itself cannot prove that no child inherited the descriptor. For a known child,
the bridge slot is released only after the process leader is reaped, its exact
owned cgroup is empty and removed, the bridge service is quiescent, and all
descriptor cleanup is confirmed. A stopped bridge that is still serving, has
uncertain descriptor cleanup, or has an unresolved spawn remains strongly
owned and prevents same-role reuse.
Stop-time reap confirmation takes the bridge owner lock nonblockingly. A busy
bridge therefore leaves the process, pin and bridge generation retained for a
later explicit cleanup pass instead of extending the bounded stop call.

The focused test uses a real local child process and the actual
`ChildClockBridge` protocol to sample the captured `Clock`. Its cgroup fixture
is only a lifecycle stand-in; this test does not prove kernel resource limits,
role service startup, READY, model loading, or numerical inference. The
clock-handoff metadata is prepared for a later fixed-child consumer; this
change does not alter role modules or bootstrap arguments.
