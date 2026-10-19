# C2 personal-coordinator runtime binding

`steamboat_security.root_c2_coordinator.load_c2_personal_coordinator_binding`
binds one protected local PERSONAL COORDINATOR role credential to the selected
C2 activation. Its explicit
`native_posix_root_c2_personal_coordinator_v1` header has a closed schema and
pins the raw header through the exact selected `RoleLaunchSpec`. The loader
checks the actual C2 selection, exact selected coordinator launch member,
protected header and opaque runtime bytes, matching certificate/private key,
and current selected C1 role credential and route-grant scope.

The coordinator uses its selected C1 role certificate for TLS identity. This
profile does not define or accept a `coordinator_stream` channel certificate.
The actual gateway channel, `ChannelPolicy`, route pins, and TLS peer checks
remain the responsibility of the existing coordinator egress and TLS factories
when a role adapter is implemented. The opaque runtime bytes are not parsed as
commands or peer paths. They do not yet contain a validated assigned offline
weight set or an authorized route adapter.

Every exposed identity, TLS-material, launch-spec, and runtime-configuration
accessor runs the liveness guard. The guard revalidates the raw C2 selected
cohort, protected files, and currently selected signed policy before returning;
it takes its final clock sample under the binding lock after storage and file
operations. A newer selected policy can be reconciled with
`refresh_selected_policy()`. Policy commits use the same caller-owned
`RootGenerationStore` and a compare-and-swap selector head; a competing binding
is accepted only when it selected the exact same signed bytes. Failures
invalidate the binding once and send bounded synchronous notifications after
releasing its lock. Notifications do not prove that a process or resource was
actually cleaned up.

The binding retains monotonic deadline floors for signed snapshot expiries,
pinned credential identities, and exact grant identities. A change in clock
uncertainty or re-signing the same policy cannot extend an observed authorization
window. A new signed snapshot expiry or grant identity can establish a new
window, while the same pinned credential retains its earlier deadline. Floor
history has fixed bounds and exhaustion requires a cold restart.

This is an inert binding prerequisite. It does not start or supervise a
coordinator, consume a launch claim, publish READY, create a channel, validate
loaded weights, or prove cleanup. The parent `LocalIdentity` is not a proof of
readiness. Root storage requires native POSIX no-follow support.

Focused portable contract checks:

```powershell
$env:PYTHONPATH = 'src'
uv run python -Xutf8 -B -m unittest tests.security.test_root_c2_coordinator -v
```

The protected selected-store integration must be run on the supported native
POSIX parent. No such coordinator integration result is claimed by this
component report.
