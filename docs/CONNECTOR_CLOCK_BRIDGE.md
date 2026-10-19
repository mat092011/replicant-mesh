# Owned child clock bridge

`steamboat_connector.clock_bridge` lets one supervised Linux child use the
parent process's exact, operator-configured `steamboat_security.clock.Clock`.
The parent samples that Clock; a fixed child asks for one sample over a private
inherited `AF_UNIX/SOCK_SEQPACKET` pair. Frames are fixed-size binary records
with a nonce, generation and strictly increasing sequence. Linux peer
credentials bind each message to the expected parent or child PID and UID.
There are no commands, JSON payloads, callback imports or remotely selected
clock values in the protocol.

The parent creates `OwnedClockBridge(clock)` before process creation, passes
`child_fd` to the fixed child, binds the actual Popen PID and UID with
`bind_child`, and transfers the returned closed `child_metadata` to that child.
The metadata contains exactly the endpoint FD, server nonce, generation, both
process identities and the kernel boot ID. The child constructs
`ChildClockBridge(metadata)` and gives `owner.clock` to its C2 binding and every
other clock-dependent owner. Once Popen has inherited the descriptor, the
parent must call `close_parent_child_copy`; a forked child must call
`close_inherited_parent_copy` and transfer the child endpoint wrapper with
`detach_inherited_child_copy` before it starts the bridge. The fixed bootstrap
and C2 child schema do not yet transport this metadata; an integration must
provide that handoff before C2 binding can start.

Each child `Clock.sample()` causes one parent sample. The child receives the
sample's wall time, monotonic time and uncertainty from that same Clock read;
it checks that the parent's monotonic value falls inside the local IPC bracket,
advances wall time to local receive time, and adds the full round-trip duration
to uncertainty. Unknown, non-finite or over-30-second uncertainty fails closed.
The child clock callbacks reuse one immutable IPC sample for the complete
`Clock.sample()` operation and return one private generation token. Any malformed
frame, identity or sequence mismatch, EOF, timeout or provider failure latches
the child bridge and its `Clock`.

Both processes pin the kernel boot ID and continually intersect bracketed
`CLOCK_BOOTTIME - CLOCK_MONOTONIC` intervals. A suspend/resume discontinuity
breaks that intersection and fails the generation; a caller must not use
`Clock.revalidate_after_resume` while a bridge generation is live or retained.
This is a same-kernel clock handoff. It does not measure network time accuracy,
make the parent's Clock trusted, or prove that a separate remote device shares
its clock domain.

At most eight generations can be reserved process-wide. A slot is retained
while its service thread remains alive or its child has not been confirmed
reaped. `stop()` only sets the stop event and consumes/shuts down owned endpoint
descriptors; it never joins the thread or waits on the Clock lock/provider.
Callers must retain the owner until `quiescent` is true after actual child reap.
An unresponsive parent Clock can leave a daemon service thread and its slot
retained until that provider returns; process restart is the recovery boundary.
This bridge is a clock transport primitive, not a role process, readiness,
policy, resource allocation or artifact authority.

Focused native validation:

```text
python -Xutf8 -B -m unittest tests.connector.test_clock_bridge -v
```

The tests require Linux `AF_UNIX` credentials, `CLOCK_BOOTTIME` and `fork`.
Windows skips these native integration checks; portable results do not establish
that inherited-descriptor behavior works on the supported Linux parent.
