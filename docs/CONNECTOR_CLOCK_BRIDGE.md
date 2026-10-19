# Owned child clock bridge

`steamboat_connector.clock_bridge` lets one supervised Linux child use the
parent process's exact, operator-configured `steamboat_security.clock.Clock`.
The parent samples that Clock; a fixed child asks for one sample over a private
inherited `AF_UNIX/SOCK_SEQPACKET` pair. Frames are fixed-size binary records
with a nonce, generation and strictly increasing sequence. Linux peer
credentials bind each message to the expected parent or child PID and UID.
There are no commands, JSON payloads, callback imports or remotely selected
clock values in the protocol.

The parent creates `OwnedClockBridge(clock)` before process creation and calls
`begin_spawn()` immediately before Popen/fork. That lease reserves the slot and
protects the child descriptor number until the caller reports the actual PID
with `bind_child`, closes its inherited copy, and later confirms reap. A caller
may use `cancel_spawn_without_child()` only when it knows process creation
definitely did not produce a child. An unknown Popen outcome retains the lease
and descriptor indefinitely. After `begin_spawn`, pass the returned `child_fd`
to the fixed child, bind the actual Popen PID and UID, and transfer the returned
closed `child_metadata` to that child.
The metadata contains exactly the endpoint FD, server nonce, generation, both
process identities and the kernel boot ID. Once `bind_child` has created this
metadata, the parent should close its inherited descriptor copy with
`close_parent_child_copy` and transfer the metadata. The child constructs
`ChildClockBridge(metadata)` and gives `owner.clock` to its C2 binding and every
other clock-dependent owner. A forked child must call
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

At most eight generations can be reserved in the connector process. A pending
spawn lease, including a stopped lease with unknown outcome, continues to
consume its slot. An unbound live owner is not quiescent. A slot is released only
after stop is terminal, both owned endpoints are confirmed closed, the service
thread has actually ended, and any bound child has been confirmed reaped.
`stop()` acknowledges the stop request and uses a nonblocking owner-lock
acquisition; if cleanup is contended, `finalize_stop()` advances it later.
Neither call joins the thread or waits on the Clock lock/provider. Ambiguous
descriptor-close results are sticky and retain the owner and slot. Callers must
retain the owner until `quiescent` is true after actual child reap. An
unresponsive parent Clock can leave a daemon service thread and its slot
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
