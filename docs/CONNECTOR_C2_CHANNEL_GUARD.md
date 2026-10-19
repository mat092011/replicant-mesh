# Coordinator channel runtime guard

`CoordinatorChannelClient` accepts an optional synchronous `runtime_guard` for
the selected C2 owner. The callback must return exactly `None`. An exception,
non-`None` value, or awaitable fences the client and rejects work. The default
`None` setting preserves the existing C1 client behavior.

The client checks the guard before request admission, after route minting and
authorization, around authorization callbacks and awaits, before enqueue and
stream I/O, while publishing replies, and before returning a result. A target
client minted by `bind_target` delegates through the same guarded client, so it
does not create an independent route or bypass owner invalidation. If a guard
fails after authorization is created, that exact authorization and route are
already attached to the request cleanup owner.

An owner may call `request_runtime_invalidation(reason)` from another thread.
This sets a sticky `threading.Event` immediately and schedules a coalesced wake
on the client loop without waiting for channel cleanup. The loop then fences
the stream and pending calls. Guard failure also fences synchronously on the
client loop. Passing no guard preserves C1 operation; requesting C2 invalidation
on such a client raises before changing its state.

This guard adds a teardown fence to the SDK client. It does not implement fixed
role startup, coordinator readiness, or broader C2 lifecycle acceptance.
