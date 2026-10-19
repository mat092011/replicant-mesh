# C2 gateway producer component

`steamboat_connector.gateway_router.GatewayRouter` owns an in-process registry of
at most eight socket-driven `ChannelStream` worker generations. Registration
accepts only a live stream committed through actual TLS, HELLO and ACK on its
`ChannelSocket`; the router adopts that stream's own writer at global fragment
sequence 2 and never creates a second writer. Aggregate stream reservations are
bounded by the router reservation. Registrations are identity-only; they do not
signal loaded readiness. Slots are keyed by exact device and worker boot, while
removal also checks the exact registration object so a delayed close cannot
remove a replacement. The stream predicate and exact stream-owned writer are
rechecked at route admission and dispatch.

`submit` accepts the actual coordinator HELLO registration, worker HELLO
registration, owner-minted C1 coordinator route guard, method, C1 metadata and
protobuf bytes. It reparses the canonical binding, checks actor and target values
against the authenticated channel records and guard, hashes the exact parsed C1
binding and raw protobuf bytes, signs delegation v2 using the gateway leaf/key,
and builds the ordinary C2 bundle. The signed worker generation is the immutable
worker HELLO generation; it is distinct from the worker TLS owner's channel nonce.
Describe's compact C1 binding omits boot and assignment, so the genuine route
guard must unambiguously select the registered device+boot slot. Any optional
Describe coordinator/tenant/worker scope fields are compared to those owners.
Other worker methods require the complete strict session binding. Request bytes
are limited to the wire protobuf bound before hashing or signing. Caller metadata
is never used as peer proof.

A per-worker lock serializes data/control counters with writer admission. A
rejected/full writer queue consumes no logical counter. Control methods and
heartbeats share a control counter; heartbeats are the fixed 13-byte `C2H1`
record (`!4sBQ`: magic, PING/PONG mode, positive logical sequence). PINGs use
the next gateway control sequence and a 60-second response deadline; the router
allows one outstanding ping per generation and a 30-second minimum interval.
PONG echoes are exact and do not consume the gateway counter. Worker-side PING
handling must bind the actual TLS+HELLO/header generation, call ingress heartbeat
validation and echo PONG on its own writer. The service must call the deadline check on a timer at least every five seconds.
A bounded timer/worker receiver integration is still required before heartbeat
liveness is accepted.

The writer alone assigns global fragment sequence numbers. Pending RPCs are keyed
by unique C1 `operation_id` and exact wire message ID, while `request_id` remains
the session owner field; this permits a control RPC such as Cancel while a Step
on the same request remains pending. Admission is bounded to eight data calls
plus one active call and eight control calls. `assert_dispatch_live` rechecks all
three owner-minted capabilities immediately before forwarding, and completion
rechecks the route before releasing the exact operation, request, method and
message entry. Cleanup responses use wire kind 7. Uncertain transport progress
must retire the stream; this producer does not retry or adopt sessions.

This is a producer/registry and heartbeat codec component. The tests use loopback
TCP through `ChannelSocket` and `ChannelStream`, with separate fixed coordinator
and worker TLS purposes under one policy and clock. It does not provide worker
execution readiness, reconnect orchestration, a heartbeat timer/receiver, or
real-route evidence. C2 and CT-12/CT-13 remain open.
