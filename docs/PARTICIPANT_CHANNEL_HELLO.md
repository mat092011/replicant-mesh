# C2 authenticated worker HELLO bootstrap

This component binds one worker's authenticated outbound TLS connection to the
fresh `GatewayWorkerIngress.stream_generation` minted for that exact worker TLS
owner. The worker sends one canonical JSON HELLO in one bounded C2F1 fragment
(HELLO, START|END, index 0, sequence 1, at most 4 KiB). The gateway checks the
boot, assignment, model, worker identity and policy revision/digest against its
actual `AuthenticatedWorkerChannel`, which is minted only after required client
certificate authentication and policy pin validation.

The worker ingress generation is carried on the wire. The gateway's independent
TLS connection nonce is not substituted for it. Optional HELLO metadata is not
peer proof. The gateway ACK is a bounded HELLO on the same wire generation at
sequence 1 and binds the exact HELLO frame digest plus a fresh gateway nonce.
Both ends feed the accepted bootstrap message into their ordinary fragment
decoder, leaving its next expected inbound sequence at 2. The caller must send
the HELLO frame exactly once and construct the normal writer with initial
sequence 2 only after the ACK commits.

The pre-decoder bootstrap incrementally reads one complete HELLO frame into a
preallocated 56 + 4,096 byte scratch buffer and rejects a bad header as soon as
all 56 bytes arrive. It rejects other kinds, wrong counters/generation,
duplicate JSON keys, unknown fields, noncanonical/trailing JSON, incomplete or
oversized frames. Each genuine TLS owner can be claimed only once for a worker,
coordinator, or server bootstrap. Consumed worker boot/generation and
coordinator actor/boot/nonce pairs remain in bounded process replay tables;
exhaustion fails closed. DATA is not admitted before ACK.
After HELLO validation, each endpoint creates its normal decoder with explicit
capacity sufficient for the maximum inference bundle, feeds the accepted
bootstrap at sequence one, and exposes the decoder reservation size. The
each committed bootstrap exposes initial sequence 2 for normal writer
construction. A registered-worker capability is immutable, identity-only, and
rechecks the exact genuine server TLS owner and authenticated channel on use;
it does not indicate loaded readiness or authorize an application round trip.
Reconnection, policy change, or owner replacement requires a new bootstrap.
The worker client's bootstrap construction, HELLO send, and ACK commit run
inside the ingress admission/liveness transaction, which checks both heartbeat
and delegation deadlines and latches an expired ingress closed. Duplicate TLS
owner claims are recorded atomically; closing a duplicate owner happens only
after releasing the claim registry lock.

Coordinator egress uses the same bounded bootstrap with a fresh nonce generated
inside the genuine `GatewayCoordinatorEgress` owner. The gateway compares the
announced actor, boot, tenant, and policy fields against its actual
`AuthenticatedCoordinatorChannel`. The server TLS connection nonce remains a
separate value from that coordinator wire nonce. Coordinator registration is
also identity-only and does not prove work readiness or authorize an
application round trip.

The focused tests use the existing actual mutual-TLS MemoryBIO component fixture.
The direct `send_hello`, `read_hello`, `send_ack`, and `read_ack` convenience
methods are test/component helpers for that fixture. A production driver routes
the generated HELLO/ACK frames through `ChannelSocket` so plaintext labels and
draining stay in the transport path, then passes each decrypted plaintext chunk
to `feed_hello` or `feed_ack` for bounded incremental parsing.
They do not establish sockets, gateway forwarding, readiness, inference
authority, resource enforcement, separate-device performance, or C2 acceptance.
