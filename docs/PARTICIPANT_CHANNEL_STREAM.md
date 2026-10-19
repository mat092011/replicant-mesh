# Metered framed C2 stream component

This component composes one exact `ChannelSocket` with one exact worker or
coordinator HELLO client/server owner. Its constructor is post-TLS: the caller
must first drive the genuine owner-minted TLS handshake through the socket
driver, so handshake records consume the same data traffic allowance as later
TLS records. It accepts no external SSL context, SSL object, or caller-asserted
peer identity. A worker HELLO server stream can expose its existing registration
only after it has validated the actual HELLO and the corresponding ACK has been
fully drained through the owned socket/TLS transport.

The client queues its exact HELLO frame once through `ChannelSocket.offer_plaintext`.
The server feeds actual driver plaintext to `feed_hello`, then queues the returned
ACK through that same driver. Client ACK validation also consumes actual driver
plaintext. No direct MemoryBIO helper sends or reads the bootstrap. Normal
fragment sequence 2 becomes available only after bootstrap commitment. The
server's application admission remains closed until the ACK's plaintext,
ciphertext and TLS output buffers have drained. A failed or ambiguous write
retires the writer, decoder, TLS owner and TCP socket; it never retries a frame.

`ChannelStream.pump()` delegates each bounded nonblocking socket iteration to
`ChannelSocket`, consumes at most one returned plaintext chunk (16 KiB), drains
the fragment decoder iterator in that call, and queues at most one outgoing
writer frame. The decoder iterator is always exhausted or closed before another
feed. Decoded bundles enter `PendingMessageLanes`, which admits at most eight
data and eight control messages under the caller's explicit byte capacity and
returns control first. Overflow retires the whole stream. Consumers receive
decoded bundle objects; method dispatch, authorization, session handling,
generation negotiation and end-to-end route claims belong to later components.

The writer uses its explicit communication reservation for up to eight pending
data messages plus one active data message, eight control messages including an
active control message, payload retention, fragment buffers, ID history and
bounded metadata. The stream's `reservation_bound_bytes` includes that writer
reservation, the HELLO decoder reservation, decoded queue bytes and metadata,
two bounded HELLO-frame buffers, socket scratch allowance, and an explicit TLS
owner reservation. The TLS reservation must be at least four 64 KiB BIO bounds;
the owner itself still enforces its own BIO and handshake ceilings. The
reservation is a component budget, not a measurement of Python allocator RSS.
Process-global HELLO replay tables are shared component state and need separate
host-level accounting when the runtime adopts this stream.

Outgoing `CONTROL`, `CONTROL_RESPONSE`, `CLOSE`, and `HEARTBEAT` fragments are
offered to the socket driver with cleanup traffic classification; data and
response fragments use data classification. Incoming cleanup mode is explicit
and irreversible. It first latches the decoder into control-only mode, then
meters socket receives as cleanup. The decoder rejects DATA/RESPONSE as soon as
the complete fragment header identifies that lane, before copying or
reassembling its payload. Before its decrypted header is available for
classification, the driver may already have read and charged TCP payload that
decrypts to as much as the bounded 16 KiB plaintext chunk, plus TLS record
overhead. Thus the charged encrypted payload can exceed 16 KiB. Once the header
is rejected, the whole stream retires and performs no further socket reads.
Entering cleanup mode with a partial header, frame, or message also
retires the stream, because its classification is incomplete. The fixed framed
caller must validate operation-specific cleanup semantics; this component does
not claim that a caller-provided kind proves cleanup intent.

The stream rechecks the genuine TLS owner's current clock, handshake deadline,
and policy or credential state at public readiness, registration, enqueue, and
pop boundaries. A failure permanently retires the socket, writer, decoder and
registration capability, including when a decoded bundle was already queued.

The stream reports actual TCP payload byte counts from `ChannelSocket`, including
handshake and TLS overhead. Those counts exclude IP headers, retransmitted
segments and other link-layer bytes. Metered counts are the local TCP socket
send/receive syscall payload lengths, not the number of plaintext bytes.
`transport_bootstrap_complete` means only that this bounded HELLO/ACK transport
exchange committed; it does not mean that a model, worker, gateway route or
inference session is ready.
`cleanup_status` reports the local close request state only; it is not an
independent proof that a remote process or resource owner has been reclaimed.

Run the portable integration tests with:

```powershell
$env:PYTHONPATH = 'src'
python -m unittest tests.connector.test_channel_stream
```

The loopback fixtures use genuine TLS owners and real connected TCP sockets. A
test-only wrapper limits actual socket sends and injects one `EAGAIN` to exercise
partial nonblocking output. These tests establish local component behavior only;
they do not establish an executing C2 route or separate-device inference.
