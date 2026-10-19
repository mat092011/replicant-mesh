# C2 bounded TLS socket pump

`steamboat_connector.channel_socket.ChannelSocket` is a bounded transport
component below C1 authorization and above an already-connected TCP socket. It
accepts only exact owner-minted worker TLS, gateway worker TLS, coordinator TLS,
or a `GatewayCoordinatorEgress` whose internal TLS child is owner-minted. It
does not accept caller-provided SSL contexts, SSL objects, claimed peer identity,
or arbitrary socket facades. Tests can opt into a wrapper with `test_socket=True`.

The owner drives TLS handshake and expiry checks from each `pump()` call, even
when the socket has no traffic. Handshake bytes use the data/startup allowance.
Each nonblocking socket operation reserves and checks at most 16 KiB immediately
before I/O, then settles the exact returned TCP payload byte count. EAGAIN and
interruption settle zero. An untrustworthy result charges the full allowance as
uncertain and retires the stream. Quota denial is reported as bounded
backpressure; the component never creates or resets a traffic allocation.

The pump retains at most one 16 KiB ciphertext chunk and one 16 KiB plaintext
chunk in each direction. It performs no more than four socket operations per
direction in one pump. Ciphertext remains pending across partial sends; if the
stream becomes uncertain, the whole TLS owner and socket are closed together.
EOF, socket/TLS faults, policy revocation, and clock/deadline failure are sticky.
The caller owns reconnect decisions; this component does not reconnect or retry.

`offer_plaintext(data, kind="data"|"cleanup")` accepts one chunk after TLS
handshake. `take_plaintext()` retrieves at most one received chunk. The explicit
incoming cleanup-only mode is irreversible and must be entered only after
pending data is drained. Application framing must be added above this component
to reject data messages while that mode is active; this transport has no message
classification and makes no readiness or HELLO claim.

The reported socket counters measure TCP payload bytes at the local socket API,
including TLS handshake records and TLS overhead. They exclude IP/TCP headers,
retransmissions, and other link-layer traffic. MemoryBIO counters are not used
as wire-byte evidence. This component does not prove end-to-end host identity or
route correctness; the terminating gateway remains a trusted TLS endpoint.

Focused local command:

```powershell
$env:PYTHONPATH = "src"
python -m unittest tests.connector.test_channel_socket
```

The tests use an actual loopback TCP connection and real owner-created TLS
engines, plus an explicitly test-only wrapper for partial sends and EAGAIN.
They verify both endpoint byte counters against the opposite endpoint and the
shared in-memory test meter. They do not establish a split-host route or
production persistent-ledger integration.
