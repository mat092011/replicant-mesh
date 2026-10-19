# C2 bounded TLS socket pump

`steamboat_connector.channel_socket.ChannelSocket` is a bounded transport
component below C1 authorization and above an already-connected TCP socket. It
accepts only exact owner-minted worker TLS, gateway worker TLS, coordinator TLS,
or a `GatewayCoordinatorEgress` whose internal TLS child is owner-minted. It
does not accept caller-provided SSL contexts, SSL objects, claimed peer identity,
or arbitrary socket facades. Tests can opt into a wrapper with `test_socket=True`.

Each genuine TLS owner exposes a non-consuming `assert_transport_live()` check.
The pump calls it before readiness, reads, writes, and every socket operation,
including flushes of already queued ciphertext. It drives handshake deadline
checks on idle pumps. Handshake bytes use the data/startup allowance.
Every nonblocking send/receive now runs through the budget's fixed
`run_socket_io` transaction: local owner lock, nonblocking ledger lock, adaptive
reservation and durable write, owner clock/deadline/policy guard, one socket
call, exact settlement and durable write. The locks remain held across that
sequence, so another role or process cannot spend the same rate/quota or strand
an allowance between operations. The API accepts no arbitrary callback or TLS
engine work. Production requires the budget and TLS owner to share the exact
same Clock instance. The lock order is driver, budget owner, ledger flock, TLS
owner, then its policy/Clock dependencies; TLS owner liveness code does not
call back into the budget.

The reservation adapts to remaining tokens and cumulative quota up to 16 KiB,
including smaller reads. EAGAIN and interruption settle zero; unknown syscall
results charge the full reservation with zero observed bytes. Known positive
I/O updates the socket counter before settlement. `io_outcome_uncertain` marks
unknown transfer, while `metering_uncertain` marks a durable-accounting failure.
Busy ledger locks, rate limits and slot exhaustion are bounded backpressure for
at most 30 monotonic seconds, checked on each subsequent pump/tick. Cumulative
quota exhaustion with queued TLS ciphertext retires the entire connection.
The component never creates or resets a traffic allocation.

The pump retains at most one 16 KiB ciphertext chunk and one 16 KiB plaintext
chunk in each direction. It performs no more than four socket operations per
direction across the whole pump call. TLS decoding continues while socket sends
are blocked, and each received chunk is decoded before another is read. A
plaintext write's ciphertext keeps its data or cleanup classification until the
TLS output buffer is fully drained; another plaintext write waits until then.
Ciphertext remains pending across partial sends; if the
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
python -m unittest tests.connector.test_traffic_budget
```

The tests use actual loopback TCP connections and real owner-created TLS
engines. They cover partial sends, EAGAIN, queued ciphertext after policy
revocation, a stalled handshake deadline, a blocked writer while six large
inbound records and a final control marker are decoded, cleanup ciphertext that
exceeds 16 KiB after its data quota is exhausted, unknown I/O outcomes, and
commit failures before and after known positive I/O. They also cover adaptive
1 KiB reads, revocation after durable reservation, hard-quota retirement, and
backpressure expiry. A genuine TLS owner with a persistent Linux ledger is
covered by a Linux-only conditional test; it is skipped on Windows. A
split-host route remains untested here.
