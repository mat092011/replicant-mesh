# C2 gateway delegation v2

This is a private C2 experiment protocol change. It does not change the C1
channel policy version or C2 fragment framing. The signed envelope has canonical
`version: 2`, uses the distinct signature domain
`steamboat-gateway-delegation-v2\0`, and requires a signed `lane` of `data` or
`control`. Version 1 and the previous signature domain are rejected; there is
no downgrade or compatibility fallback.

The worker derives a closed lane from the method: `CloseSession`,
`CancelSession`, and `SessionStatus` are control; `Describe`, `OpenSession`,
`RenewSession`, and `Step` are data. Unknown methods are rejected. The wire lane,
signed lane, and method-derived lane must match. Each lane has its own logical
counter beginning at one per ingress generation. The transport fragment counter
remains global and is not derived from either logical counter. Heartbeats share
the control FIFO and counter; the sender must allocate them in control enqueue
order.

Under the ingress admission lock, the receiver checks generation and the
expected lane sequence, verifies the complete signature and exact C1 binding and
raw request digest, then consumes the valid logical attempt before C1 grant,
session, or handler admission. A later denial therefore consumes the sequence.
Invalid signatures, malformed envelopes, out-of-order or duplicate attempts,
lane mismatch, and sequence exhaustion retire the whole generation. Counters
never wrap or roll back. The maximum accepted value remains `2^63-1`.

Existing C1 direct admission, operation-ID replay checks, session leases and
terminal behavior remain shared and unchanged. A control cancellation that
arrives before an OpenSession is ordinarily denied by C1 and cannot cancel a
later unadmitted OpenSession. A valid cancellation of an older admitted session
must leave late Step work subject to C1 terminal checks; it cannot recreate the
session owner. The core authorizer and secure runtime bridge require an explicit
wire lane so a future framer cannot infer it from caller-forwarded credentials.

This implementation does not provide a production framer, socket scheduling,
TLS changes, or real-route evidence. The C2 channel acceptance gates remain
open.
