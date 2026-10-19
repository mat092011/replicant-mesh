# C2 channel wire design

Status: implementation target frozen before channel measurements. The owned TLS
client primitive and this format alone do not establish a functioning gateway,
authenticated worker registration, resource enforcement or C2 acceptance. The
[connector design](PARTICIPANT_CONNECTOR_DESIGN.md) defines the trust boundary.

Both gateway hops use owned TLS engines with required server-side client
authentication and actual peer-certificate extraction. Each worker boot owns one
connection generation. Three assignments in one host role have three worker
boots/channels but share the same host reservation and aggregate traffic meter.
The client proves its configured key/certificate and the gateway endpoint; the
gateway must separately verify the actual received client certificate and policy.

The encrypted TCP payload is the accounting boundary. Count every received/sent
ciphertext byte, including handshake certificates, TLS records and application
envelopes. This is not Ethernet/IP overhead or retransmission accounting. The
service must report that boundary explicitly. Startup, artifacts and all roles
also share the owner allocation; a per-channel counter is insufficient.

## Fragment and message limits

A network-order fragment header uses `!4sBBH16sQ16sII` (56 bytes): magic `C2F1`,
kind, flags, reserved zero, generation (16 bytes), transport sequence (uint64),
message ID (16 bytes), fragment index (uint32), payload length (uint32).
Only START=1 and END=2 flag bits are valid. Generation and message ID are nonzero.
Transport sequences begin at one and advance exactly once per fragment, with
maximum `2^63-1`; no wrap, duplicate, gap or reordered fragment is accepted.
The receiver gets its expected generation from the authenticated channel setup,
not from an unverified data fragment. Nonces do not authenticate a connection.

Kinds are DATA=1, CONTROL=2, RESPONSE=3, HELLO=4, HEARTBEAT=5, CLOSE=6 and
CONTROL_RESPONSE=7. A fragment carries at most 16,384 payload bytes. One
partially assembled data message and one control-lane message may coexist;
fragments of another message in the same lane are rejected. CONTROL requests
and CONTROL_RESPONSE replies share the control lane. Index starts at zero and advances exactly once.
No abandoned or truncated message is retried or adopted by another generation.
Malformed input permanently faults the decoder and clears its buffered bytes.

An inference bundle header uses `!4sBBHIII` (20 bytes): magic `C2M1`, worker
method code, classification, reserved zero, envelope length, binding length and
protobuf length. Closed method codes are Describe=1, OpenSession=2,
RenewSession=3, Step=4, CloseSession=5, CancelSession=6, SessionStatus=7.
Classification REQUEST=1 or RESPONSE=2 must match the enclosing fragment kind:
DATA and CONTROL carry requests, while RESPONSE and CONTROL_RESPONSE carry
replies.
The signed delegation is at most 32 KiB, canonical C1 binding at most 8 KiB, and
protobuf at most 1 MiB. The total bundle ceiling is 1,089,556 bytes. Reject size
or shape violations before protobuf/tensor parsing. Responses carry no request
delegation or binding and must match a captured admitted request.

Only CloseSession, CancelSession and SessionStatus requests may enter CONTROL;
each control protobuf is at most 8 KiB. Their replies use CONTROL_RESPONSE,
carry no delegation or binding, and are limited to the same cleanup methods and
8 KiB protobuf ceiling (8,212 bytes total including the bundle header). This
separate control lane lets a cleanup reply complete while a large Step response
is still fragmented. HELLO/CLOSE are at most 4 KiB and HEARTBEAT at most 64
bytes. Those control messages are single logical messages; they may be
fragmented where necessary. Step and renewal cannot borrow cleanup credit.
The transport fragment counter is global to the TLS generation and remains
strictly increasing across all fragment kinds and lanes. Signed logical
operation counters are separate: delegation v2 has independent data and control
counters, each beginning at one for each ingress generation. Neither counter is
reconstructed from the other; each owner validates its own counter before
dispatch. Heartbeats share the control FIFO and logical counter.

## Queues, cancellation and accounting

There are eight pending logical data messages plus one active stage call, and a
separate eight-message control lane. A logical message is the bounded work frame
in the C2 contract; fragments are streaming pieces, not additional queued calls.
The reader, fragment writer and control service cannot await model compute.
Control is serviced before the next data fragment; a 1 MiB Step cannot force
control to wait behind its remaining fragments. Reassembly, pending and active
message bytes must fit an explicit reserved communication-memory budget. Queue
admission is immediate rejection when count or byte capacity is unavailable.

Before ciphertext reaches a socket, reserve its actual size in the shared
meter. Before receiving, reserve a bounded read allowance, then settle the exact
number received. Pending ciphertext cannot be dropped from a live TLS stream:
if it cannot be charged, retire the connection and its sessions. Stop new data
before data allowance is exhausted. A separate bounded cleanup allowance permits
only control; receiving data while in control-only mode closes the connection.
Malformed traffic still consumes its received-byte allowance. Handshake retries
consume startup/data credit and never obtain a fresh cleanup allocation.

These are implementation and test criteria. Actual framing, socket fairness,
metering, server authentication, loaded readiness and CT-12/CT-13 evidence are
still required before the channel can be advertised as ready.
