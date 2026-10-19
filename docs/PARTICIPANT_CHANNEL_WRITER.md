# C2 bounded channel fragment writer

`steamboat_connector.channel_writer.ChannelFragmentWriter` is a local framing
primitive for one already-authenticated channel generation. It does not create
a socket, perform TLS, meter ciphertext, dispatch a worker request, or establish
readiness.

Construct it with a nonzero 16-byte expected generation and an explicit
`communication_reservation_bytes`. The reservation is split into fixed writer
overhead, an independent control-byte reserve (eight maximum cleanup bundles
by default), and the remaining data-byte reserve. Fixed overhead conservatively
covers one maximum bundle's codec-validation copies, two maximum wire frames
while a frame is assembled/returned, bounded message-ID history, and bounded
Python queue/accounting metadata. `reservation_bound_bytes` reports the entire
passed reservation. The caller must reserve TLS buffers, decoded/reassembled
messages, and any copies it retains separately.

`enqueue(kind=..., message_id=..., payload=...)` accepts only immutable bytes.
Request/response bundle kinds are checked by the existing C2M1 decoder before
retention; HELLO, HEARTBEAT and CLOSE use their existing size limits. Admission
is immediate and rejected messages consume no fragment sequence. Eight data
messages may wait behind one active data message. Eight control-lane messages
are bounded in count and bytes, including a partially emitted control message.
The default fragment payload is 16,328 bytes, leaving the 56-byte C2F1 header
inside a 16 KiB transport chunk.

`next_frame()` commits one frame and advances the single transport sequence.
The returned bytes are committed to this stream: send them once, then pass that
same object to `frame_sent()` before asking for another. If the send outcome is
uncertain, call `retire()` and discard the whole stream. Control fragments are
selected before the next data fragment, and an active control message always
finishes before another data fragment is emitted. Each lane has at most one
partial logical message. A message's count and payload-byte charge remain
reserved through acknowledgment of its final committed frame. Message IDs are
retained for the connection lifetime;
after 1,024 unique accepted IDs, `rollover_required` is set and further
admission is rejected so the exact history remains bounded. Sequence exhaustion
likewise requires a new connection generation.

The writer bounds its own retained messages and one in-flight frame. The stream
owner still needs to apply its shared resource reservation to TLS/socket queues,
timeouts, cancellation, restart and ownership cleanup. Passing the focused unit
tests does not establish a functioning channel or C2 acceptance.

Focused tests:

```powershell
$env:PYTHONPATH = 'src'
python -X utf8 -B -m unittest tests.connector.test_channel_writer
```
