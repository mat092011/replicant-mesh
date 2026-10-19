# C2 bounded RPC dispatch and relay

`steamboat_connector.channel_rpc` adds a worker-side RPC service and a
gateway-side request/response relay over existing `ChannelStream` instances.
The worker service accepts only the client-side `WorkerHelloClient` stream
whose exact TLS owner is held by its `GatewayWorkerIngress`. It parses the
bounded C2 bundle and generated worker `Request`, derives the logical lane
sequence from the delegation envelope, then enters
`SecureWorkerRuntimeBridge.incoming_authorizer.authorize_gateway` with the
exact binding bytes, raw protobuf bytes and parsed request object. The core
delegation verifier and C1 authorizer remain authoritative. Worker execution
uses the bridge handler and its authorization watcher under `_run_guarded`.
Responses preserve the method and wire message ID; cleanup replies use C2 kind
7. PINGs are validated against ingress generation/control sequence and echoed
as PONGs on the worker's own framed stream.

The gateway relay accepts only actual coordinator and worker server-side HELLO
streams. It checks coordinator binding fields against that authenticated
channel, selects assignment/model from the current signed channel policy,
obtains the route guard from that same coordinator channel, and submits through
`GatewayRouter`. It retains bounded exact message-ID/method/operation mappings,
validates generated protobuf responses against the original request and route,
completes the router's pending record, then relays the response on the
coordinator stream. It also drives the router heartbeat deadline monitor and
the worker PING/PONG exchange. Any malformed message, stale capability,
uncertain send, or authorization failure closes the active stream; the relay
does not retry or adopt work.

The worker service bounds admission to nine data calls and eight cleanup calls
per stream, matching one active plus eight pending data operations and an
independent cleanup lane. The gateway router remains the admission authority
for requests queued toward workers. Socket pumping stays on the service task;
handler work is separately scheduled so cleanup can run while a Step is
computing.

The coordinator-side SDK adapter that combines `GatewayCoordinatorEgress`,
`CoordinatorHelloClient`, a metered `ChannelStream`, C1 outbound authorization
and caller response context is still pending. This component also does not
provide loaded-model readiness, model execution evidence, multi-device results,
or completion of C2/CT-12/CT-13.

Focused tests are in `tests/connector/test_channel_rpc.py` and require the
repository's isolated PyTorch/Protobuf runtime.

Each service constructor requires explicit independent data and cleanup
capture reservations. They must cover all supported admissions before parsing;
there is no default or implicit capacity. Data admission reserves
`8 * MAX_PROTOBUF_BYTES + 64 * MAX_ENVELOPE_BYTES + 16 * MAX_BINDING_BYTES +
128 KiB` per operation (currently 10,747,904 bytes), and nine slots require
96,731,136 bytes. Cleanup admission reserves
`8 * MAX_CONTROL_PROTOBUF_BYTES + 64 * MAX_ENVELOPE_BYTES +
16 * MAX_BINDING_BYTES + 128 KiB` per operation (currently 2,424,832 bytes),
and eight slots require 19,398,656 bytes. The envelope and binding factors
conservatively allow for JSON and canonical-binding object expansion before
authentication; they are accounting targets, not measured allocator peaks.
An occupied slot keeps its reservation until compute and
authorization ownership are released, including after an awaiting RPC is
canceled. Gateway relay request captures use the same independent caps.
The worker follows nested pending-task descendants before attempting
authorization retirement. Before one authorization close, it also waits on the
runtime bridge's exact-operation reclamation observer when that C1 session was
invalidated, so a separate WorkerHandler compute task cannot outlive the RPC
capture. If reclamation or authorization retirement is uncertain, that slot and
its charge stay occupied for the stream lifetime. Valid open sessions are not
waited on; successful Steps retain their cache as intended.

These reservations are separate from ChannelStream receive/reassembly and
writer queues and GatewayRouter worker-writer reservations. They bound the
configured RPC capture accounting, not Python allocator overhead, runtime
fixed state or total process memory. Role-level resource accounting must sum
co-located reservations and separately account for those costs.

After a valid delegated sequence is consumed, a C1 `SessionError` with the
ingress and bridge still live returns a bounded `EXECUTION_FAILED` response for
that exact message. A cancelled operation whose C1 owner is in
`cache-cleanup-pending` returns `CANCELLED` while its compute task, authorization
and byte reservation remain retained until confirmed cleanup. C1 session
invalidation remains authoritative; cancellation does not imply physical cache
reclamation, and subsequent session operations may receive an explicit denial.

`channel_protobuf.preflight_worker_protobuf` scans each request/response wire
payload before generated protobuf parsing. It uses a single memoryview and
scalar scanner state, rejects unknown/duplicate singular fields, invalid wire
types, nonminimal or overflowing varints and truncation, and limits nested
TensorEnvelope shape expansion to three values before protobuf sees it. The
protobuf factor, envelope expansion factor and binding expansion factor are
conservative accounting targets for decode, canonical-copy and JSON parsing
transients. They are not measured allocator peaks or a process RSS guarantee;
the native focused run must measure/control the implementation on the pinned
runtime.

Heartbeat payloads use the fixed 13-byte `C2H1` PING/PONG contract. The worker
service validates gateway PINGs against ingress generation and logical control
sequence, while the gateway relay periodically enqueues PINGs through the
router's shared control counter and checks exact PONG echo/liveness. These are
transport liveness checks, not evidence of loaded-model readiness.

Run the focused suite with:

```powershell
$env:PYTHONPATH = 'src'
python -X utf8 -B -m unittest tests.connector.test_channel_rpc
```
