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
`8 * MAX_PROTOBUF_BYTES + MAX_ENVELOPE_BYTES + MAX_BINDING_BYTES + 64 KiB`
per operation (currently 8,495,104 bytes), and nine slots require 76,455,936
bytes. Cleanup admission reserves
`4 * MAX_CONTROL_PROTOBUF_BYTES + MAX_ENVELOPE_BYTES + MAX_BINDING_BYTES +
64 KiB` per operation (currently 139,264 bytes), and eight slots require
1,114,112 bytes. An occupied slot keeps its reservation until compute and
authorization ownership are released, including after an awaiting RPC is
canceled. Gateway relay request captures use the same independent caps.
The worker follows nested pending-task descendants before attempting
authorization retirement; if retirement raises, that slot and its charge stay
occupied for the stream lifetime.

These reservations are separate from ChannelStream receive/reassembly and
writer queues and GatewayRouter worker-writer reservations. They bound the
configured RPC capture accounting, not Python allocator overhead, runtime
fixed state or total process memory. Role-level resource accounting must sum
co-located reservations and separately account for those costs.

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
