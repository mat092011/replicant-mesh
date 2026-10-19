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

Focused tests are in `tests/connector/test_channel_rpc.py`. Run them with the
repository's isolated PyTorch/Protobuf runtime, for example:

```powershell
$env:PYTHONPATH = 'src'
python -X utf8 -B -m unittest tests.connector.test_channel_rpc
```
