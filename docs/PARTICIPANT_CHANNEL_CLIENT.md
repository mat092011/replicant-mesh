# Coordinator SDK channel adapter

`steamboat_connector.channel_client.CoordinatorChannelClient` implements the
secure worker-client call shape over one coordinator-owned gateway connection.
Construction requires the exact `GatewayCoordinatorEgress` and its committed
`CoordinatorHelloClient` `ChannelStream`, plus explicit authorization watching
and separate data/control capture reservations. It accepts an actual worker
`Request` and trusted request context, mints the C1 gateway route guard, calls
`OutboundAuthorizer.authorize_gateway_outbound`, and sends the authorized C1
binding and deterministic protobuf in a C2 request bundle.

One stream pump dispatches responses to pending calls by the exact wire message
ID. Data calls reserve 8,495,104 bytes each (nine slots); cleanup calls reserve
139,264 bytes each (eight slots). These conservative values cover the existing
relay's maximum protobuf/envelope/binding captures and 64 KiB parser/object
headroom. ChannelStream, TLS, decoded queues, runtime state, and process allocator
overhead remain separate resource costs.

C2M1 response bundles intentionally omit the C1 binding. The adapter therefore
retains each exact C1 binding, request, method, expected response lane, route
guard, and generated wire ID locally, then accepts a response only from that
same live HELLO stream generation and exact pending ID/method/lane. It validates
the actual parsed `Response`, including worker/model/session/lease fields,
before completing the captured outbound authorization. This local correlation
does not establish end-to-end worker proof or model readiness.

The generation uses a monotonic, nonzero 128-bit message-ID allocator and
retires before integer wrap. It never retries uncertain mutations. Cancellation
or channel/policy loss fences the generation; pending callers fail and retain
their authorization/capture ownership until local operation cleanup finishes.
`close()` is bounded and reports `SecureTaskPending` while tasks still own work.
If authorization failure or close itself is uncertain, the adapter retains that
operation and its charged capture permanently, fences the generation, and
reports `ChannelClientOwnershipUncertain`; it never retries the close. Before
copying a caller's protobuf, the adapter checks serialized size, timeout and the
request tensor's three-dimension structural limit. It preflights raw response
bytes before protobuf parsing.

Focused fixture tests are in `tests/connector/test_channel_client.py` and use
the existing genuine two-hop TLS/HELLO fixture. They establish local adapter
correlation behavior, not a deployed route or separate-device inference.
