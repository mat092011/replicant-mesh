# Coordinator client for a fixed worker cohort

`GatewayCoordinatorEgress.register_target()` adds at most two additional worker
route views to the already authenticated coordinator egress. The primary target
counts toward the three-target bound. Each view is minted from an exact
`OutboundAuthorizer`, its enrolled host certificate, the same coordinator
identity and Clock, and the current signed channel-policy assignment. A target
tuple is immutable for the lifetime of that egress; duplicate registration
returns the existing view only when both authorizer and certificate are the
same objects/bytes. Conflicting and foreign target authorities fail closed.

`CoordinatorChannelClient.bind_target()` returns a small SDK proxy over the
same client, HELLO stream, message-ID allocator, response pump, pending-call
table, and shared data/control capture reservations. The proxy selects the
target-specific C1 authorizer and route view for each call. It does not create a
second TLS owner, HELLO stream, pump, or reservation. Responses continue to be
matched by the exact pending message ID, method, lane, and generation. Closing a
proxy closes the shared client and the whole coordinator cohort; target views
do not independently own or close the transport.

The route guard uses the same C1 scope checks and live signed-policy/deadline
checks as the primary route. The SDK proxy is only a transport adapter: it does
not install enrollment or grants, select a worker, assert process ownership, or
establish loaded-model readiness. The focused fixture exercises signed policy
and C1 authorizers over the real coordinator TLS/HELLO SDK stream with three
target boot IDs and interleaved manual replies. The third worker's
channel-policy certificate fields are synthetic; this fixture does not connect
three worker TLS endpoints or execute work on three workers. It does not
establish deployed routing or C2 acceptance.
