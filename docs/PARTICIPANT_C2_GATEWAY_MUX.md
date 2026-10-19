# C2 gateway channel multiplexer

`GatewayChannelMultiplexer` is the central demultiplexing owner for one already
authenticated coordinator channel and a fixed tuple of one to three worker
channels. It accepts only the actual coordinator server `ChannelStream` and
actual registered worker server streams whose HELLO registrations, TLS owners,
and router slots still match. The tuple is captured at construction; a worker
replacement requires a new mux generation.

The service pumps and pops the coordinator stream once per service pass, then
pumps and pops each captured worker stream once. After bounded protobuf
preflight and parsing, it selects a worker only by the exact pair of the C1
binding target device and the protobuf request's `worker_boot_id`. Describe
therefore also requires an explicit boot ID in the protobuf. Binding boot and
assignment fields, when present, must match that selected generation and its
current policy. Selected calls go through the existing `GatewayChannelRelay`
forward and return validators; the relay's own competing service loop is never
started.

Admission is aggregated over the whole mux generation: at most nine data calls
(one active plus eight pending) and eight control calls. The caller must reserve
the full capture ceiling for each aggregate lane. Every wire message ID is reserved
before decoding; up to 1,024 unique wire message IDs are remembered without
eviction, including completed calls. Reuse or history exhaustion fails the
whole mux generation. A response must return from the exact selected worker
generation with the original wire ID and method. Mismatches, route loss, policy
expiry, parse failure, and transport uncertainty stop the entire captured
cohort. Pending capture accounting is retained after uncertain failure rather
than reported as reclaimed.

At most eight mux cohorts, including stopped cohorts with unresolved pending
captures or uncertain stream closes, are retained process-wide. They keep
strong stream, writer, and request ownership; exhaustion rejects new cohorts
rather than dropping unresolved owners. A global identity claim also prevents
a coordinator, worker stream, or actual writer from being shared by a second
mux.

Heartbeat timing is centralized: the mux invokes the router liveness check
once per monitor interval and requests a PING for every captured worker. The
router's 30-second PING cadence and 60-second PONG deadline remain in effect;
the service loop checks no slower than five seconds. This component does not
provide fixed listener enrollment, automatic reconnect, SDK integration, or a
readiness claim. It is a demultiplexing component, not an end-to-end C2 phase
gate.
