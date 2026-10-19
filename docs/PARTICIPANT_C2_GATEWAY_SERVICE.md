# C2 fixed-cohort gateway service

`GatewayService` composes the existing purpose-specific gateway TLS owners,
metered `ChannelSocket`, server HELLO capabilities, framed streams, producer
router and one coordinator multiplexer. It accepts two separately supplied,
already-bound TCP listeners: one worker endpoint and one coordinator endpoint.
The operator remains responsible for binding the intended numeric local
addresses and for providing the selected fixed certificates, stores and policy.
Tests use ephemeral loopback listeners; this component makes no WAN, NAT,
public-listener or deployment claim.

Each service instance captures one coordinator boot and tenant and one to three
exact `(device_id, worker_boot_id)` worker tuples. Target certificate routes must
cover those exact policy-selected worker assignments and models. The service
does not infer a boot, select the first worker for a device, replace a connected
generation, reconnect, or retry. It accepts at most four channels in total and
enforces a five-second monotonic TLS plus HELLO bootstrap deadline. Any
unexpected tuple, duplicate channel, policy/stream fault, or cohort loss ends
the captured cohort.

Before it creates any TLS owner, BIO, HELLO decoder or accepted driver, the
constructor requires a communication-memory ceiling at least as large as
`required_communication_memory_bytes(worker_count)`. This fixed reservation
includes every maximum-size stream (HELLO reassembly, decoder/feed and fragment
scratch, decoded queue, writer queue, socket scratch and TLS-owner reservation)
plus the mux's aggregate nine data and eight control captures. The ceiling
accounts for communication buffers only; it is not a complete Python allocator,
runtime, model, cache, traffic, or physical-host budget. No stream is created
with larger decoder capacities than those included in the calculation.

Every accepted socket is wrapped by its purpose-specific `OwnedGateway*TLS`
owner and by `ChannelSocket` using the operator's already-bound gateway
`TrafficBudget` role. Socket and TLS I/O goes only through that metered driver.
The service pumps pending TLS and HELLO bootstraps. Once the exact registrations
exist for all configured workers and the coordinator, it registers the genuine
worker streams in `GatewayRouter`, transfers all framed streams to one
`GatewayChannelMultiplexer`, and thereafter delegates all stream pumping to
that mux. HELLO registration and `route_connected` indicate authenticated route
connectivity only; neither establishes assigned-model loading or inference
readiness.

`stop()` freezes admission, closes each listener once and closes pending channel
owners or the mux-owned cohort. Finalization waits for pump quiescence and for
both listener close calls to return. Close outcomes that cannot be confirmed
retain the service and its owners in a bounded process registry; they do not
free a slot for a replacement generation. A stream pump that returns after Stop
cannot commit HELLO registrations or publish/dispatch the mux. `run()` invokes
the same stop path in its `finally` block. This layer does not start workers,
issue enrollment, enable roles, enforce a shared physical compute pool, or
complete CT-11/CT-13.

The focused test module builds real TLS and HELLO over TCP loopback and checks
two exact worker boots, coordinator Open and Describe response routing,
pre-allocation memory rejection, pending-handshake expiry, fixed-purpose and
invited-boot rejection, plus deterministic Stop races during accept, TLS owner
creation, listener close and the final HELLO stream pump. Run it with the
repository's connector test command on the pinned Linux runtime; local Windows
collection may be unavailable when the optional protobuf package is not
installed. No Docker or full application run is claimed by this component.
