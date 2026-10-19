# Fixed C2 host process service

`steamboat_connector.role_worker.start(config_path)` is the fixed entrypoint
selected by `process_bootstrap` after its parent has released gate `R`. The
adapter accepts the supervisor's exact version 1 host document, constructs one
`asyncio.Runner`, and uses that runner for both startup and the long-lived
service loop. Configuration cannot select Python modules, callbacks, network
endpoints, commands, or clock providers.

Startup passes the inherited `clock_handoff` object unchanged to
`ChildClockBridge`. It opens the exact host `C2ChildBinding`, reads settings
through the selected binding, verifies the signed artifact group and exact
read-only artifact view, and bounds the sum of all channel-stream and RPC
capture reservations before model loading or network connection. The selected
host policy remains the source of component limits. The durable channel policy
and traffic ledger are opened as existing operator-provisioned state; startup
does not create or reset either store. It installs the pinned initial channel
policy through its durable owner.

Each component gets one outbound TCP connection to the endpoint in the signed
channel policy, one owner-minted TLS connection using that component's selected
credentials, an ingress bound to its exact session set, a client HELLO whose
ACK must commit fully, and a bounded `WorkerChannelRpc`. All channels share the
host's one traffic ledger, bound to the selected host parent boot ID. Each
component's C1 identity and channel certificate continue to use its own worker
boot ID. Startup returns only after all selected channels finish TLS and
commit HELLO and every resident assigned stage completes a bounded synthetic
finite-tensor step and fully reclaims the probe session's KV cache. That is
process-channel and assigned-stage readiness; it does not establish owner
phase approval, aggregate host physical-resource enforcement, remote-device
performance, or successful end-to-end inference.

Signals request event-loop shutdown. The service fences RPC admission and
closes channel owners, then performs bounded runtime cleanup. If cleanup is
uncertain, the supervisor must retain the process owner and establish actual
cgroup-empty and child-reap proof before reclaiming generation resources. The
service does not declare uncertain work reclaimed or reconnect after ambiguous
mutation. The caller must retain this service and its owners until confirmed
cleanup or process death. Traffic-generation reconciliation still requires
trusted supervisor proof through `TrafficBudget.reconcile_dead_generation`.

`GatewayDelegationVerifier` requires the exact core `ChannelPolicyStore` type.
The service obtains it only through the guarded
`PersistentChannelPolicyStore.core_store` accessor and retains the persistent
owner for the entire service lifetime; liveness checks continue through that
owner every 250 ms and before readiness. This interval detects sticky owner
storage faults but does not prove the policy namespace remains unchanged on
every RPC frame. The core object is not a substitute for the durable owner's
lifetime.

Portable contract checks:

```text
python -m unittest tests.connector.test_c2_host_service
```

These checks cover the closed outer boundary, rejection before clock/runtime
construction, fixed-role import behavior, and aggregate reservation arithmetic.
The module does not have a portable end-to-end process startup fixture. Native
startup validation requires Linux protected-root storage, inherited supervisor
descriptors and clock socket, an operator-provisioned channel-policy store and
traffic ledger, and an available signed gateway endpoint. No model downloads
are performed by the service.
