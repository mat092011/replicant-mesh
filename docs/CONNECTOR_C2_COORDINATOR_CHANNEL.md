# C2 coordinator outbound channel owner

`build_c2_coordinator_channel` composes one outbound coordinator channel from
the exact selected `C2ChildBinding`, the selected coordinator settings, a
caller-owned open `PersistentChannelPolicyStore`, a caller-owned already-open
`TrafficBudget`, and the supplied owner resource policy. It never provisions or
resets either durable store. The persistent policy core and traffic ledger must
share the binding's exact `Clock`, current UID, selected policy anchors, paths,
allocation ID, and monotonic clock domain. The coordinator traffic generation
is bound once to the selected parent boot ID.

Before networking, the owner validates the coordinator communication and
capture reservations, compares the current C1 coordinator and all three
ordered worker device/boot/assignment tuples with active C1 records and grants,
checks the durable signed worker and gateway policy, and SHA-pins the protected
gateway CA and three logical HOST certificates. The gateway endpoint comes
only from the current signed channel policy. The logical HOST certificates
authorize C1 worker operations; gateway TLS separately authenticates the
transport peer.

The transport uses one real TCP socket, one actual `ChannelSocket`, the genuine
`GatewayCoordinatorEgress`, and one fully drained TLS handshake. It then uses
the actual coordinator HELLO client and `ChannelStream` commit before creating
the actual `CoordinatorChannelClient` and its three target proxies. Teardown
fences calls and schedules bounded close. A close attempt has a five-second
maximum budget that includes lock contention and the one exact child-binding
lease exit. Pending or uncertain cleanup keeps the owner and its transport,
client, proxy, capture, policy, traffic, and binding references attached for
later cleanup or process reap. A failed build attaches
`c2_coordinator_channel_owner` to the exception whenever the partial owner has
been created; pre-owner failures attach the acquired lease.

This module owns a transport only. It does not provide the coordinator
scheduler, consumer listener, model inference, process supervision, READY
publication, or a claim of complete inference. The gateway client uses explicit
caller-created trusted request contexts for worker calls. Manual worker
responses are component transport validation only. C2 remains private and
unaccepted; C3 is unchanged.

Portable contract checks:

```text
python -m unittest tests.connector.test_c2_coordinator_channel
```

These checks do not establish selected-binding startup or a TLS route. The
positive C2 binding and real gateway TLS/HELLO integration requires the approved
Linux fixture and pinned native environment; it must be reported separately
from portable checks. No full inference or readiness claim follows from an
authenticated channel.
