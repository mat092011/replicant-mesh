# C2 fixed TLS endpoints in channel policy v2

This private, unpublished C2 experiment protocol change separates the two
purpose-specific gateway TLS listeners in the operator-signed channel policy.
The worker-initiated stream uses `endpoint_host` and `endpoint_port`. The
coordinator mTLS listener uses `coordinator_endpoint_host` and
`coordinator_endpoint_port`. The exact host/port pairs must differ. Each
factory remains fixed to its own certificate profile and CA; there is no
generic profile callback or cleartext protocol demultiplexing.

The policy envelope is canonical version 2 and uses the independent signature
domain `steamboat-channel-policy-v2\0`. Version 1 and the former v1 signature
domain have no fallback. Both endpoint pairs are signed, validated as canonical
DNS or IP values with valid ports, and published in the immutable gateway
record. A shared gateway certificate may cover both endpoint names in its SAN.
The coordinator client and server check the coordinator endpoint, while worker
clients, workers' TLS ingress, and worker TLS servers continue to use the worker
endpoint. The actual client hostname check and certificate profile remain
mandatory on each hop.

An endpoint change is a new policy revision and retires existing egress and
coordinator TLS generations, even when the gateway certificate and key stay the
same. Existing generations cannot adopt the new endpoint through policy
refresh. Operator revision, expiry, durable antirollback, equivocation, and
conservative clock fences remain in force. C1 participant leaves, snapshots,
and grants keep their existing formats.

This policy and its MemoryBIO profile-pair checks do not create or bind network
sockets. Real socket binding, the complete HELLO path, two-hop work framing, and
remote-route acceptance remain separate work. The endpoint split changes a
private C2 protocol variable and establishes no C2 phase acceptance.
