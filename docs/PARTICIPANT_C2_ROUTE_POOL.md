# C2 v2 route membership ledger

This document describes an isolated component, not a C2 phase result. The
`C2RoutePool` primitive records route-to-selected-member membership for one
operator-provisioned physical pool. It is inert: it does not authenticate a
caller, authorize a route, indicate readiness, prove RAM, represent an execution
queue, or activate/replace resource policy v1.

Version 2 deliberately models one physical route once, even when it has three
worker component caches and a co-located coordinator. The membership limit is
four selected members per route, eight live routes and 32 live member leases.
The v2 storage profile leaves the C1 route epoch fixed at 1; the profile
version is a separate discriminator and does not alter C1 session binding.
Policy v1 accounting remains summed: its worker and coordinator component cache
budgets are not deduplicated. The ledger does not change RAM or capture
accounting.

The route record pins tenant/coordinator account, coordinator device, verified
credential serial/key hash/epoch and boot, request/session/route IDs, route
epoch, attempt and model. Each selected member pins root generation, parent
boot, role, component, worker boot, host assignment, credential identity/epoch
and admission epoch, host account/device, certificate hash and key hash. Host
members can be projected from the parsed C2 host-group scope value. The
projection helper checks value shape and component membership; it cannot prove
where that Python value came from. The route is a neutral closed projection,
not a coordinator-only request context. It can be recorded from a worker-side
caller without requiring a `TrustedRequestContext`; future coordinator and
worker integrations must provide their own trusted factories. The ledger
performs no caller authorization, and these Python values are not cryptographic
capabilities. The exact closed schemas and ID grammars are validated.
Members must be present in the protected constructor allowlist, which is bound
with physical-host identity, pool ID and route cap in a configuration digest.
Changing that configuration on reopen fails closed; no migration is provided.

The operator must provision the shared ledger directory with owner-only mode
0700, then call the explicit one-time `C2RoutePool.provision` operation. It
exclusively creates a permanent configuration-bound marker and initial state;
normal construction only opens an existing marked ledger. A partial provision
cannot be retried in place. State, marker and lock files are owner-only
single-link regular files. The code never creates the directory, resets state,
evicts tombstones, or expires a reservation. A durable reservation returns an opaque random receipt; that is
not a signature or proof of caller authority. Release requires a trusted caller
to affirm actual reclamation and the exact original receipt. A per-RPC
authorization-retirement confirmation does not establish that session KV state
is gone. A future integration must use session-level evidence that the bridge
owner is removed, no RPC/queue/retained KV remains, and the core confirms cleanup,
or an exact worker-boot reap with an empty cgroup. Missing or uncertain evidence
keeps the lease live. Closed routes reject late joins; stale receipts cannot
release a later incarnation.

State is bounded to 128 KiB, 32 route records and 128 compact member records.
The eight-route and 32-live-member limits include cleanup-pending membership.
The first release closes that route to new joins while sibling leases continue
to count live until individually released. SHA-256 route/member keys keep the
eight-route, four-member case within the file cap. Once history fills, operators
must provision a new ledger through an explicitly reviewed lifecycle; this
primitive has no reset path. Unknown schemas, unsafe
files, malformed or oversized state, configuration drift and ambiguous durable
write failures fail closed. Every mutation first fsyncs a durable pending
transaction fence, and every open or operation refuses while it exists. An
uncertain state write leaves that fence for operator or supervisor recovery; a
new object cannot bypass it. After a confirmed state commit, fence cleanup has
its own result flag. If unlink or its directory fsync fails, the reservation or
release remains committed and correctly charged; cleanup is reported as
unconfirmed. If the marker reappears after a crash, opens fail closed. Operations
use both a thread lock and the shared file lock. Filesystem locking does not establish that a directory is shared by
the intended physical host; that remains an operator provisioning fact.

The current runtime does not call this component. It has no global admission
wait queue, route deduplication, physical-pool RAM enforcement, worker
reclamation integration, authentication, or readiness behavior. C2 integration
and physical-device validation remain future work.

Focused portable command (real filesystem security/race cases run on Linux):

```sh
PYTHONPATH=src python -m unittest tests.connector.test_c2_route_pool
```
