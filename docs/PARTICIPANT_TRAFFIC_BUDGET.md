# C2 aggregate traffic budget primitive

Status: reusable accounting primitive only. It is not wired into a TLS socket,
does not establish channel readiness, and does not prove that the caller
measured the encrypted TCP payload boundary described in
[the channel wire contract](PARTICIPANT_CHANNEL_WIRE.md). A later socket owner
must count TLS handshake records and all ciphertext bytes, use a fresh
allowance immediately before nonblocking I/O, and settle with the actual byte
count.

`TrafficBudget` stores one canonical JSON ledger capped at 64 KiB and one
short-held `FileLock`. The parent directory must already be private and owned
by the current UID; the state file is written atomically with mode 0600. Linux
is required for the production file lock. The operator must pass the same
allocation ID, ledger path, current UID, physical monotonic clock identity and
policy to every consumer, host and coordinator process. A private file copied
to a second path or separately provisioned inside a container is a different
ledger; this primitive cannot attest that deployment paths refer to the same
physical host allocation. Artifact transfers must use the owning runtime role's
same ledger and reservations; this module does not provide a separate artifact
budget.

Normal construction opens an existing ledger and fails closed if it is missing;
it never recreates quota during startup or restart. A trusted provisioning path
must call the explicit `TrafficBudget.create_fresh(...)` API once. That API
refuses an existing path, so a restart must use normal construction and retain
the already charged counters.

The closed policy schema is validated with the connector policy validator.
Traffic reservations for all configured roles must sum to no more than the
global send rate, receive rate, cumulative data bytes, cleanup send rate,
cleanup receive rate and cleanup total. Data and cleanup have independent
rate buckets and cumulative counters. Each direction has a one-second token
bucket burst cap. Buckets begin full only when the ledger is first created;
restoring an existing ledger never refills it. Rates are calculated with
integer byte-nanosecond units, and only elapsed monotonic nanoseconds refill
them. A backward clock, changed Linux clock identity, unreadable or malformed
ledger, or ambiguous commit/lock-release failure latches the owner unavailable.

Before an immediate send or bounded receive, the caller binds its role to a
32-character lowercase worker boot ID and reserves at most 16 KiB. At most 16
allowances may remain open or uncertain. Reservation atomically subtracts
directional tokens and charges the full maximum against role and global
cumulative budgets before an allowance object is returned. Allowances expire
after 100 ms and must be checked just before I/O. The socket integration must
enforce this timing; the primitive cannot stop a caller from using a retained
allowance later.

Settlement records actual bytes separately from conservatively charged bytes.
Only a known outcome settled before expiry refunds unused bytes. Unknown
outcomes and late settlements keep the full charge and an uncertainty record;
retries cannot make that budget available again. Unsettled state survives a
process restart as fully charged. Replacing a role generation requires an
explicit caller assertion that the old process has been reaped and its cgroup
is empty. Reconciliation purges old allowance records without refund. The
primitive does not verify that proof itself; only the trusted process
supervisor may call it after actual cleanup evidence.

An atomic-file operation can report an error after replacement but before the
directory durability result is known. The current owner then latches fault and
retains its uncertainty. On restart, either the prior fully charged state or a
known-settlement candidate may be visible; both remain conservative because
only known unused bytes can be refunded. An allowance whose reserve raised is
never returned to the caller, and no restarted owner can reconstruct an
allowance object from a ledger row. This is conservative accounting, not an
exact commit-certainty or automatic-retry protocol.

The persisted version-2 ledger is validated before use. For each aggregate and
role counter, charged bytes must equal observed bytes plus unresolved uncertain
bytes (full uncertain maxima minus their observed portions) plus the maxima of
still-open reservations. Role counters must reconcile with global counters,
and current uncertain rows must fit their recorded uncertainty and observation
counters. Each allowance token also retains its original reservation fields;
the row must match them before I/O or refund. This prevents prior or reconciled
traffic from masking an inflated reservation. Older ledger versions fail closed
and require explicit operator handling; no automatic migration resets quota.

Data exhaustion rejects more data while cleanup tokens and cleanup quota remain
independently usable. Storage or identity uncertainty rejects all admissions.
The ledger and status output contain counters, policy identity and boot IDs;
they do not record payloads, prompts or secrets. `MemoryTrafficStore` is an
explicit test-only backend. It can exercise shared in-process synchronization,
but it provides no cross-process guarantee. The Linux file-backed
cross-process test is skipped on platforms without Linux flock semantics.

Integration still needs to ensure every network-owning process uses this exact
ledger and policy, bind all role generations from accepted supervisor state,
and stop the channel if traffic cannot be charged or the receive allowance is
exceeded. This primitive is not a socket service, scheduler, fairness guarantee
or readiness signal.
