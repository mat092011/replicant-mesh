# C2 progress checkpoint — 2026-10-20

This source checkpoint saves the current C2 implementation before phase
acceptance. C0 and C1 previously passed their gates; **C2.1–C2.6 and the C2
exit gate remain open**. C3 and research-gate statuses are unchanged. Publishing
this checkpoint does not make the connector ready for production use.

## Verified component evidence

- The expanded component-36 inventory passed 1,043 unique tests with zero
  skips, failures or errors. This predates the latest focused additions and
  is not a full-repository or complete C2 regression.
- The selected host-process lifecycle case passed with real model loading,
  inherited Clock, TLS/worker HELLO, READY, stop/reap and pin release. Its
  cgroup filesystem stand-in does not establish physical quota enforcement.
- The coordinator channel client runtime guard passed 56 focused native
  tests, including the original 45 compatibility cases and 11 new cases.
- The allocation-v2 config parser passed 9 portable tests. The new pool
  accounting data contract passed 14 portable tests in its worker worktree
  and the parent checkpoint worktree (zero skips, failures or errors);
  independent source review remains pending. Neither contract enforces
  resources or establishes physical ownership.

Exact frozen source, image, timings, retained failures and numerical limits
are in the [component record](experiments/2026-10-19-participant-c2-components.md).

## Saved work that still needs validation

The [coordinator outbound owner](CONNECTOR_C2_COORDINATOR_CHANNEL.md) includes
the latest lifecycle and deadline fixes from author commit
`b83646a1420dfef9ead400cc255b4719d27291c5`. That revision still needs independent
source review and native execution of its 12-test module. Earlier review
findings remain historical failures, not acceptance of this revision.

The [selected coordinator TLS fixture](CONNECTOR_C2_COORDINATOR_CHANNEL_TESTS.md)
is an unfinished scaffold from author commit
`dee25142521a7766b9c393ad02ac4f425e5ca8c0`. Its integration case is explicitly
skipped. Coordinator generation retargeting and worker HELLO progression are
unfinished, and cleanup has not been validated. No selected coordinator
positive TLS result or complete three-worker route is claimed.

The [pool accounting contract](CONNECTOR_C2_POOL_ACCOUNTING.md) from author
commit `ab89f85bd5705ab63e6dc6acc2178e3462f4d6d9` is data only. A physical pool
owner, durable generation ledger, real cgroup attestation and backend retirement
evidence are still required. The existing default daemon remains inactive.

## Resume order

1. Independently review the final coordinator outbound-owner fixes, then run
   the focused native lifecycle tests against the accepted client guard.
2. Finish the genuine selected coordinator TCP/TLS/HELLO fixture and prove
   actual bounded cleanup. Remove its explicit skip only when it can execute.
3. Implement the physical resource owner and delegated-kernel checks, charging
   the control plane and protected headroom across all local roles. Keep
   unsupported disk/bandwidth claims explicit until their owners are composed.
4. Connect durable consent and complete enabled-role startup to the management
   daemon; finish the fixed coordinator service and selected consumer owner,
   including submit, stream and cancel.
5. Exercise enrollment, loaded/healthy readiness, numerical inference and
   responsive stop/restart/remove over the actual laptop–ZimaBlade outbound
   route. Run the complete C2 acceptance checks before closing any gate.

The laptop and authorized ZimaBlade are available. No additional hardware
blocker has been established. UID-1000 cgroup delegation remains operator setup
work. GPU, WAN and universal-NAT claims remain outside the measured evidence.

Private raw logs, generated credentials, model weights and caches remain outside
Git. The local execution journal preserves worker worktrees and exact command
records; this document provides the source-level resume point.
