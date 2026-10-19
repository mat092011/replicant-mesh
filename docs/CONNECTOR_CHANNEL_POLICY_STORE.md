# Persistent C2 channel-policy owner

`PersistentChannelPolicyStore` gives the gateway's existing signed
`ChannelPolicyStore` a small Linux durable head. It is a storage owner, not a
policy parser or an authorization layer. The core store still verifies the
operator signature, closed v2 schema, policy clock interval, minimum revision,
rollback, and equivocation rules. The owner supplies its synchronous durable
commit callback and publishes no new core view until the file and containing
directory have been synchronized.

Provisioning is an explicit one-time operation against an existing empty,
owner-only directory. The caller then installs the first operator-signed
policy. Normal startup uses `open_existing`; it never creates, repairs, resets,
or replaces a missing or corrupt head. Both paths require the exact core
`Clock`, the pinned P-256 public verification key, the expected effective Linux
UID, and an explicitly configured minimum revision and policy digest. The
persisted metadata binds those anchors to the complete signed policy bytes and
their canonical payload digest.

The directory contains one bounded head and one lifetime lock. Opens use
no-follow, descriptor-relative operations, validate the directory and file
types, ownership, modes, link counts, and namespace identities, and acquire a
nonblocking exclusive `flock`. Each update compares the current bytes and inode
with the owner's observed head before an atomic replacement and directory
`fsync`. Exact canonical-payload replay is idempotent even if the valid ECDSA
signature encoding differs. Any uncertain write, rename, synchronization,
namespace, or close outcome faults the owner and retains its lock; there is no
automatic recovery path.

The owner holds one persistent policy head rather than an append-only history.
The file limit is derived from the core 64 KiB signed-policy bound plus fixed
metadata. This prototype does not protect against a malicious process with the
same UID or full root, and no selected-runtime configuration adapter is
included here. The Linux filesystem behavior requires the focused tests on the
supported Linux image; Windows can only run syntax/import checks and will report
these filesystem tests as skipped.
