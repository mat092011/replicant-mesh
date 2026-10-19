# Participant C2 whole-cohort launch claims

`root_c2_launch_claim` is a native POSIX durable, append-only single-use claim
store for one complete selected C2 cohort. A record binds the selected selector,
activation manifest and generation hashes to every new parent
`RoleLaunchSpec` and every new host-group scope, including all child worker boot
IDs. The canonical cohort digest covers the complete parent and scope documents.
Parsing reparses nested declarations and enforces closed fields, canonical JSON,
sorted unique role/group identities, exact host-scope coverage, matching parent
credentials and epochs, unique parent/child boots, and a maximum cohort of 64
boots.

The store keeps at most 16 records, each at most 64 KiB, with a total scan bound
of 1 MiB. Its separately operator-provisioned root must be daemon-owned mode
0700; the store does not create or migrate the root and does not reuse the C1
claim namespace. Files are opened relative to a protected directory descriptor
with no-follow semantics and must be daemon-owned mode 0600 regular files with
one link. Unknown entries, unsafe inodes, malformed records, oversized scans,
and partial or uncertain writes fail closed. A claim file created with
`O_EXCL` is never deleted or retried. Historical parent and child boot IDs
cannot be claimed again under a later selector or generation, and each returning
principal's admission epoch must strictly advance.

The caller supplies a trusted synchronous `fresh_selected_validator`. It must
validate the record against the entire current selected cohort: all parent
specifications, all child scopes, selector and activation-manifest hashes, and
the current policy head. It returns exactly `None`. The callback is an owner
integration point, not an identity, proof, approval, or launch capability;
primitive descriptions and a receipt never authorize a process. The claim
store itself does not spawn, approve, establish readiness, or prove that weights
loaded.

This global whole-cohort record is not a per-daemon startup API. A future
integration must define a separate, opt-in local-plan projection and local
claim interface so each daemon can bind only the principals it owns while
proving that the projection came from the same complete selected cohort.
Global rotation still requires whole-cohort validation before any local claims
or launches. This module does not provide that projection, ownership routing,
or process-launch wiring.

The caller must hold the **same `RootGenerationStore` protected-head
serialization** continuously from fresh selected validation through the full
cohort claim and publication of ownership for every immediate `Popen`. Release
that serialization before waiting for child loader `READY`: a child may need to
write durable policy state, which can deadlock while the parent holds the
protected-head lock. If a write outcome is uncertain, operators must inspect
and resolve the store explicitly; automatic deletion or retry could duplicate
a launch attempt.

Focused portable parsing and native-store checks:

```powershell
python -m unittest tests.security.test_root_c2_launch_claim
```

The native store tests require POSIX `O_NOFOLLOW` and are skipped on Windows.
They do not establish startup wiring, process ownership, child readiness,
execution correctness, or C2 phase acceptance.
