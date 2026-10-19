# C2 local compute startup adapter

This is a bounded composition prototype for explicitly enabled local `host`
and `coordinator` compute roles. The connector role `coordinator` maps to the
selected C2 role `personal_coordinator`. A request must name the complete
enabled compute projection. The `consumer` role is rejected before owner state
is read or its durable start epoch is advanced; consumer startup needs its own
in-process ownership contract. Remote and global cohort members are never
launch candidates.

The operator supplies immutable local launch references. Startup first loads
and checks the selected host/coordinator runtime bindings, including protected
headers, before acquiring the selected-root shared transaction lock. The
backend must already have an artifact pin and the exact closed
`c2-local-compute-v2` role configuration built by the fixed-child config
module. It carries the complete canonical selected `RoleLaunchSpec`, selected
root and protected header references, plus the host's bounded canonical
operator public key (the coordinator field is null). The child loader uses
that declaration to reopen the real selected RootGenerationStore and rerun
the C2 binding checks. The backend's
`spawn_owned_start` additionally hashes the role config actually read after it
owns the start intent, closing the config-replacement race before Popen.
Before claiming, the adapter verifies that the live artifact pin uses the same
`Clock`, principal, and selected parent boot. It compares signed assignment
manifest fingerprints and component/assignment/child-boot tuples against the
selected C2 binding. For the host group, it also matches the selected catalog
digest and SHA-256 of the catalog's raw uncompressed P-256 public key, and
checks every signed assignment document digest against the selected component
hash. The pin record must contain exactly the selected component/assignment/
digest/boot tuples, and the backend's stored pin metadata must equal the live
record both in memory and in its protected role configuration. These checks run
before owner epoch advancement, claim creation, or Popen. Under the Root SH
callback it also rechecks protected header and credential material before
writing the local claim.

The personal-coordinator selected profile does not yet contain catalog digest,
catalog-key, or assignment-document-digest anchors. Coordinator startup checks
its verified documents against its own live pin and the selected model,
principal, assignment ID, component, role, and boot, but cannot claim the same
selected-scope digest binding as the host group until that profile is extended.

For each attempt, owner consent is durably advanced first and held through
selected raw-head validation, local single-use claim, and publication of every
immediate owned-process handle. Cancellation is checked at every backend
Popen gate. That callback is synchronous and only reads the independent event;
it performs no filesystem access or store locking. Any partial publication
failure requests bounded cleanup through the sealed handles for the captured
process generations. Cleanup shares one deadline across those handles and leaves
any later same-role generation untouched. Both durable-store contexts exit
before READY observation.
On READY failure, cleanup is requested and the claimed boot tuple remains
consumed. A read-only owner snapshot lock is paired with the final Root SH
check; neither readiness nor durable policy work occurs in that scope. Root SH
serializes selected-head updates, while operator-managed protected files are
checked at claim and final validation. The child adapter must still revalidate
protected material before loading or admitting work because manual file edits
are not serialized by Root SH.

The result contains plan and claim digests plus observed backend role names. It
does not prove process identity, loaded model health, or durable readiness and
must not be used as such. This adapter does not yet wire a public controller,
serve inference, or provide consumer ownership. Portable contract tests cover
pre-consent rejection, captured-config replacement, and owner snapshot
serialization. The native-only host integration uses real selected-root,
owner-consent, local-claim and signed artifact-pin stores with FakePopen and a
FakeCG; it checks claim-before-publication, both locks held through Popen, lock
release before READY, cancellation during claim-file fsync, and refusal to
reuse historical parent/child boots. It is software lifecycle evidence, not a
real child execution or kernel cgroup test. It requires Linux POSIX plus the
approved offline model artifact directory. A co-located selected host plus
personal-coordinator fixture, real Popen/cgroup execution, and child-side
protected-material revalidation remain open.
