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
backend must already have an artifact pin and an exact closed
`c2-local-compute-v1` role configuration. That profile binds the selected root,
protected configuration root/header path, local principal, selected launch
role, boot, generation, header digest, and launch nonce. The backend's
`spawn_owned_start` additionally hashes the role config actually read after it
owns the start intent, closing the config-replacement race before Popen.
Before claiming, the adapter verifies that the live artifact pin uses the same
`Clock`, principal, and selected parent boot. It compares signed assignment
manifest fingerprints and component/assignment/child-boot tuples against the
selected C2 binding. Under the Root SH callback it also rechecks protected
header and credential material before writing the local claim.

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
