# C2 component validation, 2026-10-19

Status: C2 implementation resumed at the maintainer's request after publication
of C1 (`89ea4b1`). No C2 checklist item or phase exit gate is accepted by this
report. The [implementation design](../PARTICIPANT_CONNECTOR_DESIGN.md) records
the frozen acceptance criteria and remaining integration boundaries.

The private candidate preserves the earlier C2a local foundation on the
completed C1 base. It adds conservative artifact authority checks, a separate
channel certificate profile, and an assigned-stage adapter for the real worker
handler. The earlier [C2a report](2026-10-17-participant-c2a-local.md) remains
historical component evidence; its test counts overlap and must not be added to
the counts below.

## Frozen component runs

Both runs used Linux/amd64 Docker, the pinned Python 3.12.15 and CPU runtime
lock, Torch 2.14.1+cpu, Transformers 5.19.0, eager attention, float32 and no
compression. The model/tokenizer revision remained
`Maykeye/TinyLLama-v0@298338802ab94432b917bcce11382aa151aee50f`.
Cryptography 50.0.2, cffi 2.1.1 and pycparser 3.11 were hash-pinned by the
artifact image. Model artifacts came from the existing read-only verified lab
volume; no network download was allowed during the tests.

The test containers had 2 CPUs, 6 GiB memory, 256 PIDs, no network, a read-only
root, all capabilities dropped and no-new-privileges. Writable tmpfs ceilings
were 256 MiB for scratch and 16 MiB for lab state. The harness required every
discovered case and rejected skips, failures, errors and inventory mismatch.
It had a 180-second outer traceback/termination timer. Actual container limits
were inspected before starting; each terminal container was inspected and
removed afterward.

| Run | Frozen source | Baked image | Result |
| --- | --- | --- | --- |
| Component 1, corrected harness | `a52c92cfbbdbb167cd88eef5837e4c0e76d1324c6f7dae945cfab1411c75d4df`, 340 files | `5b74e1b1b34a0054db1157b5bb599994ea2945ea6a655457461cf20bd313ef8c` | 78 unique cases passed, zero skips/failures/errors, 9.411 s |
| Component 2 | `b2eb5874905769ea895ef707557ffa4e351306da799a9365640703bb6e3a5111`, 342 files | `eb915bd9c1a31768fa5cac3caf67f9a4def20a4976ade3b2e8b7019a42a6e893` | 87 unique cases passed, zero skips/failures/errors, 9.953 s |

Full baked-source comparisons found zero mismatches for all 340 and 342 files,
respectively. The component-2 private code checkpoint was `3e512b1`; subsequent
documentation and later component implementations are not part of that image.

| Evidence | SHA-256 |
| --- | --- |
| Component-1 all-source proof log | `ac54772ac1011c013fcf3efc7bc11919b4eb3821ae6a6cf2d540c808e7ca6098` |
| Component-1 corrected test log | `8ea602b89f8aa211a6207cdf1d28c23cb12eb19c22366d5fb99d3c33ec838148` |
| Component-2 all-source proof log | `a2cbe164ac00cfc6bcec15689de11b90fd5e3af4eee9b047618462c77c773ed6` |
| Component-2 test log | `f1e35f7d4f85cbfe770e03e54c80c083f176e37d36882b8c60f976b942bf3fe4` |

The counts are successive complete component inventories; they are not 165
distinct tests. Component 2 includes the prior inventory, the reverse channel
credential separation control, seven adapter contract cases and one real
assigned-handler numerical case.

## What was checked

The local IPC and ledger checks exercise real Linux owner-only sockets and file
locks. They do not establish physical cgroup, disk or network enforcement for
executing roles. Conservative artifact verification uses the core `Clock`,
checks the signed parent catalog and assignment in one sampled transaction,
preserves monotonic fences across re-signing and uncertainty changes, and rejects
an assignment whose cached parent authority has expired. Unconfigured clock
accuracy fails closed. The numerical fixture explicitly assumes an accurate
test clock; it does not validate an operator clock source for real readiness.

The channel certificate tests check the new client-capable worker profile and
gateway service profile without changing C1's existing role/EKU definitions.
They reject profile substitution in both directions, malformed CA-signed
leaves, endpoint mismatch, excessive lifetime and conservative validity failure.
Certificate validation alone does not establish TLS channel authentication,
revocation, readiness or gateway delegation authority.

The new numerical test installs three separate signed host assignments, loads
only each assigned shard and builds actual `WorkerHandler` instances through
the adapter. Two unequal sessions interleave multi-token prefill and forced
continuations through actual protobuf requests and tensor encoding/decoding.
The synthetic token sequences are A: `[1,17,19]`, `[23]`, `[31]`; B: `[5,7]`,
`[29]`, `[37]`. Last-position logits match the complete `PipelineModel` on the
same stack with `atol=1e-3`, `rtol=0`. The test checks that closing A leaves B's
session/cache, closing B leaves zero sessions/cache, and handler shutdowns
confirm completion. This is a same-container component correctness result.

## Retained failure and corrections

The first component-1 attempt ran all 78 cases and ended with one error. The
parent's private harness lacked an `if __name__ == "__main__"` guard; spawned
ledger-test children re-executed scratch-directory creation and raised
`FileExistsError`. The resulting queue wait failed. The failed log is retained
with SHA-256
`5b7d7b645055513f718c6b6451eb968fb2317b21929e991a2b739ca3c591443b`.
The corrected attempt changed only that private harness guard and used the same
frozen source, image, 78-case inventory and resource limits. No product defect
or hardware cause is attributed to that failure.

Pre-measurement review also corrected monotonic-fence pruning, dependent catalog
authority, missing post-compute assignment checks and the numerical fixture's
interleaved cleanup expectations. Portable failures are preserved in the private
journal; they are not represented as successful runs.

## Later Linux component runs and retained failures

The next inventories added signed channel policy, physical-pool locking and
process supervision. They have **not passed** as complete inventories:

| Run | Frozen source / files | Result | Test log SHA-256 |
| --- | --- | --- | --- |
| Component 3 | `d4735811227c17cb7e20c7dd09f0a52d60c270935b100eb6a1bb50d334a1cc4c` / 352 | 149 tests, 3 failures, zero skips/errors, 12.517 s | `f40f0368e8b75f97993fb169bf50844ffdb767feb7eeddb76d86db7ac140aa31` |
| Component 4 | `25a0b44e4ae17a1b1b9eb95aed173de207605b0b896bf1b576eaf608a88e1772` / 353 | 158 tests, 1 failure, zero skips/errors, 13.269 s | `c8285de6ec0ef361b63621df0f25aff554fce5af1ba8daffd6519129a6872f76` |
| Component 5 | `4efb8d6897f2723d21a6c8a00259e9662af56fc6dea4e4722f9ea5594ceeafe7` / 353 | 158 tests, 1 failure, zero skips/errors, 11.299 s | `c68050dab5b4c806b1fc522bd61d8c4d2208d3fa49f76bf4ef9e1e4583bd6704` |

Every run used the same component-test resource/security limits stated above;
each frozen image passed a comparison of all its source files with zero
mismatches. Component 3 exposed a fixture-wide `os.write` mock intercepting real
pipe writes and a configuration test reusing its purported fresh directory.
After those corrections, component 4 exposed an undefined `real_popen` in the
native ignored-TERM test. The parent corrected it and made the child explicitly
signal that its TERM-ignore handler was installed before cancellation.

That stronger component-5 control reached a real supervisor limitation:
`request_stop` sent TERM but escalation depended on the eventual cleanup call.
The final Stop arrived after its original cleanup deadline and did not confirm
reclamation. Independent, bounded escalation is being implemented; this run is
not a passing Stop gate. No hardware or clock cause is attributed. All task
containers were inspected after exit and removed; none reported an OOM kill.

## Consumer-only image component

A separate pinned consumer image contains the six exact, hashed transport and
cryptography wheels from existing project locks. It has no Torch, Transformers,
safetensors or Hugging Face Hub distribution/module, and mounts no model or
artifact volume. The gate actively rejects imports of those model packages.
It imports the actual C1 secure client/authorizer and runs the new consumer
adapter's contract controls, validation, channel-profile and policy tests.

The first build failed because the parent added a COPY for a nonexistent
`tests/__init__.py`. That Dockerfile copy was removed; the existing test namespace
is used. The retained failed build log has SHA-256
`2a6a5d9d6c65b2b5b172add39a842b43b0a2432d79e2e1b54e94e8286be353c6`.

The corrected source was
`303d517d6c72a20df99d5ff08f3ddbbd3e892881759ec88b0842e1231f41afdd`
(361 repository files); the image was
`sha256:86f055ead1404ef15f5ac2513af4ffb4ea1e5ce828c0b5606981a3a02ae7afb6`.
All 92 source/test/script files copied into `/app` matched the frozen manifest.
Its source-proof log SHA-256 is
`fac64a41fded5f3b222b5889dc83819c155ef805cd4a5a5383f244f444b014f8`.
The gate passed **55 tests, zero skips/errors/failures, 3.183 seconds**
(3.395 seconds including dependency/import checks). Its test log SHA-256 is
`b820df9d73abf78d982be1712892d9ae10c96d643398aeeebab109ffb9244893`.

Read-back container limits were one CPU, 256 MiB RAM, 64 PIDs, 16 MiB temporary
space, no network, read-only root, all capabilities dropped, no new privileges,
and UID/GID 65534. The test process exited successfully and its container was
removed. These are model-free client component results; its fake-peer tests do
not establish actual C1 TLS streaming interoperability or a C2 gateway route.

## Artifact ownership and combined component inventory

The pin-specific component-6 attempt ran 24 tests and ended with one error. Its
close-failure fixture patched the process-wide `os.close`, accidentally affecting
directory cleanup before the intended acquisition rollback. The fixture now
isolates that operation and checks that the intended inactive-view error caused
rollback. The retained failed log SHA-256 is
`7fc1fb8c384f0c0ea0ba314bad916e4d310e08c6707148bfc02c6272b3fd0498`.
Component 7 passed all 24 cases with zero skips/failures/errors in 3.602 seconds;
its test log SHA-256 is
`6c644ccf45442c69d7b035fa595079c66e7bf97826372ed66674e82174138bf6`.

Those cases include Linux flock exclusion, child descriptor retention and
CLOEXEC with a real exec, concurrent close-once handling, retained uncertain
cleanup, conservative clock caps, resident assigned adapters and the two real
model checks. Each numerical worker still used its own installation root and
pin; this does not establish one aggregate multi-handler host pin.

Adding three active component slots exposed a serialization regression in
component 8: one of 60 tests failed because concurrent installers competed for
the nonblocking global runtime exclusion lock. Mutations now first serialize
on the existing bounded installer gate and then probe global EX **without
waiting**. If a runtime already holds global SH while awaiting the installer
gate, the mutation refuses and releases that gate. A real Linux lock race
control checks this ordering. Component 9 retained two test failures: the new
control lacked its exception import, and an older mock asserted the previous
lock order. Both were corrected; the exclusion control now checks unchanged
state through a real installer and runtime pin.

Component 10 passed **61 artifact/pin/adapter cases, zero skips/failures/errors,
4.086 seconds**. Its frozen source was
`ca32613681d861d9e5dad334f6a9d092104c7d9be21ad2b6739eb8e6c1aff899`
(362 files); its test log SHA-256 is
`252ea6ed60f9a32ff86ef19e12c784527b8ab138b87c406f18b622f6b6d6a4e0`.
This covers explicit v1-to-v2 migration, three component slots in one installer,
shared disk/catalog accounting and the pin controls above. The source-proof
log SHA-256 is
`138fee0b6d77690d5b60ab2160a0c9a1473d9da36351ed804158eacf26403f51`.

After supervisor and controller corrections, component 11 passed **216 checks,
zero skips/failures/errors, 16.114 seconds** under the original component limits.
The inventory combines all connector tests with channel certificate and policy
tests; these successive inventories reuse cases and must not be added as
independent test counts. The frozen source was
`ba4dcc6a44e031336d23aacbb7d2d6973d9b27233f7a2f012784d23698e1ac48`
(363 files), and the image was
`sha256:d3efa70ec5df12c30319ceed56d2c860afe73aa3cb045571726ad8ff05575ec1`.
All 363 source files matched. Its source-proof log SHA-256 is
`97ae8e1ad5da99204a6240f95fa7b008fb856ae3a1ae011a2e8c9aacac1940f9`;
its test log SHA-256 is
`6f5255ed65e4076aa402938657264c3ea0ff14e11173f00dbc8b3560fbbf5d47`.
The exited container was inspected and removed, without an OOM kill.

The supervisor tests execute a real TERM-ignoring child and verify escalation
and reaping. Their cgroup-population evidence is supplied by a fixture, not
kernel cgroup enforcement. The daemon shutdown test holds cleanup unresolved
for over one second and checks that its main thread retains ownership until
proof. These results still do not establish an actual executing connector,
native gateway inference or separate-device C2 acceptance.

The retained component-8 and component-9 failed test log hashes are respectively
`da60ba3f77296a2fb29c2801271a013c33c2ae5f72c1c4204845698aca0260b6`
and `7a6b307217a2bf295222d78340d608f76d0f4be72b1060cf5a4ac029bd876214`.

## Shared host pin, gateway admission and native lifecycle components

The host role now has one aggregate artifact pin for up to three active signed
assignments in the same installer. Its concrete per-assignment guards cannot
release the group. A real inherited-descriptor exec, installer exclusion, three
resident assigned handlers, unequal interleaving against the complete reference
(`atol=1e-3, rtol=0`) and zero session/cache cleanup are exercised on Linux.
The gate also checks duplicate boot rejection, descriptor alias reuse and
retained uncertain close outcomes. The supervisor's blocked-attachment control
uses a real CPython child: SIGKILL leaves its PID reserved as an unreaped zombie
until placement releases its ownership lock, then the owned child is reaped.
The attachment fixture still supplies cgroup population; it is not kernel quota
evidence.

Component 12 retained one error among 224 tests because its new model fixture
tried cleanup on a second asyncio loop. Component 13 retained one error because
it called a nonexistent `PipelineModel.close`. One retained `asyncio.Runner`
now owns execution and shutdown; reference sessions use their actual close and
diagnostic APIs. Component 14 passed all 224 cases. Component 15 retained one
error among 229 tests because an uncertain-close fixture expected a subclass
instead of the shared owner's `ArtifactPinError`; that assertion was corrected.
The retained failed test log hashes, respectively, are
`67b432fecd429647dd265855c1a596a8564fddedccb6bdc88e4df826f923b305`,
`77dfddecd2e61017afe7672793b26861fa0802ecf7571a5f6506593009a963b0`
and `9cb3635f7957138401d68c43d445d3a048655141b5d30fb892f678ea403c398d`.

Component 16 passed **229 tests, zero skips/failures/errors, 18.227 seconds**.
Its frozen source was
`cb871d4424e83dcf2417b939d9f01d89432c16ac287b64a3865a8ad56d4984ae`
(366 files), and its image was
`sha256:b6a362d047c83258f428eb89c48659bd8d237d940872b259ec0ae86f2e78457d`.
All source files matched; source-proof and test log hashes are
`30e41d785dcd72639e2df966f81d126335300b8cc0eb43679626f8f317217910`
and `cbb92d544da5a43d6ebb0619f481b123dbf32531d43970c7b9c44b42a601146a`.

Gateway delegation now enters C1 authorization and the existing secure runtime
bridge through explicit APIs, preserving grants, exact parsed-request capture,
session ownership and cleanup. Stream closure serializes with session claims.
An admission fault after a new claim but before runtime owner capture retains
the invalidated claim and fences the runtime until supervised reclamation;
it does not claim an absent cache or successful recovery. TLS client ownership
uses the actual configured key/certificate, pinned authenticated gateway and
bounded MemoryBIO I/O. A client handshake alone does not prove that the server
requested and authorized its client certificate.

Component 17 retained one error among 298 tests because its native fixture
changed a manifest fingerprint, which the actual handler correctly rejected.
The fixture now constructs synthetic signed policy for the genuine validated
manifest identity. Its retained failed log hash is
`767886129e288a0ce5bd20dba5925cfea6bb2361dbf68a5caf77fab3224bb3f5`.
Component 18 passed **299 tests, zero skips/failures/errors, 18.842 seconds**.
Its frozen source was
`cb3dd1f5c9c7476ceebe85f0cca81af276bcc80cb12f253c2a9fc40367b91d16`
(375 files), and its image was
`sha256:cbd653c2147c0191c7ad1cca6568ac2a585c016a45205a2ccf981c92be806c5e`.
All 375 files matched; source-proof and test log hashes are
`7317317f888346ae6d74369c9743c97223ecb3b6003cf49841f9fa41e8490e82`
and `94b27e563f606b0a66675c9fd424820c5fcf5207a70ca77d76610784b4ba5eb1`.
It includes a real `WorkerHandler` with a deterministic blocking executor:
stream loss during Step retains its simulated allocated cache until compute
returns, then clears it and its runtime owner. This is lifecycle evidence,
separate from the assigned-model numerical test. All component containers used
the original bounded settings, were inspected after exit and removed, and had
no OOM kill. Counts overlap previous inventories.

Review still found untested protocol weaknesses after this passing inventory:
per-fragment reassembly objects were outside payload accounting, CONTROL used
an excessive size ceiling, and suspended decoder generators could replay an
accepted frame. Corrections and new negative controls are required. Passing
component 18 does not accept those paths or establish a socket work channel.

## Separate-device OS resource enforcement component

A task-scoped probe on the inventoried ZimaBlade used native Debian Python 3.9.2
and the actual `CgroupV2Controller` source (SHA-256
`c2884d035c0826621f0c968bef742a5b2fef0e9a46f5a5b17f77de60801c6f44`).
The operator created an exclusive temporary cgroup capped at 128 MiB, 0.2 CPU
and 32 PIDs, with bounded control and delegated execution children. The probe
entered its control cgroup before dropping to UID 1000, then created its role
group without root privileges. No existing workload or global setting changed.

Read-back role limits were `cpu.max=10000 100000`, `memory.max=25165824` and
`memory.swap.max=0`. The three-second CPU loop used **310,758 microseconds** of
CPU over **3.098 seconds**, with **31 throttling events**. Its separate child
attempting a 96 MiB allocation exited with SIGKILL and incremented the role's
OOM-kill counter by one. Both children were owned by this probe. Its role,
temporary task subtree and uploaded private sources were removed. The first
attempt failed before role creation because the uploaded package lacked a
transitive client import; that failed result and complete task cleanup remain
recorded. The corrected attempt uploaded the actual dependency closure.

This establishes kernel CPU/RAM enforcement for that isolated OS component.
It does not validate the pinned CPython 3.12 execution backend, persistent pool
delegation, combined role enforcement, disk/traffic limits or C2 readiness.
The laptop and ZimaBlade remain sufficient to attempt the planned CPU scope.

## Authenticated transport and accounting components

Component 26 passed **474 tests, zero skips/failures/errors, 26.529 seconds**.
The frozen source was
`afc889c302625f5871f9273059d80206fbb1b4eca09a71984e2d6983c4383818`
(395 files); every file matched the rebuilt image
`sha256:6a09109e0df58b0d0c080c8eaa5e2a78ad5de5f9318fecf48c8777e52de18f12`.
The source-proof and test-log SHA-256 values are
`28d89fc3afe144401c76477ea6a190247511a1786b252e951331c55895a012e7`
and `b64dbff2a5a8818f29c3af0f5386cbdb2fd732196fe17238da4929803d6178f5`.
The original two-CPU, 6-GiB, 256-PID, read-only, network-isolated container
limits remained in effect. Its terminal inspection showed no OOM kill; the
exited container was removed. These counts overlap earlier inventories.

This inventory adds independently reviewed signed channel policy v2 with
separate worker/coordinator endpoints, delegation v2 with separate strict data
and control counters, bounded fragment encoding/reassembly, a control-priority
writer and authenticated HELLO registration. TLS-owner and registration
capabilities refer to actual peers; registration alone confers no work
readiness. The atomic socket meter holds one shared ledger transaction over
durable reservation, a non-consuming TLS liveness check, one nonblocking TCP
call and exact settlement. The Linux inventory includes its persistent-file
locking, no-I/O-on-contention and actual TLS/socket cases. TCP payload counts
include TLS overhead; they exclude IP headers and retransmissions.

Failures remain part of the evidence:

| Component | Result and disposition |
| --- | --- |
| 19 | 355 passed; earlier transport inventory. |
| 20 | 392 tests, two failing settlement subcases; durable-commit/cache fault handling corrected. |
| 21 | 411 tests, one file-lock fixture child failed a conservative clock check; the concurrency fixture now uses an explicit monotonic-derived synthetic wall clock, with a separate sticky wall-rollback negative. Production clocks are unchanged. |
| 22 | 418 passed; later independent review still found socket defects, subsequently corrected. |
| 23 | Aborted before execution: the parent's expected inventory was 428 rather than the discovered 427. |
| 24 | 427 tests, one stop-during-attach fixture failure; an exited fake process was incorrectly republished as a populated cgroup. |
| 25 | 474 tests, two fixed-spin socket-delivery failures on Linux; corrected test waiting as described below. |
| 26 | All 474 passed after the bounded fixture corrections. |

The cgroup fixture correction changed no production supervisor code. A
deterministic eligibility-to-publication barrier reproduces the invalid
population when its liveness recheck is removed. With that correction, the
unchanged native supervisor passed 100 repetitions of the original case and
all 42 supervisor tests, with no skips.

For the two socket cases, unchanged production code and fixed-spin tests passed
20 repetitions when only test-socket TCP_NODELAY was enabled. Under the original
socket settings, bounded real-monotonic delivery waits of at most one second
then passed 20 repetitions and all 47 socket/accounting tests without skips.
Payload, exact byte-accounting and subsequent control-delivery assertions remain
in place. Production resource limits and deadlines were not relaxed.

The gateway request producer and the composed framed socket service were not
included in component 26. Their integration, application readiness and actual
separate-device inference remain pending.

## Remaining acceptance work

The daemon still needs actual backend, assigned artifact ownership and readiness
integration. The adapter's blocking file verification has a source-reviewed
replacement using a lifetime artifact pin and live in-memory authority guard;
its single-assignment and aggregate native/numerical checks passed, while actual
supervisor handoff remains pending. Process supervision and the core gateway
bridge have source review and the component inventory above. Actual transport
and full application ownership still need acceptance; the separate OS probe
does not establish combined application enforcement.

C2 still requires actual shared CPU/RAM, disk/staging/log and traffic enforcement;
authenticated enrollment and expiring loaded readiness; the trusted terminating
gateway with two authenticated mTLS hops and signed delegation; bounded work and
independent cancellation lanes; a real consumer/personal-coordinator route; and
the exact CT-11/CT-13 numerical and lifecycle checks with executing stages and
their coordinator spanning at least two physical machines. The laptop and
ZimaBlade CPU host are available. No additional hardware requirement has been
established. No WAN/NAT universality, GPU, pooled-capacity, performance or later
research gate is claimed. C2 remains unpublished until all of its gates pass.

## Follow-up evidence after component 26

Component 26 remains a historical complete inventory:
474 passed, zero skipped, failed or errored, in 26.529 seconds, from frozen
source `afc889c302625f5871f9273059d80206fbb1b4eca09a71984e2d6983c4383818`
(395 files), with image
`sha256:6a09109e0df58b0d0c080c8eaa5e2a78ad5de5f9318fecf48c8777e52de18f12`.
Component 27 below supersedes it as the latest complete component inventory.
The selected native probes exercise bounded code paths and do not establish a
full participant-pipeline pass.

### Assigned artifact pin handoff

A read-only native overlay of source
`7a1c84f775d6b221e6cdb4760eb90f67c00acc89f636b17d1d957ec9d08a5212` (397 files)
on the pinned component-26 image passed 75 tests, zero skips/failures/errors,
in 4.609 seconds. The run used the same two-CPU, 6-GiB, 256-PID, no-network,
read-only-root, all-capabilities-dropped, no-new-privileges container controls,
with 256-MiB `/tmp` and 16-MiB lab tmpfs. It started at
2026-10-19 16:52:31.570Z and completed at 16:52:37.664Z; log SHA-256:
`b95b2c616b7e6025c1a3349d5d7ec704545c04e3b37d52802c0cb257b135ce54`.
This exercises an actual signed installed store and a real CPython `-I -S`
supervised child exec retaining inherited pin descriptors, with startup gated
by the host and coordinator locks. The fake cgroup population remains fixture
evidence, not OS attestation. It does not establish persistent pool/readiness
integration or the selected C2 aggregate startup flow.

Earlier pin inventories are retained: pin-native1 had 73 cases, 70 passed and
3 failed in 3.390 seconds; pin-native2 had 73 cases, 72 passed and 1 failed in
3.312 seconds. Their failures led to corrections for composite owner retention,
exact dup2 descriptor reuse and private fixture state mode 0700. Production
resource limits were not relaxed. The corrected third run is the selected
component result; the prior failures remain part of the record.

### Watchdog publication race

With the unchanged baked component-26 production code and the same resource
limits, a deterministic 30-ms fake SIGKILL exit delay reproduces the old
publication timing failure: the original target expects a populated group
before the fake process has exited and fails in 0.148 seconds. The corrected
fixture publishes only after child exit and passes 20 repetitions in
3.551 seconds. The log SHA-256 is
`2e63f7606ee5a8784f3cb01e419b30bbccffe649a3801d1f18e7a83a1be35d86`.
This supports the fixture timing diagnosis; it does not add a new production
watchdog behavior claim.

### Root-group policy review

Review of source `20f71ea` found a pure, inert scope/stateless policy check with
eight local tests passing, plus review-confirmed high-severity negative cases
for a wrong scope and wrong domain. The mechanism does not provide local
identity, claims, high-water persistence or readiness. C1's accepted singular
root profile cannot establish startup for three workers. Explicitly selected
C2 aggregate scope/claim policy and its cold-retirement integration remain
missing; no root-group startup acceptance is recorded.

### Historical RPC and SDK diagnostic failures

As of the earlier native probes, RPC ownership probe 5 demonstrated the production defect with
the real compute still alive after authentication closed (exit 1; log SHA-256
`4b78ee6d4b686342d998b0710e8eb85f7fe2ec687b1ef0a7455db78dfb03990c`). A later
probe corrected the first native bridge assertion but still failed when another
legitimate open stream remained alive. A follow-up closed that stream; probe 7
passed both body-cancel and stream-loss cases and zero-resource assertions, but
two expected-disconnect cleanup cases still failed. The newer native-8
confirmation-code probe is under review and has no result accepted in this
record. RPC ownership therefore remains source-review/native-unaccepted.

Native SDK probe 6 ran 12 cases with 11 passing and one failing in 2.845
seconds: short-request C1 expiry killed the global pump. Diagnostic expiry 7
traced this to `GeneratorExit` when `unittest.assertRaises` cleared frames from
a caught exception traceback shared with the live pump. The bounded fix creates
a fresh static `SessionError` so the pump does not retain that shared traceback;
the previously described shared-traceback-clearing correction was inaccurate.
At that point, SDK remained unaccepted. Raw protobuf guard 8 passed locally;
control/data reservation targets had not been measured under native peak load.

These failures are historical diagnostics and are superseded for the bounded
checks described below. They do not disappear from the record or establish the
cause of every earlier failure.

### Remaining C2 integration

Actual fixed-role backend enforcement, authenticated enrollment, selected
aggregate root-group startup, resource-pool integration and CT-11/CT-13 laptop
plus ZimaBlade routed numerical/lifecycle evidence remain incomplete. These
are the outstanding gates; no additional hardware blocker has been established.
All C2 checklist items remain open, and C3 has not advanced.

## Component 27: rebuilt full component inventory

The rebuilt component gate passed **562 unique tests, zero skips/failures/errors,
36.336 seconds**. Its frozen source is
`0bdc0d109ad9da18aace2c191e829e1c0ed2fb80e5edbbf57651cffcb678dab9`
(415 files); the rebuilt image is
`sha256:f662e256c8daae02a7e7b55fb5b9e55571c5a6776610ab7fbc7374d9a4d94e56`.
All 415 source files matched the baked source proof, whose log SHA-256 is
`970fd0a451fe8be9606568c01d9dbe01eb29e3e7ec10af176d52b605c6236ba5`.
The test log SHA-256 is
`41f178de09f23139ee8518d925b230256dd55ceb6c1cd42dd837391257cf13aa`;
the gate record hash is
`1f456c5e4c87954f91e2402b16663b865780bdcb7834fe37eb370aafa3584427`.
The test container ran on Linux/amd64 with 2 CPUs, 6 GiB, 256 PIDs, no network,
read-only root, all capabilities dropped, no-new-privileges, init and 15-second
stop timeout; `/tmp` was capped at 256 MiB and lab tmpfs at 16 MiB. It ran from
2026-10-19 17:34:44.281Z to 17:35:22.313Z, exited 0, reported no OOM kill and
was removed. This supersedes component 26 as the latest complete component
suite, while remaining a bounded component gate rather than C2 acceptance.

## Selected native egress checks

Transport native-9 used the same frozen 415-file source on the pinned
component-26 image and passed 42 tests with zero skips/failures/errors in
8.719 seconds. Its inventory was RPC 8, protobuf guard 8, SDK 12 and egress 14
cases (42 total). Its log
SHA-256 is
`8821b8d01290f99f95c986e95382805f84ffa0811522bbc0cba4a608a0b42e9d`.
This is selected native component evidence; earlier native probes 4–8 and their
failures remain retained. Together with independent main reviews of RPC source
`4f` and SDK source `1c`, which accepted these bounded changes, it establishes
source-reviewed and native-green selected RPC/SDK/egress controls. The signed C1
`WorkerHandler` native path also has bounded passing evidence in component 27.
These results establish progress on actual signed C1 worker handling and its
selected native paths. They do not establish the deployed dual-listener gateway,
whole-cohort claims, aggregate root startup or a complete participant route.

The SDK traceback correction addresses the observed pump failure mechanism.
Native-9 and the source reviews do not establish integrated consumer delivery
or phase acceptance. Transport native-9 is a bounded selected gate; the earlier
native-probe failures remain historical evidence.

## Isolated capture parser measurement

Capture native-1 ran seven tests with zero skips/failures/errors in 2.482
seconds using a 417-file source overlay on the pinned component-26 image. The
source is `33a9729871a286a6dbfe621d56e2a25f61b4275513a21b3fd1a014b328c48389`;
the log SHA-256 is
`87bcebedca9bba2c091e217508742489c23a3837a8682ac7c9a7781a4cd233c5`.
The isolated parser/wire placeholder measured Python `tracemalloc` peaks of
1,476,215 bytes for max-data, 943,692 bytes for control-density and 2,702,485
bytes for malformed-shape input. Native peak RSS delta was measurable only for
the malformed-shape case: 2,457,600 bytes. The valid max-data and control
measurements were unmeasured because the process high-water baseline masked a
new peak; those RSS results are not zero or passing native reservation bounds.
The parser is an isolated placeholder binding, not signed C1 transport or full
RPC integration, and does not establish whole-role peak memory.

## Selected cohort validator: reviewed source and native run

Selected native-1 ran 11 diagnostic tests with zero skips/failures/errors in
0.105 seconds, log SHA-256
`4a39250f8e1799d9674094d2bf76d1fe447936a31c8e9d2945616639fe198b2c`.
Main review subsequently accepted source
`c3dc33343fe9053fb76fad68450d031df6e15d2e9434405275710b8b16489c73`
(418 files; review `49d`). The inherited-main native-2 run passed all 12 tests,
zero skips/failures/errors, in 0.117 seconds. It ran from 2026-10-19
17:41:58.475Z to 17:41:59.926Z; log SHA-256:
`a0d3ecd2fdeccbb3872afd41026eb2d82456026f8f378e577352ae83c6591c7e`.
The earlier 11-case result is retained as the prior diagnostic, not an inventory
to add to the 12-case run. The accepted code remains an inert policy validator:
it supplies no local identity, claims or startup. It does not establish selected
aggregate-root acceptance.

The integrated selected-cohort implementation at `42ab8f0` is a separate
boundary: it remains an inert validator path without local identities, claims
or startup integration. The validator source review does not constitute
aggregate root-loader acceptance.

## Current C2 boundary

The whole-cohort claim, root loader, fixed-role backend integration,
authenticated enrollment, actual dual-listener gateway, shared physical
resource pool, and CT-11/CT-13 laptop-to-ZimaBlade routed numerical and lifecycle
checks remain pending. C2 remains private and unpublished with every checkbox
open. C3 has not advanced. The laptop and ZimaBlade remain available; no
additional-hardware blocker is established.

## Component 29 and latest native controls

Component 29 rebuilt the bounded Docker inventory for connector tests and 21
selected security modules (not the full repository or full C1 regression) from
a frozen 432-file source snapshot at head
`1b221ffb38eb076eed5ee6bcfc525a28370aa7e7`
(`b35138503cd218d43f37ae024b8c05e82910e64da10ecb6cc06ee74c4503b685`). The
pinned image was
`sha256:44301c3d0a5f06a5ef41e3518bc273486a9c18a47c0b118fc211ef3219722f7b`.
The test command completed with exit code 0: 705 tests passed, no skips,
failures or errors, in 38.605 seconds. The container was network-isolated,
read-only, limited to 2 CPUs, 6 GiB RAM and 256 PIDs, and had a 15-second stop
timeout; it exited 0, reported no OOM, and was removed. The source proof also
ran network-isolated with 1 CPU, 256 MiB and 64 PIDs. The component-29 source
proof, test log and gate evidence are privately retained under hashes
`232ca697d94fce0b49e94491383755ad69c38fd983ebb5dcf77d3d190c7b6ca8`,
`716987a417e93dfc9ead74191e733eece29126fbfdbad7547a2e1bc279bacd72`, and
`c36cd1761575ec462fa039589d566b35348d01964855322a2e0c39d916266fc1`.

The component-28 run remains in the record: it had 705 discovered tests, 703
passes and two failures because its image lacked the foreign-owner fixture.
Component 29 corrected that fixture in the image only; the inventory and
resource limits were unchanged. This makes the later pass useful evidence for
the same component set, not grounds to erase the earlier failure.

The latest bounded native probes also passed: local launch claims, 12 tests
(snapshot head `95da3cc441d495b6c458dd5f572c0a2875521297`, 432 files); global
launch claims, 15 tests (head `8d09794bc93164d303158d5ef11ee4aa96badf8c`,
432 files); coordinator, 9 tests (head `6994e1451ae5f89c4925223381fc2da4bf4fe3a4`,
432 files); routed-pool rules, 14 tests (head `1f0fd15abdca3b96b6525985c9e697e6b83f9fc5`,
420 files); and startup seam, 58 tests in the latest native run (head
`6c1fe368a1e55a41b8500f0efbc6dd35e2c2aaa9`, 434 files). The root-runtime
final-lock causal control failed once against the old implementation and
passed once against the new implementation. The startup seam still substitutes
fake cgroup limits. These fresh runs do not turn claims into Popen authority,
host/coordinator binding into READY, or the shared route ledger into actual
resource integration. They also do not establish acceptance of the complete
selected-root startup path.

The prior 57-pass seam run (head `eab7e01ecc0e91b0cb1b7b770a21864f078cd9df`,
log `844be488214021ec82d984a235d305a21d525ea44f4f5a72fa1fb1bc5d2b1bd3`) is
retained as historical evidence; review found
that its final polling path could leave a handle live after a final-poll error.
The corrected seam run uses source head `6c1fe368a1e55a41b8500f0efbc6dd35e2c2aaa9`
and digest `a4eca0d5cb463c024621e8aacd2633b4f0366b75f27d139dc14e7149749fb6dc`
(434 files). It passed 58 tests in 3.520 seconds with zero skips; its command
exited 0 and its log hash is
`38cbc8501e073942bb83304830a2611ee5e75fbc1c5fcd299ad6e91e4d0abd7c`.

The latest local-claim and global-claim test logs are
`6a4f6e64c7834dbeaaa49fc8ceaaa6a0abdd1ba4fb623114a39afe068c1511bd` and
`fc87688f78cc3821577af3a278aee2495c52d22a0b7fede3163081f70002918d`;
coordinator and startup-seam logs are
`a26491bd41f4ba997fb79bfe9b317eab799b4703a1d26f4dcb2277725619b960` and
`38cbc8501e073942bb83304830a2611ee5e75fbc1c5fcd299ad6e91e4d0abd7c`.
The local and global claim source snapshots contain 432 files each, with
digests `8f7e9fb3ba07968dccf63647e2f2adb1e55e9bacd00d089c374bc3e1151a3647`
and `e1f13572e259b41c069780dde66c53015920bbb3d70bcb8d69485764543c8136`.

Main review found a coordinator/host deadline-retention defect in the
coordinator (`6994e145`) and host-binding (`7e` series): uncertainty widening
checks do not retain the tightest monotonic deadline. The latest native
coordinator probe does not exercise this path. A bounded deadline-floor
correction is active in the isolated `c2-deadline-retention` work but is not
integrated; the previous native pass is not evidence for that fix.
Claim-lifetime changes and the seam fix have source-reviewed integration
commits (current integration head `8c80a13`), but no combined inventory has
been rebuilt from that head.

Failures and invalid harness runs are retained rather than counted as passes:
the earlier local-claim fsync fixture run had one failure (the canonical record
bytes were fully written, but fsync failed, so durability was unconfirmed; the
test incorrectly expected reopening to reject valid consumed history); the
next local and global FD-reuse runs each had one failure because `/dev/null` was assumed to
allocate a particular descriptor. Corrected native runs use exact `dup2`
reuse and synchronization barriers. Coordinator attempts included an empty
parent probe with zero tests (exit 0, not a pass), two attempts with four setup
errors each (eight errors total), an expiry
assertion mismatch (7 passes/1 error), and an inventory mismatch that aborted
before tests. The latest coordinator run passed its nine tests. These tests are
bounded software checks; independent acceptance review is still pending.

All C2 checklist items remain open, C3 is unchanged, and the evidence is private
and unpublished. Actual fixed-role enrollment/local startup/gateway operation,
shared physical CPU/RAM/disk/traffic and session-queue enforcement, and the
CT-11/CT-13 laptop-to-ZimaBlade routed numerical/lifecycle gate remain required.
No supported GPU or pooled-GPU performance result is established, and no new
hardware blocker has been found.

## Component 30: combined connector and selected-security inventory

Component 30 is the latest complete combined inventory. It covered all
connector tests and 24 selected security modules; it was not a full repository
inventory or the full C1 regression. The frozen source was head
`5a007e81139a50eb54fe0f8c7caa4044b52739f5`, with 445 files and digest
`2d2083006e25afbb5c7569781f394835baf528ac9ca8dae7619a767db05caa18`. The
pinned Linux/amd64 image was
`sha256:42ee4553918ba7b636d3a374d84f96094f1daed30cf97b4be50798cf3b5f6798`.
The all-source proof verified 445 files with zero mismatches. The inventory
passed 770 unique tests with zero skips, failures or errors in 45.992 seconds,
from 2026-10-19 19:04:44.454Z to 19:05:32.459Z. The container exited 0, was
not OOM-killed, and was removed. It ran with 2 CPUs, 6 GiB memory, 256 PIDs,
no network, read-only root, all capabilities dropped, no-new-privileges, init,
a 15-second stop timeout, 256 MiB `/tmp` and 16 MiB lab tmpfs.

| Evidence | SHA-256 |
| --- | --- |
| Component-30 all-source proof log | `655887c6215184cda7fc9d10c40e1811fe1fc0d6a4387715dd571575e338c19f` |
| Component-30 test log | `42200d2d6cbc1b849a64616d189116e8ceeb7e946837b77c22a70be8a182f958` |
| Component-30 gate record | `4c8e7c282faee789b4e77d94fa2b451c3e88b24b92b09e470685a18a2611ce67` |

The post-run test command attached to the inspected container and exited 0;
the retained invocation was `docker start --attach
36bfa93e4ebb2f8bf39a6783aade4434579035e083d8f136142f9e7f82bece84`. Container
metadata confirmed the pinned image, limits and read-only artifact/gate mounts.
The source proof and test outcomes are component evidence only. They do not
establish full C1 regression coverage, deployed C2 integration or phase
acceptance.

## Focused deadline follow-up and retained diagnostic failures

The final-window causal comparison ran four deadline-retention tests. The old
implementation failed all four assertions (no test errors or skips); the new
implementation passed all four with zero errors or skips. The old run used two
historical single-file overrides over a newer frozen image, so it is a hybrid
causal comparison, not a baked-source proof. This compares the historical
`1b`/`6994` implementation with the newer source at
`435734c5a5d8b3296681a81112f13d554608040b`. The logs are
`86dea0290f67877d312fade1dff13552bdc2bed53ec9be79d4ac4c4d5b9eb467` (old) and
`e6f8cf8cda5c3a9d284aae56428f93392345bc5d72833bbe37871b31410c0527` (new).
The new side used a 437-file source snapshot with digest
`0b33a9bce13b4acb5ecbf2ec207f5ce1a7b5631f318ff4b2066a28490e406b8e` and pinned
image `sha256:6a09109e0df58b0d0c080c8eaa5e2a78ad5de5f9318fecf48c8777e52de18f12`.

A separate first-window causal probe also ran four deadline-retention tests.
The old `60d` two-file hybrid failed all four expected-expiration assertions,
with zero test errors or skips; the corrected new source passed all four. The
old and new log hashes are
`8c654fdbc143a81c85e338148340f811ff17614bab363c46ea8c4ab9709a6c0e` and
`a80f5339d2658e418e5d711f9ed144fe5cfe181b43be49735496d63d780d2926`.
Neither hybrid old-source result is a baked-source proof.

A further native focused run passed 41 deadline tests with zero skips,
failures or errors in 1.139 seconds. It used the 437-file source overlay at
head `fb1ae266ca8155f7eb92cb0d17b7d4938bc4ba0c`, digest
`37c654a02be351caf9fdf6664741085e8caa634bef55ab01b3cac1d9175ffa1b`; its log
SHA-256 is `98c316c8011fdd2d1c274dc6b52ea61ab412b261635c67c7f9da5779e922b2b0`.
The later two added assertions instrumented tests only; the combined 770-case
inventory was not rerun after that test-only change. Focused passes therefore
remain distinct from the complete component-30 result.

Earlier deadline native attempts are retained: native-1 ran 33 tests with 30
passes, one failure and two errors; native-3 ran 37 with 36 passes and one
error. The errors included time-bound fixture setup/expiry behavior, and the
initial deadline implementation did not retain the tightest observed deadline.
The later focused controls above test the correction; they do not erase the
failed runs.

Gateway mux native attempts are also retained rather than counted as passes:
native-1 ran 3 tests (one pass, two failures); native-2 ran 7 (one pass, five
failures, one error); native-3 ran 7 (two passes, five failures); and native-4
ran 7 (six passes, one error). Early failures exposed the test driver's missed
coordinator-client pump, a malformed Describe fixture, and the real fragment
writer's earlier rejection of a reused ID. The test driver and fixtures were
corrected, including a boundary-specific duplicate-ID assertion; later mux
coverage is part of the component-30 inventory. These historical counts are
not additive to its 770 unique cases.

Owner-consent is a separate path from the combined inventory. Its first native
probe ran 10 tests: eight passed, one failed and one errored. The failure concerned
the fixture expecting epoch 4 where the correct result was 3; the error came
from an empty role tuple, for which the correct exception was `ValueError`
rather than the fixture's expected storage error. A later focused native probe
passed 13 tests with zero skips, log
SHA-256 `3b5328363a8cb2d3e4202dd7c169c4bf73324d02a84c6c4ed96b57d484d9618a`,
on a 440-file source at `ef72979` with digest
`eaa8fff820ba19787f73cfb1c8c1a4f95beb2b381988a889a52c6f6aeea62558`. The
latest focused probe passed 14 tests with zero skips/failures/errors in 0.028
seconds on 440-file source head `a0da6a95` with digest
`5047a68fa5f0fddb9098ad945dda39a78828f36de573aad8b7a6886e342b9810`; its log
SHA-256 is `12e962ae29b2ec427dbe0984b00082fbcb6eb686c1880204106429aef9c83e07`.
Independent source review cleared the 14-test source, which was later privately
integrated in commits `967ff7e`, `7b3664f` and
`b39c4297cdda4d0aa69e30f0d494bf0f666781d5`. This integration is outside the
combined 770-test inventory and does not establish owner controller startup,
role launch or READY. The earlier 13-test source-review-pending note is
historical. No startup/readiness claim follows from these focused probes.

## Current C2 boundary after component 30

C2 remains private and unaccepted, with every C2.1–C2.6 checkbox open. The
owner-consent store is privately integrated, but the combined suite does not
establish controller startup, fixed-role
backend enforcement, authenticated enrollment, deployed dual-listener gateway
operation, aggregate selected-root startup, shared physical CPU/RAM/disk/
traffic and session-queue enforcement, or CT-11/CT-13 laptop-to-ZimaBlade
routed numerical and lifecycle acceptance. Deadline-floor focused tests do
not complete these integrations. C3 remains unchanged; no supported GPU or
pooled-GPU performance result is established, and no additional hardware
blocker has been identified.
