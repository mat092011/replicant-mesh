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
