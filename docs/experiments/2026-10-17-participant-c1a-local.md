# Local secure pipeline evidence, 2026-10-17

Status: **C1a is unfinished; C1b and C1 remain pending.** This is evidence for
selected local correctness paths, not acceptance of the complete security gate.
The publishing branch contains C0 only. See [phase gates](../PARTICIPANT_NETWORK_PHASES.md)
and the [secure pipeline guide](../PARTICIPANT_SECURE_PIPELINE.md).

## Configuration and trust boundary

One physical Windows laptop hosted one Linux amd64 Docker validation container:
CPython 3.12.15, the unchanged hashed CPU lock, and isolated cryptography 50.0.2,
cffi 2.1.1 and pycparser 3.11 extras. The build uses the pinned base and exact
wheel hashes in [the security image](../../docker/participant-security/Dockerfile).
The CPU lock SHA-256 is
`0d893300099241375c9ef032268e162ff6ef46fe93cce1bbe6457bfd01545434`.
The [Compose configuration](../../compose.participant-security.yaml) limits this
container to two CPUs, 6 GiB and 256 PIDs; source is read-only, capabilities are
dropped, and the network is disabled. Existing verified model/cache volumes are
mounted read-only. Model checks were serialized by the parent.

The model/tokenizer is `Maykeye/TinyLLama-v0` revision
`298338802ab94432b917bcce11382aa151aee50f`, CPU float32, eager attention, batch one,
without compression. Three resident StageExecutors own layers [0,3), [3,6), [6,8)
and their session KV caches. The supervised coordinator owns embeddings, final
normalization and output head. A complete Hugging Face model on the same stack
provides the reference.

The test creates ephemeral P-256 identities through actual invitation/enrollment
APIs, with separate CA, invitation and snapshot signing roots. Actual signed
snapshot/grants, core incoming/outbound authorizers, expected-leaf verification,
original-target IP SAN verification, native opaque TLS connectors, runtime
bridges and ConsumerContextFactory carry the request. No fake authorizer or
in-memory transport is used in this matrix. Keys exist only in protected temporary
files, not in the image or repository. Worker owners and the coordinator remain
trusted with plaintext computation; this is not a privacy guarantee.

Four listeners reserve one connection slot each. Four outgoing clients reserve
three each, under one process-local NodeConnectionBudget: 16 total slots, four
pending, at most two outbound pending. Worker channels are prewarmed sequentially.
This does not establish shared accounting across independent processes.

## Measured checks

The enabled `tests.security.test_secure_pipeline` test passed with **one collected
test, no skips**. It includes a one-token unforced greedy control and prompts of
1, 128 and 1024 patterned tokens:
`token[i] = 3 + ((i * 37 + 11) % (32000 - 3))`.
Each prompt has eight identical forced continuation inputs and nine output
positions. Every one of the **27 last-position logit vectors** met `atol=1e-3,
rtol=0` against the corresponding complete-model row; greedy token IDs were
checked separately. Full-prefill reference logits stayed local. All wire
captures were last-position vectors. Fresh typed request/session IDs, event
ordering, terminal output counts and successful-path KV/session, capture and
transport reclamation were checked.

The explicit owner CaptureBudget used V=32000, Q=16, at most eight captures and a
1 GiB pool. Its per-capture logical reservation is 92,032,256 bytes; eight reserve
736,258,048 bytes. These are accounting quantities, **not observed peak RSS or a
physical memory enforcement result**.

| Check | Source digest / image ID | Retained log SHA-256 |
| --- | --- | --- |
| Patterned TLS numerical matrix, 1 test / 0 skips | source `18d9756470b9795b2ed5d46842c61e66bd0137df9cb3d47945f52b8f1cbc5c9b`; image `sha256:fde1a34a660f296182b814efbcd462a6838843cd2b6156f4c158917d433333d3` | `d41700d0d8e83e2487f92ec10281b3fcefdf13442442dd42ec4aaeabeffc6f73` |
| Exact baked-source comparison, all 206 files for that matrix | same source/image | `8621c5229d446d510550c11048770782a24db8654b41aec6a4cea0f0da75e935` |
| Coordinator/acceptor shutdown regressions, 37 tests / 0 skips | source `f9d937f6ed93e8336a5d2585410573e18d23b5149cc02e1d69fac698eb674fd2`; image `sha256:12b572f6ec019439c2e70251c262f489812f1d2d42942259a8a23d56d78fcedc` | `5b7c11f87cad2a9c17e9a5dc7ebacde0e9f5023e3d007272a206a7f25bfede56` |
| Exact baked-source comparison, all 206 files for shutdown tests | same shutdown source/image | `e2d5856f1adc73ae8f67a6ed151526b66b009e3e0a29bfa2308409db0266ca1d` |

The shutdown regressions include ordinary client-close failure, descendants
reported after the close deadline, completed-root/helper-cancellation races and
model-close timeout. Passing source sets above predate this report and subsequent
fixes; they must not be attributed to later source bytes.

Reproduction commands use the same named Compose project as the actual runs,
 `steamboat-c1a-corrected-20261017`:

```sh
docker compose -p steamboat-c1a-corrected-20261017 -f compose.participant-security.yaml build security
docker compose -p steamboat-c1a-corrected-20261017 -f compose.participant-security.yaml run --rm -e STEAMBOAT_SECURE_PIPELINE_TESTS=1 security python -B -m unittest tests.security.test_secure_pipeline -v
docker compose -p steamboat-c1a-corrected-20261017 -f compose.participant-security.yaml run --rm security python -B -m unittest tests.runtime.test_coordinator tests.security.test_secure_acceptor_ownership -v
```

The recorded actual runs used unittest loader wrappers that additionally rejected
skips and empty collections; the matrix wrapper had a 180-second watchdog. Exact
argument arrays, timestamps, exits and raw logs remain in ignored `.lab` records.

## Follow-up validation, still incomplete

A later capture/ledger/runtime-bridge suite passed **53 tests, zero skips**,
including an actual model case. Source `9d9f02289a0bafaaf4f1c3c45fc8122c37fd468b2d5f22d52919c9584f885b49`,
image `sha256:285e0e8d4f0848e0e32f28334dacab0d9e9e1bbf9580d4a10676ccf424abc626`,
log SHA-256 `f9f1f8a6fe9acb96cd2dd0332d901622474d18e222b087039d523d3137aa6876`;
all 207 baked source files matched. Independent review still found a cancelled
producer being mistaken for failed physical cleanup, cancellation of the pending
monitor losing descendant discovery, and unsafe metaclass MRO descriptor access.
These remain under repair; the focused pass does not resolve them.

Full security discovery then ran **216 tests** and failed with one error and two
failures, no skips (log SHA-256
`9b594aa6f6dadf3a67641f560ab10dbeb37fb828e19439b792a39217dfc374bc`).
Two were outdated fixtures: a hand-built request state lacked new cleanup fields;
a strict deadline assertion compared a later factory sample with an earlier
external timestamp. The corrected fixtures preserve the cleanup and deadline
assertions, using a deterministic sample for the latter. The remaining stalled
cleanup failure is the production ownership issue above, not accepted as a test
expectation change.

The corrected matrix fixture plus participant/factory context checks passed
**30 tests, zero skips**, including all 27 TLS vectors again. Setup resources are
registered immediately; teardown preserves primary and cleanup failures and
rejects unsuccessful closure. Source
`ace1f47024f7077e4663568a7a4fb3e26d4b9dcbb9b996878f250936db04703d`, image
`sha256:832fceab43047d2ac70cf9d319c80cc2fec7d4e386fa1f4b4acacac0893d5c45`,
log SHA-256 `4d59f55eed0cf0f01dc6ef1af53ef522241cdecfd3161795c3bd5751a1227a93`;
all 207 baked source files matched. These test counts overlap earlier suites and
must not be summed as unique coverage. No final consolidated pass is claimed.

The subsequent legacy control passed **318 tests, zero skips**, using immutable
image `sha256:3558da7ba4907487f29a092fec3cb57681b91999628ee31670ac0589977408f7`
and source `dc2b79789c2b57a8b266c35a2c0613e9c9d69d9f88fa606aeff7df160f287451`.
Log SHA-256: `85850f40aa9b2243a17617ac6089732518be36380b92e80e4433f0efdf103f88`.
The common plaintext service/scanner code was unchanged by later secure-owner
changes. A focused owner/scanner follow-up passed **121 tests, zero skips** on
source `8bd961b671b52a4a4ff2d490a2e32dc31286194df61adeff0eb8e0b9537bc1dd`, image
`sha256:26e7b7b469185be9dbcfcda6cc760a4d585ba9b58bb9a7079587761a1b15297c`,
log SHA-256 `e8de84eb72112b01dcd29786ae01a346e310daaf070f0805cb0ae0e25086c734`.
That follow-up still precedes the late-child-after-monitor-exhaustion repair.

The retained CPU in-process correctness smoke on that latter image passed all
**eight comparisons**, with finite logits, maximum absolute error 0.0, greedy
agreement, cancellation/session-limit checks, and zero final sessions/cache
reservations. Compact report SHA-256:
`5d853ca4ba398871dc1a4da03e3c32a008b802abf2c1bec3f1c70b18a7365b28`;
log SHA-256 `f44acfdaa9cbbe682864769461e0ac1f11da05f57f0557536b4a99c1b0719e2e`.
The first smoke invocation returned success but its temporary report was not
retained; it was rerun with a task-owned result mount to retain the comparisons.
This control uses no network and establishes no secure-path performance result.

The [capture observation record](2026-10-17-participant-c1a-capture.md) adds the
actual-model stalled-writer and pending-CPU gate, with observed RSS and verified
cgroup limits. It is explicitly fake-authorization/in-memory-transport component
evidence. A later full-security run passed 232 tests with zero skips on source
`e61b0cfbd1d492895356a6c94fb5dbb620fd2ac22e3d9b41fa87d7b084071706`, image
`sha256:a8c56734aa9ddd243a42aa4ae961eb9341e48a6e6be499a18a92abb09ffc0091`,
log SHA-256 `9cd50174eed556e4614b02174d7139c72caaa6c5b4ceafd285ac2428a8dd3989`.
Further review exposed a listener late-descendant shutdown gap and authenticated
capacity-error handling gaps. Those changes and expanded real TLS lifecycle
coverage remain under validation; 232 passes do not declare C1a accepted.

The expanded real TLS lifecycle test passed in isolation on source
`45a572e140969be3b82506ea22e5924473d02fdad632d11a71048340bec7046b`, image
`sha256:03b5e25a13a8551213fba11cd2c462fdb01f1eb2e550f033339d45639de70176`,
log SHA-256 `57c0502ed808e9ce89100ddffcbc4cf7c321f297514034b33588f321c12b9ce8`.
It includes the original 27-vector control, a four-token greedy continuation,
two unequal concurrent requests, the context boundary, and eight held capture
requests followed by a rejected ninth request. Concurrency here does not by
itself prove physical stage overlap or a separate-device benefit.

A subsequent **244-test consolidated run failed one test, with zero skips**.
The eight-capture case returned `CLEANUP_UNKNOWN` for one request; fencing the
shared channel then cancelled four other requests. Five capture reservations
remained pending and coordinator shutdown did not confirm closure. Source
`1690769a665ed11229cd1283ae78234541edb23e84a96c64847328a830790d8c`, image
`sha256:e257ab423ae3354c46ed595afa3a90b5986b2bcbba0a783704d8df0778424374`,
log SHA-256 `8bcc6bb93e8530452a931639cc0eceeacc5e83ec8e790a18f84afb1552041012`.
All 211 baked files matched that frozen source manifest; proof-log SHA-256
`cab7aa432dcaf8568bba3a2cf0aba9faaa591deb59deae6bdab2a973bb5c74d0`.
The cause remains under diagnosis. The isolated pass does not override this
failure, and no consolidated C1a acceptance is claimed. Independent review also
requires a binding-bound application rejection trailer before the client can
classify capacity exhaustion as confirmed pre-admission rejection; that repair
remains under validation.

One subsequent observational diagnostic attempt used that same frozen image
and source, with a parent-mounted bounded cleanup observer as an explicit
experimental variable. It ran 244 tests with zero skips and failed before the
target eight-capture helper: the security clock reported `CLOCK_UNSAFE`.
The target was not observed, so this is neither reproduction nor resolution of
the original cleanup failure. Diagnostic-log SHA-256:
`8fa9cb808cfefc7d5ce0a2a5b373bace3f3df1e71f16c4bf9e52d4217771cba0`;
observer-script SHA-256:
`e8d5c592b10726ce86cfb517b3414afda6166faf818cf3acc960bf9a55ae0b35`.
No repeated diagnostic attempts were made to obtain a pass.

A separate deterministic host probe demonstrated a synchronization defect in
`Clock.sample`: one thread can be preempted after reading wall time, another
thread can commit its newer sample, and the first can then trigger a false
rollback alarm despite strictly increasing provider reads. This uses injected
providers, not a measurement of actual host-clock rollback. Probe-log SHA-256:
`4115f6455425de8689d78f2c1342f0dc0fb9ce4464182e4f984fa657a2968eab`.
The synchronization repair serializes provider reads, comparison and latch
updates. Its focused Linux check passed **31 clock/identity tests with zero
skips** on source `2920c1de216e78f73fa74bda31bc84169ad2a9fac7335874df8a04776f629ca7`,
image `sha256:11fe880e94ca17189fd9434e63be8a5cc70c9a7708933a66d7c1250fb632a531`;
log SHA-256 `bec98cd0ceb09aac729842fa64773dca02d19bc729f1564165652eb41e690b31`.
All 215 baked files matched the frozen manifest; proof-log SHA-256
`24bbe9de1a302355c0f423e196dbedc775167bef8aa2c228651f3dccb932c292`.
The unchanged rollback and restart-latch tests remain required. Independent
review and consolidated real-model checks are still pending. This source finding
and focused pass do not establish the cause of either Linux failure.

The first paired marker/deadline repair image passed 193 of 195 focused checks
with zero skips. Two fixtures failed before completing their intended oracles:
one created a child before a barrier and then asserted no child existed; an
older fake gRPC context lacked the required trailer setter and never reached
its synthetic abort. The independent review confirmed both contradictions.
The tests are being repaired without changing their retention or abort
expectations. Source `bb87283eea2953c674fbf5b4601f77c1a272e03b0a42d1c160745aabbe363f87`,
image `sha256:d7e9c3a89ee5b63575578f693d74999231c483f2c02140d8ccedd2c2816551c5`;
failed-log SHA-256 `ffb5b3fc09929c68e315b1d63412bd10dbecbbf656226043eca0c708f4965321`.
The real TLS/C-core oversized-first-reply negative passed within this run.

On that same image, the expanded real TLS lifecycle case passed in isolation
again, with zero skips (log SHA-256
`7fe150238b6e7c15930bca3f01832a8dd35c946eb4eead38457f7208f6937ba6`).
All 215 baked files matched the manifest; proof-log SHA-256
`b8387c95543fdf8fe82aea79acb6c844ec9605fcc153c00caeae57b5fa56ff1f`.
This isolated pass does not override the previous consolidated failure.
Review also identified missing descendant registration if asynchronous
authorization close reports pending child tasks. Its repair and the expanded
public-client cancellation tests remain unvalidated.

The combined marker/owner candidate then passed **208 focused Linux tests,
zero skips**, including both corrected fixtures, the clock/identity suite,
public-client cancellation cases, asynchronous-close descendants and eight
fault-fixture cleanup cases. Source
`42074fb51d53f15b039d2364561444db3064969fa9fa1669b907effd0a4a40ce`, image
`sha256:d39b1463b0ea9f5dfafdd81e5eb095d251ace7074f8b31ef8b71bb18a5ac9f5e`,
log SHA-256 `66f20d410e67ccb0269dcc4d3a8a674924776795102f25a2109e9c5d316845c2`.
All 217 baked files matched; proof-log SHA-256
`1b7f1690f3bb04c999a0e7647f8db79bdb98a0799a41ac35a4d89fc0a3b2bc6f`.
A separate review found that an already-completed monitor's reported child can
be omitted when the operation independently transfers pending ownership. That
repair remains pending and is outside the 208-test result.

The first two-case real TLS reply-loss run on that same image **failed both
cases with zero skips** (log SHA-256
`ebea372109e45d6aa92a68af33ae35ae18ec4d76e314c756558fcda771f4419f`).
The Step case failed in its inherited numerical baseline before injection,
with an opaque execution failure, an unconfirmed coordinator close and one
pending capture reservation. The Open case reached the injection and reclaimed
the worker session, but its terminal-code assertion expected `EXPIRED_SESSION`
and observed `CANCELLED`; teardown retained the same failure and resources.
Source inspection shows core hard-expiry invalidation uses the trusted
cancellation path, while the handler also has an independent expiry path. A
strict causal oracle and a bounded diagnostic are being prepared; no broad
acceptance of cancellation codes or passing fault result is claimed.

The monitor-graph follow-up passed **213 focused Linux tests with zero skips**
on source `ec56f2bca7f5d694cd5ab7f20f9e9e313a7090a3070f9f69c7c1136a973aa2dc`,
image `sha256:dd87830659ec61d85e662bd117c8d1f7b09dda59c8ff15cb1897db0c5d431b29`;
log SHA-256 `53d3ebc41ee325bdfb11e1f2e3148487131fc8b5f7b4d24dcd5fa3e782c9727f`.
The 217-file proof log has SHA-256
`9e9522959508f3619aa5eb9619242ff9bd84df35f2452f2057fb9ae68820fbde`.
Independent review then found a different finalizer path that could suppress a
watcher error raised during cancellation. That repair remains pending; the
213-test pass does not establish coverage of that path.

One observational Step-case diagnostic against the preceding frozen
`d39b1463...` image passed its baseline and injected fault without reproducing
the earlier failure (one test, zero skips; 14.858 seconds). Log SHA-256:
`94ade9c33f3a15930672729d2752539efec8ea0d1ac63a585c29ff3253b25728`;
script SHA-256 `a87f4af59b7129f5e1b7c24c09abdcc5a7d04895289650e4ca0bb41bea26c426`.
This is an experimental diagnostic, not acceptance. Its scalar observer bypassed
protobuf dynamic field access, leaving worker status/reclaimed/session fields
empty; 26 of 282 events were discarded by its 256-event ring. The observed
coordinator cleanup results were true, but no initiating failure was captured.
The missing observation fields are being corrected before a separately frozen,
bounded diagnostic batch. The earlier failures remain unresolved.

A corrected, predeclared bounded diagnostic batch stopped after the second of
at most five cohorts. It captured a real supplied wall-clock rollback followed
by authorization revocation and cleanup failure. The [clock diagnostic note](2026-10-17-participant-c1a-clock.md)
records its measured deltas, exact source/rebuilt-image identities, observer
variables and limits. This identifies the clock-failure path in that reproduction;
it does not retrospectively diagnose every earlier failure or accept C1a.

## Final consolidated attempt before the private checkpoint

The final consolidated security attempt at source
`1c7fff83d2719553aae9bc3c29e5cfc4f80b865ccd1f16b5fafa1d9e0b228076`
ran **289 tests, zero skips, with one error** in 84.712 seconds. Its image is
`sha256:433ec54fe377e175e440f4ecb5f9f8fb17b17e191fba3d928b7f679d693cea85`;
all 218 baked source files matched the frozen manifest (proof-log SHA-256
`d118bbdeb53d7c7b737282fe8bd47729a1378324e9f6925a8fce0ff139714fe1`).
The required real-model and capture suites were enabled; no required skips were
accepted. Full log SHA-256:
`a8af4575f53c8f19b5d1ebfbac533f18fd02210f061549bd559e9e11017a4dc5`.

The error was in the PartialOpenReplyLoss case's numerical baseline, before its
reply-loss injection. It reported `CLOCK_UNSAFE: clock moved backwards`, an
unconfirmed coordinator close, and one retained capture reservation. This run
did not collect the provider deltas from the separate clock diagnostic above;
that diagnostic's measured deltas must not be attributed to this run. The Step
reply-loss case and expanded TLS lifecycle case passed in this attempt. The
suite failed as a whole and is not C1a acceptance. There was no retry of the
consolidated model suite to obtain a pass.

Review of the guarded finalizer also found a cyclic exception context introduced
while preserving pending task ownership through finalizer cancellation. A narrow
repair and its affected checks follow this source identity. They cannot turn
this consolidated attempt into evidence for the later source.

On the same `1c7fff83...` source/image, the compatibility control passed
**318 tests with zero skips** (71.064 seconds; log SHA-256
`6bd6c7edfaab0e71dfc6cf1a4fa1d3e51e84fa3d81a890b6bbe2875ae79813d4`).
The retained CPU smoke report passed eight logit comparisons, all finite with
zero maximum absolute error and greedy agreement, confirmed cancellation and
session-limit rejection, and ended with zero sessions, positions and cache bytes.
Its log SHA-256 is
`ea7f7f70447c5e3417ad135bfdbccb5245e79ed904ee380f9c00504ed3bebbaf`;
report SHA-256 is
`cd55e41044780b7cd7fb205f1a49e4071ad3de2d187471c73710091fddd0d5c0`.
These controls exercise the existing CPU execution path, not separate devices,
GPU execution or the full security gate. They precede the exception-chain repair.

The narrow finalizer repair removes secondary exception links back to the
primary handoff before linking the errors. Tests traverse both cause and context
links for cycles and cover both authorization-closure modes, a primary with or
without an explicit cause, and monitor-pending root merging. Primary identity,
original explicit cause, task roots and transfer state remain required.
Independent rereview and Linux checks of this repair are recorded separately.

After the exception-chain repair, **222 affected Linux tests passed with zero
skips** in 37.162 seconds. These cover transport (including real local TLS),
authorization bindings, capture ownership, clock serialization, descendant
cleanup and the fault-fixture oracle. Source identity:
`e8aafa5528bfe0ce5f5f214f26d767c5ef299562a3324eede288d1599c0d95e6`;
image `sha256:275990ffec14f388870553642300d99f6eca123e7b362ae7f567a74a2b5178f2`.
All 218 baked files matched the manifest; proof-log SHA-256
`cbf9ee4a36fc28f8f4685a5172a6bf1d00517d099f83de0f984eff21778b01b6`.
The affected-suite log SHA-256 is
`001f4ab2114f6849d3a4dff32b4969252454129c5fb33fbafa2befe7c02107a4`.
Independent configured-model review found no remaining material finding in the
two-file repair. This is scoped source and regression evidence, not phase
acceptance. The model security suite was not rerun after this repair; its last
consolidated attempt remains failed. Test totals above overlap and must not be
added into a purported unique acceptance count.

## Failures retained and remaining limits

Earlier actual TLS attempts failed because the server context factory started a
fresh deadline after authorization, and because OpenSession's idle lease exceeded
its remaining lifetime. The factory now accepts the receive-time absolute cap;
OpenSession samples one remaining lifetime and clamps idle lease to it. The
original failures and unchanged-validator diagnostics remain retained.
A preceding repeated-token prompt matrix passed but did not match the frozen
patterned-input protocol; the patterned rerun above is the applicable result.

Independent configured-model review found no numerical oracle or authentication
substitution defect in the matrix. Setup/teardown ownership, indirect traceback
references, nested pending ownership and the caller final-wait repairs have
subsequent focused Linux evidence. The independently reviewed listener-shutdown
patch had no remaining material scoped source finding. These bounded conclusions
do not resolve the consolidated cleanup failure above.

C1a remains unaccepted. The consolidated clock/cleanup failure and earlier
failures are retained; causes remain unresolved where not independently
diagnosed.
Focused unit and component results, the capture observations, and the expanded
lifecycle and reply-loss cases apply only to their recorded source identities.
They do not establish complete cancellation, disconnect, restart/boot
invalidation or ambiguous-mutation coverage. The current work is being saved as
an isolated, unaccepted checkpoint under the user's instruction to stop before
additional hardware is needed. This is not a claim that all laptop-local work
is exhausted, or that another device is the only way to investigate the clock.
No C1a gate is declared passed by this report.

No supported GPU, second physical device, tested outbound gateway, real WAN route
or participant cohort was available. These results establish neither separate-device
inference, speedup, useful pooled memory, production enrollment nor research gate
completion. C1b requires actual separate machines; C0-only publication is preserved.
