# C1a focused follow-up, 2026-10-18

**Status:** Trial 38 passed its seven-test real worker-process component with
zero skips. Its consolidated full regression ran 630 tests with zero skips
and failed one inherited pipeline case during its valid baseline. C1a, C1b,
C1 and P2 remain unaccepted; component and physical interleave evidence below
do not replace the full gate. The cause of the full failure remains unknown.

## Frozen inputs and bounded result

Trial 17 used 250 source files, source SHA-256
`11b4b5f56a40ae721d0d52172c5d90d7d363a7ae6dfac3ae4349ffd9fbf1af4a`, in the
Linux/amd64 security image `sha256:57626869381fbfdb50624a3fb5d563f90cbf023ca6e6cfa5f152ea7b91c2fc6c`.
All 250 baked source files matched (proof log SHA-256
`3f643fcafd20614da718f5938afce0169547ae3026fbdcdd163c75b4b827f296`). The
model/tokenizer revision, manifest, runtime, and CPU-only limits are unchanged
from the [earlier C1a evidence](2026-10-17-participant-c1a-local.md). Actual
local CPU model-completion tests ran in this trial; there was no additional
physical split-host inference trial.

The focused suite passed **11 tests, zero skips**, in 27.349 seconds of unittest
runtime (not inference performance). Its retained log SHA-256 is
`3bc504b135c134292402bee2b81d65f03f2c9af7cff72f7b4bd894e3e3b53023`. It covered
three completion/lifecycle cases and eight issuance cases. The completion cases
exercised native TLS cancellation after real cache mutation with restart fencing
retained, actual worker retirement and verified child exit within the 40-second
same-host monotonic bound, and stage-3 observations in order A0/B0/A1/B1. The
requests had unequal 5/11-token prompt lengths; the stage partition remained
3/3/2. This local observation makes no remote overlap claim. The strict parser
case also passed.

Issuance tests used generated CAs, signer keys, credentials, and CSRs; exercised
the actual protected loader and baked foreign-owner fixture; and checked freshly
parsed intent membership, authority aliases, unchanged corresponding authority
cases, new-leaf-only expiry during signing, and policy changes. This tests only a
private uncommitted candidate primitive. No certificate cohort was published or
admitted, and no final approval or activation was produced.

## Reproduction commands

The image build command was:

```sh
docker compose -p steamboat-c1a-corrected-20261017 -f compose.participant-security.yaml build security
```

The focused command enabled the completion and issuer unittest modules inside
the isolated security service. Its required-no-skip runner and 220-second
watchdog are part of the actual command:

```sh
docker compose -p steamboat-c1b-local-20261018 -f compose.participant-security.yaml run --rm -e STEAMBOAT_SECURE_PIPELINE_TESTS=1 security python -B -c 'import os,threading,unittest;timer=threading.Timer(220,lambda:os._exit(124));timer.daemon=True;timer.start();suite=unittest.defaultTestLoader.loadTestsFromNames(["tests.security.test_secure_pipeline_completion","tests.security.test_root_transition_issuance"]);r=unittest.TextTestRunner(verbosity=2).run(suite);timer.cancel();raise SystemExit(not r.wasSuccessful() or bool(r.skipped) or not r.testsRun)'
```

The full security gate used both opt-ins and passed:

```sh
docker compose -p steamboat-c1b-local-20261018 -f compose.participant-security.yaml run --rm -e STEAMBOAT_SECURE_PIPELINE_TESTS=1 -e STEAMBOAT_CAPTURE_BACKPRESSURE_TESTS=1 security python -B -c 'import threading,os,unittest;watchdog=threading.Timer(240,lambda:os._exit(124));watchdog.daemon=True;watchdog.start();suite=unittest.defaultTestLoader.discover("tests/security",top_level_dir=".");result=unittest.TextTestRunner(verbosity=2).run(suite);watchdog.cancel();raise SystemExit(not result.wasSuccessful() or bool(result.skipped) or result.testsRun==0)'
```

These commands reproduce the recorded trial using project
`steamboat-c1b-local-20261018`; the image build command above uses the separate
`steamboat-c1a-corrected-20261017` project as recorded.

The full run completed **471 tests with zero skips** in 134.858 seconds of
unittest runtime (not inference performance), exit 0. It started at
`2026-10-18T11:16:46.493Z` and completed at `2026-10-18T11:19:03.569Z`.
Log SHA-256: `b717ec4b3b39484807543cd34cb78ec9b2228ade369b058d572bef80d719781c`.
It used the same frozen source and image and passed the same 250-file baked
source proof. The full regression did not include the native TLS disconnect
case reported below. At the time of Trial 17, root activation, durable
high-water state, and actual boot/restart behavior remained open; later Trial 23
added a private high-water component. Neither suite unlocks C2b or accepts C1a/C1.

## Trial 18: native TLS disconnect

Trial 18 passed **2 tests, zero skips**, in 37.413 seconds of unittest runtime
(not inference performance), exit 0. The test closed an actually owned native
TLS worker-3 channel after real cache mutation while computation was held. It
verified channel shutdown and connector-close evidence, SDK Step attempt counts
`[1, 1, 1]` (not packet-level retry evidence), worker-3 operation failure with
no output, and retirement of all workers with fences retained and child exit
confirmed within the 40-second same-OS monotonic bound. The strict report parser
case also passed. This was a local CPU model test, not a physical ZimaBlade run
or root cutover. This focused run adds two tests; it is not a combined 473-test
aggregate or a rerun of the full trial-17 suite.

Trial 18 used 252 source files, SHA-256
`3dd1ddf631ca56503a4dbaa82a0b3976a07a4d2d6f5745275c6a72997425998a`, and image
`sha256:7dcbf728a7d207e6db839161fd2c23d17fec578e0becb4ab6d1ec2af23811928`. All
252 baked files matched (proof log SHA-256
`2f0a8364a5ac0cdd14a2894bc5813b928521e3180bb756f84a62e7971cba99ae`). The
focused log SHA-256 is
`6187d9c95dd075c6c3853a70cf474c8ef1e14481495c74b2eebc696178029401`.

The recorded command was:

```sh
docker compose -p steamboat-c1b-local-20261018 -f compose.participant-security.yaml run --rm -e STEAMBOAT_SECURE_PIPELINE_TESTS=1 security python -B -c 'import os,threading,unittest;timer=threading.Timer(220,lambda:os._exit(124));timer.daemon=True;timer.start();suite=unittest.defaultTestLoader.loadTestsFromName("tests.security.test_secure_pipeline_disconnect");r=unittest.TextTestRunner(verbosity=2).run(suite);timer.cancel();raise SystemExit(not r.wasSuccessful() or bool(r.skipped) or r.testsRun!=2)'
```

This closes the specific local TLS-disconnect test gap. At the Trial 18 point,
root activation, durable high-water state, actual boot/restart coverage, and
physical C1b lifecycle evidence remained open; Trial 23 later added a private
high-water component. C1a and C1 remain unaccepted.

## Trial 19: cold-transition component checks

Trial 19 passed **22 tests, zero skips**, in 2.003 seconds of unittest runtime
(not inference performance). The four focused modules exercised closed launch
declarations, protected fixed-launcher files, actual owned POSIX processes and
their process groups, READY identity checks, cancellation and generation fences,
real certificate/CSR policy binding, and protected final approval with the whole
old-key proof cohort. A live grandchild blocked retirement after its leader exited.
The retirement guarantee assumes trusted operator code stays in its process group;
it does not establish kernel containment of arbitrary escaping processes.

The image was `sha256:bf1b45f6bfe418caf6c54fddd0e704af261e6fba49f12b7ddf2ee28906d766e7`.
All 260 candidate files matched source identity
`917570f7f40fd26992d2af9f33bdafa341ec99c211a02d8bcbb2104ff4567d9d`;
source-proof log SHA-256:
`74f034e1e70dd250e83fe4e54b0d3b8b6f2dfe35fd73ec909dd69e9db079f294`.
Test log SHA-256:
`da314d9cdad6cf573c8da88482956910a19589d4ff293e119fb5d0995e5291c1`.
The test command was:

```sh
docker compose -p steamboat-c1b-local-20261018 -f compose.participant-security.yaml run --rm -e STEAMBOAT_SECURE_PIPELINE_TESTS=1 security python -B -c 'import os,threading,unittest;timer=threading.Timer(180,lambda:os._exit(124));timer.daemon=True;timer.start();names=("tests.security.test_root_transition_launch","tests.security.test_root_transition_retirement","tests.security.test_root_transition_policy","tests.security.test_root_transition_final_approval");suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(n) for n in names);r=unittest.TextTestRunner(verbosity=2).run(suite);timer.cancel();raise SystemExit(not r.wasSuccessful() or bool(r.skipped) or r.testsRun<20)'
```

This component run preceded the later generation-cleanup helper, policy review
fixes and snapshot durable-commit seam. It does not validate those later changes.
At Trial 19, durable activation, policy high-water persistence, actual service
launch/admission epochs and TLS root cutover remained incomplete. No C1a/C1b/C1
acceptance follows.

## Retained trial history

Failures remain part of the evidence. Trial 13 ran 10 tests with zero skips: nine
passed, including native TLS capture denial followed by a fresh successful
request and peer-only expiry; one errored because the test indexed an optional
`capture_submission_attempted` field absent on pre-admission refusal. Trial 14
ran 457 tests with zero skips and ended with one failure and three errors. Its
backward-clock lifecycle case latched `CLOCK_UNSAFE`; no exact cause was
established, and clock settings were not changed. The detailed results and log
identity remain in the [parity report](2026-10-18-participant-two-device-parity.md).

Trial 15 ran 36 focused tests, zero skips, with one failure and one error; the
other 34, including unchanged lifecycle, root foundation/proof/preparation, C0
negative TLS, capture-positive, and CT05 coverage, passed. Log SHA-256:
`e6336d912be9c0d551bcb71d2ddc697ca11fee1c553626013abcdca6e75413c6`.
Trial 16 ran three completion tests with zero skips; two passed and one failed
on a generic zero-owner assertion after child fencing. Log SHA-256:
`28154bb172a1da0ee1c10886dd85a106eff72d476887a679b2cbfaf3b470e14a`.

A preceding trial-14 lifecycle failure remains unexplained even though a fresh,
unchanged lifecycle case passed in trial 15. No root cause or production fix is
claimed. A preliminary child diagnostic invocation failed at Python tool-import
setup before its case ran; a later child-baseline script reported a generic
worker-step failure without establishing cause. Its package-context change is
another experimental variable, not a confirmed repair. Trial 17's focused and
full passes do not supersede these failures or establish their cause.

## Trial 20: retained storage-boundary failure

Trial 20 ran 45 focused tests with zero skips and ended with three errors. The
fault-injection sweep injected failures while writing/fsyncing a selector temp
file and before selector replacement; reopening the store correctly rejected
the unexpected `selector.tmp.*` entries as ambiguous. The test harness had
incorrectly assumed store construction would still succeed and errored before
asserting this fail-closed rejection. The production behavior was not weakened.
The failure remains retained: image
`sha256:0b836a8919c1ddbb59a28732a43f32ca0387344b35ce30bc2abd5b0f4eb6f3c0`, and
log SHA-256
`87355310da80bed56f4004af6557e5431a3e427030230ce77e8a4e0b13178534`.

## Trial 21: focused cold-transition checks

The focused Trial 21 suite passed **51 tests, zero skips**, in 2.238 seconds of
unittest runtime (not inference performance). Source identity was
`c9172cd100c0d5d5c526c1fc494950f0b4959aecca00c0c142fd075d60bf1b46`; image
was `sha256:1f4a899566b2b4150a7bf674f5ded560d230ec53b6d99b4293f7e52624735d2e`; all
263 baked source files matched (proof log SHA-256
`e7545124cb57351887ebbaafd38f4f18bd1e3a727edc715ae211b45dbbb16ff7`). Focused
test log SHA-256:
`6807907defeba3d9a25ec4eb005ae291d0a2364ad2e3fd9180358e400a3a22b6`.

This includes low-level root-generation storage checks and a snapshot-durable
commit seam, but no actual durable high-water persistence. The storage API is a
cold-selection/bundle primitive only: it requires an already provisioned root
and trusted synchronous validator; it does not authorize, bootstrap, approve,
activate a cohort, or claim readiness. A snapshot durable-commit hook is not
proof that snapshot high-water state survives restart. Policy-refresh remains an
immutable blob/schema-extension design item. Process-group retirement assumes
trusted operator code does not escape the owned group; it is not kernel
containment. Fault injection covers single operation boundaries, not power loss
or combinations of simultaneous failures. The foreign-owner case checks the
actual baked inode guard read-only; it does not prove a fully provisioned store
with a foreign-owned selector.

The full Trial 21 security regression passed **524 tests, zero skips**, in
176.694 seconds of unittest runtime (not inference performance), exit 0. It
started at `2026-10-18T11:54:37.574Z` and completed at
`2026-10-18T11:57:36.476Z`. Its log SHA-256 is
`12ace22e8165f2bf45d86d991578391bae045211c0b5cf17a38683830c2a030f`.
The run used the same frozen 263-file source, Linux image, and matching baked
source proof listed above. The 524 count is the observed full discovery total;
it is not presented as arithmetic aggregation of focused suites. The full
regression includes the previously covered native TLS disconnect,
cancellation/interleave, and the 51 new focused checks. Documentation was
updated after those frozen source/image checks; no code or test bytes changed
for this report update. No C1a/C1 or later-phase acceptance follows from these
test results.

The recorded full-regression command was:

```sh
docker compose -p steamboat-c1b-local-20261018 -f compose.participant-security.yaml run --rm -e STEAMBOAT_SECURE_PIPELINE_TESTS=1 -e STEAMBOAT_CAPTURE_BACKPRESSURE_TESTS=1 security python -B -c 'import threading,os,unittest;watchdog=threading.Timer(240,lambda:os._exit(124));watchdog.daemon=True;watchdog.start();suite=unittest.defaultTestLoader.discover("tests/security",top_level_dir=".");result=unittest.TextTestRunner(verbosity=2).run(suite);watchdog.cancel();raise SystemExit(not result.wasSuccessful() or bool(result.skipped) or result.testsRun<500)'
```

## Trial 22: launch-claim checks

Trial 22 used 265 source files with identity
`82be40abb9db390bbf40d1d779e4dbea68e26d5b77429d56e9fc838232bcc0f6`, image
`sha256:f181953b2298fd99244c66c10b8713fe94369e982f88df71926c9281098c8011`,
and an all-files proof with zero mismatches (proof-log SHA-256
`15c381664bf7224547c661cfee9dc6607d18b5c5cf5fd37eedbebd6fde6380af`).
It passed **16 tests, zero skips**, in 0.037 seconds of unittest runtime
(not inference performance); log SHA-256:
`e7c9619d4a4ccb0d7adcdb15cb54c43590d349637b9da2874a2fdbec39c72370`. This run
preceded later launch-claim test-strength and process-split changes. It is a
retained earlier component result, not a substitute for Trial 23's focused and
full checks.

## Trial 23: strict-v2 root policy high-water and regression

Trial 23 used 266 source files with identity
`10c1aa7161ccdb8fd5babf9096343d7974d2ccb8131c1120fb38b729ababfc92`, image
`sha256:6d8665956e1f692bd3ffcaf27123998cfa8cbb6ae8a9ba81ab26633d3316fdb5`, and
an all-266-files source proof with zero mismatches (proof-log SHA-256
`8747de07f16f00cd01a8490678a4db5a6576d5fab3bcddfe568e32bf2e90fc62`). The
focused high-water suite passed **84 tests, zero skips**, in 2.714 seconds of
unittest runtime (not performance); log SHA-256:
`f7a755d5f9aa458c9a50477bbee3e9434439a1a998b010a67da4428826c3c555`.
The complete security discovery passed **557 tests, zero skips**, in 176.686
seconds of unittest runtime (not performance), exit 0. It ran from
`2026-10-18T12:19:15.326Z` to `2026-10-18T12:22:14.327Z`; log SHA-256:
`fbee8c249c2cffeb86cf657d79911050cf7d88a9ee0d934c1af2052a765a928e`. The
557-test count is the observed discovery result, not a sum of focused suites.
All results used the same frozen source/image and baked-source proof. Trial
22's launch-claim run predates this freeze and its count is not added to 557.

The storage component uses a strict schema-v2 selector (the private v1
predecessor from Trial 21 was not a published API), immutable baseline
generation artifacts, and separately pinned active-policy blobs bounded by 64
files, 64 KiB each, and 4 MiB total, with no garbage collection. A single root
lock and selector head protect cold selection and ordinary signed policy
refresh. Tests cover revision/digest high-water updates, a cold verifier's
minimum-revision floor, equal-canonical re-signature idempotence, rollback and
same-revision equivocation rejection, pending-marker recovery of the exact new
policy blob, and a competing eligible cold transition versus refresh where
only one expected-head compare-and-swap wins. Final trusted validation and
fresh wall/monotonic checks run after selector-temp fsync and immediately before
atomic replacement.

These checks establish a private persistence component, not a supported runtime
hook or startup/admission path. Launch-claim tests cover whole-cohort permanent
boot/epoch consumption in actual POSIX components, but root startup does not
yet consume those claims. The process spawn/observe split is not yet composed
into root startup. End-to-end root activation, live READY/death verification,
TLS root cutover, and physical C1b lifecycle remain incomplete; therefore C1a,
C1b, C1, and P2 remain unaccepted.

The image build used the separate project `steamboat-c1a-corrected-20261017`:

```sh
docker compose -p steamboat-c1a-corrected-20261017 -f compose.participant-security.yaml build security
```

The focused high-water command used project `steamboat-c1b-local-20261018`:

```sh
docker compose -p steamboat-c1b-local-20261018 -f compose.participant-security.yaml run --rm -e STEAMBOAT_SECURE_PIPELINE_TESTS=1 security python -B -c 'import os,threading,unittest;timer=threading.Timer(180,lambda:os._exit(124));timer.daemon=True;timer.start();names=("tests.security.test_root_transition_launch","tests.security.test_root_transition_retirement","tests.security.test_root_transition_policy","tests.security.test_root_transition_final_approval","tests.security.test_snapshot_durable_commit","tests.security.test_root_transition_storage","tests.security.test_root_transition_highwater","tests.security.test_root_transition_launch_claim");suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(n) for n in names);r=unittest.TextTestRunner(verbosity=2).run(suite);timer.cancel();raise SystemExit(not r.wasSuccessful() or bool(r.skipped) or r.testsRun<80)'
```

The full security command enabled both required opt-ins:

```sh
docker compose -p steamboat-c1b-local-20261018 -f compose.participant-security.yaml run --rm -e STEAMBOAT_SECURE_PIPELINE_TESTS=1 -e STEAMBOAT_CAPTURE_BACKPRESSURE_TESTS=1 security python -B -c 'import threading,os,unittest;watchdog=threading.Timer(240,lambda:os._exit(124));watchdog.daemon=True;watchdog.start();suite=unittest.defaultTestLoader.discover("tests/security",top_level_dir=".");result=unittest.TextTestRunner(verbosity=2).run(suite);watchdog.cancel();raise SystemExit(not result.wasSuccessful() or bool(result.skipped) or result.testsRun<550)'
```

## Trial 24: cold activation composition

The focused run passed **90 tests, zero skips**, in 3.764 seconds of unittest
runtime (not inference performance). It used 268 files with source identity
`bab3c707b3ff64a0c2eed105a1a940ef23b3dd8933f8ad1959d82d49cc6a55e9` and image
`sha256:d7032c4f7f5b9ff6781448da40ee719b06e06d7051047ca3a0744c2dc633485f`.
All 268 baked files matched (proof-log SHA-256
`2215fa0536a3c0b0c111b26fee6271b5de02198fe8bc88cf386f73fb77a3c846`).
The focused log SHA-256 is
`7f9c259384143c4bc6060a623a103114fb182fd9afc5c6c6c15edcac8d87ee88`.

The activation composition reloads protected preparation/final approvals and
checks every old-key possession proof against the current selected old policy.
It requires the actual owning supervisor's sealed retirement capability for the
whole old cohort before selecting exactly 13 public artifacts under the store
CAS. Tests exercise real owned process startup/READY, rejection while the old
cohort is alive, retirement after actual process-group exit, successful cold
selection, and an independent new-policy verifier rejecting old material.
They also reject changed policy, approval, CSR, proof, plan, head, and foreign
retirement capabilities. Mutable caller containers are copied before use.

The final validation runs after selector-temp fsync and immediately before
replace. A controlled test expires a short grant's original monotonic deadline
there while its wall interval, snapshot, and credentials remain live; the old
selector remains and the pending transaction fence is retained. The test's
21-second monotonic-only advance remains within the Clock discontinuity bound.
Host-only fixture checks caught and corrected a clock closure and a missing
import before this Linux freeze; they are not separate Linux pass claims.

This run does not include the forthcoming runtime binding/startup adapter. It
does not prove fresh service incarnation, consumed startup claims, actual TLS
root cutover, or physical C1b fault handling. The full 557-test result remains
trial 23 evidence and does not include these two new activation files. No
phase acceptance or additional physical run follows.

The build used the same build project as trial 23. The focused command was:

```sh
docker compose -p steamboat-c1b-local-20261018 -f compose.participant-security.yaml run --rm -e STEAMBOAT_SECURE_PIPELINE_TESTS=1 security python -B -c 'import os,threading,unittest;timer=threading.Timer(180,lambda:os._exit(124));timer.daemon=True;timer.start();names=("tests.security.test_root_transition_activation","tests.security.test_root_transition_launch","tests.security.test_root_transition_retirement","tests.security.test_root_transition_policy","tests.security.test_root_transition_final_approval","tests.security.test_snapshot_durable_commit","tests.security.test_root_transition_storage","tests.security.test_root_transition_highwater","tests.security.test_root_transition_launch_claim");suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(n) for n in names);r=unittest.TextTestRunner(verbosity=2).run(suite);timer.cancel();raise SystemExit(not r.wasSuccessful() or bool(r.skipped) or r.testsRun<90)'
```


## Trial 25: initial root-runtime binding

Trial 25 passed **101 focused tests, zero skips**, in 3.301 seconds of
unittest runtime (not inference performance). It used 270 source files with
identity `c093d9845078799a1bd084f4ed58ed2a59880cd407c8a0ab5491109017976e28`,
image `sha256:99e5a13be7da282d676370a17b2640f80f929f56ea18cf5464e34091db6941c8`,
and an all-270-file baked-source proof with zero mismatches (proof log SHA-256
`bd4d00eb95cdaab58462f9ae3f70aac9a3d16c55e5fbbfb7ae00d6421093a839`). The
focused log SHA-256 is
`b04db23aa770144755a2f852fe3a59f6c1ff0bb7a73a0563cd9960444b362e55`. This
freeze covered the initial root-runtime binding only; it did not contain the
later SnapshotStore durable hook.

The actual command was:

```sh
docker compose -p steamboat-c1b-local-20261018 -f compose.participant-security.yaml run --rm -e STEAMBOAT_SECURE_PIPELINE_TESTS=1 security python -B -c 'import os,threading,unittest;timer=threading.Timer(180,lambda:os._exit(124));timer.daemon=True;timer.start();names=("tests.security.test_root_runtime","tests.security.test_root_transition_activation","tests.security.test_root_transition_launch","tests.security.test_root_transition_retirement","tests.security.test_root_transition_policy","tests.security.test_root_transition_final_approval","tests.security.test_snapshot_durable_commit","tests.security.test_root_transition_storage","tests.security.test_root_transition_highwater","tests.security.test_root_transition_launch_claim");suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(n) for n in names);r=unittest.TextTestRunner(verbosity=2).run(suite);timer.cancel();raise SystemExit(not r.wasSuccessful() or bool(r.skipped) or r.testsRun<100)'
```

## Trial 26: durable root-runtime integration failure

Trial 26 ran **110 focused tests, zero skips**, in 3.238 seconds of unittest
runtime, and failed with one assertion failure and one error. It used 270 source
files with identity
`8190d69389389880efc2c6e282628adaa9ed807357828c54047df505b9c67fcf`, image
`sha256:2af4f502be93e2cca43958d01c1d136a818be8305f2bdd7e77776d3f87283d22`,
and an all-270-file proof (proof log SHA-256
`dc6e1a231699b6477058bbff4cdc1959122afa1cfafa69203ee338f2f81f1349`). The
focused log SHA-256 is
`f89e393c82d6499ba318b0dda8628feb12db150fb225c15ac3b1852ca6d25c5e`.

The new two-binding race assertion failed because a concurrent writer saw the
first writer's selector tempfile as an unexpected root entry during its
pre-flock namespace scan. This was a storage-validation ordering defect; the
protected storage changes move the full namespace scan behind the verified flock
while preserving the post-lock rejection of unknown names. The other error was
in the existing owned-process retirement test, where `/proc/cmdline` became
unavailable during the immediate retirement check. A separate frozen-image
process diagnostic passed the group/session/executable-pin checks and a later
full recheck, but did not establish the exact cause; this remains unresolved.
The main trial's failure and error remain retained.

Two same-image diagnostics also remain historical results: the frozen race
reproduction failed one assertion in 0.040 seconds (log SHA-256
`ca4f390ae20822fc71271ebabde9c7bef7b1a074986da804e214554827cb0622`), and the
process diagnostic ran 40 tests and stopped after one error in 7.108 seconds (log SHA-256
`bfca7ded2618c64ac1e71c8cac33c7da352ac3c992c413a697ad169767d1fd8c`). The
storage lock-order correction and deterministic contention tests were added
after trial 26. Trial 27 had not run at this freeze; the subsequent focused
results are recorded below.

The actual trial-26 command was:

```sh
docker compose -p steamboat-c1b-local-20261018 -f compose.participant-security.yaml run --rm -e STEAMBOAT_SECURE_PIPELINE_TESTS=1 security python -B -c 'import os,threading,unittest;timer=threading.Timer(180,lambda:os._exit(124));timer.daemon=True;timer.start();names=("tests.security.test_root_runtime","tests.security.test_root_transition_activation","tests.security.test_root_transition_launch","tests.security.test_root_transition_retirement","tests.security.test_root_transition_policy","tests.security.test_root_transition_final_approval","tests.security.test_snapshot_durable_commit","tests.security.test_root_transition_storage","tests.security.test_root_transition_highwater","tests.security.test_root_transition_launch_claim");suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(n) for n in names);r=unittest.TextTestRunner(verbosity=2).run(suite);timer.cancel();raise SystemExit(not r.wasSuccessful() or bool(r.skipped) or r.testsRun<110)'
```

## Trials 27–28: retained worker-adoption fixture failures

Trial 27 ran 172 focused tests with zero skips and one error in 8.548 seconds
of unittest runtime. Its 271-file source identity was
`ac8d8138cbf4eea5afe5cc75e09532b42450ce47ba188f7f338ad37da5bd5415`; image
`sha256:56b81a1d4367e774e94f27fd0cc8fe0d3c9e277baa1af9211ca1adba2ed924a4`;
all-file proof log SHA-256 `9f31bb477cbf8336bfd7155402d47bdd588df4f0b242eba87d4de8e1440f0117`.
The error was a test fixture trying to create a worker private key that already
existed. Focused log SHA-256:
`195b2e87efa977b1c06f745095d66c03a923d974986bf9294aeeccbe880e4e25`.

Trial 28 used 271 source files, identity
`7a68a3e96ecfdef411f109488cf6028e7d21939ef8cfdc0fc243ec31b89afd11`, image
`sha256:ac6ca76881497ffeda3840c777c2404b6b68c46b6dfd069f62ece11d746d3bcf`,
and all-file proof log SHA-256
`1d6cb10252e7adda57ad5c9af24b937c105dea9250008425ea3c476e2390a082`. Its 172-
test, zero-skip focused run ended with two fixture errors: the existing-key
collision and a test-order contamination that left a fake manifest loader
installed before real worker-state import. Focused log SHA-256:
`22295e80ce31a9d72b632a41bcc34af35d52d3da75771a337800df603049dab7`. A separate
real signed-authority/StageExecutor adoption diagnostic passed one test in
2.901 seconds (log SHA-256
`13028b070140350ec3bbba1c61cc33e7dc689aaaa3df630d6fd2a1997160f05e`). This
diagnostic does not replace the failed combined run. The trial-29 test-order
repair changed test setup only, not production behavior.

## Trial 29: focused runtime/adoption pass; full regression failure retained

Trial 29 used 271 source files with identity
`e95b1a4587bc673d9d2144b7ca4a75010be0405c88e3c827fbe3edb7fb12f90a`, image
`sha256:4eef687b0c7720cbb1d8f1ad38381d91412d0b9988847bac3607c6693b573973`,
and an all-271-file proof with zero mismatches (proof log SHA-256
`41f7b6573f2f16b2d8ece84bfeebbc00f35b93b1480d5b5ae8ab097cf8deb680`). The
focused runtime/adoption suite passed **172 tests, zero skips**, in 7.307
seconds of unittest runtime (not inference performance); log SHA-256
`6089abd1ccbbb64d0378a3089072c082fa24ee21f898c4557cb0f67bf29da6a0`. It covered
the actual worker adoption path with signed authority, `StageExecutor`, and
unmocked shutdown alongside root-runtime, storage, launch, and retirement
checks. This is component evidence; it does not consume the whole-cohort claim
or prove root CLI startup/TLS cutover.

The full security discovery ran **596 tests, zero skips**, in 174.165 seconds
of unittest runtime (not inference performance), from
`2026-10-18T13:13:04.922Z` to `2026-10-18T13:16:01.296Z`; it exited 1. Log
SHA-256: `b6c36da2fe51884a14041d3aa1c9c12be6b703b6b637d24bc721490839eaa246`. The
single error was in the inherited secure-pipeline case: a worker returned
`EXECUTION_FAILED: Worker step failed`, coordinator close was not confirmed,
and cleanup reported one pending capture. The exact cause is unknown; this is
not evidence of a diagnosed production defect or a clean full regression. The
failure remains retained.

Trial 29's focused command was:

```sh
docker compose -p steamboat-c1b-local-20261018 -f compose.participant-security.yaml run --rm -e STEAMBOAT_SECURE_PIPELINE_TESTS=1 security python -B -c 'import os,threading,unittest;timer=threading.Timer(180,lambda:os._exit(124));timer.daemon=True;timer.start();names=("tests.security.test_secure_worker_lab","tests.security.test_secure_cohort_lab","tests.security.test_secure_cohort_supervisor","tests.security.test_root_runtime","tests.security.test_root_transition_activation","tests.security.test_root_transition_launch","tests.security.test_root_transition_retirement","tests.security.test_root_transition_policy","tests.security.test_root_transition_final_approval","tests.security.test_snapshot_durable_commit","tests.security.test_root_transition_storage","tests.security.test_root_transition_highwater","tests.security.test_root_transition_launch_claim");suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(n) for n in names);r=unittest.TextTestRunner(verbosity=2).run(suite);timer.cancel();raise SystemExit(not r.wasSuccessful() or bool(r.skipped) or r.testsRun<160)'
```

The full regression command was:

```sh
docker compose -p steamboat-c1b-local-20261018 -f compose.participant-security.yaml run --rm -e STEAMBOAT_SECURE_PIPELINE_TESTS=1 -e STEAMBOAT_CAPTURE_BACKPRESSURE_TESTS=1 security python -B -c 'import threading,os,unittest;watchdog=threading.Timer(240,lambda:os._exit(124));watchdog.daemon=True;watchdog.start();suite=unittest.defaultTestLoader.discover("tests/security",top_level_dir=".");result=unittest.TextTestRunner(verbosity=2).run(suite);watchdog.cancel();raise SystemExit(not result.wasSuccessful() or bool(result.skipped) or result.testsRun<580)'
```

The security image build command was:

```sh
docker compose -p steamboat-c1a-corrected-20261017 -f compose.participant-security.yaml build security
```

A matching ZimaBlade source overlay was built and source-proved with image
`sha256:ebe5eaedba721f9d5b4a4186156015d12c3f117e1e73b4ab24847f827a72495b`
(overlay record SHA-256 `1ea3351425b1b0c0c20be660a7110b779a976c88b393dafaac5c609dbc35705e`).
The physical interleave run described in the parity report was subsequently
performed on this frozen local/remote image pair; it does not erase Trial 29's
full-suite failure. The later trial-32 startup component composes claim/spawn/READY, but actual
service startup and TLS root cutover remain incomplete; C1a, C1b, C1, and P2 remain unaccepted.
The 596-test failure does not close or waive any gate.

## Trials 30–32: process-startup component and retained regression

Trial 30 passed nine focused component tests with zero skips in 0.394 seconds
of unittest runtime (not inference performance), using 273 source files with
identity `e15529c98c772f760e3abc30a97a8dc05539fb4a84491e4b4f89c35280b1d446`
and image `sha256:90ecdc60662b8928b71f2939b828f28bae71ccd73c5f3db258bd5475803ed5b8`.
The test log SHA-256 is
`3006b93ffab28c43e070fe01a79178115d97bd8111917b947d40d84b2db6362a`. This
exercised CLI framing and protected root binding with mocked service wiring;
it did not test the whole-cohort claim/spawn lifecycle or establish actual
CLI TLS/model startup.

Trial 31's 76-test run had zero skips and the cases passed, but exited 1 solely
because the parent harness required at least 80 tests. It is retained as a
harness-threshold failure, not a gate pass (log SHA-256
`d15e296160905b2ef275d63ae249bdcc53facd68410d3fe19b22dff8df1d830e`). Trial 32
then passed **78 tests, zero skips**, in 14.251 seconds of unittest runtime
(not performance), using 275 source files with identity
`0293a39ccf691ce5b60d79acdf9a80a226b3d57811e6562505fdabb6ac4d41df` and image
`sha256:d2f7c541cd384cb73001fd257cfe32c5be69b6b905f8ff49a7b47aa3421d78eb`;
all baked files matched (proof log SHA-256
`3b0c6e56a785fa15b1efdb9842f3da7bee1b63e5513c7d78913beb372f2fe0e3`) and the
test log SHA-256 is `f99c4c0811cdd4813f02c6b6a2ec406ef951a03c0cbe4ff4461f3a5e4a375c35`.
The process component exercised claim consumption, owned spawn, READY, deadline,
and cleanup. It remains component evidence; actual root-worker CLI/TLS/model
cutover and whole-cohort startup are still untested.

## Frozen Trial 29 diagnosis and physical interleave follow-up

A separate frozen-image diagnostic failed its first case with a negative
wall-clock delta at `clock.py:106`, `CLOCK_UNSAFE`, fencing, and an
unauthenticated worker step. This is evidence from that diagnostic only; it does not establish the
cause of the original full-suite failure or an operating-system mechanism. A
separate three-run observer batch passed in 60.639 seconds but saw no negative
sample, so it did not reproduce or repair the issue. Trial 29's full-suite
failure remains retained and unexplained.

The later physical `c1b-interleave-v1` run passed six requests and 35 vectors:
four baseline requests/27 vectors, then two unequal 5/11-token prompts/eight
forced vectors. Maximum absolute error was `3.445148468017578e-05` for baseline
and `9.5367431640625e-06` for the extension. The worker-3 post-RPC first
prefill/decode trace was A0/B0/A1/B1; the causal stage-1 barrier and remote
all-owners-global-zero check were confirmed. Both local and remote processes
exited gracefully, with containers, private files, and job root removed and no
pending transport operations. The run lasted `2026-10-18T13:46:52.172Z` to
`2026-10-18T13:47:45.513Z`; this is setup-through-cleanup wall time, not an
inference latency or performance measure. Frozen source was
`e95b1a4587bc673d9d2144b7ca4a75010be0405c88e3c827fbe3edb7fb12f90a`, local image
`sha256:4eef687b0c7720cbb1d8f1ad38381d91412d0b9988847bac3607c6693b573973`, and
remote image
`sha256:ebe5eaedba721f9d5b4a4186156015d12c3f117e1e73b4ab24847f827a72495b`.
The sanitized result SHA-256 is
`19f4b025a8a7df163deca47cf342ae5ef7a543c83f97202dd496942733869013`; log
SHA-256 is `9777e4dcdee6030b9ffab096bff8654a03d357321f9b570d2a0555e501366e47`.
This is a bounded correctness/interleave observation, not proof of all-step
compute overlap, performance, or WAN behavior. Physical fault/restart/drain
cases and whole C1 acceptance remain open.


## Trials 34–35: retained real worker-process fixture failures

Trial 33 was built but not executed: source review caught calls to a nonexistent
`BootstrapContext.close()` method before the Linux run. Trial 34 then ran seven
tests with zero skips in 0.088 seconds and failed one fixture setup: a manually
allocated `TestCase` had not run its constructor. Its source identity was
`1348abb4ca5c6eb6e91885cc77762daa3e97ad8ae1a277a3e34b588fb7e6ef6f`, image
`sha256:6d3555591baa26a75a63e65a6a73efec479bad729b54f6375a94e4f9e8c14888`,
and test-log SHA-256
`d11fc1df7e921526fb45963e7bfb1969889b15169e5ad5cc63a2415b92d1ab0b`.

After fixing that fixture constructor, trial 35 ran seven tests with zero skips
in 3.372 seconds and failed the actual worker-process case before READY. The
child emitted the fixed startup-failure packet; the supervisor correctly
rejected it as a READY record. The underlying child exception is not yet known.
Its 278-file source identity was
`3ca5e9769813921e824cf19603c0d073c52a7ed57fffbf37e39d1658e00e1079`, image
`sha256:6397d09c9e5d69c1f8d7669bc79caf277d4beb1166deccef1fe98a1c0dee77e4`,
baked-source proof SHA-256
`1a5e75b6511d813bfe43d6495cd83114df23d17ac3165f98759c0c49701fd62f`,
and test-log SHA-256
`b8552dd17133f1170ecc59c57cd3569a8fccfe514aadb5000e5e94c3a291645a`.
The six closed coordinator-configuration parser cases passed in each run,
but neither combined run passed its gate. Times above are unittest elapsed
time, not inference performance. No actual root-worker TLS/model READY or
whole-cohort root cutover is established.


## Trials 36–38: real fixed worker-process startup and mTLS component

The frozen trial-35 diagnostic caught a `ValueError` at the existing protected
Unix-socket directory check. The fixture had omitted creation of its required
owner-owned 0700 acceptor directory. After creating and validating that
directory, trial 36 reached real worker READY and graceful shutdown, but failed
its client fixture on a nonexistent candidate revision field. Trial 37 used the
actual protected selector's policy floor and then correctly denied Describe:
the private fixture lacked that exact signed permission. Bootstrap capability
bounds do not supply an authorization grant. Both failed combined runs are
retained (seven tests, zero skips): trial 36 took 5.503 seconds, log SHA-256
`1eed374dd3138d3d688e50f1116d7a7e20732c4a958b9b1674b5363e3eef1a93`;
trial 37 took 5.610 seconds, log SHA-256
`653a1769fec0db849deae9ed04d651b81a92822f74646c580baf0ba8c7510ebb`.
These are test elapsed times, not inference performance.

After adding the genuine fixture Describe permission, trial 38 passed
**seven tests, zero skips**, in 5.636 seconds, exit 0. Its 278-file source identity
was `0f67aa3d96e7dbe711f490c89b43777a25f81b77b75e2b9fbaaee7895094d094`,
image `sha256:53886b0cdd63fa58f5e780a2d6307d4598b65c375ab7aadba59d9df6fce519cd`,
baked-source proof log SHA-256
`591a225579193ee564f14eb8c8b1c3ef60dc5ddd9a6ecef485b082573a430618`,
and test-log SHA-256
`f25a6ef381fcad71f643acaa5e7bb309174599cdfaf547cd9fda8f434a3ee365`.

The positive case exercised the protected pinned bootstrap under Python `-I`,
the fixed read-only root-worker CLI, its actual selected-root binding/store/Clock,
real model loading and native TLS listener, exact launch READY, authenticated
coordinator Describe, zero connection reservations after client close, and
graceful worker exit 0 with confirmed runtime cleanup and process-group
retirement. Six closed coordinator-configuration parser cases also passed.
No production authorization or clock check was weakened. This is a local
component result: whole-cohort launch claims, root activation, new-root Generate
numerical parity and ongoing service health remain separate requirements.
The consolidated trial-38 result is recorded below; its failure remains open.


## Trial 38 full regression: retained valid-baseline failure

The same frozen trial-38 image ran **630 tests with zero skips** in 189.489
seconds of unittest elapsed time, exit 1. It started at
`2026-10-18T14:12:27.393Z` and completed at `2026-10-18T14:15:39.132Z`; test-log
SHA-256 is `c5e0a793f5e224f7092bcf2a5c9de9b316a545a7cad661a52982f89108593dfb`.
One inherited `MutatingStepReplyLossTests` case failed in the ordinary valid
Generate matrix, before its reply-loss injection. The public failure was
`EXECUTION_FAILED: Coordinator operation failed`; coordinator close and one
capture reservation were then unconfirmed. That public error does not establish
a clock, model, or transport cause. All earlier failed runs remain retained.
A later frozen-image, bounded three-case diagnostic passed, without explaining
or repairing the full-suite failure. No clock or validation setting was changed.
This elapsed time is not inference performance; the consolidated gate failed.


## Trial 39: root coordinator authority component

Trial 39 passed **17 tests, zero skips**, in 5.049 seconds of unittest elapsed
time (not inference performance), exit 0. Its 280-file source identity was
`301ee469be64af2a2ee735fe8fea3d01a7790994a42e345f0c3933f6d9910400`, image
`sha256:be9f7286a5fade9517b2d87937ac86241e88f809fd38ed51e598bea58c2170e4`,
baked-source proof log SHA-256
`cefa40159ed75634d5cfa67fb3b8aee120cce943abfb20a289c3783ac99ffbf9`,
and test-log SHA-256
`0c4cf5fbce43272dd91ee5023b359c2eadb436ce40dca1a7e4a1f6ed5738b773`.
The existing flat reference volume was mounted read-only at `/reference`,
with `STEAMBOAT_REFERENCE_DIR=/reference`; all base container restrictions
remained enabled.

The coordinator component used genuine coordinator/three-host certificates,
signed grants, protected file reads and common final Clock validation through
the actual adapter. Artifact/reference read-only checks, reference hashes and
manifest verification were real. Heavy model and network factories were
controlled in that coordinator test. Its separate short-grant case kept one
Clock from first installation, advanced wall and monotonic coherently only
after final material reads, and proved READY was withheld after expiry.
Additional checks covered signed grant removal, partial-start cleanup, unknown
ownership/status reporting and strict callback behavior. The real fixed worker
process/mTLS Describe case and six configuration parser cases also passed.
This does not establish a real coordinator CLI with three native worker
services, whole-cohort launch claims or new-root Generate parity. The full
trial-38 failure remains open; no full trial-39 suite was run.


## Trial 40: cancellation components pass; physical cancellation pending

Trial 40 passed **85 focused tests, zero skips**, in 8.782 seconds of unittest
elapsed time (not inference performance), exit 0. Frozen source identity is
`21416991a336342872a890ef3e143771e111205ace93c35ac6452b6e9cf4defe` (280
source files); the image is
`sha256:9fe0a21a9578ee4bd0cdbd7bb1d2404cbfb5dc92c95f9f6178ad0fb5e25fc079`.
The all-source proof SHA-256 is
`06ef1cc4dc7f7c138fa99836a1901be97b3043beb95162e1d5c8228557b49cdf`, and the
focused log SHA-256 is
`c2a6dbf0809002075a5a382a841393b84d44f0f0853574dca4616357113e6545`. The run
started at `2026-10-18T14:32:39.246Z` and completed at
`2026-10-18T14:32:50.037Z`.

The run covered the cohort, supervisor and worker tests, closed coordinator
configuration/runtime checks, and the real worker-process component. It
validated the cancellation profile's bounded held-session, request-reclamation,
and retained-fence reporting paths. It did **not** execute cancellation against
the physical two-host cohort, so no physical cancellation, local owner-process
disposal, or end-to-end cancellation result is established. This component
result does not accept C1a, C1b, C1, or P2; physical cancellation and the other
remaining lifecycle/fault gates are still open.

The executed command used project `steamboat-c1b-local-20261018`, the security
compose file plus the protected reference override, and the required pipeline
opt-in. Its exact Python test selection and no-skip/count watchdog were:

```sh
docker compose -p steamboat-c1b-local-20261018 -f compose.participant-security.yaml -f .lab/participant-network/coordinator39-reference-override.json run --rm -e STEAMBOAT_SECURE_PIPELINE_TESTS=1 security python -B -c 'import os,threading,unittest;timer=threading.Timer(120,lambda:os._exit(124));timer.daemon=True;timer.start();suite=unittest.defaultTestLoader.loadTestsFromNames(["tests.security.test_secure_cohort_lab","tests.security.test_secure_cohort_supervisor","tests.security.test_secure_worker_lab","tests.security.test_root_coordinator_config","tests.security.test_root_coordinator_runtime","tests.security.test_root_worker_process"]);expected=suite.countTestCases();print("expected_test_count",expected,flush=True);r=unittest.TextTestRunner(verbosity=2).run(suite);timer.cancel();raise SystemExit(not r.wasSuccessful() or bool(r.skipped) or r.testsRun!=expected or expected<80)'
```


The later physical `c1b-cancel-v1` run of this same frozen trial-40 source
passed, including request reclamation and confirmed owned process disposal.
See the [separate physical record](2026-10-18-participant-two-device-parity.md#physical-cancellation-after-remote-prefill).
The trial-40 component result alone remains distinct from that actual run;
the failed full trial-38 regression and C1 acceptance are still open.


## Trial 41: fixed coordinator CLI composition

Trial 41 passed **29 tests, zero skips**, in 6.867 seconds of unittest elapsed
time (not inference performance), exit 0. Source identity was
`cd3557b4716b0f688dc0b064261a355bd5786c077cb8edfa21192a3a5e14547e` (282 files),
image `sha256:9d0c6e3f5f08059b7fbf2c970166fcc03f1658c1172ad57d35027c8696f02752`,
all-source proof log SHA-256
`7a9e73c12384f224265f30e65f92bfbad179ad5f2c0a4c4f2df2b60633986272`, and
focused log SHA-256
`4dd459e1ede66cd5a8aee793ed19b5ff28636eb1e893444e3d88300d5442f993`.
The command started at `2026-10-18T14:45:29.782Z` and completed at
`2026-10-18T14:45:38.299Z`.

The added CLI composition cases exercised actual protected input/config reads,
canonical bounded framing, one shared Clock/store/binding, stop-before-READY,
header/status collision rejection before loading, and retaining the store while
runtime ownership is unresolved. Loader/store/runtime boundaries were controlled
in those composition cases. The previous genuine authority component, closed
configuration parser and real root-worker process/mTLS Describe also passed.
The selection was `tests.security.test_root_coordinator`,
`test_root_coordinator_config`, `test_root_coordinator_runtime` and
`test_root_worker_process`, with the required pipeline opt-in, read-only reference
volume, no-skip/exact-count assertion and 120-second watchdog.

This does not establish an actual coordinator child serving three native TLS
workers or the cold root-cutover Generate gate. A new opt-in process test is
being reviewed separately. The failed full trial-38 regression remains open;
no full trial-41 run or C1 acceptance is claimed.


## Trial 42: real fixed coordinator process and three TLS workers

Trial 42 passed the single required Linux process integration test with zero
skips in 17.000 seconds of unittest runtime (not inference performance), exit 0.
Frozen source SHA-256 was
`ea9e89c5d68018e0d30364ac1f05b9aff8405ab74abfce5c8c47ae3d65b6a8ed` (283 files),
image `sha256:bd7fc50c1a9b1ff16881a581a945162dbaf4344ef8129748c78d00d508485e9a`,
all-source proof log SHA-256
`37faf6be312edaf8c84ef1ea1db298d414c5ab837729bc7d9141c7bf52400069`, and
process-test log SHA-256
`2f12dd34dc1a79df338e3f3dafb013bda1932309fa4c1620590363b319bc5d02`.
The command started at `2026-10-18T14:55:36.078Z` and completed at
`2026-10-18T14:55:54.948Z`.

The test launched the unmodified fixed coordinator under Python `-I` and the
actual owned-process supervisor, using protected role configuration, a real
selected-root loader, current signed policy and genuine PKI. Three real
`StageExecutor`/`WorkerHandler` services ran native TLS listeners in the parent
test process. The child loaded its actual model, verified worker preflight and
opened its real consumer listener before emitting the exact READY frame.
A genuine authenticated consumer request captured nine finite last-position
vectors for prompt `[7, 13, 31]` plus eight identical forced feedback tokens.
Every vector and greedy selection matched the same-stack complete-model
reference within `atol=1e-3, rtol=0`.

The process accepted graceful SIGTERM, exited 0 and supplied a final
`stopped`/`shutdown_confirmed` status. Its registered process group was absent
and the actual retirement capability was validated. All parent workers and
bridges shut down with confirmed cleanup; transport reservations were zero.
The test-provisioned initial six-artifact selected root is deliberately a
trusted fixture. This component does not establish operator approval, whole
launch-claim consumption or a cold root cutover. Those remain separate local
C1a requirements. The full trial-38 failure and C1 acceptance remain open.

The executed selection was `tests.security.test_root_coordinator_process` with
`STEAMBOAT_SECURE_PIPELINE_TESTS=1`, the security compose service, read-only flat
reference override and pinned image above, a 120-second watchdog and exact
one-test/no-skip assertion. The exact operational command is retained in the
private execution journal.


## Trial 43: partial-Open components

Trial 43 passed **73 tests, zero skips**, in 17.201 seconds of unittest elapsed
time (not inference performance), exit 0. Source SHA-256 was
`251f0cbc2e1f8e0dc7d7dbfd355854a9067fdeb27975fcc104bc655000c7dc50` (283 files),
image `sha256:8bae668710c123efd9212d8f732246c4798cbbee331ccce74159619051f4d732`,
all-source proof log SHA-256
`657a3c5cd5c3e5eee658487e42455d87a692cf32d31fe2cb36704cfa3319ce6a`, and
focused log SHA-256
`35e5818307817d49f060fd2fe3646c4fd00501919e05178f5250fa8eb455fd4b`.
The command ran from `2026-10-18T15:03:56.377Z` to
`2026-10-18T15:04:15.466Z`, selecting the cohort, supervisor and worker lab
modules plus the real root-coordinator process test, with the required model
opt-in, pinned image/read-only reference, exact count/no skips and 120-second
watchdog.

The new fixed `c1b-partial-open-v1` profile injects caller-boundary loss only
after a real validated worker-3 OpenSession reply and a fresh correlated
reservation observation. Its component tests cover strict schema/identity
checks, zero-cache held-Open status, bounded expiry polling, exact integer
types and truthful held ownership. These are component checks. The subsequent
physical attempt failed during its ordinary baseline before fault arming; it
did not execute the partial-admission extension. See the
[retained physical attempt](2026-10-18-participant-two-device-parity.md#first-physical-partial-open-attempt).
The current worker-client Open outcome provenance fix is separate and has not
yet been integrated or executed; this trial does not claim it.


## Trial 44: retained worker-Open regression fixture failure

The 284-file trial-44 source
`717d55c6eb78d8115368fad2fdd0ca37c82f28413f50e9ae2226f6396cf73a38`
(image `sha256:c45a4a14ab96d22038de5f74297b293697f40136ddce7b3a2a7f36b8a5f97d62`)
ran 34 tests, zero skips, with one error in 21.632 seconds of unittest time,
exit 1. The new Open outcome regression imported a metadata helper from the
wrong module and failed before creating its runtime resources. The other 33
selected transport and known-capacity controls passed; the combined gate failed.
The all-source proof log SHA-256 is
`97b485eedc96a3e14fb5ccf87ec0e2e7e6ac473bb8486e2c578c37e41fe2b0b5`;
test-log SHA-256 is
`921a1df29898a578c87c676daccfa177d1c370ec7fd0ed092230e6b3fda94c95`.
The run spanned `2026-10-18T15:19:53.682Z` to `2026-10-18T15:20:17.041Z`.

The candidate production fix conservatively treats raw worker gRPC receive
exhaustion and invalid post-dispatch Open replies as unknown execution outcomes,
preserving the coordinator's unknown reservation fence. It does not change the
wire format or the bridge's existing fail-closed behavior. The test-only import
was corrected after this retained failure; the affected integration still
requires execution on the rebuilt candidate. No passing gate or C1 acceptance
is inferred from source review or the 33 other passing checks.


## Trial 45: retained receive-cap fixture failure

Trial 45 ran 79 tests with zero skips and one error in 17.388 seconds of
unittest time, exit 1. The 284-file source SHA-256 was
`44701f694a76ec2c1c93155df4f8a067f47adb1fb125a7790f253aef4717e79d`, image
`sha256:d3402d842645f66cc33aca73b2e052584ebd9f1c9f24d484ae3ec10f076dff81`,
all-source proof SHA-256
`29938e1ecee2cbcf8fec942bd5a0ffd1266080f892b54a649c3ffe9de567b5ac`, and
test log SHA-256
`e6a93612ccfd53df89ee52adf82ff7f738d725b9f0b03fd6206f3e3bfaab3084`. It ran
from `2026-10-18T15:26:13.399Z` to `2026-10-18T15:26:32.708Z`. The other 78
checks passed, including real coordinator generation and Step component checks,
but the new test failed during coordinator startup before reaching the intended
OpenSession receive-cap condition.

A bounded diagnostic on that frozen source confirmed why: the 220-byte
worker-2 cap rejected its 231-byte Describe response. Worker 1 used the
normal 1 MiB cap and accepted its 228-byte response; worker 3 was never called. The diagnostic ran from
`2026-10-18T15:30:09.300Z` to `2026-10-18T15:30:16.181Z`; its log SHA-256 is
`f642afcf94190cd95fd370ac5a295cb7aa7f281b9e69cdb8432e2fa86d9357e6`. Its
diagnostic harness SHA-256 was
`c52e60378afbc1cefcf6aa73df5667915b81cf54f4dc482f35ac10b8fc4ca916`.

## Trial 46: worker Open outcome regression passes

Trial 46 passed the one required Linux integration test with zero skips in
17.378 seconds of unittest time, exit 0. The frozen source contained 284 files, with source SHA-256
`43ea767f39e70c4c6cf23985bb7957aaf728c8592dd829ae03b2cb251d82402a`. The image was
`sha256:93ac394789e3d75599ceb445416edaf735390c8dfd86606018f5e3714995008d`,
all-source proof SHA-256
`438f52044eab98276aee3ae7682148ab031e9cfc0f4c4d788afc229ce7a59c53`, and test
log SHA-256 `ec79ef3a36c7848bed5d8363284f2cf6797bd0dba1dc8a04c68a5f39e15df7e2`.
The run spanned `2026-10-18T15:36:09.344Z` to
`2026-10-18T15:36:28.481Z`.

The test used three real StageExecutor/WorkerHandler bridges and native TLS
with C0 authorization. It confirmed a real 256-byte client receive cap allowed
both Describe replies and the OpenSession request, while the accepted
OpenSession response exceeded that cap. The coordinator retained and charged
the unknown OpenSession owner, remained unavailable, did not retry or issue a
Step, and performed the known first-worker cancellation. The real unknown
worker lease expired and both its session and bridge ownership retired, while
the coordinator fence remained. A malformed parsed view after a real
successful OpenSession also remained unknown. The handler's genuine
tombstone-capacity error was observed before the bridge invalidated
authorization; the client outcome therefore remained unknown. A separate
controlled client test exercises the coordinator's known-capacity control,
but the native test does not claim a known protobuf-capacity reply through the
authorization bridge. This is a transport/admission test using an
admission-only model stub; no model stage or generation ran.

Trial 46 does not close the pending physical partial-admission profile, root
cutover, the latest consolidated regression, or C1/P2 acceptance. Earlier
failures remain retained above; no result is inferred from the component pass.

## Related physical C1b Step reply-loss run

A later two-host `c1b-step-reply-loss-v1` run passed its narrow caller-boundary
unknown-outcome profile after a four-request, 27-vector baseline. The controlled
fault discarded a real validated worker-3 Step reply only after remote cache
commit and fresh status confirmation; it did not inject network packet loss.
The exact result, frozen source and image identities, local failure state, and
cleanup evidence are in the [two-device parity report](2026-10-18-participant-two-device-parity.md#physical-step-reply-loss-run-1).
This C1b result does not supersede the failed consolidated security regression
or change this report's C1a, C1, or P2 status.

## Trial 47: retained cold-cutover fixture failure

The one opted-in Linux cold-cutover test ran with zero skips and failed during
fixture construction in 3.044 seconds of unittest time. Root transition
issuance rejected the old credential because it was outside the configured
300-second renewal window. The failure occurred before cohort process startup,
so this trial supplies no approval, retirement, activation, root-selection,
READY, or Generate evidence. It is a retained fixture failure, not a result
about the protected transition path.

The frozen source contained 286 files with digest
`84eab5b31af038d5cb3637b19f8d83ebe95c2389a07fb47abe77376635229169`; the image
was `sha256:55852039038a433c22d390a2dc37b640b524d1754e048bc8cc822b3024b823e9`.
The baked-source proof verified all 286 files (log SHA-256
`bf21b1f66aec2582b29e861b57789411a4dfd535e78a61ad3166546a14bef8df`). The
failed test log SHA-256 is
`e835b65b630168d161ba446929bfeb430572b914934465748e195efad4de603a`; the
command ran from `2026-10-18T15:52:07.739Z` to
`2026-10-18T15:52:12.273Z`, exit 1. This attempt does not supersede or explain
the failed consolidated security regression; root cutover and C1a, C1b, C1 and
P2 remain open.

## Trials 48 and 49: retained cold-cutover fixture and API errors

Trial 48 ran four selected tests with zero skips and one error in 2.991 seconds
of unittest time (three identity controls passed). The cold-cutover fixture
reached final possession-proof construction but supplied preparation-intent
principal objects to a proof bound to the finalized declaration; exact declaration
membership rejected them before any cohort process started. Its 286-file source
digest was `6f3185b3915b798bca5d552fc9f5fd38b0cf3af4f2e6b04acc16dde2678bd237`,
image `sha256:40b327f359be50cc1cd968b59f2ce663994ca86aa72c26618870d98ef2cfe928`,
all-source proof log SHA-256 `8f33fdfedf6dd4375bb34442511c628c6a19ff4877fb63175d9458da87596edb`,
and test log SHA-256 `250f628ed91d38e25f39bc029f295e45dc3d921927ab977fa8a6130d8a7b79c0`.
The run spanned `2026-10-18T15:57:24.933Z`–`2026-10-18T15:57:29.703Z`.

Trial 49 also ran four tests with zero skips and one error, in 13.910 seconds
(three identity controls passed). The old cohort startup returned, then the
test called `read_selected()` without its required trusted validator. Cleanup
also failed because it hashed owned launch specs in incidental order. Its 286-file source digest was
`895db322bd9835b7b0d34b7452872b16f59eee09a4f7ab8070b3081a63e94801`, image
`sha256:487f2d3cadbcb8bb54a068681663e98b7c97e5ed06b3b585722288a878a18dbc`,
all-source proof log SHA-256 `79c2db1c8750633a3786730eae16a2a20893b267528f2d40deaa6b377eab0599`,
and test log SHA-256 `d44e6b24232186edf032a18b75f3aaa754558321b3f04ceb88c63b8f07915414`.
The run spanned `2026-10-18T15:59:50.795Z`–`2026-10-18T16:00:06.449Z`.

The fixture now keeps the 900-second default for ordinary identity tests while
the cold-transition setup issues real 300-second leaves and verifies their
remaining validity with the real Clock. Final proofs use exact finalized
declaration members. Every selected-root read uses the startup component's
closed-plan validator, and cleanup sorts and verifies unique owned role specs
before computing the digest. These are fixture corrections, not production
guard changes; Trial 50 below shows the cold-cutover component still has an
unresolved cleanup-status failure.

## Trial 50: capacity components pass; cold-cutover cleanup remains unresolved

The capacity component selection passed 56 tests with zero skips in 2.849
seconds of unittest time (not inference performance), exit 0. The frozen source
contained 286 files with digest
`049aa3e28c8c9920df476bc77f957a8b250cd6fcbc7efaf5c87cb852f1dd4ae2`, image
`sha256:bd688c235f35d7e09cf962d98120118f3ae36413e9949600803d611caaa2582b`,
all-source proof log SHA-256
`161589e9731693cd2037b5c9cc9f3ede053ebd433700c75789f4abeb8d595a6e`, and
capacity test log SHA-256
`2a16faef215377b36318e252378aeda19fe4bb892235e39d58adc9f50f2fa820`. The
run spanned `2026-10-18T16:04:19.212Z`–`2026-10-18T16:04:23.886Z`. This is a
component gate only; the physical capacity profile has not run.

On the same source and image, the four-test cold-cutover and identity selection
failed with one failure and zero skips in 48.573 seconds of unittest time
(three identity controls passed).
Old-cohort startup, an old-root Generate, and retirement reached their checks,
but final status validation reported old worker 3's resource status incomplete.
The failing resource field has not been identified. The run spanned
`2026-10-18T16:04:40.123Z`–`2026-10-18T16:05:30.553Z`; its log SHA-256 is
`f6250b68cee7df559f006b46ca4d2accd3c265e29fb9c618b544c921b8fe4df1`. No
successful new-root activation, READY cohort, or cold cutover is established.
The bounded failure diagnosis and physical capacity run remain open, and C1a,
C1b, C1 and P2 remain unaccepted.


A single bounded diagnostic on frozen Trial 50 reproduced the final-status
failure (one test, zero skips, 48.531 seconds, exit 1). All three old workers
reported confirmed component shutdown and zero sessions, caches, tombstones,
queues, authorizations, bridge owners and transport reservations. Their
`requires_restart=true`, `unavailable=true`, `ready=false` state is expected:
normal `bridge.stop()` calls the runtime fence before stopping. The final test
had incorrectly required a healthy restart flag after shutdown. Its corrected
stopped-state predicate preserves every resource and actual process-exit check;
live readiness checks remain unchanged. This diagnoses the reproduced predicate,
not the earlier consolidated failure, and does not establish a successful cold
cutover. Diagnostic harness SHA-256:
`028ea8fb0d03de8410c5d0ff68536a9bcb04b3a762f21f764f95c31418d0a22f`;
log SHA-256:
`c9f2f2d850f2f9b086bdf05e7076f89e31a70d2da7a19e9b85ae267d29a0f2cb`.
It ran from `2026-10-18T16:07:57.844Z` to `2026-10-18T16:08:48.159Z`.

## Trial 51: actual local cold root cutover

After correcting only that stopped-state assertion, the selected Linux suite
passed four tests with zero skips in 131.653 seconds, exit 0. Three were identity
fixture controls; one exercised the actual five-role cold transition. The old
cohort served an authenticated Generate, refused a live whole-cohort retirement
attempt without changing the selected store, and then actually exited its owned
processes and groups. The test activated the operator-approved 13-artifact bundle,
independently reopened the selected store, checked rollback/equivocation refusals,
and started the new five-role cohort through the real worker/coordinator CLIs and
whole launch claim. New inference passed a greedy token check and nine finite
captured last-position vectors at `atol=1e-3, rtol=0`.

The trusted initial test bootstrap also contained 13 pinned artifacts, with
placeholder history; it was not an independently proven initial transition.
The parent test client performed inference with the protected consumer binding;
the consumer child checked that binding and liveness. A bounded test observer
delegated to the original outbound authorizer unchanged. An old consumer leaf
received a native denial on raw mTLS Coordinator.Describe at the new live
endpoint, paired with successful new inference and no extra outbound worker
bindings. Old boot/epoch/context refusals were local loader/outbound controls,
not stale Generate requests proven to reach that endpoint. Final resource-zero,
exit-0 and process-group-absence checks passed. Real Clock uncertainty was 0.5
seconds; no clock provider or security guard was replaced.

The 286-file source digest was
`e5fd2259bc94d0ffe405e8f42e24312b8e93dbb90d752169b5e8ca523ae2462b`, image
`sha256:c9654b6c1dc2fadb7f682701ee9d1fcbd70e846171db5a55ecb0fcd5b09bf805`,
all-source proof log SHA-256
`12715001e1ea5d372c20cb4c685de15593d7d85ee306f2286388d9e4f5fab24e`, and
test log SHA-256
`1abe1f3757863d21002fa4c26779b6412159b768034a49802095ac79c166f45d`.
The command ran from `2026-10-18T16:18:33.921Z` to
`2026-10-18T16:20:47.632Z`. This is a single Linux host correctness/lifecycle
result, not separate-device restart, inference performance, or C1 acceptance.
It does not explain the retained Trial 38 consolidated failure.

## Trial 52: capacity synchronization and boot-authority components

The focused Linux selection passed 65 tests with zero skips in 4.144 seconds,
exit 0: 57 cohort/supervisor checks and eight boot-authority checks. The capacity
fixture now waits for the actual three-stage active-job array and seven distinct
queued requests, rather than treating Open attempts as proof that continuations
have resumed into the queue. Boot helpers preserve the CA, signer and participant
credentials while signing an immutable higher-revision policy with fresh boots;
they build genuine core Authorization/ConsumerContextFactory objects and enforce
protected key paths. The Open positive is a core authorization claim without
worker allocation. These tests do not execute a network Open, model, or physical
restart, and do not establish durable policy rollback protection across processes.

The source contained 288 files, digest
`25b827d889f2a546ad688e764511b9675df1fd72d4f6145ee27a76aa2a69e487`, image
`sha256:186ec6325d1a1ccae7bb04ee4845b4e34de62c9f904e5a0683af2415c793f523`,
all-source proof log SHA-256
`7fb3e1cab8216869111932be4bb73aa3bbb62351d44cdafec91da6d1829e69db`, and
test log SHA-256
`17a75b1a89a72d14a97aa8ed7a1df1d3d3353fb34914ed4c7c23bf4d87308054`.
The command ran from `2026-10-18T16:35:07.035Z` to
`2026-10-18T16:35:13.198Z`. C1a, C1b, C1 and P2 remain unaccepted.

## Trial 53: retained-owner graph and restart-contract components

The focused Linux gate passed all 73 discovered tests with zero skips in 2.858
seconds, exit 0. It checks exact request/context/slot/task identity for partial
Open ownership retained until process exit, rejects unrelated owners, and keeps
logical cleanup explicitly unconfirmed. It also covers the genuine probe's
bounded pre-admission deadline and the closed two-generation restart contracts,
including actual nested C0 validators and lightweight package imports. These
contract checks do not perform a physical restart.

The held-capacity connection predicate was corrected from 16 to 15: three fixed
listener slots plus four outbound clients reserving three slots each. Eight
Generate streams reuse those clients; the configured hard maximum remains 16.
One frozen Trial 52 diagnostic reported 15 connections after the original failure
cleanup; that post-cleanup snapshot cannot identify every pre-failure conjunct.
The correction follows the actual reservation graph, rather than treating that
snapshot as complete causal evidence. Earlier failures remain retained.

The 290-file source digest was
`0efbcc83547fc2fda3c6bddc607705af4abcb11e7a572848b38afbcc7dd62acf`, image
`sha256:58a36f9ea604da3af80b7e902c8a26102d6fa47a81e1676d6263fe6784f15e5b`,
all-source proof log SHA-256
`f6f7e4d2930cabecdb63016afc1ceed0af0116bb2db712b6d28d8bc1a9b5e581`, and
test log SHA-256
`b29f6098994277c5691e88c37918ada8512de1cc401857393273045dd02c3046`.
The test command ran from `2026-10-18T16:55:43.143Z` to
`2026-10-18T16:55:47.874Z`. The later physical partial/capacity results are
recorded separately; the failed consolidated gate and C1 acceptance remain open.

On that same frozen image, the preserved private insecure CPU coordinator module
also passed seven tests with zero skips in 9.592 seconds, exit 0. Its two real
model integration tests compare one/three/eight concurrent requests and greedy
feedback against the reference and cancel one stream while preserving another
cache; five trace-validation controls are separate synthetic checks. This is a
same-host control, not a GPU or separate-device speedup. The command ran from
`2026-10-18T17:02:29.256Z` to `2026-10-18T17:02:40.532Z`; log SHA-256:
`b82059ced66ac98147457df44d8918b6613889d0de45c230f07e5793d49d2b44`.

## Trial 54: restart integration components

The Linux cohort, supervisor, boot and restart-contract selection passed all 86
tests with zero skips in 4.430 seconds, exit 0. The source adds a distinct
two-generation owner lifecycle, real probe authorization/closure checks, cached
first-cleanup outcomes, strong retention on uncertain disposal, exact result
correlation and unchanged READY provenance. Component validation does not replace
the physical run; restart run 1 subsequently failed new-generation setup.

The 290-file source digest was
`fd589bf2e445e59241441dd3cd255f11ac276f2ea61653278fa15ffe61f90136`, image
`sha256:2f26168a6e6ccc93e427e15aebe7d8905414c854d0ad449b0f360fb348b36350`,
all-source proof log SHA-256
`2256b98fe66611cdc413efd14ca0bcb9c8945840a7cf4810939163a8edf1c255`, and
test log SHA-256
`12b7ea023de803e80f320ddb5682bb1056b3636ef9f1b9ca60f449a4aaada2d6`.
The command ran from `2026-10-18T17:15:30.543Z` to
`2026-10-18T17:15:36.995Z`. The consolidated regression remains open.

## Trials 55 and 56: restart and owner-control component gates

Trial 55 passed 89 focused tests with zero skips in 2.944 seconds of unittest
time, exit 0. The selection covers restart integration components; it does not
run the worker owner-adapter module or a physical drain or role-removal run. Its
290-file source digest was
`87a2b515422928ce118c5eb5080a3e7aea954458b5b431e7870fb4f7cd9107c1`, image
`sha256:983ba97e34a63c14a1c16d3ca8b49b72fbe88f6b9ff8f929086f3e8ff54c156a`,
all-source proof log SHA-256
`1ab42da8860e804fe2214fc870879fa6f0a9715c381390e318d293f3a346bab1`, and test
log SHA-256
`dd523793899a614557fd98f51a3e8dbc58dfe2dfbb5162f39888ac8793bf5cc4`. The
focused run spanned `2026-10-18T17:23:32.704Z`–`2026-10-18T17:23:37.557Z`.

The second physical restart attempt reached the new worker's protected READY
acknowledgement, then failed before its next expected observation; the original
failing branch remains unattributed. A separate frozen diagnostic reproduced an
old-binding-probe `SecureTransportError` caused by `TimeoutError`; it did not
observe a native `UNAUTHENTICATED` status. This separate run does not establish
that the original restart failure had the same cause. The old remote worker exited 0 in 1.844 seconds from the
parent's monotonic stop arm; the new remote worker also exited 0 and both remote
job roots were removed. The local operator exited 143, so graceful local
shutdown was unconfirmed. This is not a successful restarted-cohort inference
or proof that an old binding was explicitly denied.

The physical result SHA-256 is
`9533b7fd86d81539786db3e1b2cb3e724e3ae83df0257730506b6232061c4854`; its log
SHA-256 is
`eef2b75c06582590b8cadb7af26436b2206e77655eba7b2bee42892a07138f26`. The
single frozen diagnostic result SHA-256 is
`78b6e35ff83a181f47612b5ef336b0c47e606fb6862e23bdf6056803f839dda7`, and its
log SHA-256 is
`dd033ef39b4e061574b7fd892529450406e811289a2cf4451f378dc4b5271ed8`. The
diagnostic retained the original source, images, Clock and acceptance criteria;
it ran from `2026-10-18T17:29:37.343Z` to `2026-10-18T17:30:53.914Z` and does
not replace or explain the original run.

Trial 56 passed 122 tests with zero skips in 5.669 seconds, but the required
regression harness expected at least 123 tests and returned exit 1. Treat this
as a failed gate despite the test runner's `OK` output. Its selection covered
runtime-binding and protected owner-inbox component suites; it did not run the
worker owner-adapter module. No physical drain or signed role-removal run
occurred. The source contained 292 files with digest
`b90273dde42dbeb5f8fdaea857bc2580acbc3c135fc5f09d072cc46a07a90daa`, image
`sha256:6523a51db689421ec761ef1e1d204841db18251dc8dcf35b5e8800f14f895b54`,
all-source proof log SHA-256
`4577ec25e7247c4706d9ef14260cc62ac368ebeb03e070122b484d483b1f6fb1`, and test
log SHA-256
`0a6ee0ee82b47851b87b938cd73ea2e3f070e78e9205e4a19825f2163145e181`. The run
spanned `2026-10-18T17:37:11.581Z`–`2026-10-18T17:37:19.307Z`.

No C1a activation, complete restart, physical drain/removal, or C1/P2 acceptance
is established by these runs. The consolidated regression and other physical
fault/lifecycle requirements remain open.

## Trials 57 to 59: owner-adapter fixture repair and Linux gate

Trial 57 ran 159 tests with zero skips but failed with two errors after its new
two-policy tests passed real session claims: the fixture supplied a
`SimpleNamespace` where the real claim API requires a subscriptable `Binding`.
Trial 58 ran 187 tests with zero skips and failed with two errors because the
owner-control enable helper was missing from the test module imports. The
independent audit found no other missing helper. These failures occurred before
the corresponding owner actions; neither run established a physical owner flow.

Trial 59 passed all 187 required Linux tests with zero skips in 5.797 seconds,
exit 0. It includes the shared protocol and publisher gates, and exercises two
signed policy updates on one live store, immutable command intents, the
command-bound notice, and rejection of a second policy that omits an original
local serial. The owner-control flow tests use component fixtures for the
bridge/status; they do not establish physical drain, removal, or TLS denial.
Actual POSIX publication tests cover the P-256 signer/verifier path, FIFO
rejection, and post-publication fsync failure.

Trial 57 source/image/proof/log SHA-256 values are respectively
`19913328e5d79ffee3c33f750aece19f3ae0ef9bf42ff1d8559c9e460a08002e`,
`c76a4de89c7f9cdfe5315595647232e2b8b5b4e39bb58feecccac6c9f18c0fb3`,
`db8aa56d3c830d6a5ef9a8a65daf7c6e4b1478ecbaae3535fb5bcbfdb50ea58e`, and
`06faee40c458827d1d308bf72b2179650be5b98af8047fbb638fe07d6b4678bc`.
Trial 58 values are
`24f7ce8ef2154d65c9e7fa34548c61eb316b8dce680363ea2ad16e4c04744e4b`,
`08d08b796c7de2c2196e72681ff87dfe589ede7e3890a1fc0f574caebf8ddf1b`, and
`3d0c63e95051c10c85718c555e66f3c275dbdff0ef7c25eb08add26236535730` for
source, image, and log. Trial 59 source, image, proof, and log SHA-256 values
are `d21ee8f2a5197feb7543db612ebf906cf029d7ef557b06c1bea17d85006db9b9`,
`842eecc137593f5189bf4b07dbf0f379ae0d2df60f25d46d31baff2d524c7180`,
`2755e6fad64931b51c8fb414b5b85f0ae5a503f6b408ca58d53a92e182507926`, and
`839ef19915ced26420a948bbb7db0b0b67acde8e450cf5f4dde99eb16832f61c`.
The run occurred from `2026-10-18T18:09:55.918Z` to
`2026-10-18T18:10:03.694Z`.

## Physical restart run 3: stale-control check failed

The physical restart run reached the new worker's READY acknowledgement and a
new Describe. It then failed before the first native old-session `SessionStatus`
refusal. The corrected nonce location identifies where the probe stopped; the
underlying native exception was not recorded. The old and new remote processes
exited 0 and their containers and private job roots were removed. The local
operator exited 143, so graceful local shutdown was unconfirmed. This is not
proof of old-binding rejection or successful new-generation inference.

The source audit separately identified a possible listener-capacity conflict
between the held new Describe and the fresh caller, and a close-before-RPC-abort
ordering at the first unestablished rejection. These are source observations,
not established causes of this run. Physical result SHA-256:
`5ac9e01fe3d84b9134e0ef5704fbcdd20360df9287180d2ba7928211a4660965`; log
SHA-256: `e16da8d00ae91c32ec610cb34b82aeb53501ac7cb82537fb5b4d5c3837dfd035`.
The matching remote image was
`sha256:c76071138134ee99fd1927576ab886efb83e24a6a571888aa02be81d8c285e7e`,
and its overlay record SHA-256 was
`92c69fa76791fea28b0550de5b1261d5a6dc6c33f8531db57feadfd6dd7c0735`.
The run spanned `2026-10-18T18:13:20.300Z`–`2026-10-18T18:14:37.706Z`.

C1a activation, actual owner drain/removal, current full regression, and C1/P2
acceptance remain open. The earlier full-regression failure remains unexplained.

## Trials 60 to 63: helper gate and retained consolidated failure

Trial 60 passed all 201 required Linux tests with zero skips in 7.700 seconds.
It adds the reviewed public owner-material derivation and controller publication
helpers to the prior focused selection. This is component evidence; no physical
owner drain or removal profile ran.

Trial 61 built and proved its source image, but Windows rejected the test
process spawn with `ENAMETOOLONG`: the explicit required-case list exceeded the
command-line limit. No tests ran. The next private harness mounted the exact
hashed gate script read-only instead of sending its source in an argument.
Required cases, pass predicates and runtime resource limits were preserved.

Trial 62 discovered 783 tests and included all 758 explicitly required case IDs,
including the 630 retained from Trial 38. It ran with both secure-pipeline and
capture-backpressure integration flags enabled, zero skips and a 600-second
outer watchdog. The run failed after 361.667 seconds with five failures and one
error. Its failure records identify a production-method extraction fixture
missing the new drain method, supervisor status fixtures missing the exact
active-session-ID field, and a handoff filename test still bounded to seven
observations after the restart profile added ten. This does not explain the
different historical Trial 38 failure.

The parent reviewed the two fixture-file corrections without changing production
validators or expiry assertions. Trial 63 passed their complete 41-test Linux
selection with zero skips in 0.761 seconds. Historical test IDs were retained;
the filename test now checks the finite boundary at ten and rejects eleven.
This focused pass does not turn Trial 62 into a successful consolidated run.

All three executed test gates proved 296 source files. Trial 60 and 62 source
digest was `3bef8152d6be6f172ad6766d83c63887031f10978fe91a912a3b0383e62c1741`;
their image SHA-256 values were respectively
`03b6aef2e66f7a3f5d61edb30ffa6594c66655e3e4a0c5cb589e1dbee93b23c8` and
`eb0180d64c0cff56f6e0ab7c7659273dc941c29b7cb1df80ad31fc9bb9ae1570`.
Their all-source proof log SHA-256 was
`0cced34f043b0b8865334154459e79780b6f7df261048829e62d070220b40bed`.
Trial 60 test log SHA-256:
`c76e784ced9e6c63722a963add5fff71e194dae3ba9707ea42b43efe1c3e4a75`.
Trial 62 test log SHA-256:
`cde0b5b21f2261920064570e36376c5adbc6125b966410559418f5b3302e7b13`.
Its frozen gate-script SHA-256 was
`2e8328e9544db8e02f9caeda1a67568a085a713266d49d651ce506cfb9e4207b`.

Trial 63 source, image, proof-log and test-log SHA-256 values were respectively
`82a85935e2a776446c301075725ad4a6c1d73546bbf38d66fb87592a96e279cd`,
`acbbdc6174b0cefb9074426493df38afb177d8417ee0ae8f19a5c6eeb0ea70ad`,
`a71770a5bf3d3d4ffd33a451d4d02e21e06fb63d924fe09caaa787d27c8e3340`, and
`6017422990f6e134fa172f2c80e42db6b1a02758f9343f421106c6488844c074`.
Trial 62 ran from `2026-10-18T18:31:37.972Z` to
`2026-10-18T18:37:42.263Z`; Trial 63 ran from
`2026-10-18T18:46:00.263Z` to `2026-10-18T18:46:02.218Z`.

The restart amendment, genuine first-RPC rejection coverage, owner-result
validation and physical drain/removal profiles still require integration and
acceptance. No clean current full regression, C1a/C1b/C1 acceptance, P2 result,
GPU result or additional physical run is established by these checks.

## Trials 64 and 65: native-binding component fixture and rerun

Trial 64 ran all 248 required Linux test IDs with zero skips, but failed with
one error in `test_restart_routed_authorizer_keeps_genuine_old_and_new_core_bindings`.
The test's otherwise-valid Step request omitted the bounded tensor envelope, so
the strict production wire validator rejected it before the intended
authorization sequence. This was a test-fixture defect, not a reason to weaken
wire validation. The fixture was corrected to carry shape `[1, 1, 64]`,
`float32_le`, `batch_sequence_hidden`, and matching 256-byte input/output data.
Trial 65 then passed all 248 required Linux tests with zero skips in 8.652
seconds. The selection covers genuine C0 bindings, restart cleanup components,
the earlier helper cases, and 41 fixture controls; it is component evidence,
not a successful physical restart or owner-removal run.

Trial 64 source digest, built image, all-source proof log and test log SHA-256
are `0c7478691f881a3c8dadccacff10fb0efb629463d654d94d79a918d75b5c2715`,
`sha256:d6bbd975de643dff7b25a5a7632ef55f793ec8bac2224518ad4a9148ec0241e6`,
`83745a37ba14e069bf2b73ad17dd0602a2faa8957d4a4fc94e36a0dd5fcb5046`, and
`b8eeb5f65354825f4042b57b25eed41c092b386cda00385f641d39797718513c`.
Trial 65 values are
`ed951dbf1a7ad74c0d9971b0237f2502ac0ec9cccfed58cbb8bc5f122ba60225`,
`sha256:b0f7531b1d32fa78a6f611442aa179397d2789611a08a9f6a52daece6fedfe2b`,
`a0f8442112e46b47897316928d89a9b9ed38bcc5f093eeb7158534d71f51be1d`, and
`41523428c446267e809ffbe82d24afebedbce586c83fd40eb68a64cb42ea28e4`.
The matching remote overlay verified the same 296-file source digest and kept
the 14-layer base plus dependency/runtime configuration unchanged. Its image
was `sha256:82336ef2810a1ea0b30c1619cd44009aea84263567284abb86edcb7eef69adf1`,
overlay-record SHA-256 `bcd0684fccff955c479bc1327c2c32bf800a1d4235155ea09d6ef2f4894110d7`,
and verification-log SHA-256
`e44f69574458d6ef456eebfe182019cf24ca11e16e7fe809160b5940f2a04660`.

The follow-on physical restart run 4 is recorded separately in the
[two-device parity report](2026-10-18-participant-two-device-parity.md#physical-restart-run-4-generation-two-listener-setup-failed).
It did not accept the restarted cohort or prove old-binding rejection. The
corrected fixture makes Trial 65's focused component pass meaningful, but does
not alter this physical failure or close C1b, C1, or P2.

## Trials 66 and 67: native restart-owner controls and corrected fixtures

Trial 66 ran all 311 required Linux tests with zero skips in 29.804 seconds,
but failed with one failure and five errors. The failures were bounded to the
new fixture set: three errors imported the coordinator server from the wrong
module, one used consumer identity where `ConsumerContextFactory` requires the
personal coordinator identity, one inspected a pending reservation through the
connection after correct retirement had cleared it, and one expected native
`UNAVAILABLE` where the actual credential rejection is `UNAUTHENTICATED`. Review
corrected these fixtures and added sequence-width advancement to the counting
cache before the rerun; no production wire validation or status mapping was
relaxed.

Trial 67 passed all 311 required Linux tests with zero skips in 35.245 seconds.
The gate retained all 248 earlier required IDs and ran the nine native C0
groups, owner-protocol and archive/handoff checks, and the actual POSIX-path
controls. Its Step control uses a counting cache that validates and advances
the sequence position while returning the same activation; it loads no model
weights. This is component-level native authorization and lifecycle evidence.
It is not a physical Remove profile, accepted restart, or clean current full
regression.

Trial 66 source digest and built image ID SHA-256 are
`ed32618c4f6f54b7d567f5eac10f1688db013ec77109e8bddbf5b6c84daf9af6` and
`sha256:88f14167cf876249c1cf9fb6f4fbd03b8b7c74c871748e5d82073864b0c29df1`.
Its source-proof log SHA-256 is
`5673b9c52d49c620433ff0e7b48130ef5347bd3a6fad9d297e4bddecb61cdf6a`, and test
log SHA-256 is
`6dba015f721d9c0af3b19d3ed60b56de203458d72c2c5c91d647d77f34d12544`.
Trial 67 source digest, image ID, source-proof log, and test-log
SHA-256 values are respectively
`544f8466a07b1cad8081c9a7dc167383b7631e7d49f242ebadc785c15ab020fb`,
`sha256:3e43883868a33ed2b6e6277f50b9eaa64894c40424d39b9a7bd6e79ac250611f`,
`3450a4e090b4322ea1f0e8b04bead3a5753483bde61516d81ccdff0e202b61a2`, and
`5b0dff6d1fe3b2aa1b0cbe23b1479ca3eb5ed05ca33664bcd54c9669e2df1233`. Both
images verified the 298-file source inventory with no mismatches.

The matching ZimaBlade overlay for Trial 67 also verified all 298 files and
preserved the 14-layer base, dependency environment, and runtime configuration.
Its image is
`sha256:fa4cfd7accf1b5643bd4094d5f98f8bc180e686e9ee164e18c972b85473e7ec2`;
overlay-record SHA-256 is
`cc17b82c2688b72da763f0fb087f4e350e1d515f4f639603140e480bfa93b59d`, and
verification-log SHA-256 is
`cf4fe97ead7d38d40c7a4459f61c31c3f429b9bf99eb8644ad160263fbaf515b`.

Physical restart run 5 later failed at `operator_result` with
`SupervisorError`; the cohort and failure location were null, so the specific
cause remains unrecorded. Its new worker reached protected READY, which
confirms setup progress only. No accepted baseline, native old-binding
rejection, or restarted inference is established. Both remote generations
exited 0, their containers and private job roots were removed, and no transport
operations remained pending. The old worker exited 1.907 seconds after the
causal stop arm. The local operator exited 143 and its container was removed;
graceful local shutdown was unconfirmed. The run spanned
`2026-10-18T19:37:17.064Z` to `2026-10-18T19:38:52.051Z`, with command exit 1.
Physical result SHA-256 is
`4d857e92dc0251d3ad768c624d38c6d0e87dc7e1fe3a00eeae6979b0f380ca53`; log
SHA-256 is
`34c75193ae2507a6ff8015a6060e49220694a2f7c8fa16ad000313cd20c66a55`.
It used Trial 67's source digest
`544f8466a07b1cad8081c9a7dc167383b7631e7d49f242ebadc785c15ab020fb` and
local/remote images
`sha256:3e43883868a33ed2b6e6277f50b9eaa64894c40424d39b9a7bd6e79ac250611f` and
`sha256:fa4cfd7accf1b5643bd4094d5f98f8bc180e686e9ee164e18c972b85473e7ec2`.
Restart acceptance, physical drain/removal, the current full regression and
C1a/C1b/C1/P2 acceptance remain open.

## Trial 67 diagnostic and separate offline analysis

The frozen Trial 67 `RST5-diag1` command ran the existing supervisor on the
actual physical restart setup from `2026-10-18T19:44:44.248Z` to
`2026-10-18T19:46:16.963Z`. This on-host diagnostic observed the secondary
`cohort_result:restart_binding` rejection at
`secure_cohort_supervisor.py:2411`; it did not establish the original RST5
failure's cause, which remains unrecorded. Diagnostic result SHA-256:
`6d0e578c5e26ca25599b8b04d1718879c9daa6633444f4b7524ef41fd9b0d797`; log
SHA-256: `d79351b8728371fea15f43cf350b7f5eac65ab7601a86cb9a3c713cb52e5733a`.

A separate copy-only offline analysis then examined the retained protected
result without changing it. It found that the validated held-status observation
had 20 fields while the strict restart-result projection expects 11; the
upstream projection mismatch explains that later secondary rejection. The
copied status was adjusted only to reach that final predicate. The original
protected result remains retained privately (SHA-256
`073f03e952aebd67eb8fc29ef2f6e1381c5d6a1a2e7e7dcbad28e9a318b21422`); no
separate result or log hash is claimed for the offline analysis.

The later reviewed producer projection selects the 11 validated fields and
leaves final validation strict. Neither diagnostic establishes restart
acceptance, a numerical baseline, native rejection, owner drain, or removal.
C1a, C1b, C1 and P2 remain unaccepted.

## Trial 68: current required component gate

Trial 68 passed all 311 required Linux tests with zero skips in 35.658 seconds
of unittest runtime (not inference performance), exit 0, from
`2026-10-18T19:58:44.851Z` to `2026-10-18T19:59:22.815Z`. The 298-file source
digest is `6d7ef737af2b80e641b9c1bd3130ac4cee43cc66b6d6a28afc6f0f8258aca009`;
the image is `sha256:3864f8cec9de794794dd4cab2b49174199912d36df2358e05849c5afe1a45f23`,
and the baked-source proof reported zero mismatches (SHA-256
`07aa9f79d9ed3d436633c6eb6f26f3b4468d992b0e4375452b6f5a14db91bd3b`). The
test log SHA-256 is
`157085ec364bdf5e2fadc96c9f80f7ab218bdf037b85de0bc9d86061ad34710b`. The
gate includes a narrowly reviewed restart-projection check; owner-controller
changes were not integrated into this image. This component pass does not
establish physical restart, drain, or removal.

The matching ZimaBlade overlay verified all 298 files on the unchanged
14-layer base and dependency/runtime configuration. Its image is
`sha256:e6d52af4ed9783e020eee6077a48db90aadd90a499253b9ba51be1e28779b6b3`; the
overlay record SHA-256 is
`7363180e15cc7e2643cbab4986978eec35d3cb58ad9b40ee192073c6f60bb591`.

## Physical restart run 6: old baseline RemoteError

Physical RST6 failed during the old cohort's first baseline with
`RemoteError`, before the held-status projection or generation-two startup.
The version-1 failure record carried no error code, so this run does not identify
a clock failure or implicate the later projection. The new generation was not
accepted. The old remote worker exited 0; its container and job root were
removed with no pending operations. The local operator exited 143 and graceful
shutdown was unconfirmed. The run spanned `2026-10-18T20:03:46.925Z` to
`2026-10-18T20:04:34.734Z`, exit 1. Physical result SHA-256 is
`f99053688443fc9edb1957862d77b7f2863ef5e5bcd9b9fc3a59e641412fb222`; log
SHA-256 is
`8bb4139708d364aa0b7cad846ec29b3369b1b0542405b5cdf5d88e0169666f49`.

## Trial 69: consolidated required Linux gate

Trial 69 completed all 825 required tests with zero skips and one failure in
367.458 seconds of unittest runtime (not inference performance), exit 1. Both
secure-pipeline and capture-backpressure opt-ins were enabled. The run spanned
`2026-10-18T20:16:50.079Z`–`2026-10-18T20:23:00.305Z`. All 783 required IDs
from the earlier full gates and current AST inventory were present; none were
missing. Source identity remained the 298-file Trial 68 pre-owner source
`6d7ef737af2b80e641b9c1bd3130ac4cee43cc66b6d6a28afc6f0f8258aca009`, with image
`sha256:eacf30c273d3f8a6167ee3f8511fd484a8bac1b2bca134e8d6028d504462faad`.
Source-proof SHA-256:
`07aa9f79d9ed3d436633c6eb6f26f3b4468d992b0e4375452b6f5a14db91bd3b`; gate SHA-256:
`73fb4848204cb497f40437ca8b652f06f7bd49300c4dc954834f747a36be443a`; log SHA-256:
`2f3295d9b503645549b6c5f66f4709c8da1910e4702ea5ac3a838a10d088cb72`.

The sole failure was
`SecureGenerateCancellationProcessTests.test_fenced_cancellation_owner_is_disposed_by_confirmed_child_exit`.
Its child exited 1 after `RemoteError CLOCK_UNSAFE: clock moved backwards`
during baseline generation, before the lifecycle/cancellation hook. Teardown
did not confirm closure and one capture reservation remained. This does not
show that cancellation injection ran; the environment cause is unestablished.
No clock settings or criteria changed, and this result does not explain RST6's
unclassified error or earlier full-gate failures. Scoped containers were
removed; BuildKit remained. The final integrated owner-profile full regression,
physical restart and owner drain/removal remain pending; C1a, C1b, C1 and P2
remain unaccepted.

## Trial 70: owner-flow controlled gate retained failure

Trial 70 ran 357 required tests with zero skips, one failure and one error in
36.306 seconds of unittest runtime, exit 1, from
`2026-10-18T20:40:15.874Z` to `2026-10-18T20:40:54.516Z`. The gate included
the 311 retained component cases and new controlled producer/controller flow
cases. Source identity was 300 files with SHA-256
`94b9a9504f7fc6f4973faaceac8b614bf6f78bde4e0f72f978fc12d2e3be39cd`; image
`sha256:3d6358ec07a1074af4265dbc992a90ab1e388c4341b0068aafa64d08cb402a97`;
source-proof SHA-256
`d4f731800a4845041b98d079d42e3694549a4c475647f84ca5f6d80a22fb6a92`; frozen
gate SHA-256 `aabff1ba669e9e19b23cf27803402b87b465303bc2443ebd0aaa6b59c0988269`; and
log SHA-256
`9a7f3518c05982a606aeabae23991396490d08291965dad894031736a0e8ba99`.

The failure was the full-Remove controller fixture: the configured endpoint
was loopback, and actual `run_supervisor` correctly rejected it before READY.
The error was the outer producer final-STOP fixture's `listener_slots=0`, below
the configured minimum of one; its reserved count of zero was valid. Parent
corrected these two cases in tests only; production code was unchanged. The
`validate_cli` case mocks I/O preflight and does not prove the complete CLI path.
These controlled fixtures are not numerical or physical evidence. There was no
matching source overlay or physical run. Trial 71 was only being prepared; no
result is claimed. The owner-integrated qualifying gate, physical restart and
drain/removal, and C1a/C1b/C1/P2 acceptance remain open.

## Trials 71 and 72: controlled owner-flow rerun

Trial 71 ran 357 required tests with zero skips and one error in 35.897 seconds,
exit 1, from `2026-10-18T20:45:36.219Z` to `2026-10-18T20:46:14.412Z`. Its full
Remove controller path reached a successful controlled result; the final test
then raised `TypeError` by calling `set(material_files)` when those records are
dicts. The negative variants were not reached. The six producer and outer
cleanup cases passed. The 300-file source digest is
`8548bf4bd18f3414fb3eab9e1514819c6056785fbfaa7ed3d3840dc7557eb05f`; image
`sha256:3d4e1baa018dd38d1b10e2503cda533f6b3e2ffd18fab1ac73c434f5c83a1421`; proof
SHA-256 `d4a59401452fec77ea5b60da00d3bb564f2a883f4d71e615b60ef666c4190efa`; log
SHA-256 `5b4f2158cefdb5ad080c207932857a406dde988e011c63140e07a39a60d5f2dd`.

Trial 72 passed all 357 required tests with zero skips in 34.309 seconds,
exit 0, from `2026-10-18T20:48:54.061Z` to `2026-10-18T20:49:30.510Z`. All 311
retained IDs and 46 new controlled-flow IDs were present. The gate exercised
controlled drain and Remove transcripts and the producer's direct probe and
cleanup paths. The 300-file source digest is
`982fa70c36c32c1ad8aa26314d1cb45664093b045e9f1ed3711bfd67d5ff45cc`; image
`sha256:436124f973cddd51a3948ab423192941a60f01f43de378e77dad32af8b516fd9`; proof
SHA-256 `d44cee6f92e5d62bb44860975a9c041b94611523689bf3132784181c50b8ec00`; gate
SHA-256 `aabff1ba669e9e19b23cf27803402b87b465303bc2443ebd0aaa6b59c0988269`; log
SHA-256 `78d6c6802718639489f351cdb494d38bb77714313c1f193fdcdb9ccff0e9817b`.

These controlled fixtures use mocked I/O and a synthetic 4-request/27-vector
baseline; they do not establish new numerical or physical behavior. The matching
Trial 72 ZimaBlade overlay completed successfully from
`2026-10-18T20:50:04.607Z` to `2026-10-18T20:50:15.887Z`, exit 0. It verified
all 300 files of source digest
`982fa70c36c32c1ad8aa26314d1cb45664093b045e9f1ed3711bfd67d5ff45cc`, preserved
the 14-layer base, kept runtime and dependencies unchanged, and reported no
cleanup errors. Remote image:
`sha256:3d511160da90152ed793664252315156c86b9c5214f9152ceb78e86b6af39fca`;
overlay-record SHA-256:
`be5e799d08322637735c2ce2df85b6a8328e4f1080e24fa311810025b8cd0cdb`; log
SHA-256: `0a2d0276da36e4c91c29c11af3ed965b1bca66e3364d0b833f5df8c7ad8a9c81`.
The guarded drain and Remove specifications had been prepared but neither had
been run at that update; physical RST7 was still running then. The later RST7
result is recorded below. No full consolidated owner-integrated gate or
physical drain or Remove result is established; C1a, C1b, C1 and P2 remain
unaccepted.

## Physical restart run 7 and drain run 1

Physical RST7 passed from `2026-10-18T20:51:36.641Z` to
`2026-10-18T20:53:10.472Z`, exit 0, on the Trial 72 source and image pair. The
old and new generations each completed four requests and 27 vectors; maximum
absolute error for each was `3.445148468017578e-05`. Both stale-binding controls
were rejected with native `UNAUTHENTICATED`. Same-leaf continuity, boot and
snapshot changes, and binding/transport identity checks passed. The old remote
retired in 1.922 seconds under the same-host monotonic clock. The local operator
and both remote processes exited 0; scoped cleanup was confirmed and no
transport operation remained pending. Result SHA-256:
`f51d0b166d37f04be473bee4d6186965163b806bb597d3aedf7a6af8c931e6ee`; log
SHA-256: `68bcc73cc109f37ebbfb94c4c4a517b850b15ae412393c4eb7e12254533752a7`.
This is a bounded physical restart result; it does not accept a C1 phase or
explain earlier failures.

Drain run 1 failed before remote READY or any remote worker/job launch, from
`2026-10-18T20:54:32.447Z` to `2026-10-18T20:54:45.511Z`, exit 1. The local
status recorded `failure_stage=supervisor` and `ModuleNotFoundError`, without
the original module name. A same-source preflight reproduced a missing
`steamboat_security` import when the frozen `-c` launcher supplied only the
operator runtime path; adding the source `src` directory allowed Clock and
SnapshotStore imports without importing Torch, gRPC or generated protocol
modules. This is a retained harness setup failure, not evidence about drain
lifecycle behavior. The local operator exited 143, but its container removal
was confirmed; no remote process/job was attempted and no transport work was
pending. Result SHA-256:
`0ab6043324cdfefa55c426b35381342cb0a121bb95150d7dc5033148eb0bff00`; log
SHA-256: `806b1fec16f2602eb297b71ab9ff99a102620aa98ac70453ecccdb74dc8a367c`.

Drain 2 and Remove 2 were not yet prepared or run at this update. Owner drain
and signed removal, the final integrated full gate, and C1a/C1b/C1/P2 acceptance
remain open; no hardware limitation is established.

## Physical Drain 2: canonical command publication failure

The corrected private host launcher supplied the frozen source `src` directory
before importing the supervisor; import-only preflight loaded the actual Clock
and SnapshotStore without Torch, gRPC or generated protocol modules. Drain 2 then
ran on the unchanged Trial 72 source/image pair from
`2026-10-18T21:02:45.610Z` to `2026-10-18T21:03:45.863Z`, exit 1. It reached
remote READY and published command 1, then failed at
`owner_action_response:invalid`. Result SHA-256:
`33769c0492e42afa57d6609b00fd7fa4647cffb2201248438a30cad93e70b039`;
log SHA-256:
`c2b7c0e417b1490e2f20d4e59f09950bf09c129a412e090ff1cb74d866296fcb`.

A subsequent bounded, protected, read-only command/ACK check confirmed stable
metadata and an accepted `draining` ACK. The actual published command was 281
bytes, SHA-256
`36c65788f88e362409f5676e36c07750efc7cfbbb439e5ca61814ca73e094a6a`;
the parsed canonical command was 280 bytes, SHA-256
`b8eba526f14a5aafe48a02dbbee50d955e45b1a347e5bafa5c2593aab78156a1`.
The ACK matched the canonical hash, and the file hash exactly matched canonical
bytes plus a newline. The supervisor's general control writer appends that
newline, whereas command publication and replacement require the exact canonical
bytes. Synthetic publication receipts in the controlled flow fixtures masked
this discrepancy. This observation identifies the publication defect without
weakening the strict response validator or diagnosing unrelated earlier runs.

The remote process exited 0, but complete shutdown/cleanup authorization was
unconfirmed, so its container and private job files were retained. The local
operator exited 143 and its container was removed. No pending transport
operations remained. Physical Drain and Remove, final-source CPU controls, and
the consolidated security regression remain open; no phase is accepted.

## Trial 73 and retained physical Drain 3

Trial 73 passed all 358 required Linux tests with zero skips in 35.861 seconds
of unittest runtime, exit 0, from `2026-10-18T21:08:24.908Z` to
`2026-10-18T21:09:03.085Z`. The supervisor now publishes canonical command bytes
without a newline. A new regression derives command-1/2 receipts from the
actual publisher arguments and checks the second prior-file hash; the shared
response validator remains strict. Both Remove command records also pass its
canonical-byte checks. This remains component evidence with controlled I/O.

The source inventory contains 300 files, digest
`d85c2b6ef66231c2b733f47cab58e9763afb49ee6f6e5effaa5db857507fd07a`;
local image `sha256:2d6d6dcd3cdf4d5ca2276d0e7bc6dbcc852daede9621811ddb67e1cd5a84e253`;
source-proof log SHA-256
`723070382788a8cc71d1a17e03ff6dba39265abf1fde6532dd8329300395e211`;
frozen gate SHA-256
`5da0e8bf37e7d97e2ad22f0e432e9397f320a6366dc4dc0f7e09cd5f9ad144a7`;
test-log SHA-256
`fbe6ac07a9e48b1d6b4b917637fa6a7e72be9149b25662aa89f09f02fa0729e3`.
The matching overlay passed from `2026-10-18T21:09:09.378Z` to
`2026-10-18T21:09:19.084Z`, verified all 300 files with no mismatches, preserved
14 base layers and unchanged runtime/dependencies, and reported no cleanup
errors. Remote image:
`sha256:2c4c30198438fad0891ef784c317ebf3f7730376cf7ff5e04fdca21000e421c1`;
overlay-record SHA-256:
`6662c4c6464790a4b92dc7614ca93e2cf14d942a6e5de20ae5fd48d063e545dd`;
overlay-log SHA-256:
`df74600579c771cf8edea42187c8f98a156c04a6966bf6e280714924fac3aa20`.

Physical Drain 3 ran from `2026-10-18T21:09:27.719Z` to
`2026-10-18T21:10:26.411Z`, exit 1. It reached READY and completed command 1
with a canonical 280-byte receipt and accepted ACK. The producer then failed
at the fresh OpenSession native-UNAUTHENTICATED assertion; the version-2 record
retained its location at `secure_cohort.py:6770`, but no original error code.
The remote process exited 0, with graceful compute shutdown and shutdown
confirmed, but owner cleanup authorization was incomplete: its container and
private job files were retained. The local operator exited 143 and its container
was removed; no transport work remained pending. Result SHA-256:
`680ecb86bcbf539e88aaecbe4d6250521046272efc0b49829bc5344f6ff71ecf`;
log SHA-256:
`02bc354a93eb1b9c23647822b085147ec3f8752ca0f4f5ba57eaaaa5fa504fe5`.

A separate local diagnostic ran one new real-native TLS test against the
unchanged Trial 73 image with only its frozen test module mounted read-only
(test SHA-256 `0a5ca05c33ced17d46b137d3f8757625370a73f14d8ac7696260598dfe684138`).
It failed the native status assertion in 0.106 seconds, with actual
PERMISSION_DENIED versus required UNAUTHENTICATED; log SHA-256
`a86ce57a4bc44fc7162abfbef5910bd2ffdfb678a0e2f66996fb449523058e82`.
This reproduces the source-level drain-admission mapping mismatch, without
recovering Drain 3's unrecorded status. A dedicated drain-Open denial type and
narrow status mapping are prepared for new validation; the producer's strict
predicate remains unchanged. Remove has not run. The 872-ID full regression
request and Trial 73 CPU-control command were prepared but not run at this
point. Physical Drain/Remove, final-source controls, full discovery and C1/P2
acceptance remain open.

## Final-source Trial 75 controls and Trial 76 regression

The [final C1 validation record](2026-10-18-participant-c1.md) records the
current status separately from the historical attempts above. Trial 75 passed
359 required focused Linux cases with zero skips, including the first-RPC
native drain refusal and retained-capacity/EOF cleanup regression. The frozen
300-file source digest is
`abfe2848c3b6b343dd4a2572cec1d45bf67d1f23f2a6df3b6c583445a5f055f5`;
the focused log SHA-256 is
`898c9e813fce339b9f5bd411e24d7cd94cc35c716d8a9134227f3e93cfcd90f6`.
The matching physical overlay verified all 300 files and preserved its runtime,
dependencies and 14 base layers. Physical Drain 4 and Remove 4 subsequently
passed their independently reviewed bounded checks.

The same-source M1/M2 every-prefill controls ran two tests with zero skips,
exit 0, in 6.600 seconds. Each report has 27 comparisons with maximum error 0
and fully reclaimed session/cache owners; M2 records 81 Step messages. Their
combined log SHA-256 is
`22386f0a82fe224cd63fbf7c25f2645b5e862f6c5dee49b9c923546ac97d01e6`.

Full Trial 76 failed: 873 required cases, zero skips, one failure in 357.484
seconds with both opt-ins enabled. The partial-Open reply-loss extension did
not confirm injection after its baseline completed. The original consumer or
observer failure was masked and not retained; no clock, transport or runtime
cause is established. Failed log SHA-256:
`de27b849ca0f5c947f349d5a90c08cd895f510c5b8ec8696d87a8e5341c7a7e0`.
One isolated diagnostic then passed the unchanged test on the same image with
bounded observational wrappers. It neither explains that failure nor replaces
full qualification; diagnostic log SHA-256:
`35b347dd5e5e3221df7385fc31c0b3de0c69d13e3cb8b1ba31b2b06672cb40dd`.
Native-Zima qualification of the same 873 IDs is being prepared, not yet run.
C1 remains open pending a clean full regression and acceptance review.

## Native ZimaBlade full run 3

The same-source native Linux Docker qualification ran all 873 required cases
with zero skips, exit 1, in 791.774 seconds. The other 870 cases passed,
including partial-Open reply loss. Three isolated root-process cases errored:
root-worker READY, root-coordinator READY, and old-root startup during cold
cutover. Each reached its existing READY timeout and then failed to confirm
process-group cleanup. Child stderr was discarded, so no clock, CPU, permission
or hardware cause is established. A focused observational diagnostic is being
prepared without changing the original criteria.

The run used the frozen 300-file source, 2 CPUs/3 GiB/256 PIDs and a
preregistered 900-second whole-suite watchdog; all internal deadlines and
criteria stayed unchanged. It did not hit the outer watchdog. Actual cgroups,
source and unchanged public fixtures were verified, and the outer owned
container was confirmed absent after exit. That disposal does not erase the
three failed in-test cleanup assertions. The
[full record](2026-10-18-participant-c1.md#native-host-qualification-attempt)
retains the exact images, administrative preflight aborts and limits.

Result SHA-256:
`3355469d82b8d45accdb64e75be4ea0eaa2e6c1aedb2d55484b4ffbe8d7db124`;
log SHA-256:
`cc862fe34decc08dee76adee7032213cb255b29b68fe5115977ee28989572297`.
Neither this failed run nor combined successes across different failed suites
complete the clean full-regression requirement. C1 remains unaccepted.
