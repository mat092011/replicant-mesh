# C1 fixed invited cohort: final validation record

**Status: C1 validation and exit criteria accepted by the parent on 2026-10-19.**
Trial 78 passed the required full software regression: 878 unique required cases,
878 run, zero skips, failures or errors in 367.862 seconds. Bounded physical
and numerical evidence is recorded below with its own frozen source and image
identities. Trial 76, Native ZimaBlade run 3, Trial 77 and full-history DIAG3
failures remain preserved with unknown causes; no hardware cause is established.
C2-C9 and broader research gates retain their existing statuses. The maintainer
requested stopping after C1.

## Scope and environment

This is a bounded CPU correctness and lifecycle experiment for an invited,
trusted cohort. The laptop runs the consumer, coordinator, embeddings/head,
complete-model reference and layer ranges `[0,3)` and `[3,6)`. A physically
separate ZimaBlade runs `[6,8)` over the actual authenticated LAN route. SSH is
strict host-pinned administration, not the inference transport. Prompts are
synthetic. Worker owners and the coordinator remain trusted; transport encryption
does not hide computation from worker owners.

The public model/tokenizer is `Maykeye/TinyLLama-v0`, revision
`298338802ab94432b917bcce11382aa151aee50f`, manifest
`33aec5e084dc12cef677821fcc8ca55a00f74298531f1a97d499658e6930254d`.
The checked CPU stack uses Torch `2.14.1+cpu`, Transformers `5.19.0`, gRPC
`1.84.0`, Protobuf `7.36.2` and Safetensors `0.8.0`, float32, eager attention,
and no activation compression. The same-stack complete model is the reference.

The laptop has 32 GB physical RAM and a 16.3 GB Docker VM. ZimaBlade has an Intel
Celeron N3450, four logical CPUs, 8,169,467,904 RAM bytes, Debian 11/kernel 5.10,
and Docker 24.0.5. Laptop containers are bounded to 2 CPUs/6 GiB/256 PIDs;
the remote worker uses 2 CPUs/3 GiB/128 PIDs. Configurations retain read-only
filesystems, dropped capabilities, protected credentials and bounded transport,
request, queue, context and execution resources. See the
[physical-host inventory](2026-10-18-participant-two-device-preparation.md) and
[reproduction guide](../PARTICIPANT_TWO_DEVICE_LAB.md) for exact setup and limits.

## Physical-run frozen evidence

The measured Windows working-tree build snapshot contains 300 files with SHA-256
`abfe2848c3b6b343dd4a2572cec1d45bf67d1f23f2a6df3b6c583445a5f055f5`.
Both local and remote all-file proofs found zero mismatches. The source overlay
preserved all 14 remote base layers, runtime configuration and dependencies.

| Purpose | Image SHA-256 |
| --- | --- |
| Trial 75, physical-run local operator and CPU controls | `dbca1f1250cdfc79bfaf8d980da8e81f099e2df3b7930dd22310e94e42d2edce` |
| Physical worker, matching Trial 75 source | `46ff779d1c17c40e76c4540383067d1063409aaa2b2d94d08102cc2e4744d94b` |
| Rebuilt Trial 76 full security gate | `275d282022d47dff42f62524fc2761a177a66b461333413e4088eec33b847e93` |

The two local images have identical complete filesystem-layer lists and checked
runtime configuration; both independently verified the same 300 source files.
This report and subsequent acceptance/status reconciliation are documentation
changes after that executable snapshot, not additional model execution.
Git's LF/CRLF normalization changes raw source digests on checkout; this build
digest is not the identity of the subsequently committed Git tree. Dependency
lock bytes remain fixed to LF by the existing `.gitattributes` rule. The final
release check records the published checkout separately.

| Check | Actual result |
| --- | --- |
| Required focused Linux gate, Trial 75 | 359 required cases, zero skips, exit 0; includes the actual first-RPC drain denial and EOF/resource cleanup regression. |
| Final security discovery, Trial 76 | Failed: 873 required cases, zero skips, one failure in 357.484 seconds; both opt-ins enabled. Partial Open reply-loss did not reach its validated injection. |
| Native ZimaBlade full qualification, run 3 | Failed: 873 required cases, zero skips, three errors in 791.774 seconds. The isolated root-worker, root-coordinator and cold-root-cutover process tests reached READY and cleanup timeouts. The other 870 cases, including partial-Open reply loss, passed. |
| Matched M1/M2 controls on Trial 75 | Two tests, zero skips, exit 0; each report contains 27 every-prefill/forced-decode comparisons with maximum error 0. All session/cache owners reclaimed; M2 records 81 Step messages. |
| Physical Drain 4 | Passed, independently audited; baseline 4 requests/27 vectors, maximum error `3.445148468017578e-05`. Original 30-second deadline retained, continued Step/Renew and native fresh-Open refusal confirmed; both processes exited 0 with cleanup and no pending transport work. Local disposal 4.344 seconds. |
| Physical Remove 4 | Passed, independently audited; baseline 4 requests/27 vectors, maximum error `3.445148468017578e-05`. Both policies/native refusals, zero resources before Remove, owned exit 0, cleanup and retained public intent/verifier evidence confirmed. Local disposal 2.656 seconds. |

The numerical tolerance is `atol=1e-3, rtol=0`. Physical baselines compare finite
last-position vocabulary vectors for patterned prompt lengths 1/128/1024 with
eight identical forced feedback inputs each, plus a separate greedy request.
The M1/M2 controls separately compare every prefill position. Their reported
test durations and command spans are not inference performance measurements.

## C1 acceptance map

| Criterion | Evidence and qualification |
| --- | --- |
| C1.1 / CT-02-03: explicit peer-authenticated transport | Native mTLS worker/coordinator services and clients, exact identity/binding checks, wrong-root/role/identity and actual first-RPC refusals. Trial 78 passed the required full regression. |
| C1.2 / CT-04-06: invited identities, protected identity material with expiry/revocation checks and session ownership | Offline invited issuance, scoped grants and session binding; strict clock/snapshot behavior; actual local five-role cold root cutover in Trial 51. Trial 78 passed the required full regression. |
| C1.3 / CT-02-06: bounded admission and failure handling | Connection/handshake ownership, installed C-core bounds, serialization extremes, unknown Open/Step outcome fences, cancellation/disconnect and cleanup cases. No ambiguous Step retry. Trial 78 passed the required full regression. |
| C1.4 / CT-13: actual devices and route | Frozen laptop/ZimaBlade inventory, fixed layer placement, pinned artifacts/runtime and actual mTLS LAN inference. |
| C1.5 / CT-11/13: numerical and lifecycle checks | Physical baseline/happy/context, ordered interleave, cancellation, partial admission, capacity, Step reply loss, RST7, Drain4 and Remove4 passed their bounded checks. Trial 78 passed the required full security regression. |

The [C1a follow-up](2026-10-18-participant-c1a-followup.md) retains all failed and
component runs. The [two-device report](2026-10-18-participant-two-device-parity.md)
records actual cross-host results and their distinct source/image identities.
The earlier successful physical checks are not presented as runs of the final
image: the final deltas address owner-command publication and the drain-only
admission status, with matching focused and physical owner reruns.

## Retained failures and limits

Drain 1 failed host launch imports. Drain 2 exposed a published-command newline
versus canonical digest mismatch; the fixed regression hashes actual publisher
arguments. Drain 3 failed a native-status assertion with its original status
unrecorded. A separate real TLS regression on unchanged old source reproduced
PERMISSION_DENIED instead of the frozen UNAUTHENTICATED contract; the correction
changes only new Open admission during drain. The strict refusal predicate,
original drain deadline, cleanup and authority-retention criteria were preserved.

Earlier failed full suites and RST1-RST6 remain failed and retained. Full Trial 69
reported `CLOCK_UNSAFE` during baseline generation before its cancellation hook;
its environmental cause remains unestablished. A current pass would not diagnose
that event or promise permanent clock stability. No clock clamp, global clock,
firewall, tunnel or security-policy change was used to obtain these results.

Full Trial 76 also failed: the inherited numerical baseline completed, but the
partial-Open reply-loss extension never confirmed injection after a successful
real TLS response. Its assertion masked the original Generate/observer failure,
so no clock, transport or runtime cause is established. The exact failed log
SHA-256 is `de27b849ca0f5c947f349d5a90c08cd895f510c5b8ec8696d87a8e5341c7a7e0`.
At that Trial 76 checkpoint, no clean qualifying full regression had passed; C1 remained open despite the
successful physical owner-control gates.

One isolated observational diagnostic subsequently ran the same partial-Open
test against the unchanged Trial 76 image and criteria. It passed one test with
zero skips; sanitized observations confirmed the intended accepted Open and
injected reply loss. This did not reproduce or explain the full-suite failure,
and does not count as a clean full regression. Its log SHA-256 is
`35b347dd5e5e3221df7385fc31c0b3de0c69d13e3cb8b1ba31b2b06672cb40dd`.

## Native-host qualification attempt

The native ZimaBlade full run used the same 300-file build snapshot, all 873
unique required IDs, both opt-ins, pinned source/image/artifact proofs and
zero-skip gate. Its preregistered host variables were 2 CPUs, 3 GiB and 256 PIDs,
with a 900-second whole-suite watchdog. Only that outer watchdog changed from
the laptop's 600 seconds; internal READY, request, clock, numerical, cleanup
and owner deadlines stayed unchanged. The main container retained a read-only
root, no network, dropped capabilities and no-new-privileges. Two isolated
read-only image-fixture hash attestations alone added `DAC_READ_SEARCH`; no
host mounts or network were supplied to those helpers. Public fixture bytes,
modes and the foreign-UID fixture were unchanged before and after execution.

The actual run spanned `2026-10-18T22:05:40.745Z` to
`2026-10-18T22:19:05.809Z`, exit 1, without an outer timeout or log truncation.
Its cgroup values were memory `3221225472`, CPU `200000 100000`, and PIDs `256`,
with UID 0. The exact source proof verified all 300 files without mismatches.
Record SHA-256:
`3355469d82b8d45accdb64e75be4ea0eaa2e6c1aedb2d55484b4ffbe8d7db124`;
full log SHA-256:
`cc862fe34decc08dee76adee7032213cb255b29b68fe5115977ee28989572297`.
The outer owned qualification container was confirmed absent. This does not
convert the three in-test cleanup errors into successful lifecycle evidence.

All three errors reached the existing ten-second per-child READY bound, then
failed to confirm process-group cleanup within its existing bounds. The
supervisor discarded child stderr, so these traces do not establish a CPU,
instruction-set, clock, permission or other hardware cause. One isolated
observational root-worker diagnostic is being prepared with unchanged test
criteria; it cannot replace a clean full regression.

Two preceding native launch attempts stopped during administrative preflight,
before model tests. Run 1 used a filesystem API unavailable in host Python
3.9.2; run 2 used UID 0 for source-proof inputs protected for UID 1000. Their
records remain retained. A separate exact source-proof diagnostic observed
permission denial opening the verifier as UID 0; the corrected helper reused
the UID 1000 profile from the earlier successful source proof. No existing
source-proof input or model fixture was chmodded or chowned.

Only this invited CPU/LAN configuration is covered. GPU support, WAN performance,
pooled-memory benefit, speedup, public enrollment, outbound-only connector
installation, credits and a community pilot are not established. The laptop's
AMD 890M exists but its supported backend remains unvalidated. Historical failed
runs may retain protected private artifacts when cleanup authorization could not
be proved; successful-run cleanup must not be generalized to those failures.

## Isolated root-worker observations (2026-10-19 local date; 2026-10-18 UTC)

Two one-case observational diagnostics ran with the same immutable 300-file
source snapshot (`abfe2848c3b6b343dd4a2572cec1d45bf67d1f23f2a6df3b6c583445a5f055f5`),
remote image (`46ff779d1c17c40e76c4540383067d1063409aaa2b2d94d08102cc2e4744d94b`),
UID 0, 2 CPUs, 3 GiB memory and 256 PIDs, with network disabled and all
capabilities dropped. Both retained the original readiness and cleanup criteria.
Each ended with one error, zero skips and `diagnostic_valid=true`:

| Run | UTC interval | Result | Child observation | Record SHA-256 | Log SHA-256 |
| --- | --- | --- | --- | --- | --- |
| Root-worker diagnostic 1 | `22:35:17.135–22:35:43.104Z` | Error after 15.739 s; READY `10.001 s`, cleanup `5.011 s` | Child remained running (`R`) without stderr; cgroup memory rose from 234 to 308 MB and PIDs were 7. Outer container absent; fixtures unchanged. | `72573e9416bc522bafab44e47fbdc08479d59823c3ef65cc962899e6fcf2ed26` | `d126fca2f20e9a1a8e62c982dcf9e9227c824c4bab0aa7120d26949c27632a58` |
| Root-worker diagnostic 2 | `22:41:13.294–22:41:37.968Z` | Error after 15.740 s; READY `10.001 s`, cleanup `5.004 s` | Child remained running (`R`). | `f19d5b78173ce38b1fe97601bcec7988d83978c04255772ac552d4bc7e7bf20b` | `1e7803a658f74c8f0a5cba0a77699f0c8829ed497b091ee4fbb4c9e3dee67b16` |

Diagnostic 2 changed only the bootstrap (`311f8cf9` versus original
`86dce376`). At about 9.5 seconds, one-shot `faulthandler` reported an extra
observer thread and a stack through Transformers `fetch__all__` (line 2985),
`create_import_structure` (`__init__.py`, line 814), `StageExecutor` (line 37),
and `sync_build_runtime` (line 414) / `serve` (line 1161). No locals or secret
values were captured. This identifies a sampled path, not the cause of the
original full-run errors, all three failures, or a hardware requirement. Neither
diagnostic qualifies C1; a clean full 873-case regression and the main review
remain pending. The source-only diagnostic provenance fix is being prepared; no
full rerun is queued and no runtime change is established.

## Trial 77 consolidated full regression (2026-10-19 local date)

The current-source Trial 77 ran all 873 required IDs (873 run), with zero skips,
one error and exit 1 in 372.851 seconds. The command ran from
2026-10-18 22:52:06.209Z to 22:58:21.727Z UTC. The preregistered run used the same 873
IDs as Trial 76, a 600-second global limit, both required flags, UID 0, 6 GiB,
2 CPUs and 256 PIDs, with all capabilities dropped, no-new-privileges, a
read-only root and no network. Source SHA-256 is
`dcf7974c8c5189330c84408e5fa3e49dc1d9328e47e0ed0e24d29b00853c3b9b`; image
SHA-256 is `27b703e574759540885c3fb4711cac2b5bb29cb28fe3d019df088a0a27448bb4`.
The 301-file source proof had zero mismatches (source-proof log SHA-256
`c08cd20ceace9153cce844bd59194bca6482f7f6e342769af0a567260fd7fa9c`); gate
SHA-256 is `c0282cbe31b076cecd8d42fdaf16d0a0d2f1504a7b23fef6af2883f40894f505`.
The run log SHA-256 is
`6c43bba6882c2d001d8a95cbae4a866f342563cadb04b53c612f954c9f8a6da7`.

The sole error was
`tests.security.test_secure_pipeline_completion.SecureForcedInterleavingCompletionTests.test_consumer_generate_crosses_real_secure_three_stage_pipeline`.
The inherited baseline matrix Generate failed before the lifecycle/interleave
hook. The secure RPC surfaced generic `RemoteError(EXECUTION_FAILED)` with its
outcome unknown. Teardown did not confirm coordinator close or worker-2 bridge
shutdown, and `cleanup_pending_captures=1`. The owned Docker container was absent
after exit; fixture cleanup was not confirmed.

Relative to the prior `abfe2848…` snapshot, this run added the failure-provenance
observer (`4edf…`) and documentation changes; the other 243 non-documentation
files were byte-identical. Partial-Open reply-loss and all three root-process
cases passed in this run, but do not erase the Trial 76 laptop failure or Native
ZimaBlade run 3 errors. Neither Trial 77 nor those failures establish a clock,
hardware or other cause. A current parent/main bounded read-only failure audit is
underway; the root and remote C0 checkouts are clean at `f63…`. C1 remains open
and unaccepted, no full repeat is queued, and work stops after C1 as requested.

## Trial 77 focused baseline diagnostic 1 (2026-10-18 UTC)

The one-test baseline diagnostic passed: one test, zero failures/errors, zero
skips, 17.980 seconds, exit 0. It ran from
`2026-10-18T23:10:55.627Z` to `2026-10-18T23:11:15.769Z`. The 180-second outer
watchdog started before application imports and remained armed through process
exit; internal deadlines were unchanged. It used the same immutable Trial 77
image (`27b703e574759540885c3fb4711cac2b5bb29cb28fe3d019df088a0a27448bb4`),
301-file source snapshot (`dcf7974c8c5189330c84408e5fa3e49dc1d9328e47e0ed0e24d29b00853c3b9b`),
base environment and test criteria. Diagnostic hooks delegating each original call once, and `DIAG_RESULT`,
were added for observation. Observer data records an ordinary bridge-fence stop:
`operation_count=0`, `owner_count=0`, `admitting=0`, and
`unconfirmed_cleanup=false`.

The command, run log and observer JSON are at
`.lab/participant-network/results/c1b-full77-baseline-diag1/`. The frozen command
record retains `status=prepared_not_executed`, but also records the actual start,
completion and exit code; the run log and observer JSON show the completed pass.
Run-log SHA-256: `e220b705198fa7c00e5fc8bf7dca8cf0bb44937dd09bc521a0cab133734e38fe`;
observer SHA-256: `1aef3c78ccb2aebbedaf4947618ac90f5b027a29351f81114086e5a4e8e5d631`.
This focused pass does not reproduce or explain the failed 873-case Trial 77 and
does not qualify C1. C1 remains open pending a clean full regression and review.
## Trial 77 focused baseline diagnostic 2 (2026-10-18 UTC)

The diagnostic-only run exercised up to five fresh instances of the same single
baseline case, stopping on the first failure. All five passed with zero skips;
the measured test durations were 18.072, 14.004, 14.289, 14.179 and 13.859
seconds. The run exited 0 over
`2026-10-18T23:20:19.830Z`–`2026-10-18T23:21:36.457Z`. One 180-second outer
watchdog covered the run. The same immutable Trial 77 image
(`27b703e574759540885c3fb4711cac2b5bb29cb28fe3d019df088a0a27448bb4`), source
snapshot (`dcf7974c8c5189330c84408e5fa3e49dc1d9328e47e0ed0e24d29b00853c3b9b`),
base environment and internal criteria were retained. The `Clock.sample` hook delegated each existing call exactly once,
without extra provider reads. Clock errors used bounded deduplication by
iteration and static category. No clock, native-status or authentication event was observed.

The observer recorded 15 events: five iteration starts, five ordinary
bridge-fence stops and five passing results. The owned container was absent after
exit; this does not confirm fixture cleanup. The command and run records are in
`.lab/participant-network/results/c1b-full77-baseline-diag2/`; the outcome record
is `.lab/participant-network/coordination/full77-baseline-diag2-outcome.json`.
The frozen command record still says `status=prepared_not_executed`; its run
timestamps and exit code, the log and observer show the completed execution.
Log SHA-256: `af03b95af681bea03753f073517fe65a32cecd8c84c667dd2d9ecdcd716bb8b3`;
observer SHA-256: `d9b0d131a4eb8455b103307a57e667d1a6309b887bb34e1207d215d441b31ded`.

This focused diagnostic does not recreate the prior 873-case history, explain
Trial 77's full-suite failure, qualify C1, or establish that new hardware is
needed. At the end of this diagnostic, no further full run had been queued. C1 remains open pending a clean full
regression and review.

## Trial 77 full-history diagnostic 3 (2026-10-18 UTC)

The diagnostic-only full-history run selected the same 873 test IDs and original execution order
with zero skips. It exited 1 after 309.379 seconds with one error. The run
started at `2026-10-18T23:34:06.542Z` and completed at
`2026-10-18T23:39:18.822Z`. The error was
`RootCutoverOwnedProcessIntegrationTests.test_approved_cold_cutover_claims_new_five_role_root_and_generates`:
`new_startup.start` timed out in `observe_ready` because the owned process did
not emit READY before its deadline (`root_transition_retirement.py:499`). This
case occurred before the target observer hooks were active.

The original Trial 77 interleaving target then passed its diagnostic with four
ordinary events (inventory, activation, bridge stop, deactivation), no error
event, all seven hook and instance restoration proofs true, and no cleanup
uncertainty reported by the bridge fence. The full-history failure therefore
remains unexplained; this diagnostic does not qualify C1 or establish a hardware
cause. The owned container was absent after exit. No further full run was queued.

The run log and observer record are under
`.lab/participant-network/results/c1b-full77-history-diag3/`; the outcome record
is `.lab/participant-network/coordination/full77-history-diag3-outcome.json`.
Log SHA-256: `6e0a6a0645847c740c78426cdea12e67eac52131d2c3e7ed7ec9fb6c84738843`;
observer SHA-256: `e7111750344af4954b3c59cc1fbe428b6aa01931a8150de0224d98c9788e8fa7`.
C1 remains open and unaccepted pending a clean full regression and review.

## Root cutover READY file diagnostic 1 (2026-10-19 UTC)

The focused original-profile test passed: one test, zero errors, zero failures, zero skips, in 131.660 seconds. It ran from `2026-10-19T00:09:35.280Z` to `2026-10-19T00:11:49.087Z` and exited 0. The fixed Trial 77 image, 301-file source snapshot, original 2 CPU / 6 GiB profile, 10-second per-role READY limit, 60-second shared startup limit, 15-second cleanup limit and 180-second outer watchdog were retained. The observer captured all ten child exits and restored the hooks; the parent verified the owned container absent.

In the observed startup, old-stage host READY times were 5.568–5.719 seconds and the old coordinator was 9.095 seconds; new-stage hosts were 5.319–5.471 seconds and the new coordinator was 8.781 seconds. These observer elapsed times describe this diagnostic only and are not benchmark measurements. The 216 bytes of captured stderr were an expected wrong-root TLS rejection during the negative probe; raw stderr is not included in this report.

The run record, log and observer JSON are under `.lab/participant-network/results/c1b-root-cutover-ready-file-diag1/`; the outcome record is `.lab/participant-network/coordination/root-cutover-ready-file-diag1-outcome.json`. Log SHA-256: `a54d36dfe77bbca414c1db55a51c7595d621643cd69966e289eda1e1b9630549`; observer JSON SHA-256: `4da4b26b72755a59c850bb9c18f2ee60b7ff5d14758914070d2c8cd9ffe2ec9b`.

This focused pass does not qualify C1, establish the cause of prior full-suite failures, or provide evidence of a hardware requirement. C1 remains open pending a clean full regression and review.
## Prospective root READY dispatch control runs (2026-10-19 UTC)

The old four-case synthetic regression was run as a RED control against the unchanged Trial 77 image and explicit test overlay. It ran four tests with zero skips and produced the four expected behavioral failures in 0.775 seconds, exiting 1 from `2026-10-19T00:14:51.545Z` to `2026-10-19T00:14:53.495Z`; there were no setup errors. The failures showed coordinator dispatch before workers were ready and error/cancellation behavior that did not meet the assertions. Log SHA-256: `74780b2cd39498fae8ac53d2ae04d7fb2e1c4d54561f472817085d1de4bb9ff2`.

The updated five-case synthetic regression then passed against the same Trial 77 image with explicit read-only test and startup source overlays. It ran five tests with zero skips in 0.966 seconds, exiting 0 from `2026-10-19T00:16:50.995Z` to `2026-10-19T00:16:53.170Z`. The overlays used test SHA-256 `282737727ffe8297587c0b7d1e021c0a7c513f2dc28c3ae8440eb7297608a0d6` and startup SHA-256 `f447cab719c5ab17962973a971fb026cf614ea197e436ab0b6c1dfdf484d6ed7`; log SHA-256: `3c0ce17be77195c96651055162b27f0d9327d09b8e79ed8cf8848a94448d60ff`.

The coordinator bootstrap waits for host listeners before its model initialization, while the previous runtime started all role READY observations concurrently. The prospective change waits for host READY before observing the coordinator, keeps the consumer independent, and promptly checks every already-dispatched role failure. All five processes remain strongly owned before observation; the original shared 60-second deadline, at-most-ten-second observation bounds, cleanup limits and result-to-process mapping remain enforced. The earlier focused original-profile observation measured coordinator READY at 9.095 seconds for the old root and 8.781 seconds for the new root. Those observations motivate review of the ordering change but do not establish the cause of any historical full-suite failure. Both controls used overlays on the existing image; they are not a rebuilt-image qualification. The rebuilt 878-required candidate regression subsequently passed as Trial 78; see the completed-run record below. At this diagnostic checkpoint, C1 remained open and unaccepted; no hardware cause was established.

The command and log records are under `.lab/participant-network/results/c1b-root-startup-ready-order-red1/` and `.lab/participant-network/results/c1b-root-startup-ready-order-green1/`; the input control files are under `.lab/participant-network/coordination/root-startup-ready-order-red1/` and `root-startup-ready-order-green1/`.

## Trial 78 rebuilt full security regression (2026-10-19 UTC)

The rebuilt candidate passed the required full security regression: 878 unique required tests, 878 run, zero skips, zero failures and zero errors in 367.862 seconds; exit code 0. The run started at `2026-10-19T00:18:33.957Z` and completed at `2026-10-19T00:24:44.383Z`. The immutable image was `593d1e79b98f85947e5ad759c1aa108a0288cdd045afaa1c97d40f86dee31305`; the frozen source digest was `ef3b8222941bd6a233a47fae2e0c70dfa0f37cc7a6bdf98dfcbec8e439426d52` across 302 baked files. The source proof covered all 302 files with zero mismatches. The gate hash is `454c703ba11f694641f91c3db56f06eb39307c7eacb3430deac3927d74caf5d5`. Parent verification confirmed the exact 878-ID set, original 600-second watchdog and preservation of all 873 earlier required IDs, resource caps and opt-ins, and that all 245 non-documentation candidate files matched the frozen snapshot. No source or test overlay was used; the owned container was absent after the run.

The existing bounded worker-before-coordinator READY change ran with the original shared deadline, per-observation limits and cleanup bounds. This full pass supports that candidate's required software regression; it does not establish the cause of earlier failures. Trial 76, Native ZimaBlade run 3, Trial 77 and full-history DIAG3 failures remain recorded with unknown causes; no hardware cause is established. The latest full-run image was validated on the laptop; the split-host evidence retains its earlier frozen image and source identities. Physical RST7, Drain4 and Remove4, Trial 75 M1/M2 controls and the focused 359-case gate remain the separately bounded evidence described above.

The run log and receipt are under `.lab/participant-network/results/c1b-full78/`; the outcome record is `.lab/participant-network/coordination/full78-outcome.json`. Source-proof log SHA-256: `fa4ca82385be85fbc8b12b0a0ab5ae1f1a852107ca0cf2d4aef62e67e643cfff`; run-log SHA-256: `fa31823531c7da3d0b659e23ab3afe86cabec9e0e3ed0e4e177908ef9e2d9c73`; receipt SHA-256: `421b68962dc8024c026643222ee26c57283f3efe0369d7d926161616d74d2b82`.

At completion of this run, independent terminal review and parent phase acceptance were pending. The parent later accepted C1 validation and exit criteria on 2026-10-19 after independent review.

## Parent acceptance (2026-10-19)

The parent independently reviewed Trial 78 and accepted the C1 validation and exit criteria. The required software regression passed all 878 unique cases with zero skips, failures or errors in 367.862 seconds, using the original 600-second watchdog and unchanged 873 earlier required IDs. Parent review confirmed the exact required set, resource caps and opt-ins, all 245 non-documentation candidate files matching the frozen snapshot, and no source or test overlay. The full run was on the laptop; physical RST7, Drain4 and Remove4 and the focused 359/M1/M2 evidence retain their separately recorded frozen source and image identities. The prior Trial 76, Native ZimaBlade run 3, Trial 77 and full-history DIAG3 failures remain preserved with unknown causes. Trial 78 does not explain those failures, and no hardware cause is established. The AMD 890M backend remains unvalidated. C2–C9 and research P0–P8 statuses are unchanged; work stops after C1 as requested.
