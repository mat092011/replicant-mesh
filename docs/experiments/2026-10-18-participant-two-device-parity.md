# First split-host baseline parity, 2026-10-18

Later focused C1a evidence and retained trial 13–17 history are in the
[C1a follow-up report](2026-10-18-participant-c1a-followup.md).

**Result:** the first actual split-host `baseline-v1` cohort passed four
requests, 27 captured logit vectors, and observed local/remote cleanup. A fresh
expanded `c1b-happy-v1` cohort later passed seven requests and 36 vectors. These
are bounded CPU correctness results only. C1 remains unaccepted: C1a acceptance
and the broader C1b lifecycle profile remain open, as does the P2 gate. An
earlier expanded-profile attempt failed before producing a cohort summary and
remains retained and unexplained.

## Frozen execution

The candidate source SHA-256 was
`7cb443eed708a88609ba84d2f14746824c796fc1e331858ecfe07c7b1a154e82`; all 237
baked source files were verified. The laptop image digest was
`89fdd183f21ff2111e552815e1724b0d4a55d715cb3ebb33a020693d7effd90c`; the
separate physical-host image digest was
`744e039505deef2647c83bc9e92c786b87825b9a440edfba2cfce8dc59b068de`.

The laptop (`LAN-A`) hosted the consumer, coordinator, embeddings/head, complete
model reference, and workers 1/2 with ranges `[0,3)` and `[3,6)`. The second
physical CPU host (`LAN-B`) ran worker 3 with range `[6,8)`: Intel Celeron N3450,
four logical CPUs, 8,169,467,904 RAM bytes, Debian 11, kernel
`5.10.0-25-amd64`, and Docker 24.0.5. The laptop used Docker 29.8.2 under WSL
kernel `6.6.87.2`, with 32 GB physical RAM and a 16.3 GB VM. Only CPU execution
was verified; the laptop's AMD 890M integrated GPU was physically present but
unused, and its supported GPU backend remains unvalidated.

Container caps were 2 CPUs, 6 GiB, and 256 PIDs on `LAN-A`, and 2 CPUs, 3 GiB,
and 128 PIDs on `LAN-B`. The cohort had a 300-second total bound, 60-second
startup bound, and 15-second teardown bound. The route used C0 mTLS for the
trusted, fixed invited cohort. SSH was strict trusted-host administration only;
it was not the inference route. Prompts were synthetic. Worker owners remain
trusted with visibility into their computation under the C0 threat model.

The run used `Maykeye/TinyLLama-v0` revision
`298338802ab94432b917bcce11382aa151aee50f`, manifest fingerprint
`33aec5e084dc12cef677821fcc8ca55a00f74298531f1a97d499658e6930254d`, Torch
`2.14.1+cpu`, Transformers `5.19.0`, float32, eager attention, and no
compression. The complete-model reference used the same pinned stack.

## Numerical and cleanup result

Four requests completed. The greedy control used tokens `[7, 13, 31]` and one
output token. Patterned prompts of lengths 1, 128, and 1024 used token formula
`3 + ((i * 37 + 11) % (32000 - 3))`; each received eight identical forced
feedback inputs. Nine last-position vectors were captured per prompt, 27 total.
Logits were finite, greedy and forced-feedback outputs matched, and maximum
absolute error was `3.445148468017578e-05` (`atol=1e-3`, `rtol=0`).

Both actual processes exited 0 gracefully. Local and remote containers were
removed; private role files and the scoped remote root were removed with strict
confirmation. No pending transport operations or recorded failures remained.
The 47.357-second wall time includes SSH administration, bundle transfer,
startup, computation, and cleanup. It is not an inference-latency, TTFT, ITL,
throughput, or speedup measurement.

The sanitized run report SHA-256 is
`549bb8a9f92756eb51f07a03faeca2ff3b13ff8813bb8d10385d87113d6c0e15`; the
command log SHA-256 is
`fc8c364c52d6383530151838c95f33da7d165fa62a9639d02f1157d838c1b1b6`. On the
same image, fresh M1/M2 controls passed 2 tests with zero skips in 9.936 seconds
(log SHA-256
`f432186c665f5c5e6d767221bd4e84549bdefbc6c05fbef2acd6a50228ce2811`). A
separate 9-focused suite passed 171 tests with zero skips (log SHA-256
`0d52ba714767cd197d367657c32c141063660ad88b81f13f0c80787cf9574562`). These
are scoped checks, not an aggregate C1 acceptance result. Earlier full 391-test
local and `LAN-B` runs remain separate same-host controls.

## Retained failures and limits

Five earlier actual baseline attempts remain retained: (1) `inspect_schema`
framing failed before SSH; (2) pinned Paramiko 3.5.1 exclusive SFTP mode failed
before worker start; (3) Docker image-inspection JSON exceeded its bound before
worker launch; (4) an invalid Docker 24 read/write bind field failed before
worker launch, after which the parent verified no worker containers and removed
only the strict scoped root; and (5) a deferred coordinator-server import reached
remote READY and clean exit 0 but produced zero vectors. Their chronology and
available log identities are summarized here.

After the baseline pass, the first expanded `c1b-happy-v1` attempt failed after 37.934
seconds with a null cohort summary. The remote worker reached READY, exited 0,
and had confirmed cleanup; the local operator ended with exit 143, not graceful
success. Its failure log SHA-256 is
`60d81811db007b02c0fe7ad59a7512949d826cdea8e5e36f331dcea870eba200`. The
failure-location diagnostic consumer was prepared for parent validation; it did
not convert the failed run into a pass. The subsequent happy-profile pass is
recorded below. That earlier attempt provides no remote-overlap evidence and no
C1 acceptance.

C1a and C1b remained unaccepted at the baseline point. Its remaining list was
eight/ninth capacity, cancellation, drain, Open/Step/reply-loss, and restart/boot
invalidation. The later cancellation pass below closes only that recorded case;
the other physical lifecycle cases and whole C1 acceptance remain open.
The bounded results establish no GPU support, pooled-memory benefit, energy
reduction, WAN behavior, pooled-memory capacity, or speedup. No private IPs,
hostnames, host keys, credentials, role keys, run IDs, or container IDs are
included.

## Expanded profile follow-up

A fresh `c1b-happy-v1` cohort subsequently passed seven inference requests and
36 last-position vectors: the four baseline requests plus unequal concurrent
5/11-token prompts and the 1,151+1 context boundary. The over-limit 1,152+1
request was rejected by local client preflight before tensor allocation or
coordinator submission; it made no remote compute claim. The nine extension
vectors had maximum absolute error `9.5367431640625e-06`; the baseline maximum
remained `3.445148468017578e-05`, within `atol=1e-3, rtol=0`.

Both processes exited 0, all task containers/private files were removed with
confirmed cleanup, and no transport operation remained owned. The report
records `remote_overlap_observed: false`: concurrent correctness and idle
heartbeats do not prove overlapping remote compute or ordered interleaving.
The command wall-clock span was about 60 seconds including setup and cleanup,
not an inference latency measurement.

This run used frozen source
`852c2207cc0cc17abb3d99cb734d9b18afedc059ddb9d0e446be05a073d69bef`, with bounded
failure-location diagnostics added as an experimental variable. Its report
SHA256 is `d517354079c7f82a20c0d22d94d50373d3bd9e92a3b7375805e4ff2a74bbe02e`;
command log SHA256 is
`3ea8fc243707249657253eafa9b2b9a8f5d6d8fac76da95901e889af86cd0925`. The
earlier expanded-profile failure remains retained and unexplained; this pass
does not retrospectively diagnose it. The focused 184-test Linux run passed
with zero skips, but excluded the then-failing new C0 TLS-negative matrix and
preceded correction of its synthetic abort oracle. It is not a complete C1a
acceptance gate. C1a, the remaining physical lifecycle cases and whole C1
acceptance remain pending. A private whole-cohort issuance candidate primitive
is now implemented and focused-tested, but final policy approval, integration,
publication, activation, durable high-water persistence, and physical root
lifecycle remain incomplete. The two-approval preparation-intent/final-approval
path is not a runnable end-to-end workflow.

## Trial 14 follow-up

The full trial-14 run completed 457 tests with zero skips, 1 failure and 3
errors. `unittest` reported 220.194 seconds elapsed; this is test-suite runtime,
not inference performance. Log SHA-256:
`13a4711d0e5a70e2b716f5a12f71438ba47144b64acf4293b279370e82369fb3`.

Two new completion tests used the wrong
`ConsumerRequestContext.session_id` API; those call sites are now corrected but
remain unexecuted. A component-capacity refusal test assumed an optional `handle`
key existed before submission; its assertion now handles the absent key while
retaining no-submit and cleanup checks. An existing eight-active lifecycle case
failed when the injected clock moved backwards and latched `CLOCK_UNSAFE`. No
exact cause was established; the bounds and fail-closed behavior held, and no
clock settings were changed. This is not a green trial or evidence that a
production defect was fixed. A later focused suite passed the corrected
completion cases and unchanged lifecycle coverage; see the [C1a follow-up
report](2026-10-18-participant-c1a-followup.md). That pass does not establish the
exact earlier cause or supersede the failed full trial, which remains retained.

## Trials 15–17 focused follow-up

Trial 15 ran 36 tests with zero skips, one failure and one error; the other 34
passed, including unchanged lifecycle coverage, root foundation/proof/
preparation, C0 negative TLS, capture-positive, and CT05 checks. Its log SHA-256
is `e6336d912be9c0d551bcb71d2ddc697ca11fee1c553626013abcdca6e75413c6`.
Trial 16 ran three completion tests with zero skips: interleaving and strict
parser cases passed, while a child-fencing case failed on a generic zero-owner
assertion. Its log SHA-256 is
`28154bb172a1da0ee1c10886dd85a106eff72d476887a679b2cbfaf3b470e14a`.

Trial 17's focused suite passed 11 tests with zero skips in 27.349 seconds of
unittest runtime (not inference performance), log SHA-256
`3bc504b135c134292402bee2b81d65f03f2c9af7cff72f7b4bd894e3e3b53023`. It
covered three completion/lifecycle cases and eight private issuance cases,
including the POSIX protected loader and baked foreign-owner fixture. Source
SHA-256 was
`11b4b5f56a40ae721d0d52172c5d90d7d363a7ae6dfac3ae4349ffd9fbf1af4a`; all 250
baked files matched (proof log
`3f643fcafd20614da718f5938afce0169547ae3026fbdcdd163c75b4b827f296`). The
image was `sha256:57626869381fbfdb50624a3fb5d563f90cbf023ca6e6cfa5f152ea7b91c2fc6c`.
The full trial-17 security regression then passed 471 tests with zero skips in
134.858 seconds of unittest runtime (not inference performance), exit 0. It
started at `2026-10-18T11:16:46.493Z`, completed at
`2026-10-18T11:19:03.569Z`, and has log SHA-256
`b717ec4b3b39484807543cd34cb78ec9b2228ade369b058d572bef80d719781c`. It used
the same frozen source and image with both secure-pipeline and
capture-backpressure test opt-ins. C1a root activation, actual TLS disconnect,
and boot-change requirements remain open. No trial here establishes C1a, C1,
or P2 acceptance; no activation, publication, or physical root cutover occurred.

## Physical interleave follow-up

The `c1b-interleave-v1` run used the pinned source and local/remote images listed
below and passed six requests and 35 captured vectors. The original baseline portion
contributed four requests and 27 vectors, with maximum absolute error
`3.445148468017578e-05`. The extension contributed two unequal 5/11-token
prompts and eight forced vectors, with maximum absolute error
`9.5367431640625e-06`. Both remain within the configured `atol=1e-3, rtol=0`
correctness tolerance.

The observed worker-3 post-RPC first-prefill/decode trace was A0/B0/A1/B1; the
causal stage-1 barrier and remote all-owners-global-zero check were confirmed.
This demonstrates the recorded bounded interleave sequence only; it does not
claim all-step overlap, throughput improvement, or WAN performance. Both
processes exited gracefully, containers and private files were removed, the
remote job root was removed, and no pending transport operation remained.
The run spanned `2026-10-18T13:46:52.172Z` to `2026-10-18T13:47:45.513Z`, including
setup and cleanup, so the wall time is not an inference-latency measurement.

Frozen source identity was
`e95b1a4587bc673d9d2144b7ca4a75010be0405c88e3c827fbe3edb7fb12f90a` (271 files),
with local image
`sha256:4eef687b0c7720cbb1d8f1ad38381d91412d0b9988847bac3607c6693b573973` and
remote image
`sha256:ebe5eaedba721f9d5b4a4186156015d12c3f117e1e73b4ab24847f827a72495b`.
The sanitized result SHA-256 is
`19f4b025a8a7df163deca47cf342ae5ef7a543c83f97202dd496942733869013`; command
log SHA-256 is `9777e4dcdee6030b9ffab096bff8654a03d357321f9b570d2a0555e501366e47`.
This result does not close physical fault/restart/drain cases or C1 acceptance.


## Physical cancellation after remote prefill

The `c1b-cancel-v1` run passed on the same two physical CPU hosts. Its baseline
completed four requests and 27 last-position vectors at the existing tolerance.
The cancellation request completed its prefill through the remote third stage
and delivered exactly one output token. A gate then held the first decode at
worker 1 after actual KV mutation. A fresh remote observation bound the same
session to resident committed cache before the parent armed cancellation.
After cancellation the cumulative output count remained one and stage Step
counts remained `[2, 1, 1]`; no mutating Step was retried.

Fresh local and remote global checks confirmed session, KV, queue and
authorization-owner reclamation. The intermediate local state was
`fully_reclaimed`, with zero active requests, streams, captures and capture
reservations. `model_cleanup_complete` was still null at that request-level
observation; subsequent owned process exit supplied the disposal boundary.
The parent measured 6.922 seconds from its own causally prior arm through
independently confirmed local operator exit, within the frozen 40-second bound.
This is a conservative cancellation-to-disposal upper bound on one monotonic
clock, not a subtraction of clocks from different hosts or a latency benchmark.

Both actual processes exited 0 gracefully. Their containers were removed;
remote private files and the scoped job root were removed with confirmed
observation, and no transport operation remained pending. C1a, the other
physical lifecycle/fault cases, C1 and P2 remain open.

The run used frozen source
`21416991a336342872a890ef3e143771e111205ace93c35ac6452b6e9cf4defe` (280 files),
local image
`sha256:9fe0a21a9578ee4bd0cdbd7bb1d2404cbfb5dc92c95f9f6178ad0fb5e25fc079`
and remote image
`sha256:2a81359fae0ed15722664323ede4811c929655cd0910e95c78498df26ab8d98f`.
The remote source overlay preserved all 14 base layers, dependencies and runtime
configuration, and its baked-source proof verified all 280 files. Overlay
record SHA-256 is
`17d3ca01c8f3b73e969f4132d5d3525ff72c2ee741090ca4a2bfec82f9224844`.
The result SHA-256 is
`d11d385d8d56caa8282afdb8f5ec57bbf499a7deed7bbf77eba821ecef1c6e44`;
command-log SHA-256 is
`bbddfb5b4a3d9b4c1d46ff23a7f6671a96875dd0d65ea4c141e8e5ad6ad50cba`.
The command ran from `2026-10-18T14:41:12.648Z` to
`2026-10-18T14:42:06.377Z`, including setup and cleanup. The private journal
retains the exact operational command; the selected profile is reproduced with
`lab.secure_cohort_supervisor --profile c1b-cancel-v1` and the documented
operator arguments, using both immutable image IDs above.


## First physical partial-Open attempt

The first `c1b-partial-open-v1` attempt failed in the original forced-feedback
numerical baseline, before the partial-admission extension or its causal arm.
The reported exception was `RemoteError` from the baseline Generate path;
no completed cohort summary was produced. Its underlying cause is unknown.
This run supplies no partial-admission, unknown-lease expiry or 40-second
disposal result. The earlier cancellation pass remains a separate result.

Remote readiness was observed; the remote worker exited 0 with confirmed
shutdown. The local operator exited 143 after the failure and stop request,
so its graceful exit was unconfirmed. Both owned containers were removed;
remote private files and the scoped job root were confirmed removed, and no
transport operation remained pending. Cleanup does not turn the failed
baseline into a pass. This failed attempt remains retained.

The frozen source was
`251f0cbc2e1f8e0dc7d7dbfd355854a9067fdeb27975fcc104bc655000c7dc50` (283 files),
local image
`sha256:8bae668710c123efd9212d8f732246c4798cbbee331ccce74159619051f4d732`
and remote image
`sha256:2e2d6445a8d73af3a7f803c13ba9606d6cdaebb8fab05e0c089cdf8da593543f`.
The remote overlay proved all 283 source files while preserving the pinned
base dependencies and runtime; its record SHA-256 is
`5c0558d134b24a6c3f2728cbc8c4f2010c88043e4e7393b4be3ed5955115647d`.
Result SHA-256 is
`33447b4871c920586cd8be298f046d8b7366978d3f35c75db6ba5bd8717586f2`;
command-log SHA-256 is
`fa96c5c3053906833d74cba3ae0920d2869dbe1b5f5c996dd87a3dd09a4ad9ad`.
The command ran from `2026-10-18T15:07:49.485Z` to
`2026-10-18T15:08:34.383Z`, exit 1. This span includes setup and cleanup and
is not an inference-performance measurement. No clock or validation setting
was changed, and no clock cause is attributed to the generic failure.

## Physical Step reply-loss run 1

The physical `c1b-step-reply-loss-v1` run passed its narrow profile with exit 0.
Its embedded baseline passed four requests and 27 captured vectors at
`atol=1e-3, rtol=0`. The controlled fault then discarded a real, validated
worker-3 first-prefill Step reply at the caller boundary. Before the reply was
discarded, a fresh remote status confirmed that the same session had committed
cache and was idle. This tests an unknown caller outcome after a successful
remote mutation; it does not simulate network packet loss.

The validated Step covered sequence 0, positions 0–3 and three tokens, with
hidden size 64 and a `[1, 3, 64]` float32 little-endian activation. The remote
worker reported 3,072 committed and allocated cache bytes. Each of the three
workers received exactly one OpenSession, Step and CancelSession; the faulted
request was not retried and emitted no token. A later independent remote status
confirmed no active session, cache, compute, queue, authorization or bridge
ownership. Local state was reported as
`resources_reclaimed_service_failed`: the request state was absent, active
requests, streams, captures and worker sessions were zero, known leases were
reclaimed, and the coordinator was unready. The intermediate local status still
reported 15 existing transport connection reservations and zero pending
reservations; those 15 were not misreported as zero during the service-failed
observation.

The parent measured 6.844 seconds from its causally prior same-host monotonic
arm through independently confirmed local operator process exit, within the
40-second bound. Both actual operators exited 0 gracefully with confirmed
ownership and cleanup. Both containers were removed; the remote private files
and job root were removed, and the final result listed no pending transport
operations. The command ran from `2026-10-18T15:46:08.625Z` to
`2026-10-18T15:47:02.207Z` (53.582 seconds including setup and cleanup), not an
inference-latency measurement.

The frozen source digest was
`43ea767f39e70c4c6cf23985bb7957aaf728c8592dd829ae03b2cb251d82402a` across
284 files. The local image was
`sha256:93ac394789e3d75599ceb445416edaf735390c8dfd86606018f5e3714995008d`; the
remote image was
`sha256:19c52a313015eb414c769cb61e0b9508b72e1ae48a19702cce18ce330c077a0d`.
The remote source overlay preserved all 14 base layers and verified all 284
baked source files; its record SHA-256 is
`8a27e03ef2f287959ca610843c5dd607774c1aa6adcc33fd3f7295c0191a967f`. The
sanitized result SHA-256 is
`9aa1e6805e1d25241652689b9b761785d56898044295389b73e572d359597d6f`; command
log SHA-256 is
`6409f0a0525d42b9f29b773ed122e47e5a7cde9c7169d0cbf12046443b6520f6`.

This result closes only the tested caller-boundary Step-reply-loss case. It
does not establish recovery or service resumption. The partial-Open run remains
a retained baseline failure, root cutover and the latest consolidated
regression remain open, and C1a, C1b, C1 and P2 are unaccepted. Earlier failures
remain retained.

A second partial-admission attempt stopped at local Docker preflight before
creating a container, contacting SSH or creating a remote job root: the older
immutable local image was absent after a later build moved its mutable tag.
No fault arm or disposal interval was measured. This retained setup failure
does not explain run 1 or exercise partial admission. Its log SHA-256 is
`24409d253ab50561010cd6feeb3d99d52f53b9770cb8dde4c875d57bc28bbf9c`
(`2026-10-18T15:54:28.812Z` to `2026-10-18T15:54:29.409Z`, exit 1).
Subsequent builds retain a unique private image tag.

## Retained capacity and partial-admission failures

Physical capacity run 1 failed at the compound held-queue predicate before the
fault arm. Its exact failing branch is unknown. There was no causal arm or
elapsed disposal measurement, so the aggregate failed 40-second criterion does
not establish a measured time overrun. The local operator exited 143 with
unconfirmed graceful shutdown; the remote worker exited 0 with confirmed
shutdown. Both owned containers, remote private files and the scoped job root
were removed; no transport operation remained pending. It used frozen Trial 50
source `049aa3e28c8c9920df476bc77f957a8b250cd6fcbc7efaf5c87cb852f1dd4ae2`,
local image `sha256:bd688c235f35d7e09cf962d98120118f3ae36413e9949600803d611caaa2582b`
and remote image `sha256:dac84e67f89a281a35cc43c8c3cd2df2a4f09dc4f7bec239e91f70de4421dc90`.
Result SHA-256: `666fa90bc490526c620d48136d0093417857279cbb60b6e6105089122804debb`;
log SHA-256: `8f4a61c344b4e3a5a9303f612d6d53b07d7f38628a6ea682841207c0959ad80c`.
The command ran from `2026-10-18T16:14:22.610Z` to
`2026-10-18T16:15:12.801Z`, exit 1.

Physical partial-admission run 3, using the same frozen images, reached the
armed case but failed operator-result validation. The actual local exit was
15.562 seconds after the parent's causal monotonic arm, within 40 seconds, but
exit 143 and unconfirmed graceful shutdown failed the composite disposal gate.
The exact original validation rejection was not recorded. Both containers and
remote private job resources were removed, the remote worker exited 0 with
confirmed shutdown, and no transport operation remained pending. Result SHA-256:
`994fae02ac6244dbf2448e2785eedada145ff717cac7474bfb3f56e0a2d6804d`;
log SHA-256: `ea4eb3c30bc7a20e7b4394a8e905501b2dbd553b0b58b6d5d2ec67030f7caedd`.
It ran from `2026-10-18T16:22:44.389Z` to `2026-10-18T16:23:46.123Z`, exit 1.

One bounded diagnostic on the same frozen source reproduced a rejection at
`cohort_result/partial_baseline`. The original partial extension reported its
validated Open-reply loss, no Step, lease expiry and remote cleanup. Local state
truthfully retained one unknown coordinator request and its two stream owners.
Cleanup reported three errors for that same graph, while the result classifier
recognized only the coordinator-close error; the baseline was therefore marked
failed and the original sanitizer rejected it. This diagnoses the reproduction,
not necessarily run 3's unrecorded rejection. The candidate correction must prove
exact request/context/slot/task identity and preserve actual exit-0 and 40-second
requirements; it has not passed a physical run. Diagnostic harness SHA-256:
`20e3f448315420ebfc88b973b0d394ab0dbde69dd1e23b28b50b57a11da8226d`;
log SHA-256: `ef7b23cc9cf51436b4b12a1c6d97ab0f47fd83ddcbe1ca4dc6aad25b1c40c3e4`;
result SHA-256: `7cb4a502ee78f47fd44dd52c2cc1c6f5fcf2c98790739dacc54d09ee0b0c049d`.
It ran from `2026-10-18T16:31:51.684Z` to `2026-10-18T16:32:54.033Z`, exit 1.

After the focused Trial 52 synchronization checks passed, physical capacity run
2 passed the strengthened queue wait, then failed the downstream-work/transport
predicate before the arm. Its exact failed branch was not recorded. No disposal
time was measured. Its source
digest was `25b827d889f2a546ad688e764511b9675df1fd72d4f6145ee27a76aa2a69e487`,
local image `sha256:186ec6325d1a1ccae7bb04ee4845b4e34de62c9f904e5a0683af2415c793f523`
and remote image `sha256:f37bd873ca42e5fce5a290a9c31311451ff87806cb8de1cfbb7112c85fb4a8d3`.
The remote overlay verified all 288 source files, preserved 14 base layers and
the dependency/runtime configuration; record SHA-256:
`11cb6918ab5d63f2941c3583ba6907bc0c9bb44f9128f40d83fe92979f0be282`.
Result SHA-256: `79edc4c19d648a576488aa9bcc5a906492d6f5721d61d1bfbb6075cd5d8f602e`;
log SHA-256: `dbc0b8270d332477564a15573ca0bee4c58121036b0d10897ec194c8e2ff805e`.
It ran from `2026-10-18T16:47:48.512Z` to `2026-10-18T16:48:41.396Z`, exit 1.
These retained failures leave capacity, partial admission and C1 acceptance open.

## Physical partial admission run 4

Run 4 passed the narrow `c1b-partial-open-v1` profile on Trial 53. After baseline
four-request/27-vector parity, it discarded an actual validated worker-3 Open
reply at the caller boundary. The producer and sanitizer require one Open per
worker in order, no Step, no generated output, and no retry. The unknown remote
lease had an actual 9,706-ms maximum lifetime; fresh protected status confirmed
its expiry and global remote reclamation. This is controlled caller-boundary
reply loss, not measured packet loss or automatic recovery.

The coordinator truthfully remained unready with one unknown Open request and
one stream owner in each service. Logical cleanup was false. After component
close, local worker/cache/bridge/authorization/capture/transport owners were zero;
the exact original retained request/slot/task graph and three tagged cleanup
errors remained strongly owned until actual OS exit. Earlier intermediate status
had 15 static connection reservations; those were not misreported as zero.

The parent confirmed actual local process exit 0 at 14.672 seconds after its
causally prior same-host monotonic arm, within 40 seconds. Both owned containers
exited 0 gracefully and were removed; remote private files and job root were
removed, with no pending transport operation. The command ran from
`2026-10-18T16:59:20.216Z` to `2026-10-18T17:00:19.101Z`, exit 0.
Result SHA-256: `0d1556069e5551ed17f61135da0968c6808abf799044b0f2f92e9d003603574d`;
log SHA-256: `a93f72e9c88bf2ecab1c6227189b35f32b7ac1dbf09e9ef619224baadff3fe3f`.

Both this run and capacity run 3 below used the same 290-file source digest
`0efbcc83547fc2fda3c6bddc607705af4abcb11e7a572848b38afbcc7dd62acf`, local image
`sha256:58a36f9ea604da3af80b7e902c8a26102d6fa47a81e1676d6263fe6784f15e5b` and
remote image `sha256:2dc9611ff2d02bc763205fee1d3bd50d6ffe085bd8101ca6bc778b1bbc6cc42f`.
The remote overlay verified all 290 files and preserved 14 base layers and the
dependency/runtime configuration. Its record SHA-256 is
`7ec5d1967722acce0738d2bb03fbca17a5eb1777846f6cf60e7dc724273dc6c3`.

## Physical capacity run 3

Run 3 passed `c1b-capacity-v1`: baseline four-request/27-vector parity, followed by
eight real captured one-token requests. A real stage-1 prefill held mutated KV
while seven other distinct sessions queued behind it. Fresh protected remote
status confirmed exactly the eight expected Open owners. A ninth capture request
received `CAPACITY_EXHAUSTED` before coordinator submit, tensor allocation or any
worker Open/Step; used-request accounting did not change. All original eight
request/session pairs then completed, with eight finite reference comparisons
and maximum absolute error `1.430511474609375e-6` (`atol=1e-3, rtol=0`).

Fresh remote status confirmed global reclamation, and local request/stream/cache/
capture/compute owners were zero while the fixed 15 connection reservations were
still held for the live service. Both actual processes subsequently exited 0,
both containers and the remote private job resources were removed, and no
transport operation remained pending. Actual local disposal was 7.672 seconds
after the parent's causal monotonic arm, within 40 seconds. The command ran from
`2026-10-18T17:00:49.456Z` to `2026-10-18T17:01:41.806Z`, exit 0.
Result SHA-256: `02b2d579a473be906ab9d49d3bbb98b686c3e3f8c843713fe893bd7433534dca`;
log SHA-256: `27d475823a476c305416f47c17f73ecdaabb7ef87b0f92688bf7e5e44892ec75`.

These are correctness, admission and bounded-disposal results, not inference
performance measurements. Physical restart, owner drain, signed identity removal/
revocation and the consolidated current regression remain open. C1a, C1b, C1 and
P2 remain unaccepted; earlier failed runs are retained.

## Retained physical restart run 1

The first `c1b-restart-v1` run failed new-generation setup, exit 1. The old
worker had actually exited 0 in 1.843 seconds from the parent's causal monotonic
stop arm, and its container/private job resources were removed. The next
generation had no verified CID and no READY acknowledgement. The frozen source
contains a deterministic double creation: the outer supervisor exclusively
creates the new job directory, then its launch helper attempts the same exclusive
mkdir again before upload or Docker dispatch. The recorded failure is the generic
`ssh_command/command_failed`; source control flow identifies this concrete defect.
It does not establish a completed restart or fresh-route inference.

The failure report conservatively retained the new directory as launch-unknown;
the local operator exited 143 and its graceful shutdown was unconfirmed, although
its container was removed. A separate parent audit verified the exact new
container name absent and the exact task-owned directory empty, UID/GID1000,
mode0700 through a no-follow descriptor walk. Only that empty directory was then
removed with the bounded owned-job removal helper; no transport operation remained
pending. This later cleanup does not change the failed experiment's result.
Cleanup audit SHA-256:
`4d7a6a3e04d6eb14a8d7b91ce09f63a86e07d1773e77f4b66265c7144613531c`.

The run used Trial 54's source
`fd589bf2e445e59241441dd3cd255f11ac276f2ea61653278fa15ffe61f90136`, local image
`sha256:2f26168a6e6ccc93e427e15aebe7d8905414c854d0ad449b0f360fb348b36350` and
remote image `sha256:c6b3a8033a284a82113724d2de6d48f911e65ae0e26658548983b0146d39a503`.
All 290 remote source files and the unchanged 14-layer base/dependency/runtime
configuration were verified; overlay record SHA-256:
`ebb3fb49cbe1c3de622b3ee83d3ba3dc0aad9198eac8e0696d85b89c9d09fcd0`.
Result SHA-256: `b60ef01bdf2d1de1d38cf8d7831b850a668695277c962c3c5af8b6fd9835616b`;
log SHA-256: `be95f06ce7b5409283da7530ddcce80865923dc16e76529c55a6d0fb081c425f`.
The command ran from `2026-10-18T17:18:03.957Z` to
`2026-10-18T17:19:07.060Z`. The candidate fix keeps one directory creator and
marks launch-attempted only immediately before actual Docker dispatch; earlier
upload/setup failures remain distinct from an ambiguous container launch.

## Physical restart run 2: READY reached; failure unattributed

The second `c1b-restart-v1` attempt reached the new worker's protected READY
acknowledgement, then failed before its next expected observation; the original
failing branch remains unattributed. A separate frozen diagnostic reproduced
an old-binding-probe `SecureTransportError` caused by `TimeoutError`; it did not
observe a native `UNAUTHENTICATED` status. This separate run does not establish
that the original restart failure had the same cause, and explicit rejection of
the old binding or successful inference after restart remains unproven.

The old remote worker exited 0 in 1.844 seconds from the parent's monotonic stop
arm. The new remote worker also exited 0; both remote job roots and containers
were removed. The local operator exited 143, so graceful local shutdown was
unconfirmed. No restarted-cohort Generate result was accepted.

Physical result SHA-256:
`9533b7fd86d81539786db3e1b2cb3e724e3ae83df0257730506b6232061c4854`; log
SHA-256:
`eef2b75c06582590b8cadb7af26436b2206e77655eba7b2bee42892a07138f26`. Frozen
diagnostic result SHA-256:
`78b6e35ff83a181f47612b5ef336b0c47e606fb6862e23bdf6056803f839dda7`; log
SHA-256:
`dd033ef39b4e061574b7fd892529450406e811289a2cf4451f378dc4b5271ed8`. The
diagnostic preserved the original source, images, Clock and criteria; it is
separate diagnostic evidence only. Restart, physical drain/removal, the consolidated
regression and C1/P2 acceptance remain open.

## Physical restart run 3: stale-control check failed

The third `c1b-restart-v1` run reached the new worker's protected READY
acknowledgement and a new Describe, then failed before the first native old
session `SessionStatus` refusal. The corrected nonce location identifies the
failed observation, but the underlying native exception was not recorded. The
old and new remote processes exited 0; both containers and private job roots
were removed. The local operator exited 143, so graceful local shutdown was
unconfirmed. No old-binding rejection or successful restarted inference is
established.

A separate source audit found a possible listener-capacity conflict between
the held new Describe and the fresh caller, plus close-before-RPC-abort ordering
at the first unestablished rejection. Neither source concern is confirmed as the
cause of this run. Physical result SHA-256:
`5ac9e01fe3d84b9134e0ef5704fbcdd20360df9287180d2ba7928211a4660965`; log
SHA-256: `e16da8d00ae91c32ec610cb34b82aeb53501ac7cb82537fb5b4d5c3837dfd035`.
The remote image was
`sha256:c76071138134ee99fd1927576ab886efb83e24a6a571888aa02be81d8c285e7e`;
its overlay record SHA-256 was
`92c69fa76791fea28b0550de5b1261d5a6dc6c33f8531db57feadfd6dd7c0735`. The run
spanned `2026-10-18T18:13:20.300Z`–`2026-10-18T18:14:37.706Z`.

Actual restart, drain, and signed removal remain incomplete; C1 and P2 remain
unaccepted.

## Physical restart run 4: generation-two listener setup failed

The fourth `c1b-restart-v1` run failed, exit 1, after the new worker reported
READY but before an accepted restarted-cohort baseline or a native old-binding
probe. The retained result locates a `ValueError` in
`validate_private_unix_directory`, reached while `_run_real_pipeline` created
the generation-two secure worker server. The nested restart-generation socket
directory exceeded the acceptor's private Unix-directory path bound. No
restarted inference or old-binding rejection is established. A shorter child
path correction is prepared but has not yet been validated by an accepted
physical rerun.

Both remote workers actually exited 0, their containers and private job roots
were removed, and the result reports no pending transport operations. The old
remote worker exited 1.922 seconds after the parent's causal monotonic stop arm.
The local operator exited 143, so graceful local shutdown was unconfirmed.
The new worker's READY status confirms setup progress only; it does not make
this failed restart a successful result.

The run used the Trial-65 remote overlay: 296 verified source files, the same
14-layer base and dependency/runtime configuration, and image
`sha256:82336ef2810a1ea0b30c1619cd44009aea84263567284abb86edcb7eef69adf1`.
Overlay-record SHA-256:
`bcd0684fccff955c479bc1327c2c32bf800a1d4235155ea09d6ef2f4894110d7`. The
physical result SHA-256 is
`48e76e45366cc5611748b2bb39930494cf431d6e4440c9ab622f19b50ce08e90`; log
SHA-256 is
`85f74d64f56c7a460b24613e2c7828e51459e698bd55b60a205b9fe408990a52`. The
run spanned `2026-10-18T19:10:20.022Z` to `2026-10-18T19:11:36.868Z`.

This result does not repair the earlier failed full regression, establish
physical owner drain or signed identity removal, or complete C1b, C1, or P2.

## Trials 66 and 67: native restart-owner component gate

Trial 66 failed its 311-test required Linux gate with zero skips, one failure,
and five fixture errors. Trial 67 passed all 311 required tests with zero skips
in 35.245 seconds after the bounded fixture corrections. The gate covered the
nine native C0 groups, owner-protocol and archive/handoff checks, all 248 earlier
required IDs, and actual POSIX-path controls. Its counting-cache Step control
advances only after checking the supplied position and uses no model weights.
This component result does not establish a physical Remove profile, accepted
restart, or current full regression. Exact trial digests and retained failure
details are in the [C1a follow-up report](2026-10-18-participant-c1a-followup.md#trials-66-and-67-native-restart-owner-controls-and-corrected-fixtures).

Trial 67's matching ZimaBlade source overlay verified 298 files against digest
`544f8466a07b1cad8081c9a7dc167383b7631e7d49f242ebadc785c15ab020fb`, on the
same 14-layer base with dependency and runtime configuration unchanged. The
image is
`sha256:fa4cfd7accf1b5643bd4094d5f98f8bc180e686e9ee164e18c972b85473e7ec2`;
overlay-record SHA-256 is
`cc17b82c2688b72da763f0fb087f4e350e1d515f4f639603140e480bfa93b59d`, and
verification-log SHA-256 is
`cf4fe97ead7d38d40c7a4459f61c31c3f429b9bf99eb8644ad160263fbaf515b`.

## Physical restart run 5: operator result failure, cause unrecorded

The fifth `c1b-restart-v1` run failed at `operator_result` with
`SupervisorError`. The retained cohort is null and has no failure location, so
the specific cause is unrecorded. The new worker reached protected READY, but
there was no accepted baseline, native old-binding rejection, or restarted
inference. Both remote generations exited 0; their containers, private files
and job roots were removed, with no pending transport operations. The old
worker exited 1.907 seconds after the causal stop arm. The local operator
exited 143 and its container was removed; graceful local shutdown was
unconfirmed.

The run used Trial 67 source
`544f8466a07b1cad8081c9a7dc167383b7631e7d49f242ebadc785c15ab020fb` and images
`sha256:3e43883868a33ed2b6e6277f50b9eaa64894c40424d39b9a7bd6e79ac250611f` and
`sha256:fa4cfd7accf1b5643bd4094d5f98f8bc180e686e9ee164e18c972b85473e7ec2`.
Physical result SHA-256 is
`4d857e92dc0251d3ad768c624d38c6d0e87dc7e1fe3a00eeae6979b0f380ca53`; log
SHA-256 is
`34c75193ae2507a6ff8015a6060e49220694a2f7c8fa16ad000313cd20c66a55`. The
command ran from `2026-10-18T19:37:17.064Z` to
`2026-10-18T19:38:52.051Z`, exit 1. The result does not establish restart,
owner drain, signed identity removal, or C1b/C1/P2 acceptance.

## Trial 67 on-host diagnostic and separate offline analysis

The frozen Trial 67 `RST5-diag1` command ran the existing supervisor on the
actual physical restart setup from `2026-10-18T19:44:44.248Z` to
`2026-10-18T19:46:16.963Z`. This on-host diagnostic observed the secondary
`cohort_result:restart_binding` rejection at
`secure_cohort_supervisor.py:2411`; it did not establish the original RST5
failure's cause, which remains unrecorded. Diagnostic result SHA-256:
`6d0e578c5e26ca25599b8b04d1718879c9daa6633444f4b7524ef41fd9b0d797`; log
SHA-256: `d79351b8728371fea15f43cf350b7f5eac65ab7601a86cb9a3c713cb52e5733a`.

A separate copy-only offline analysis examined the retained protected result
without changing it. The copied status was adjusted only to reach the final
predicate; the unchanged validator rejected a 20-field held-status observation
where the fixed projection requires 11 fields. The copied status exposed the
upstream projection mismatch behind the on-host diagnostic's secondary
rejection. The protected source result remains private (SHA-256
`073f03e952aebd67eb8fc29ef2f6e1381c5d6a1a2e7e7dcbad28e9a318b21422`); no
separate result or log hash is claimed for the offline analysis.
A reviewed producer projection now preserves the strict validator. Neither
operation establishes accepted restart, baseline, native rejection, physical
drain, or removal.

## Required component gate and physical restart run 6

Trial 68 passed 311 required Linux tests with zero skips in 35.658 seconds of
unittest runtime (not inference performance), exit 0, from
`2026-10-18T19:58:44.851Z` to `2026-10-18T19:59:22.815Z`. Its 298-file source
digest is `6d7ef737af2b80e641b9c1bd3130ac4cee43cc66b6d6a28afc6f0f8258aca009`,
image `sha256:3864f8cec9de794794dd4cab2b49174199912d36df2358e05849c5afe1a45f23`,
and source-proof SHA-256 `07aa9f79d9ed3d436633c6eb6f26f3b4468d992b0e4375452b6f5a14db91bd3b`.
The test log SHA-256 is
`157085ec364bdf5e2fadc96c9f80f7ab218bdf037b85de0bc9d86061ad34710b`. The
matching ZimaBlade overlay verified the same 298 files; its image is
`sha256:e6d52af4ed9783e020eee6077a48db90aadd90a499253b9ba51be1e28779b6b3`
and overlay record SHA-256 is
`7363180e15cc7e2643cbab4986978eec35d3cb58ad9b40ee192073c6f60bb591`. Owner
controller changes were not integrated into this gate.

Physical RST6 failed during the old cohort's first baseline with `RemoteError`,
before the held-status projection or generation-two startup. Its version-1
failure record had no error code; it does not identify a clock failure or
implicate the later projection. The old remote worker exited 0 and its container
and job root were removed with no pending operations. The local operator exited
143 and graceful shutdown was unconfirmed. The run spanned
`2026-10-18T20:03:46.925Z` to `2026-10-18T20:04:34.734Z`, exit 1. Result
SHA-256: `f99053688443fc9edb1957862d77b7f2863ef5e5bcd9b9fc3a59e641412fb222`;
log SHA-256: `8bb4139708d364aa0b7cad846ec29b3369b1b0542405b5cdf5d88e0169666f49`.

Trial 69 completed 825 required tests with zero skips and one failure in
367.458 seconds of unittest runtime, exit 1. The sole failure was a cancellation
process test whose child reported `CLOCK_UNSAFE: clock moved backwards` during
baseline generation, before its cancellation hook; teardown was unconfirmed
with one capture reservation retained. The cause is unestablished, and this
does not explain RST6 or earlier full-gate failures. See the [Trial 69
record](2026-10-18-participant-c1a-followup.md#trial-69-consolidated-required-linux-gate)
for source/image and log identities. The final integrated owner-profile full
regression, physical restart, drain/removal and C1a/C1b/C1/P2 acceptance remain
open.

## Trial 70: controlled owner-flow gate retained failure

Trial 70 ran 357 required tests with zero skips, one failure and one error in
36.306 seconds, exit 1, from `2026-10-18T20:40:15.874Z` to
`2026-10-18T20:40:54.516Z`. The loopback endpoint in the full-Remove controller
fixture was correctly refused by actual `run_supervisor` before READY. A
separate outer producer final-STOP fixture error used `listener_slots=0` below
the configured minimum of one. Both corrections were test-only; the
`validate_cli` preflight still mocks I/O. The controlled flow tests do not
establish numerical or physical behavior. There was no matching overlay or
physical run. See the [Trial 70 evidence](2026-10-18-participant-c1a-followup.md#trial-70-owner-flow-controlled-gate-retained-failure)
for source/image and log identities. Trial 71 had no result at report time. The
owner-integrated qualifying gate, restart, drain/removal and C1a/C1b/C1/P2
acceptance remain open.

## Trials 71 and 72: controlled owner-flow rerun

Trial 71 ran 357 required tests with zero skips and one error in 35.897 seconds,
exit 1. Its Remove controller path reached a successful controlled result, but
the final test errored on `set(material_files)` with dictionary records; negative
variants were not reached. All six producer and outer-cleanup cases passed.
Trial 72 then passed 357 required tests with zero skips in 34.309 seconds,
including 311 retained IDs and 46 new controlled-flow IDs. These runs used
mocked I/O and synthetic baseline vectors, so they add no physical or numerical
evidence. The matching ZimaBlade overlay completed from
`2026-10-18T20:50:04.607Z` to `2026-10-18T20:50:15.887Z`, exit 0, verifying all
300 source files with runtime and dependencies unchanged and the 14-layer base
preserved. Remote image:
`sha256:3d511160da90152ed793664252315156c86b9c5214f9152ceb78e86b6af39fca`;
overlay record SHA-256:
`be5e799d08322637735c2ce2df85b6a8328e4f1080e24fa311810025b8cd0cdb`; log
SHA-256: `0a2d0276da36e4c91c29c11af3ed965b1bca66e3364d0b833f5df8c7ad8a9c81`.
The guarded drain and Remove specifications are prepared but unrun; physical
RST7 remained in progress. Details and identities are in the [C1a follow-up](2026-10-18-participant-c1a-followup.md#trials-71-and-72-controlled-owner-flow-rerun).
The integrated qualifying full gate and physical owner drain/removal remain
open, as do C1a/C1b/C1/P2 acceptance.

## Physical restart run 7 and drain run 1

Physical RST7 passed from `2026-10-18T20:51:36.641Z` to
`2026-10-18T20:53:10.472Z`, exit 0, using the Trial 72 source/image pair. Old
and new baselines each completed four requests and 27 vectors, with maximum
absolute error `3.445148468017578e-05`. Both stale-binding controls returned
native `UNAUTHENTICATED`; same-leaf continuity, boot/snapshot changes, and
binding/transport identity checks passed. Old remote retirement took 1.922
seconds on the same-host monotonic clock. The local operator and both remotes
exited 0 with scoped cleanup confirmed and no pending transport work. Result
SHA-256: `f51d0b166d37f04be473bee4d6186965163b806bb597d3aedf7a6af8c931e6ee`;
log SHA-256: `68bcc73cc109f37ebbfb94c4c4a517b850b15ae412393c4eb7e12254533752a7`.
This bounded restart pass does not accept a C1 phase or explain earlier failures.

Drain run 1 failed before remote READY or remote worker/job launch. The local
status recorded a supervisor-stage `ModuleNotFoundError` without its original
module name. A same-source preflight found the frozen launcher omitted the
source `src` import path required for `steamboat_security`; this is a harness
setup failure, not a drain lifecycle result. The local operator exited 143 but
its container removal was confirmed. No remote process/job was attempted and
no transport work was pending. Result SHA-256:
`0ab6043324cdfefa55c426b35381342cb0a121bb95150d7dc5033148eb0bff00`; log
SHA-256: `806b1fec16f2602eb297b71ab9ff99a102620aa98ac70453ecccdb74dc8a367c`.
Drain 2 and Remove 2 were not yet prepared or run. Physical drain and removal,
the final integrated gate, and C1a/C1b/C1/P2 acceptance remain open.

## Physical Drain run 2: canonical command publication failure

Drain 2 used the Trial 72 source/image pair after the private host launcher's
source import path was corrected. It ran from `2026-10-18T21:02:45.610Z` to
`2026-10-18T21:03:45.863Z`, exit 1, reaching remote READY and command 1 before
`owner_action_response:invalid`. A protected read-only check confirmed an
accepted `draining` ACK and stable command/ACK metadata. The published command
was 281 bytes, while the canonical command was 280; the file's hash exactly
matched canonical bytes plus a newline. The worker ACK used the canonical hash.
This identifies a supervisor publication-byte defect, not a refused Drain command
or an accepted drain lifecycle result. See the [detailed retained record](2026-10-18-participant-c1a-followup.md#physical-drain-2-canonical-command-publication-failure)
for hashes and limits.

The remote process exited 0 but cleanup was not authorized; its owned container
and private job files were retained. The local operator exited 143 and its
container removal was confirmed; no transport operation remained pending.
Result SHA-256:
`33769c0492e42afa57d6609b00fd7fa4647cffb2201248438a30cad93e70b039`;
log SHA-256:
`c2b7c0e417b1490e2f20d4e59f09950bf09c129a412e090ff1cb74d866296fcb`.
Remove 2 was prepared but not run. Physical drain/removal, final-source controls,
the integrated qualifying gate and C1/P2 acceptance remain open.

## Trial 73 and retained physical Drain 3

Trial 73 passed 358 required Linux tests with zero skips in 35.861 seconds.
The canonical publication-byte regression uses actual publisher arguments;
the matching physical-host overlay verified all 300 files with unchanged
runtime/dependencies and all 14 base layers preserved. Exact source/image and
log identities are in the [Trial 73 record](2026-10-18-participant-c1a-followup.md#trial-73-and-retained-physical-drain-3).

Drain 3 ran from `2026-10-18T21:09:27.719Z` to `2026-10-18T21:10:26.411Z`,
exit 1. Command 1's canonical-byte receipt and accepted response passed, then
the fresh OpenSession native-refusal check failed at producer line 6770.
The original native status was unrecorded. The remote exited 0 with confirmed
shutdown and graceful compute shutdown, but cleanup authorization was incomplete
and its container/private files were retained. The local operator exited 143
and its container was removed; no transport work remained pending. Result
SHA-256 `680ecb86bcbf539e88aaecbe4d6250521046272efc0b49829bc5344f6ff71ecf`;
log SHA-256 `02bc354a93eb1b9c23647822b085147ec3f8752ca0f4f5ba57eaaaa5fa504fe5`.
A separate local real-TLS regression reproduced the old runtime's drain status
mapping mismatch; it does not recover this run's original status or accept
physical Drain. Remove remains unrun, and final-source controls, full discovery
and C1 acceptance remain open.

## Physical Drain 4 and Remove 4

Both final-source owner-control runs passed their frozen checks and independent
evidence review. Each baseline completed four requests and 27 finite vectors
with maximum absolute error `3.445148468017578e-05`, within
`atol=1e-3, rtol=0`. The [final validation record](2026-10-18-participant-c1.md)
identifies the exact source, images, controls and remaining full-suite gate.

Drain 4 ran from `2026-10-18T21:19:27.039Z` to
`2026-10-18T21:20:51.744Z`, exit 0. Actual published canonical commands and
receipts matched. A repeated drain preserved the original 30-second deadline;
Step/Renew continued on the held session, while a fresh Open was refused with
native UNAUTHENTICATED under the original authority. The observed KV allocation
grew from 3,072 to 4,096 bytes before expiry. Physical resources reached zero
at the deadline; both processes exited 0, their owned containers/private jobs
were removed, and pending transport work was zero. Local disposal took 4.344
seconds on one controller monotonic clock, within its 40-second bound. Result
SHA-256 `be6fa4776d203aea49aba59344dbb6b8892165e31a5d9024f93b6926b1ec6e58`;
log SHA-256 `247f535cd9ab787b99289a08436afbdd2dcb16e8f1ca77c9b3af5c82e014deda`.

Remove 4 ran from `2026-10-18T21:22:13.445Z` to
`2026-10-18T21:23:13.209Z`, exit 0. Two signed revisions and their exact public
intent/verifier provenance were checked; the target device, local credential
serials and grants were revoked. Old Status and fresh Open each received the
required native UNAUTHENTICATED refusal under the original authority. Resources
were zero before the second Remove command; its terminal observation matched
the actual owned exit 0. Both processes exited 0 with owned cleanup and zero
pending transport work. Local disposal took 2.656 seconds on one controller
clock. The three public evidence sidecars were retained as declared; they
contain no private signing key. Result SHA-256
`4e088558695f1c0e74218e1e88ff7c06e0415c9c87114701d522099e5f3e9f5d`;
log SHA-256 `76b9daf71d482215d7ad36dd834311cabf217d9f4f93bc390662047fcf0b075a`.

These are bounded idle-KV owner-control checks, not hung-compute disposal or
performance claims. Historical failed runs remain failed; their cleanup is not
inferred from these successful runs. C1 remains open pending clean full
security qualification and final acceptance review.
