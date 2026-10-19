# Participant two-device preparation, 2026-10-18

**Status:** C1 remains unaccepted. This report preserves preparation history and
records one later authenticated split-host `baseline-v1` parity pass; it does not
establish the expanded C1b lifecycle profile, full C1a acceptance, or P2
acceptance. The subsequent `c1b-happy-v1` attempt failed with no cohort summary.
The cross-device acceptance target is listed in
[CT-13](../PARTICIPANT_CONTRACTS.md#acceptance-test-matrix), and the bounded
baseline evidence is summarized in the [parity report](2026-10-18-participant-two-device-parity.md).

## Frozen candidate and host

The inspected candidate contained 222 source files, with selected-source digest
`9e515581071971ce304e2f671df0235299131ae0d0bed22ea872021d344664b5`. The local
Docker 29 image was `sha256:cf7c3398f25e2f9bc404bd94d999ee4927ba2db1bcb478bdd1c8a3b647758e6e`.
The remote baked-source proof verified all 222 files against that digest before
the model control. The transferred archive was 374,433,401 bytes with SHA-256
`ca8d1bb231557800ec2340be44e2f6ff7c1ebe6d4912f179547d9b929080e1f3`.

The physical `LAN-B` host inventory reported 8 GB RAM, four CPU cores, an Intel
Celeron N3450, Debian 11, kernel 5.10, and 11.6 GB free root disk before this
image was added. The CPU has no AVX or AVX2. Host and network identifiers are
omitted. Local Docker 29 and remote Docker 24 image IDs differ; the inspected
root filesystem layers, environment, entrypoint, command, and working directory
matched. The initial exact metadata assertion failed because Docker represented
the unset `User` field as null locally and an empty string remotely. A corrected
check normalized only that unset field; the probe explicitly ran as UID 1000.
This is not a claim that the image IDs are bitwise identical.

## Physical-host CPU model control

The parent ran the existing `lab.benchmark check` control on `LAN-B` with the
pinned public artifacts and same-stack full-model reference. The effective
container invocation used `--network none`, a read-only root, dropped all
capabilities, `no-new-privileges`, UID 1000, two CPUs, a 3 GiB memory cgroup,
128 PIDs, and read-only artifact/reference mounts. The checked cgroup values
were `memory.max=3221225472`, `cpu.max=200000 100000`, and `pids.max=128`.
PyTorch used two threads, float32, eager attention, and serialized in-process
stages; there was no RPC or network route.

The container launcher set this benchmark argument vector:

```text
lab.benchmark check --backend pytorch --artifacts /artifacts --reference /reference --output /results/zima-cpu-check.json
```

The output recorded defaults of 10 requests, concurrency 1, 128-token prompts,
8 new tokens, greedy decoding with EOS ignored, and `atol=0.001`. The pinned
model and tokenizer revision was
`298338802ab94432b917bcce11382aa151aee50f`; runtime included Torch
`2.14.1+cpu`, Transformers `5.19.0`, and NumPy `2.5.4`.

All eight comparisons passed: prefill, forced-decode, cross-session decode after
close, and a fresh session after close. Every logit vector was finite, greedy
tokens agreed, and maximum absolute logit error was `0.0`. Cancellation closed
its session; the session limit rejected the excess session. At completion all
three stage diagnostics reported zero active sessions, reserved positions, and
allocated cache bytes. The report JSON SHA-256 was
`e5f4364a65ff77820fc5d6c7c3c4a83216be633c2b5f1dabadd652232db0bc2c`.

The artifacts archive was 9,000,257 bytes, SHA-256
`cc2b20be5324dd302985e0e1fb972eba12faee1cfdd0d4c5d7b40ae3b665e386`; the
reference archive was 7,671,902 bytes, SHA-256
`3c87457e24af7327287e86d405bfc6fc7f07ee5dffcc82da771e1ec714579b64`. The
actual C0-pinned source and artifact hashes were checked after loading. Existing
cache contents were not mutated. This is same-host CPU model compatibility
evidence, not remote C1 numerical parity, multi-device execution, GPU
performance, pooled-memory capacity, or measured speedup. The check measured
cache tensor bytes, not process RSS or allocator peak memory.

## Worker process and TLS probe

The fixed `lab.secure_worker` CLI was exercised using the parent-verified
configuration schema and the actual loaded StageExecutor. A defined-event-only
probe passed C0 checks, native TLS Describe, heartbeat, and confirmed shutdown;
its log SHA-256 is
`1f9f762fb1d2396793d5b96c74d1bc4bb6e36a2189d96b4ce912d9a481291456`. An earlier
probe on the same image retained a failure because the parent oracle expected a
status event where the worker emitted the defined heartbeat event. TLS and
cleanup were confirmed in that attempt; its retained log SHA-256 is
`f9d61f270e0f5f2907e71402935fc45811a474f5d46e32b58db6be708e9e5600`. The
corrected probe did not exercise Step, model inference, numerical network parity,
or a full three-stage route.

The Linux security subset ran 20 selected new unit tests with zero skips and all
passed; its log SHA-256 is
`f312b01ebc0231524b90d772fa04799184e231bb1d5b1786533a67ea6e1922b7`. These are
selected tests and are not added to any aggregate C1 test total.

## Clock observations and remaining work

`ntp.service` was active on the physical host; `timedatectl`'s `NTP=no` reflected
the separately masked `systemd-timesyncd`, not the active service. Read-only
kernel clock diagnostics reported state 0, maxerror 616,776 microseconds, and
esterror 407 microseconds. Five seconds of raw sampling produced 29,784 samples
with no observed backstep. A ten-second laptop sample produced 107,879 samples
with no observed backstep. Windows time reported a public NTP source and 1.25
seconds root dispersion. These are bounded observations, not clock-stability or
cross-host synchronization guarantees; NTP is unencrypted and the operator is
trusted. No global clock change was made. The worker still requires an explicit
positive operator-approved uncertainty bound no greater than 30 seconds.

At this earlier checkpoint, the latest reported full C1a security run had 289
tests with one `CLOCK_UNSAFE`/unknown-cleanup failure. That failure is retained;
the historical WSL clock event remains unexplained and is not diagnosed by the
sampling above. Later full-suite runs are recorded below. The physical-host M1
control reported above completed and passed its eight same-host comparisons; it
supplies no remote route or performance result.

The active-grant and unknown-readiness repairs passed scoped independent source
review. A Linux run on the first repaired source failed two negative grant
subcases because its fixture supplied a public certificate with mode 0644; it
never reached the intended grant check. That failure remains retained. The
fixture now supplies an explicitly protected copy, requires POSIX semantics,
checks the exact rejection, and first proves that valid signed policy reaches
the executor-construction seam. The repaired 24-test Linux subset passed with
zero skips on source digest
`24b91136621d15064a3c389250b5f6acb9199e82652d8ba22239c19953307efc`;
its log SHA-256 is
`caf5408da3e1fc97504346035a0b6d09727ce21095ab0b754ef4c2fe28a374dd`.

At that checkpoint, the candidate contained `lab/secure_cohort.py`; its baseline
covered four requests and 27 captured vectors, while lifecycle extensions were
still pending. A rebuilt 226-file source with digest
`609888a44eef3610200b5a7d639d91f7df43b1163bf20d8c9318303f19a1262e`
passed all 37 selected Linux tests with zero skips, including 13 synthetic
handoff tests. The log SHA-256 is
`096a4cd4d6dd2ac1e68adba9aaa3c3f318b8436045cf86122635220400d8e96c`.
All 226 baked source files matched their frozen hashes. This did not validate
the physical route; at that checkpoint, independent harness review and supervisor
implementation were still in progress. Counts above are separate runs, not an
aggregate C1 total.

At this earlier checkpoint, required next work was a real authenticated C1 route
with the coordinator and executing stages spanning at least two inventoried
hosts, followed by CT-11 numerical wire capture, interleaving, context limits,
capacity, cancellation, partial admission, restart/boot invalidation, drain, and
confirmed cleanup. The baseline route later passed, but those broader cases remain
pending. See the
[two-device lab guide](../PARTICIPANT_TWO_DEVICE_LAB.md) and [CT-13 checklist](../PARTICIPANT_CONTRACTS.md#acceptance-test-matrix).

No WAN or gateway behavior, GPU execution, pooled-memory usefulness, throughput,
energy, or separate-device speedup is established by this preparation work.

## Later validation and first split-host attempt, 2026-10-18

The laptop and the provided ZimaBlade CPU host are both available. At frozen
source `fa764e1e2f5019dc8fd709fc979d775b2fd0460e482d87bdc13b62ebbf2f1927`
(231 files), each independently passed the full 391-test suite with zero skips:
the local run took 99.774 seconds (log SHA-256
`43b6969ad960e19e4a264a7478ccd6bf7ffedc48ecccdd16123b02f0339398d3`) and the
ZimaBlade run took 374.200 seconds (log SHA-256
`c676e863100d0f79518f93b2a7d5def65cabfae1b7a04ac849a2c5c537cbf27b`). These are
separate host-local suite runs, not cross-host inference and not an aggregate
782-test result.

The original 313-test physical run failed one expiry-attribution assertion; that
failure remains retained. The immutable original-deadline fix was independently
reviewed, an advancing-time regression passed, and the later 391-test runs passed.
This does not explain the older WSL `CLOCK_UNSAFE` event. No clock clamp or global
clock change was made.

After endpoint, report, and configuration changes, source
`f89db5d874235bb153a7ab6b88fb5e2e88c309453c8f7164747503afc83f7679` (234 files)
passed baked-source proof and 146 focused Linux tests with zero skips (log SHA-256
`543fc3d581d9d6ed1ab7cb6671c529f1785c4fae3c944bb88474be5962e0b632`). The 51 core,
worker, and identity files were byte-identical to the `fa764e1` candidate. The
optional host operator environment was clean-installed with hashes and root-
verified; its actual pinned Paramiko 3.5.1 channel check passed. See the
[participant operator README](../../docker/participant-operator/README.md) for
isolated setup and verification instructions.

The first actual split-host supervisor attempt failed locally at `inspect_schema`
because Go-template output used literal backslash-n text where the parser expected
seven lines. The failure occurred before SSH or remote setup; no remote computation
or numerical result was produced. The supervisor retained the candidate container.
The parent independently verified its full Docker identity, stopped that owned
container with exit 143, and removed it. This was not a graceful success. The
failure log SHA-256 is
`d8d5631810b75c2d2394825530dbdbce9cd6bf8a9c409f2361c095effa94ca08`; the parent
cleanup record is `baseline1-parent-cleanup.json`. The next attempt reached bundle
upload but also failed before worker start; at that checkpoint, no end-to-end
launch had passed.

## Second split-host attempt and SFTP preflight, 2026-10-18

At candidate source `09100f11a607`, baseline 2 failed during `bundle_upload` with
`transport_error` after 15.039 seconds, before any remote worker started. The
pinned Paramiko 3.5.1 SFTP mode `x` creates exclusively but does not permit writes.
The resulting empty tar had mode `0644` and remained fenced by cleanup. The local
operator stopped and removed its container with exit 143; this was not graceful
success. The parent independently verified that no worker containers remained and
that the task-owned mode-`0700`, UID-1000 root contained only the zero-byte regular
file, then removed only that root. The retained failure log SHA-256 is
`36428d1b295af631596db860514357578292f424043d774476b308226c6e202d`.

A separate actual Paramiko 3.5.1 SSH public 24-byte sentinel transfer probe passed:
the file had UID 1000, the expected SHA-256, and mode `0600`, and only the scoped
root was removed. The probe used exclusive `wx`, retained the returned handle,
and set and verified mode `0600` with `stat` before writing bytes. Its log SHA-256
is `ddb4484548b8e5b58f72d94586370d04e9b9fde2c1f607a5137fb12325c1eab6`. The
probe ran no Docker or model process and does not
validate supervisor bundle upload, worker startup, or inference. At this
checkpoint, no split-host numerical pass had yet been recorded.

C1 remains unaccepted. The expanded C1b numerical profile and lifecycle gates
remain pending, as do all prior C2–C9 and P0–P8 statuses. No supported GPU,
pooled-memory benefit, speedup, or WAN claim is established. Reports use only `LAN-A` and
`LAN-B`; private network and operator identifiers are intentionally omitted.

## Latest focused validation and third split-host attempt, 2026-10-18

The latest frozen source contains 237 files with SHA-256
`a43f4b573c63abcbbfcd1d7dcabf1ce79c5998e0e39e4081f4921126c176964a`. Its focused
Docker suite passed 163 tests with zero skips (log SHA-256
`6d558fb5f8d59e39ca294b99042fc597653dfbedbd5009051735e562f2fe2549`). The two
earlier 391-test full-suite passes remain separate same-host controls; neither
demonstrates distributed inference.

With pinned Paramiko 3.5.1, the SFTPFile deadline probe transferred 196,589 bytes
in six 32-KiB packets. Normal control, delayed acknowledgement, and expiry between
operations passed with a roughly 500-ms caller cutoff. Outstanding write/close
operations remained owned until actual retirement. The probe made no network
connection (log SHA-256
`ea87ef477dd4edb63affbb34731c972ef0660a300125aa115dd298f4c4e89429`). Initial
timing fixtures failed their own criterion (`0.06 * 6 < 0.5`); a corrected
`0.12`-second-per-packet setup met the individual socket timeout while exceeding
the total deadline. An unraisable GC fixture error was also fixed; subsequent
clean probe runs passed. A distinct real-SSH 24-byte public sentinel transfer
using the new helper verified the expected hash, owner, mode `0600`, and scoped
root removal (log SHA-256
`820b0861349983492e1fdb5fa786b70949820a601308cc91f6c3f31db3056120`). These
transfer checks do not validate bundle launch or inference. Failed-close ownership
review is clear, and a run-level persisted-report race guard was tested; these
are scoped implementation checks, not phase acceptance.

The third actual baseline attempt failed after private bundle extraction at the
bounded `ssh_command/output_bound` step, after 14.887 seconds and before any remote
container launch. Docker image inspection produced 6,243 bytes against a 4,096-byte
bound; selector preparation is underway and has not passed. The local operator
stopped and removed its container with exit 143, not graceful success. The raw
record confirms automatic private-root/file cleanup and zero pending transport
operations. The retained failure log SHA-256 is
`d016f90b73ac7e8531d258e7060d2ffc2bc55db86d2c0495f3be61afac7c1281`. Together
with the two earlier attempts recorded above, all three failures remain retained.
At that checkpoint there was no remote worker launch or cross-host numerical
result. The later baseline pass and subsequent happy-profile failure are recorded
below. No physical pass for the opt-in `c1b-happy-v1` extensions (unequal prompts
5/11, context boundary 1151+1, and local over-limit preflight) is established;
idle heartbeat evidence is not proof of remote route overlap. No hostnames,
addresses, host keys, credentials, or role-key paths are recorded here.

## First split-host baseline pass and expanded-profile failure, 2026-10-18

Actual split-host baseline attempt 6 (`baseline-v1`) later passed on frozen
source `7cb443eed708a88609ba84d2f14746824c796fc1e331858ecfe07c7b1a154e82`, with all
237 baked source files verified. Four requests completed and 27 finite
last-position logit vectors matched the same-stack complete-model reference;
maximum absolute error was `3.445148468017578e-05` (`atol=1e-3`, `rtol=0`).
The two physical CPU hosts ran the coordinator and executing stages across the
split. Processes exited 0 gracefully; local/remote containers, private role
files, and the scoped remote root were removed with strict confirmation. The
47.357-second total includes setup and cleanup and is not a performance
measurement. The complete sanitized record, image digests, limits, report/log
hashes, and evidence boundary are in the [parity report](2026-10-18-participant-two-device-parity.md).

The five earlier failed actual baseline attempts remain retained: inspect framing;
SFTP exclusive-write permissions; image-inspection output over the bound; the
invalid Docker 24 read/write bind field (no worker containers remained and the
parent removed only the strict scoped root); and the deferred coordinator-server
import that reached remote READY and exit 0 but captured zero vectors. Details for
the earlier attempts remain above. The subsequent `c1b-happy-v1` attempt failed
after 37.934 seconds with no cohort summary. Remote READY, exit 0, and cleanup
were observed, but the local operator exited 143 rather than gracefully. Failure
log SHA-256:
`60d81811db007b02c0fe7ad59a7512949d826cdea8e5e36f331dcea870eba200`. No happy
extension or remote-overlap pass is claimed; the failure-location diagnostic
consumer is prepared for parent validation.

C1 remains unaccepted. C1a negative-TLS, CT05 serialization, root-rotation, and
secure lifecycle cases remain open; C1b still needs the expanded profile and
capacity, cancellation, drain, reply-loss, and restart/boot cases. The historic
WSL `CLOCK_UNSAFE` event remains unexplained. No GPU, pooled-memory, WAN,
throughput, or speedup claim follows from the baseline result.
