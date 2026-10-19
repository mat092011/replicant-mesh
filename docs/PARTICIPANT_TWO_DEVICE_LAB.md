# Participant two-device lab

**Status, 2026-10-19:** C1 validation and exit criteria were accepted by the
parent after Trial 78 passed 878 unique required cases with zero skips,
failures or errors in 367.862 seconds. The full software regression ran on the
laptop; separate bounded evidence covers physical RST7, Drain4 and Remove4.
Trial 76, Native ZimaBlade run 3, Trial 77 and full-history DIAG3 failures
remain recorded with unknown causes; Trial 78 does not explain them, and no
hardware cause is established. See the [C1 final validation
record](experiments/2026-10-18-participant-c1.md) for exact full-run and
physical source/image identities and limits, and the [separate-device
report](experiments/2026-10-18-participant-two-device-parity.md) for route
evidence. The maintainer requested stopping after C1; C2–C9 and research
P0–P8 retain their prior statuses.

The acceptance target is [CT-13 in the contract test matrix](PARTICIPANT_CONTRACTS.md#acceptance-test-matrix):
the executing coordinator and route stages must span at least two inventoried
physical hosts. A second host running only a thin client, or an unused registered
worker, does not satisfy it. Use `LAN-A` and `LAN-B` as sanitized names in reports;
publish no private addresses, host identifiers, SSH material, credentials, or
protected file paths. The current bounded evidence is in the
[preparation report](experiments/2026-10-18-participant-two-device-preparation.md)
and the [first split-host parity report](experiments/2026-10-18-participant-two-device-parity.md).

## Available worker process

The fixed-assignment worker CLI currently implemented in this candidate is
started with:

```text
python -m lab.secure_worker --config /run/steamboat/worker.json
```

This is a nonproduction worker process for the pinned three-stage assignment,
not a general participant daemon or remote administration interface. The strict
JSON object is bounded to 16 KiB and closed-schema version 1. Its exact required
keys are:

```text
schema_version, protected_root, account_id, device_id, boot_id,
assignment_id, worker_name, model_id, model_revision, manifest_fingerprint,
listen_ip, listen_port, clock_uncertainty_seconds, certificate_path,
private_key_path, cohort_ca_path, snapshot_verification_key_path,
signed_snapshot_path, artifact_directory, acceptor_directory, status_report_path
```

The parser rejects duplicate, missing, or unknown keys, nonfinite values, invalid
typed IDs, unsupported worker names or model revisions, and invalid paths. The
three worker names are `worker-1`, `worker-2`, and `worker-3`. `listen_ip` must
be a canonical private or loopback IPv4 literal and the port must be explicit.
The clock uncertainty value must be finite, positive, and no greater than 30
seconds. All path values must be absolute and satisfy the parser's containment
rules; credential and policy paths are distinct and remain under the protected
root, while model artifacts are outside it. This list contains field names only:
do not commit an operational JSON file or any path values.

For the optional isolated host-side SSH environment and its pinned verification
procedure, see the [participant operator README](../docker/participant-operator/README.md).

## Operator setup and launch bounds

- Create the protected configuration root for the worker owner with mode `0700`;
  keep its configuration, leaf certificate, role private key, public CA,
  snapshot-verification key, and signed snapshot owner-only with mode `0600`.
  Use offline operator enrollment. A participant receives only its role key and
  the public CA/verifier/signed snapshot material. CA signing keys stay with the
  trusted operator and are never copied into a participant deployment.
- Mount the pinned artifact tree read-only. The CLI checks that the mount is
  actually read-only using `statvfs`, rejects links and special files, and checks
  the artifact manifest and hashes before starting the runtime. Keep artifacts
  and caches read-only; do not use peer-supplied code or automatic retry after an
  ambiguous operation.
- Use the exact configured numeric IPv4 identity. TLS verification checks the
  IP subject alternative name and the pinned expected leaf on the actual
  channel. Do not substitute DNS, a hostname override, a same-CA leaf, or a
  transport bypass.
- A trusted external supervisor must enforce a 60-second startup watchdog, a
  15-second termination watchdog, and host cgroup limits. The worker status
  reports that these limits are externally configured; it does not verify or
  enforce them itself.
- Treat stale or unknown status, readiness, cleanup, or resource ownership as
  unavailable. Do not infer cleanup from a process exit request. Retain the
  owner's fence until trusted observation confirms reclamation.
- Set a positive clock-uncertainty bound no greater than 30 seconds only from
  an operator-approved time source and explicit uncertainty budget. Observed
  samples with no backsteps are not a stability guarantee. Never use zero
  uncertainty, clamp a rollback, or change host time as part of this lab.

## Evidence boundary

The worker's active-grant and unknown-readiness repairs passed scoped independent
source review. Earlier corrected policy/identity/worker and synthetic-handoff
subsets passed their recorded Linux checks; these are implementation evidence, not
physical-device parity. Bounded physical baseline and lifecycle checks passed.
The required full software regression also passed; C1 acceptance is recorded in
the final validation report.

At the frozen 231-file source, local and ZimaBlade each passed the full 391-test
suite with zero skips. The runs took 99.774 and 374.200 seconds respectively.
These were separate host-local test runs, not a single distributed inference or
numerical route. The later 234-file endpoint/report/configuration candidate passed
baked-source proof and 146 focused Linux tests with zero skips. Its 51 core,
worker, and identity files were byte-identical to the earlier green source. Exact
source digests and log hashes are in the [preparation report](experiments/2026-10-18-participant-two-device-preparation.md).

An earlier frozen source contained 237 files (SHA-256
`a43f4b573c63abcbbfcd1d7dcabf1ce79c5998e0e39e4081f4921126c176964a`) and passed
163 focused Docker tests with zero skips (log SHA-256
`6d558fb5f8d59e39ca294b99042fc597653dfbedbd5009051735e562f2fe2549`). This is
historical evidence; the two
391-test runs remain same-host controls only.

The first actual split-host `baseline-v1` pass used frozen source
`7cb443eed708a88609ba84d2f14746824c796fc1e331858ecfe07c7b1a154e82`; all 237
baked source files were verified. The local and remote image digests were
`89fdd183f21ff2111e552815e1724b0d4a55d715cb3ebb33a020693d7effd90c` and
`744e039505deef2647c83bc9e92c786b87825b9a440edfba2cfce8dc59b068de`. The laptop
host ran consumer, coordinator, embeddings/head, full-model reference, and workers
1/2; the separate Celeron N3450 CPU host ran worker 3. Resource caps were 2 CPUs,
6 GiB, and 256 PIDs locally, and 2 CPUs, 3 GiB, and 128 PIDs remotely. Both hosts
used the same pinned TinyLlama revision, manifest, Torch `2.14.1+cpu`, Transformers
`5.19.0`, float32, eager attention, and no compression. C0 mTLS protected the
invited worker route; SSH was only trusted administration, not the inference
route.

Four requests completed: the synthetic greedy `[7, 13, 31]` one-token control and
forced-feedback prompts of lengths 1, 128, and 1024. The patterned prompt tokens
used `3 + ((i * 37 + 11) % (32000 - 3))`; eight identical forced continuations
yielded nine last-position vectors per prompt, 27 total. Logits were finite and
greedy/forced-feedback outputs matched; maximum absolute error was
`3.445148468017578e-05` against `atol=1e-3`, `rtol=0`. Actual local and remote
processes exited 0 gracefully; containers, private role files, and the scoped
remote root were removed with strict confirmation, and no transport owners
remained. The 47.357-second wall time includes SSH, bundle, startup, computation,
and cleanup; it is not an inference-latency or throughput benchmark. The sanitized
[parity report](experiments/2026-10-18-participant-two-device-parity.md) records
the report and command-log hashes, separate M1/M2 controls, and limitations.

The optional host operator environment was clean-installed with hashes and
root-verified; the actual pinned Paramiko 3.5.1 channel check passed. See the
[participant operator README](../docker/participant-operator/README.md) for its
isolated environment instructions.

A pinned Paramiko 3.5.1 SFTP deadline probe transferred a 196,589-byte fixture in
six 32-KiB packets. Normal, delayed-acknowledgement, and expired-between-operations
cases passed with a roughly 500-ms caller cutoff; in-flight write/close ownership
was retained until actual retirement. This probe made no network connection
(log SHA-256
`ea87ef477dd4edb63affbb34731c972ef0660a300125aa115dd298f4c4e89429`). Earlier
probe setup attempts did not satisfy the timing criterion, and an unraisable GC
fixture error was corrected before the clean runs. A separate real-SSH 24-byte
public sentinel transfer and scoped-root removal passed (SHA-256
`820b0861349983492e1fdb5fa786b70949820a601308cc91f6c3f31db3056120`); it did not
run Docker or a model.

Five failed actual baseline attempts remain retained: `inspect_schema` framing;
SFTP exclusive-write permission; image-inspection JSON over its bound; an invalid
Docker 24 read/write bind field (with no surviving worker container and scoped
root removal independently confirmed); and a deferred coordinator-server import
that reached remote READY and clean exit but produced zero vectors. The first
three attempt details and logs remain in the preparation chronology. A later
`c1b-happy-v1` run failed after 37.934 seconds with no cohort summary: the remote
worker reached READY and exited 0 with cleanup confirmed, but the local operator
ended with exit 143 rather than graceful success. Its failure log SHA-256 is
`60d81811db007b02c0fe7ad59a7512949d826cdea8e5e36f331dcea870eba200`. No happy
extension or remote-overlap claim follows from that run. The bounded
failure-location diagnostic is prepared for parent validation. No hostnames,
addresses, host keys, credentials, or role-key paths are recorded here.

The first actual split-host supervisor attempt failed locally in `inspect_schema`
because Go-template output contained literal backslash-n text instead of the
expected seven lines. It failed before SSH or remote setup; no remote computation
or numerical result exists. The supervisor retained the candidate container, which
the parent independently identity-checked, stopped with exit 143, and removed.
That cleanup was not graceful success. In the second attempt, baseline 2 failed at
SFTP `bundle_upload` after 15.039 seconds because pinned Paramiko 3.5.1 mode `x`
was exclusive but not writable. No remote worker started; the empty tar was
fenced, and the local operator's container stop/removal with exit 143 was not a
pass. A separate 24-byte public sentinel transfer probe verified the corrected
0600-before-write flow and scoped-root cleanup, but did not run Docker or a model.
The two failed attempts and their exact logs are retained in the
[preparation report](experiments/2026-10-18-participant-two-device-preparation.md).

The original 313-test physical run failed one expiry-attribution assertion. The
immutable original-deadline fix was independently reviewed, an advancing-time
regression passed, and later 391-test runs passed; the earlier failure remains in
the record. The historical WSL `CLOCK_UNSAFE` event also remains unexplained; no
clock clamp or global clock change was made. At that earlier preparation point,
C1a acceptance remained open for the
actual C0 negative TLS matrix, CT05 serialization extremes, root-rotation operator
API, and secure cancellation/socket-disconnect/changed-boot/interleaving evidence.
At that point C1b still required the expanded numerical profile and eight/ninth
capacity, cancellation, drain, Open/Step/reply-loss, and restart/boot invalidation
cases. Subsequent numerical, interleave and cancellation passes are recorded
in the separate-device report. Since this earlier preparation status, physical
partial-admission, capacity, and Step reply-loss runs passed, while restart,
owner drain and signed identity removal/revocation remain open. Trial 68 adds
native component evidence only; it is not physical restart or Remove evidence.
No supported GPU, pooled-memory benefit, WAN performance, or separate-device
speedup is established. See the [preparation report](experiments/2026-10-18-participant-two-device-preparation.md)
for dated evidence and retained failures.

Trial 68 passed all 311 required Linux tests with zero skips in 35.658 seconds
of unittest runtime (not inference performance). The 298-file source inventory
and matching ZimaBlade overlay are pinned in the [Trial 68 evidence](experiments/2026-10-18-participant-c1a-followup.md#trial-68-current-required-component-gate).
The Trial 67 `RST5-diag1` command at 19:44 UTC was an actual on-host diagnostic;
a separate offline copy-only analysis later found a 20-versus-11-field
projection mismatch at `secure_cohort_supervisor.py:2411`. That analysis does
not establish the original RST5 cause. Physical RST6 failed during the old
cohort's first baseline with `RemoteError` and no error code, before generation
two. The old remote exited 0 and was removed; the local operator exited 143.
The consolidated Trial 69 gate later completed 825 required tests with zero
skips and one failure: a fenced cancellation child hit `CLOCK_UNSAFE` during
baseline generation before the cancellation hook, leaving teardown unconfirmed
and one capture reservation. Its cause is unknown and does not diagnose RST6.
At the Trial 69 checkpoint, the final integrated owner-profile full regression,
restart, drain/removal, and C1a/C1b/C1/P2 acceptance remained open. See the [Trial 69 record](experiments/2026-10-18-participant-c1a-followup.md#trial-69-consolidated-required-linux-gate)
and [RST6 record](experiments/2026-10-18-participant-two-device-parity.md#required-component-gate-and-physical-restart-run-6).
