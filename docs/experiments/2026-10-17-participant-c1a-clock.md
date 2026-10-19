# C1a clock diagnostic, 2026-10-17

**Status:** bounded diagnostic evidence only. C1a remains unfinished; this note
does not accept a phase or security gate. See the [local C1a pipeline report](2026-10-17-participant-c1a-local.md)
for the separate numerical and lifecycle evidence and its limits.

## Run and provenance

The predeclared diagnostic requested five fresh cohorts, stopped on the first
failure, and prohibited retries. It stopped after cohort 2. Cohort 1 passed its
single targeted test with no skips; cohort 2 errored in that test with no skips.
These are per-cohort outcomes, not an aggregate suite result.

The recorded Docker run used `linux/amd64`, no network, 2 CPUs, 6 GiB memory,
256 PIDs, a read-only root, dropped capabilities, and `no-new-privileges`. The
verified `/artifacts` and Hugging Face cache volumes were read-only. Offline
Hugging Face/Transformers mode and two-thread OMP/MKL settings were enabled. The
pinned reference was `Maykeye/TinyLLama-v0` revision
`298338802ab94432b917bcce11382aa151aee50f`. The container command was
`python -B /app/.lab/participant-network/diagnose_secure_baseline.py --cohorts 5`;
the exact host argv, mounts, environment and timestamps are in the parent
`baseline-diagnostic-frozen-combined1-five-stop-first-failure-1792272153604.command.json`
record; the batch exited 1 on its first error. The one-test target was
`tests.security.test_secure_pipeline_faults.MutatingStepReplyLossTests.test_consumer_generate_crosses_real_secure_three_stage_pipeline`.

The script SHA-256 is
`781366779edd6c4df052a92ee604ce91f7339beb15684b5d2ca97d2f6bd303f9`; the batch
log SHA-256 is
`53af2c0a9e1a7eb6c7024d68545bcc8b97b833722e9e331ed134b56b9dc88a82`. The
corrected native protobuf scalar-observer probe exited 0 and checked request
session, response code/reclamation, payload-field exclusion, and the cohort cap;
its recorded command is `baseline-diagnostic-v2-native-protobuf-probe-1792272136757.command.json`
and its log SHA-256 is
`d7a452d9c5b7dab5be9e3086ab94e7cef4ef1bf8afb9377c6f6f00ecdee883ed`.

The tested image was rebuilt as
`sha256:0303a40d69c9c737d5ae54ea90a15df553ea92126404c032e06948465e7f0cb4`.
The original image index `sha256:d39b1463b0ea9f5dfafdd81e5eb095d251ace7074f8b31ef8b71bb18a5ac9f5e`
was unavailable and its local cache was partial. The exact frozen 217-file
source was recovered from the verified layer beginning `16185c3c`; a baked-source
proof reported 217 files and no mismatches for digest
`42074fb51d53f15b039d2364561444db3064969fa9fa1669b907effd0a4a40ce` (proof log
SHA-256 `1b7f1690f3bb04c999a0e7647f8db79bdb98a0799a41ac35a4d89fc0a3b2bc6f`). The
rebuilt image retained all 13 dependency layers and matching `Env`, `WorkingDir`,
`Entrypoint`, `Cmd`, and `User` configuration. It is not claimed to be bitwise
identical to the unavailable original image. The corrected protobuf observer and
`asyncio_standard_slow_callback_task_repr_suppressed` log filter are diagnostic
variables, not acceptance evidence.

## Observed clock event

The frozen source already contains a lock around the `Clock.sample` transaction:
the provider read, anomaly checks, and latch updates occur under the same lock.
`Clock.system` uses the configured wall and monotonic providers; their defaults
are `time.time` and `time.monotonic`. The diagnostic wrapped the original
`Clock._read` and `Clock.sample`, delegating to each exactly once. It did not add
provider reads, make authorization calls, clamp time, or substitute a provider.

In cohort 2, retained event n155 recorded `CLOCK_UNSAFE` with
`wall_delta_seconds=-0.00011920928955078125` (about -0.119 ms) and
`monotonic_delta_seconds=0.0011910110006283503` (about +1.191 ms),
`fault_latched=true`, and `restart_required=false`. This is direct evidence that
the supplied wall reading moved backward in this reproduction while monotonic
time advanced. The event sequence then recorded guard revocation, Step and
CancelSession `ProtocolError/EXECUTION_FAILED`, and coordinator cleanup
`cleanup_complete=false`; some remote CancelSession calls returned reclaimed,
but cleanup as a whole remained unconfirmed.

The clock rejection and subsequent fail-closed behavior are measured. The
inference is limited to this cohort: the observed rollback is consistent with
the request entering the clock-failure path. The observer did not introduce a
sampling interleaving, but this does not identify why the wall provider returned
a lower value. The WSL, kernel, hypervisor, and NTP/time-service mechanism remains
unknown; this result does not explain every earlier clock or cleanup failure.
No retries, global clock changes, or fake healthy provider were used.

## Remaining limits

This diagnostic is not a complete security run and does not establish C1a
acceptance. The later consolidated attempt ran 289 tests with zero skips and one
error in a PartialOpen baseline before injection: backward-clock rejection and
unconfirmed cleanup. Subsequent scoped repair checks do not override that failed
run; see the [local evidence record](2026-10-17-participant-c1a-local.md).
C1b still requires access to a second physical host, an
authenticated route, and a stable trusted-clock dependency. Their absence does
not diagnose or prove the cause of this local wall-clock observation. C3 GPU
work remains later scope; no GPU, separate-device inference, WAN route, or
participant-cohort result is claimed here.
