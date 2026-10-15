# M2: activation protocol and worker session lifecycle

M2 implements the contract in [the runtime plan](PYTORCH_PIPELINE_PLAN.md): a
Protobuf schema, bounded tensor codec, one-stage worker handler, serialized
in-memory transport and a loopback gRPC adapter. It builds on the
[M0/M1 partitions](PYTORCH_RUNTIME.md). [M3 worker services](PYTORCH_WORKERS.md)
extend this handler with queues, private Docker RPC and process supervision.
Coordinator scheduling remains M4 work. This page describes the M2 behavior;
its default in-process handler still rejects busy compute instead of queueing.

## Run the checks

From the repository root with Docker Desktop's Linux engine:

```powershell
docker compose -f compose.pytorch.yaml build prepare
docker compose -f compose.pytorch.yaml run --rm prepare
docker compose -f compose.pytorch.yaml run --rm tests
```

The Compose project retains its existing `steamboat-pytorch-m1` name and volumes.
Its test container has no external network; loopback sockets remain available.
It sets `STEAMBOAT_PROTOCOL_TESTS=1` and both offline model paths. M2 integration
checks fail if those model paths are missing. Without that opt-in variable, M2
tests skip so the historical Petals/dependency-free environment still works.

To run only the lifecycle tests (no model required in this subset):

```powershell
docker compose -f compose.pytorch.yaml run --rm tests python -m unittest discover -s tests/runtime -p test_worker_state.py -v
```

Unique numerical observation reports appear under `.lab/pytorch-results/`.
`STEAMBOAT_PROTOCOL_REPORT` can select a directory or an unused JSON filename;
existing files are never overwritten. The test process exit status establishes
suite success. See [the M2 validation record](experiments/2026-10-14-pytorch-m2.md).

The benchmark CLI still measures the M1 direct in-process adapter. M2's sequential
three-handler test driver is a correctness fixture, not a coordinator scheduler.

## Wire contract

The schema is [worker.proto](../src/steamboat_runtime/protocol/worker.proto).
The [schema guide](../src/steamboat_runtime/protocol/README.md) records the pinned
compiler and regeneration command. No new runtime dependencies were required.

Each request carries protocol version `1` and a bounded timeout. Session operations
also identify the manifest fingerprint, worker boot ID and opaque session ID.
Describe permits unknown model/boot identity for discovery. Every other operation
must match the loaded worker. Open returns a random lease token; later operations
must present that lease. Session IDs are 1–64 ASCII letters, digits, underscores
or hyphens. A new handler generates a new boot ID, invalidating earlier leases.

| Operation | Behavior |
| --- | --- |
| `Describe` | Assignment, identity, readiness, limits and available/live resources |
| `OpenSession` | Reserve positions, set idle lease and fixed maximum lifetime |
| `RenewSession` | Extend idle expiry only, bounded by the original lifetime |
| `Step` | Validate next sequence/absolute position and activation, execute owned layers |
| `CloseSession` / `CancelSession` | End the session; report whether cache reclamation is complete |
| `SessionStatus` | Committed position/sequence, lifecycle state and cache accounting |

A Step starts with sequence zero and position zero. A successful operation advances
the sequence by one and position by `token_count`. Success replies echo the boot,
model, session, lease and operation identity; the client checks them before accepting
the activation. Unknown fields and fields irrelevant to an operation are rejected.

Tensors use shape `[1, token_count, 64]`, layout `batch_sequence_hidden` and dtype
`float32_le`. The payload is exactly `token_count * 64 * 4` contiguous little-endian
bytes. Decoding copies to independent writable storage. Shape, dtype, byte counts,
maximum positions and finite values are checked before creating a Torch tensor.
There is no pickle, arbitrary operator dispatch or executable object payload.

Requests and replies are capped at 1 MiB before Protobuf parsing; gRPC also enforces
its receive/send ceiling. The maximum supported 1,152-position activation needs
294,912 payload bytes. Metadata and tensor fields are validated at the handler
even for direct calls. Error messages are bounded and contain no activations.

Stable errors include `INVALID_INPUT`, `INCOMPATIBLE_MODEL`, `CAPACITY_EXHAUSTED`,
`EXPIRED_SESSION`, `STALE_WORKER`, `OUT_OF_ORDER`, `TIMEOUT`, `EXECUTION_FAILED`,
`CANCELLED`, `CLOSED_SESSION` and `UNKNOWN_SESSION`. Transports return `Response`
objects; `raise_for_error` provides an optional exception interface. Locally invalid
wire payloads/replies raise `ProtocolError` before callers can advance state.

## Lifecycle and bounded execution

Each `StageExecutor` loads only its assigned transformer layers from verified
artifacts. Its `WorkerHandler` owns that stage's session caches. All state transitions
occur on one asyncio event loop; Torch execution runs in a dedicated single thread
with inference mode enabled in that thread. Control operations remain responsive
while computation is blocked. A busy worker rejects another session's Step with
`CAPACITY_EXHAUSTED`; a second in-flight operation for the same session is
`OUT_OF_ORDER`. M2 does not queue compute calls.

The worker admits at most eight sessions with at most 1,152 reserved positions
each, checks the 12,288-position and 16 MiB stage cache budgets, and rejects excess
work. An accepted duplicate Open with the same bounds returns the existing lease;
conflicting reuse fails. Open/Step/Renew refresh idle expiry. Idle leases are at
most 120 seconds, while the lifetime established at Open is at most 300 seconds
and can never be renewed. A periodic task checks expiry at least every five seconds.
Each operation timeout is at most 30 seconds and Step is clipped to the remaining
session lifetime. Only local monotonic time is used for these deadlines.

Close, cancel, timeout or expiry immediately invalidates future work. If compute
is in flight, the response says `reclaimed=false`; the reservation and cache remain
owned until its thread finishes. Late activations are discarded and only then are
cache references cleared. An execution failure after possible mutation invalidates
that session; another session's prefix is preserved. Close/cancel are idempotent.

Completed terminal sessions leave tombstones for 30 seconds, the maximum RPC
lifetime. Default total active-plus-tombstone capacity is 64. Admission fails when
that bound is reached; protected IDs are never evicted early to admit new work.
After expiry an ID may be reused with a new lease, but callers should generate fresh
IDs. Delayed Steps with the old lease cannot operate on the replacement session.

If a terminal operation still has not finished after the configured 15-second
grace, readiness becomes false and `requires_restart=true`. Shutdown waits at most
its supplied/default grace and returns false if compute is still active. M2 does
not terminate a Python thread or restart a process. The process supervisor required
to enforce that recovery boundary is implemented in [M3](PYTORCH_WORKERS.md);
reservations are deliberately retained while a thread might still access their memory.

`allocated_cache_bytes` is exact for idle/finished state. While computing, it reports
the last committed count with `cache_bytes_exact=false`, because temporary/in-flight
allocations are not sampled concurrently. SessionStatus reports that session's bytes;
Describe totals committed bytes across sessions. Counts exclude allocator-retained
RSS, temporary attention buffers and loading peaks. Successful replies measure
thread dispatch delay as `queue_ms` and the actual stage call as `compute_ms`;
wire encoding/decoding is outside compute time. Immediate error/timeout replies
may lack completed timing data. There is no stage queue in this milestone.

## Lost replies and trust

Neither transport automatically retries. A lost reply can mean that computation
already committed. Repeating its sequence produces `OUT_OF_ORDER` and never executes
it twice. The future coordinator must fail that request, close all known leases,
and use expiry for reservations whose Open reply was lost. Querying status is
diagnostic; it does not reconstruct a lost activation or enable transparent replay.

The gRPC adapter binds/connects only to `127.0.0.1`. It supports bounded local
integration tests, with no authentication or public worker deployment. Loopback
results establish protocol correctness, not Internet performance or multi-device
execution. Worker services, supervision and restart integration are the next gate.
