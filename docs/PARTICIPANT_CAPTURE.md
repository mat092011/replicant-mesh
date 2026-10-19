# Participant last-position capture

Capture is an opt-in validation path for one last-position logit vector. It is
not full-prefill capture, a performance feature, or a physical memory limit.
C1a remains under validation; C1 remains pending.
The wire contract and trust boundaries remain those in
[PARTICIPANT_CONTRACTS.md](PARTICIPANT_CONTRACTS.md#last-position-logit-capture-and-communication-reservations).

## Fixed bounds

The pinned vocabulary is `V = 32000`. A finite float32 value is budgeted at up
to 32 JSON bytes; the event envelope adds 4096 bytes:

```text
L = V * 32 + 4096 = 1,028,096 bytes
```

This is below the unchanged 1 MiB message ceiling. The coordinator checks the
actual serialized event size and rejects nonfinite, wrong-shape, or oversized
vectors; it does not truncate. Only the last input position may be captured
over the wire. Full-prefill logits remain in-process only.

For output queue size `Q` from 0 through 16, each active capture reserves:

```text
(Q + 2) * L
+ (Q + 2) * (V * 4 + 512)
+ 2 * (V * 32 + 128)
+ 2 * L
+ 64 MiB transport/allocator headroom
```

At `Q = 16`, this is 92,032,256 logical bytes per capture and 736,258,048 for
eight captures. The default owner pool is 1 GiB. These are conservative
accounting values, not a measured RSS bound or proof of physically exclusive
memory. Separate shared-pool enforcement remains a distinct dependency.

## Service wiring

The owner constructs `CaptureBudget` for the coordinator's actual output queue
and passes it to `SecureCoordinatorService` or
`create_secure_coordinator_server`:

```python
from steamboat_runtime.capture_budget import CaptureBudget, CaptureBudgetConfig
from steamboat_runtime.secure_coordinator_service import SecureCoordinatorService

budget = CaptureBudget(CaptureBudgetConfig(
    output_queue_slots=coordinator.limits.output_queue_tokens,
    capacity_bytes=1 << 30,
    max_active_captures=8,
))
secure_service = SecureCoordinatorService(
    service,
    authorizer=authorizer,
    authorization_watcher=authorization_watcher,
    request_context_factory=request_context_factory,
    capture_budget=budget,
)
```

Capture requests fail before request-context creation or model submission if no
owner budget is configured, or if the actual manifest vocabulary / queue size
does not match the budget. Noncapture requests remain available without a
capture budget. Reservation occurs before coordinator submission or capture
materialization. The peer cannot choose `V`, `Q`, pool capacity, or active
capture count.

## Reclamation and failure behavior

The ledger is released only after request cleanup and descendants complete,
the actual supervised CPU operation retires, the coordinator confirms the
session/output references are reclaimable, trusted context-factory release
completes, and authorization closure returns successfully. Capture buffers
move to `cleanup_pending` at cleanup start and remain charged while any of
those steps is pending. One Generate owner waits for guarded operations and
cleanup descendants, reclaims coordinator references, awaits context-factory
release, then awaits authorization closure. The slot keeps a strong reference
to the trusted context, capture lease, and both stream reservations until close
is confirmed; a slow, failed, or ambiguous close fences the service and retains
all accounting. Only that owner decrements the secure service stream count.
`CoordinatorService._finish` retains its original decrement by default; secure
Generate opts out so cleanup cannot decrement the same slot twice. Merely
observing `Task.done()` or a terminal response is insufficient.

On write failure, `CoordinatorService._write` clears its local event, encoded
payload, and write-task references. At the bounded write boundary it follows
cause/context exception chains and scans retained traceback-frame locals with
one shared 4096-node budget and cycle checks. The scan follows only exact
built-in tuple, list, dict, set, and frozenset containers; it invokes no custom
getters or iterators and does not inspect the Python heap or arbitrary objects.
It clears only completed frames whose local container graph reaches the exact
event, encoded payload, or write task, preserving unrelated frames. It fails
closed if the write task is live, a container subclass or scan bound makes
ownership ambiguous, or a relevant frame cannot be cleared. The secure stream
wrapper clears its payload reference as it exits. This includes timeout
conversion chains where `TimeoutError` retains a cancelled writer traceback.
The installed gRPC writer remains a trusted boundary; this reference scan is
not a physical RSS limit, which requires separate process memory enforcement.

If reclamation, context release, task completion, or authorization close is
failed or uncertain, the slot and authorization remain strongly owned, the
capture bytes remain reserved, and the service fences new work as unavailable.
Nested `SecureTaskPending` task roots and recursively reported late descendants
remain discoverable from the retained slot and runtime pending-task registry;
retirement of the reported tasks does not by itself confirm reclamation or free
accounting. The Generate caller waits at most the secure cancellation grace for
its final cleanup owner. If cleanup remains live or finishes unconfirmed, the
RPC raises an explicit `SecureTaskPending` outcome while leaving that owner
uncancelled and the service fenced. Actual request cancellation still propagates
as cancellation while the cleanup owner remains retained. There is no
time-based release, queue drain during live production, or claim that Python
can terminate a blocked CPU thread. An unconfirmed owner requires
operator/supervisor recovery; do not mark the service ready or free the lease by
administrative guess.

## Tests and limits

`tests/security/test_secure_capture.py` contains unit-only fake seams for
configuration mismatch and noncapture compatibility, eight-versus-nine
admission, a full 16-item queue with cancellation-resistant production,
repeated request cancellation, held and failed reclamation, direct and
`wait_for` timeout exception-chain write failures, nested tuple/list/dict
traceback references and scan exhaustion, late descendants from an already
observed `SecureTaskPending`, the real `_run_guarded` pending-ownership path,
slow/failed authorization closure, and the combined context/capture/stream
owner. A real `generate_rpc` unit flow with no transport deadline covers bounded
final cleanup and request cancellation while the owner remains blocked. A
focused service-counter test preserves the plaintext `_finish` default and
checks secure deferred ownership. Its
opt-in `STEAMBOAT_COORDINATOR_TESTS=1` case uses the actual `StageExecutor`,
`WorkerHandler`, `Coordinator`, and supervised CPU model against existing
offline artifacts. If the flag is set without artifact/reference paths, setup
fails rather than silently skipping the required integration case. For example,
in the prepared Linux test environment:

```sh
STEAMBOAT_COORDINATOR_TESTS=1 \
STEAMBOAT_ARTIFACT_DIR=/artifacts \
STEAMBOAT_REFERENCE_DIR=/reference \
python -m unittest tests.security.test_secure_capture
```

On this Windows host, the documented unit run collected 26 tests: 25 passed and
the opt-in model case was skipped. Because `google.protobuf` is unavailable, it
used in-memory import-only stubs for protocol modules and generated message
classes. It validates unit seams, not real protobuf, gRPC, TLS, or network
behavior; the bounded traceback scanner was also directly exercised.

A separate parent-recorded Linux component run passed 3 tests with zero skips,
including two real CPU-model capture cases. Its source manifest covered 211
files (digest
`ca4c074c4f43c0839a753705d8fafad11323680c686a61132dcf7578f664caab`), and the
image was `sha256:bb00d80b50b8a51b44ecbe0f55823b339aa8d6790a2c0831d399f4bb2ee42b3e`.
The test log SHA-256 was
`debf4d77d25e76a1142f8f9adf2a13fe44d85847d126a7ac4d385a0c9194cd0c`. The
container had a 6 GiB memory limit and two CPUs. The supervised coordinator,
three StageExecutors, WorkerHandlers, scheduler, output queue, and capture
reclaimer were real, but authorization metadata and worker transport were fake
and in-memory; this did not exercise TLS or socket backpressure.

Observed process RSS was 413,364,224 bytes baseline and 425,553,920 sampled
peak for the pending-supervised-CPU-future case; the full-queue/stalled-writer
case measured 471,396,352 baseline, 472,772,608 sampled peak, and 475,500,544
process high-water bytes. These are one-run observations under the stated
container limits, not an acceptance threshold, worst-case bound, or physical
enforcement guarantee. Sampling may miss short peaks; the 1 GiB CaptureBudget
remains logical accounting, not general RSS enforcement.

Separately, the recorded real-model TLS matrix passed one test with zero skips
and compared exactly 27 last-position vectors: prompt lengths 1, 128, and 1024,
each with nine output positions, against the complete-model reference; greedy
token IDs were checked separately. This numerical TLS matrix is not the
component stalled-writer test and does not establish capture socket-fault or
general memory behavior. Two newer fault cases exercise caller-boundary
conditions, not raw socket faults, and still require Linux combined validation.
Later source changes and retained combined-suite fixture/cleanup failures mean
these subset results do not establish C1a or C1 acceptance. No GPU, separate
device, WAN, or general physical RSS bound is established.
