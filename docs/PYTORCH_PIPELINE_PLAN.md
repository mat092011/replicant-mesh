# Plan: an owned PyTorch pipeline runtime

Status: proposed implementation, 2026-10-13. No replacement runtime is implemented
by this document. The working Petals lab and its measured results are preserved
on `main` at `9723c1b`; this plan starts from that commit.

## Objective and scope

Replace Petals in the primary execution path with three small PyTorch worker
services, an explicit session protocol, and a coordinator that schedules
independent requests. Reuse the existing Docker network simulation, workload
fixtures, complete-model comparisons, and reports. Keep Petals available as an
optional historical baseline with isolated dependencies.

The replacement makes layer execution, cache ownership, queueing, and failure
behavior directly inspectable. The existing [smoke report](experiments/2026-10-13-local-lab.md)
provides comparison evidence; it does not validate the proposed runtime.

The first implementation supports only the pinned tiny Llama checkpoint, CPU
float32, eager attention, unpadded batch size one per session, and fixed layer
assignments. Dynamic batching, chunked prefill, GPUs, BLOOM, direct worker links,
discovery, migration, automatic recovery, credits, and public internet deployment
remain later work. Pipeline overlap comes from different sessions; consecutive
tokens from one session remain dependent.

## Target architecture

| Component | Responsibility |
| --- | --- |
| Preparation job | Download the pinned checkpoint and prepare verified weight slices and a manifest |
| Client / benchmark driver | Submit public fixtures, record admission-inclusive latency and received tokens |
| Coordinator | Own tokenization, embeddings, final normalization, output head and sampling; manage sessions and stage queues |
| Worker 1 | Execute global layers `[0,3)` and own their session KV caches |
| Worker 2 | Execute global layers `[3,6)` and own their session KV caches |
| Worker 3 | Execute global layers `[6,8)` and own their session KV caches |

Use the existing checkpoint and tokenizer revision:
`Maykeye/TinyLLama-v0` at `298338802ab94432b917bcce11382aa151aee50f`.
The manifest must prove that assignments cover all eight layers exactly once,
without gaps or overlaps, and that every component uses the same model identity.

The coordinator sends a tensor to worker 1, receives its output, sends it to
worker 2, and then worker 3. It applies the final normalization/head and selects
the next token. That token's embedding starts the next step for that session.
This preserves the current Petals lab's client-mediated activation route and
component placement. Measure direct stage-to-stage forwarding separately later.

Workers keep only their assigned weights resident. The coordinator retains only
its input/output components. Slice safetensors during preparation, record hashes,
and load offline; do not keep a complete model in every worker. Report temporary
loading peaks as well as steady-state weight and cache memory. Account explicitly
for tied input/output weights and for the tiny model's large client-side share.

Use PyTorch with a narrowly scoped Transformers Llama adapter, rather than writing
attention kernels. Proposed transport is asynchronous gRPC with Protobuf metadata
and bounded raw tensor bytes. Select and pin supported package versions in M0;
these are design choices to validate, not claims of tested compatibility.

## Milestones and acceptance gates

All milestones below are pending. Complete each gate before depending on it.
They implement parts of research phases P0–P3 in [PLAN.md](PLAN.md); they do not
complete the separate-device or pooled-memory research gates.

### M0 — Freeze interfaces, resource limits, and comparisons

1. Define a backend-neutral session interface used by `lab/benchmark.py`: open,
   prefill/decode step, close, and diagnostic status. Preserve existing CLI behavior;
   add an explicit backend selection for pipeline runs without importing Petals
   in the new runtime's dependency path.
2. Freeze the model manifest, assignments, dtype, attention implementation, tensor
   layout, timing boundaries, fixture token IDs, and output-length/EOS policy.
3. Select supported PyTorch, Transformers, gRPC, and Protobuf versions, build the
   CPU image, resolve and lock its Python dependencies, and record the base-image
   digest. Keep legacy Petals dependencies in a separate image/environment.
4. Set initial hard limits: eight active sessions, 1,152 input positions per
   session, one active compute call per worker, eight queued stage operations,
   and 32 waiting coordinator admissions. Reject excess work explicitly.
5. Set explicit experimental time bounds: 30 seconds waiting for admission,
   300 seconds from submission to request completion (including admission), and
   at most 30 seconds per RPC, clipped to the remaining request budget. Bound the
   outgoing token queue to 16 tokens; cancel a consumer whose full queue does not
   drain within 30 seconds. Treat these as configurable limits, not performance
   targets.
6. Give worker sessions a 120-second idle lease, checked at least every five
   seconds. Accepted open/step/renew operations renew it; an explicit renewal every
   30 seconds keeps an admitted session alive while waiting in coordinator queues.
   Stop renewing on termination. Renewals cannot extend the session's maximum
   lifetime, set at open from the remaining request budget. Give cancelled or
   timed-out compute at most 15 seconds to finish before a supervisor outside the
   compute process terminates/restarts that worker and invalidates all its leases.
   Bound tensor/message bytes from the accepted shape before allocation and freeze
   a transport message-size ceiling.
7. Require a pre-run correctness gate. Start with the existing provisional
   `atol=1e-3, rtol=0`; establish a tighter bound where repeated local controls
   justify it. Never relax a failed comparison silently.

**Deliverables:** interface and manifest specification, resource-budget table,
dependency lock, proposed commands marked as such until runnable.

**Gate:** configuration rejects gaps/overlaps, wrong checkpoint hashes, unsupported
model architectures/dtypes, and impossible resource reservations. The new image
can import its required runtime without Petals, Hivemind, or bitsandbytes.

### M1 — Prove a partitioned model in one process

1. Implement the Llama layer adapter and weight loading for the three fixed slices.
   Keep a complete-model reference using the exact same new software stack.
2. Preserve absolute token positions, RoPE behavior, causal masks, and the entire
   committed prefix during decode. Map cache indices consistently between a
   stage's local list and the checkpoint's global layer numbers; never assume
   that global layer 3 becomes cache layer 0 without adapting both sides.
3. Keep KV state explicit per session and per owned layer. Expose logical cache
   length, reserved positions, and allocated bytes for tests and measurement.
4. Run all three slices sequentially in one process before introducing RPC.
   Compare every prefill-position logit and each forced decode-position logit
   with the complete model, including prompts of 1, 128, and 1,024 tokens.
5. Test two interleaved unequal-length sessions and exact context boundaries.
   Compare greedy sequences separately and record close competing logits when
   selection differs; forced-token checks always use identical contexts.

**Deliverables:** model adapter, partitioned reference, numerical fixtures/tests.

**Gate:** all comparisons meet the frozen tolerance with finite logits. Parameters
reside only in their intended component, cache positions advance correctly, and
closing one session does not change another session's results.

### M2 — Define and implement the protocol and cache lifecycle

Implement the contract below against an in-memory worker handler first, then the
binary transport. No Python pickle, `torch.load` on received bytes, arbitrary
operator names, or executable payloads are allowed in the protocol.

| Operation | Required behavior |
| --- | --- |
| `Describe` / `Ready` | Return protocol/model identity, worker boot ID, assigned range, supported shape/dtype, limits and available capacity; ready only after weights are loaded and checked |
| `OpenSession` | Accept an opaque session ID, requested maximum positions and lease; reserve cache capacity; return worker boot ID and a session lease token |
| `RenewSession` | Renew a live lease within its original lifetime budget; never resurrect expired, cancelled or closed state |
| `Step` | Validate identity, lease, sequence number, absolute start position and tensor envelope; execute only this worker's fixed layers; return activations and committed end position |
| `CloseSession` / `CancelSession` | Idempotently mark closed/cancelled, discard queued work, and release caches safely; acknowledge when reclamation is complete |
| `SessionStatus` / metrics | Expose session state, committed positions, reservations, active operations, allocated cache bytes and errors |

Every step carries protocol version, model/manifest fingerprint, worker boot ID,
session ID and lease token, operation sequence, absolute start position, token
count, shape, dtype, byte count, and a bounded timeout budget. Use contiguous
little-endian float32 tensors shaped `[1, token_count, hidden_size]`; reject
unknown layouts and inconsistent lengths before conversion or allocation.
Responses echo operation identity and report local queue/compute durations.
The coordinator tracks the end-to-end deadline on its own monotonic clock and
passes remaining budgets; workers use local monotonic timers, not remote clock
values. Report explicit invalid-input, incompatible-model, capacity-exhausted,
expired-session, stale-worker, out-of-order, timeout, and execution-failed errors.

Enforce these state rules:

- A step is legal only for the next sequence number and when its start position
  equals that stage's committed cache length. Enforce the reserved context bound.
- At most one operation mutates a session's cache at a time. Validate the complete
  envelope before mutation. If execution fails after possible mutation, invalidate
  the session; do not pretend the cache was rolled back.
- Version one does not retry `Step` automatically. A timeout can mean that a worker
  already advanced its cache. Fail that request and close its sessions on every
  worker; never blindly resubmit or emit a token twice. Later retries require
  bounded replay receipts and payload-identity checks as a separate feature.
- Duplicate open with the same session parameters returns the same reservation;
  conflicting reuse fails. Duplicate close/cancel is safe. Keep bounded closed
  session tombstones for the RPC lifetime so delayed messages cannot reopen state.
- Cancellation/expiry marks an in-flight operation for discard; it cannot forcibly
  interrupt a PyTorch kernel. Release cache only after that operation finishes.
  Reject subsequent steps and suppress late outputs. Supervisory process restart
  handles a wedged worker, invalidating all sessions on that worker.
- A new boot ID after restart invalidates prior leases. Idle expiry recovers
  abandoned reservations; coordinator loss cannot keep caches indefinitely.

**Deliverables:** `.proto` schema, tensor codec, worker state machine, contract tests.

**Gate:** malformed/oversized tensors, wrong identities, duplicated/reordered
steps, context overflow, stale leases and expiry cannot corrupt another session.
Test lost responses and cancellation during compute. Logical allocations and
reservations return to baseline after cleanup; allocator-retained RSS is reported
separately from live cache ownership.

### M3 — Serve the three fixed workers

1. Package the model adapter and protocol handler as one worker image configured
   by a fixed assignment. Load weights once at startup and keep them resident.
2. Separate the network event loop from inference execution. Allow one active
   compute operation per worker and a bounded queue; expose queue time and cache
   reservations. Set inference mode in the actual execution thread. A supervising
   process must remain able to terminate a wedged inference process after the
   declared grace period; an event-loop timeout alone is insufficient.
3. Start three processes, then three Docker containers. Resolve workers through
   static Compose DNS names and the manifest; the new path needs no DHT/bootstrap.
4. Enforce readiness checks for loaded weights and correct assignment. Shutdown
   stops admission, discards queued work, and closes outstanding sessions safely.
5. Add process-level integration tests for refusal, disconnect, worker restart,
   and expiry. Restart invalidates affected requests explicitly; recovery/replay
   is outside this first implementation. Exercise renewal while queued and expiry
   after coordinator loss; verify watchdog termination and invalidation when
   cancelled compute exceeds its 15-second grace.

**Deliverables:** worker entry point/image, readiness and diagnostics, integration tests.

**Gate:** the three remote stages match M1's forced-token outputs and stay within
configured CPU, memory, queue and session bounds. A missing or incompatible worker
prevents admission; a failed worker produces a bounded error rather than a hang.

### M4 — Coordinate and schedule independent requests

1. Place tokenization, embeddings, normalization, output projection and greedy
   sampling in the coordinator. Keep the public benchmark/client thin.
2. Admit a session only after all three workers reserve capacity. If any worker
   refuses, release earlier reservations; if a response is lost, close the known
   session ID best-effort and rely on bounded lease expiry as the final cleanup.
3. Track each request's current token position and next stage. Maintain FIFO stage
   ready queues with one outstanding step per session and one active call per
   worker. While worker 2 handles session A, worker 1 may handle session B.
4. Advance a session to the next stage only after validating its response. Emit
   the sampled token only after the final stage completes. Feed that token back
   before scheduling the next decode step for that session.
5. Bound the admission queue and apply backpressure at every stage. Propagate
   deadlines and client cancellation across all reservations and queued work.
   Bound the outgoing token queue too; cancel clients that do not consume results.
6. Keep prompts bounded and unchunked initially. FIFO fairness operates at stage
   call boundaries and cannot preempt a long prefill. Record that limitation and
   test that later requests make progress; batching/chunking require a new gate.
7. Record stage-dispatch/response events on the coordinator's monotonic clock and
   local compute spans on workers. On this same-host lab, anchor spans using a
   verified shared monotonic time base before claiming compute overlap. On real
   hosts, account for clock alignment uncertainty; throughput alone is not proof.

**Deliverables:** coordinator, bounded scheduler, session ownership and traces.

**Gate:** 1, 3, and 8 concurrent requests produce the reference results, with no
cross-session state, repeated output tokens from retries, or starvation. Partial
admission, cancellation, slow clients and worker failure release resources within
the declared bounds. A trace demonstrates useful work from different sessions
overlapping on different workers; one session's causal order remains intact.

### M5 — Reuse Docker, network simulation, and numerical comparisons

1. Add a separate Compose manifest for the new runtime, with `worker-1`, `worker-2`,
   `worker-3`, and `coordinator` services. Keep the existing manifest runnable for
   Petals. Use separate project names to avoid containers or profiles colliding.
2. Extend `Set-NetworkProfile.ps1` to accept an explicit Compose file/project and
   validated target services. Preserve existing invocations; shape the coordinator
   in the new manifest because it relays activations. Preflight every target,
   record qdiscs, and reset in `finally` even when inference fails.
3. Retain internal networks, no public ports, offline verified weights, and bounded
   CPU/RAM quotas. Budget coordinator and load-generator CPU explicitly so moving
   work out of the old client does not add unreported resources. Grant `NET_ADMIN`
   only where shaping is required. No host networking changes are needed.
4. Extend the benchmark adapter to select complete-model local, Petals, or the new
   pipeline. Preserve public prompts, token fixtures, forced continuations,
   warm-up exclusion, fixed output length, failed-run retention and JSON reports.
   Include coordinator admission wait in client-observed first-token latency.
5. Pass the correctness gate, then reproduce the original short 128-input/8-output
   runs at concurrency 1 and 3 and the 1,024-input/64-output, concurrency-8 capacity
   smoke. Add protocol, cancellation, restart and cleanup cases from M2–M4.
6. For performance evidence, use 128/1,024 prompt tokens, 64 output tokens and
   1/3/8 active sessions. Sweep delay alone at 0/10/25/50 ms per egress direction,
   rate alone at 20/100/1,000 Mbit/s, then selected combined settings. Measure RTT
   and achieved bandwidth; configured caps are not measurements.
7. Prespecify three repetitions and at least 100 completed requests per selected
   configuration, retaining every failed attempt and stopping at 200 attempts per
   repetition if the completion target is not met. Publish underfilled/failed runs;
   do not silently run until failures disappear. Use a recorded balanced run order
   and report host contention/thermal conditions. Label the full sweep as later
   work if only smoke configurations have been collected.
8. Report per-request TTFT and decode intervals, aggregate completed-output
   throughput, admissions/rejections/timeouts, stage queue and compute durations,
   serialized bytes, loading time, cache allocations and client/worker memory
   peaks. Keep prefill and decode separate and describe the remaining unexplained
   end-to-end time; do not subtract timestamps from unrelated hosts.

**Deliverables:** new Compose lab, shared shaping/benchmark tools, versioned report.

**Gate:** a clean build starts all three workers and coordinator without Petals;
all correctness/lifecycle checks pass; the saved experiment includes configuration,
failures, metrics, traces and verified network reset. Historical Petals results
remain labelled by their older software versions. Direct speed comparisons
require matched versions/resources/topology or an explicit cross-runtime caveat.
The complete-model control must use the same stack as the new workers; add
resource-matched whole-model replicas before drawing efficiency conclusions.

## Proposed file layout and implementation order

Paths below are planned; they are not runnable components yet.

| Path | Intended contents |
| --- | --- |
| `src/steamboat_runtime/model.py` | Llama adapter, weight manifest and assigned-layer loading |
| `src/steamboat_runtime/protocol/` | Protobuf schema, checked tensor codec, errors |
| `src/steamboat_runtime/worker.py` | Worker service, bounded execution and session state |
| `src/steamboat_runtime/coordinator.py` | Admission, stage scheduler, token feedback and cancellation |
| `src/steamboat_runtime/client.py` | Benchmark adapter and streamed-token client |
| `tests/runtime/` | Model equivalence, protocol, cache, scheduling and failure tests |
| `docker/pytorch/` | Independent runtime image and locked dependencies |
| `compose.pytorch.yaml` | Three workers and coordinator using private static discovery |
| `lab/benchmark.py`, `scripts/Set-NetworkProfile.ps1` | Reused entry points with explicit backend/lab selection |
| `docs/experiments/` | Sanitized measurements and comparison reports |

Implement M0 and M1 first as one reviewable slice: manifest, backend interface and
in-process layer parity. Then land protocol/state handling (M2), remote services
(M3), scheduling (M4), and lab comparisons (M5). Keep code and evidence for each
milestone together. Update this document and the research plan with actual gates
passed; proposed work and measured results must remain distinguishable.
