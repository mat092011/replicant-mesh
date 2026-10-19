# Capture backpressure and reclamation checks

`tests/security/test_capture_model_backpressure.py` adds two opt-in CPU tests
for the capture ownership path and an always-collected task-ownership helper
regression. The model tests reuse the setup from
`SecureCaptureModelIntegrationTests` through a module-qualified helper lookup;
they do not inherit that test class or expose its positive test to this
module's unittest discovery.

The helper regression uses a completed `SecureTaskPending` wrapper whose
exception has already been gathered. The root is available through fixture
cleanup collection; the regression verifies `_join_owned_tasks` collects it
before deciding there are no live descendants and waits for its held child.

## Evidence boundary

The fixture loads the pinned offline `Maykeye/TinyLLama-v0` revision
`298338802ab94432b917bcce11382aa151aee50f`, then runs the real supervised
`CoordinatorModel`, three `StageExecutor` instances, three `WorkerHandler`
instances, the coordinator scheduler, and `SecureCoordinatorService.Generate`.
Generated capture vectors come from actual model execution; the tests do not
prefill an output queue or substitute a tensor.

The capture ledger is configured explicitly for vocabulary 32,000, 16 output
slots, at most 8 active captures, and a 1 GiB logical pool.

This is component evidence only. The reused fixture has fake authorization and
`InMemoryTransport` worker clients. Calling the secure adapter directly does
not establish authentication, TLS, the native connector, or real-network
behavior. The stalled writer is a deterministic local test context.

## Cases

The stalled-write case holds the first serialized token event and waits until
the real producer has filled all 16 queue slots and is blocked on another
`Queue.put`. It then cancels Generate and pauses at the actual capture
reclamation call. While reclamation is paused, the test checks that the 92,032,256
logical bytes remain in cleanup-pending state and authorization, context, and
both stream counters remain owned. It releases the reclamation gate and checks
that the producer, queue, model work, worker sessions and caches retire before
those owners are released.

The stalled-write case releases its reclamation gate within the configured
five-second cancellation grace. When reclamation is confirmed, it requires the
secure service and runtime owner to remain available, the coordinator to remain
ready, and the model not to require restart.

The supervised-future case blocks entry to the actual coordinator `_finish`
operation with a `threading.Event`, then calls the original operation after the
test releases the gate. It checks that cancellation does not release capture
bytes, authorization, context, or stream ownership while the real CPU future is
active. It then verifies the original computation finishes and reclamation
completes before the ledger reaches zero. The test holds the operation beyond
the five-second cancellation grace. The secure service/runtime fence must latch
within six seconds of the cancellation timestamp, using one absolute deadline
for the reclamation-start and fence waits. After that fence, the caller has a
separate, bounded one-second allowance to exit with ordinary cancellation or
an explicit `SecureTaskPending` outcome. The secure service/runtime owner must
remain unavailable after physical cleanup; operator restart is required to
clear that fence. Coordinator readiness and the model's `requires_restart`
state are recorded independently, without assuming they recover automatically.
The JSON marks 6 GiB as the
configured expected container limit; the parent runner must verify the actual
cgroup limit before execution.

The operation gate fails closed after 25 seconds if the test cannot release it.
The Generate request timeout remains 30 seconds and the fixture's trusted
context lifetime remains 20 seconds; neither runtime limit is extended.

Both tests sample Linux process RSS with `psutil` and process high-water RSS
with `resource.getrusage` at baseline, during the held state, after request
cleanup, and after fixture shutdown. The baseline is sampled after the model
fixture has loaded and before the request starts. They print one compact
sanitized JSON line per case, containing the pinned test configuration, queue
and producer state, model supervision state, ledger state, exact logical
logit/reservation sizes, and sampled memory values. The tests impose no RSS
pass threshold. The 92,032,256-byte per-capture reservation is logical
accounting, not a physical RSS guarantee. The runner's 6 GiB container ceiling
is only reported as the configured expected container limit. This test neither
reads nor enforces the cgroup limit, and reservation arithmetic does not prove a
physical RSS bound.

## Run in the prepared Linux image

The opt-in flag makes missing artifacts or runtime dependencies fail setup
rather than silently skip the test:

```sh
STEAMBOAT_CAPTURE_BACKPRESSURE_TESTS=1 \
STEAMBOAT_ARTIFACT_DIR=/artifacts \
STEAMBOAT_REFERENCE_DIR=/reference \
python -m unittest tests.security.test_capture_model_backpressure
```

The test caps Torch intra-op and inter-op threads at two before setting up the
reused fixture. Input IDs follow the public deterministic formula
`3 + ((i * 37 + 11) % (32000 - 3))`. Parent Linux execution is still required;
this worktree has not run the model, gRPC, or Docker checks. These tests do not
complete the authenticated C1a pipeline, the real-network capture path, a
physical memory-bound measurement, or phase acceptance.
