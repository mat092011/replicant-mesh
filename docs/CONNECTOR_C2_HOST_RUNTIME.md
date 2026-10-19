# C2 host assigned-stage runtime composition

`steamboat_connector.c2_host_runtime.build_c2_host_runtime` composes a loaded
host role from an already validated C2 child binding, inherited signed artifact
group pins, and a read-only `ArtifactInstaller`. It verifies that the complete
selected component set, group record, signed catalog fingerprint, assignment
documents, worker boot IDs, core `Clock`, verifier, account, device, role, and
artifact root agree before constructing any assigned stage executor. The
catalog digest and public-key pin, every selected assignment digest, and the
complete inherited group record must match. It also checks each component's
queue ceiling, the aggregate host session/KV/queued-call allocations, and the
host reservation against global owner limits before loading the first weight.

The builder uses the same selected C2 binding clock for catalog verification,
assignment guards, worker handlers, session bindings, and authorization. Secure
worker bridges are created with the selected-root runtime guard and the
binding's synchronous teardown notification fences bridge admission. Confirmed
shutdown is bounded to five seconds; the returned owner retains the child
binding lease, pins, handlers, authorizers, sessions, and bridges until cleanup
is confirmed. If loading or cleanup is uncertain, the raised exception retains
the partial owner as `c2_host_runtime_owner`; callers must keep it alive until
cleanup is confirmed or the supervising process is reaped. The caller retains
the inherited child pin set through process reaping; this assembler never closes
those descriptors. It fences every constructed bridge before beginning bounded
cleanup, then spends one shared five-second deadline across bridge and handler
shutdown. After that cleanup is confirmed, it retains the model, executor, and
bridge references until selected-root lease retirement is confirmed, then drops
them. The five-second close budget includes waiting for another close
operation to release the close lock and retiring the child-binding lease. Lease
exit runs in one retained worker-thread task because it can wait on the selected
root store lock. If that task has not completed within the budget, close raises
and keeps the task, lease, pins, handlers, and bridges owned; it never retries
an uncertain lease exit. A close-lock timeout fences bridges immediately and
retains all owners. This does not establish process RSS reclamation; the
supervisor must still reap the child process.

This is an in-process model/runtime assembly layer. It does not start a process,
open a network listener, publish readiness, claim a role, or wire transport
requests into the bridges. It is not evidence of full C2 host startup or a
READY state. Resource narrowing covers the declared session count, KV bytes,
cache positions, queued calls, and request timeout only; it does not establish
aggregate memory, CPU, disk, bandwidth, capture, or physical-device
enforcement. Those remain responsibilities of the supervised role adapter and
its owner-policy enforcement path.

The positive numerical test requires the approved offline model fixture mounted
read-only at `/artifacts` (or `STEAMBOAT_C2_STARTUP_ARTIFACTS`). It executes
forced token steps through an actual assigned stage and compares them with the
same signed shard in the local pipeline reference. This checks assigned-stage
composition only; those numerical calls invoke the handler directly. The same
native test separately sends a `Describe` operation through the runtime guard
and real C1 authorizer using a fixture-signed coordinator credential and grant.
That exercises guarded core admission without opening a network transport. It
does not establish cross-device behavior, a complete-model output, transport
admission, or end-to-end readiness. Run the focused module with:

```text
python -m unittest tests.connector.test_c2_host_runtime
```

The actual-artifact tests are skipped when the POSIX environment or offline
fixture is unavailable. No model downloads are performed by this module.
