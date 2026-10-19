# C2 assigned coordinator runtime

`build_c2_coordinator_runtime` assembles one CPU coordinator head from an exact
selected coordinator child binding, its one genuine inherited coordinator
artifact pin, and the active read-only coordinator assignment. Before loading
weights, it compares the signed catalog and assignment bytes from the actual
read-only installer view against the inherited pin guard, verifier key,
assignment identity and digest, model-manifest fingerprint, active installation
record, and selected runtime settings. The normalized selected `artifact_root`
must exactly match the installer root. The owner policy must validate and fit
the global limits;
the effective CPU session capacity and request deadline narrow the signed
manifest, owner reservation, and global policy. The weight reservation must
cover the signed coordinator safetensors file size.

The runtime exposes guarded tokenizer, embedding, and output-head calls plus a
one-token finite-shape health check. Model operations use the assigned
coordinator model's bounded CPU executor. Caller cancellation or request timeout
does not release an executing future. Shutdown has a shared maximum five-second
budget, including close-lock contention, and is successful only after the actual
model confirms its CPU work has drained and the selected-root lease exits. The
exact lease exit runs once off the event loop and remains strongly owned while
waiting for its lock. A
timed-out drain remains fenced and retains the model, child-binding lease, and
pin-set references; after actual CPU work finishes, a later bounded close can
confirm reclamation. A faulted lease exit retains all references for
process-reap cleanup. The inherited pin set is caller-owned and is never closed
by this runtime.

This is model assembly only. It does not start a process, open the declared
consumer listener, connect to workers, schedule complete inference, enforce
whole-process memory/CPU/physical-pool limits, or establish readiness. Runtime
settings' worker certificate paths and listener values remain inert declarations
until a future selected transport factory verifies and consumes them. The
selected coordinator launch specification pins the complete runtime settings
bytes; those settings carry the assignment and catalog anchors checked here.
That does not change the launch specification schema or make the settings
themselves an authority source.

Focused checks:

```text
python -m unittest tests.connector.test_c2_coordinator_runtime
```

The native integration test requires Linux, the approved offline `/artifacts`
model fixture, and the pinned runtime stack. Portable tests do not establish
model loading, numerical parity, network service behavior, process startup, or
readiness.
