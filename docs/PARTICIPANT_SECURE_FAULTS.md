# Secure pipeline reply-loss fault cases

This opt-in test extension adds two caller-boundary reply-loss cases to the
real authenticated pipeline described in
[`PARTICIPANT_SECURE_PIPELINE.md`](PARTICIPANT_SECURE_PIPELINE.md). Each case
inherits that harness, runs its one-token greedy control and 27-vector
same-stack numerical baseline, then injects one fault into a fresh cohort
shared by that case's control and fault. The tests use real enrollment and
signed grants, pinned numeric-IP mTLS, the owned CONNECT transport, generated
worker `Request` messages, three
`StageExecutor`/`WorkerHandler` instances, `SecureWorkerRuntimeBridge`, the
core incoming and outbound authorizers, `ConsumerContextFactory`, and the
supervised coordinator model. There is no in-memory transport, fake
authorization, or replacement tensor result.

## Cases

The prompts are synthetic token IDs generated with
`3+((i*37+offset)%(32000-3))`, for `i=0,1,2`. The fixed offsets are 23 for the
partial Open and 47 for the lost Step response. Both requests ask for three
tokens and carry a 10-second timeout. Capture is disabled for these fault
requests; the shared capture budget must remain empty.

1. **Partial admission.** The worker-1 `OpenSession` client wrapper first
   awaits the real TLS call. It verifies that the actual successful protobuf
   reply corresponds to a live worker handler session, then raises one
   `EXECUTION_FAILED` at the caller boundary. It does not return a made-up
   response. The test requires exactly one worker-1 Open, no Open on workers 2
   or 3, and no Step. The coordinator must retain its `unknown_opens` marker,
   fail the request with no output and `cleanup_complete=false`, fence further
   work, and retain the service slot while the lease may still exist. The test
   waits for the original bounded 10-second worker lease to expire and checks
   the actual handler cache, the present worker core binding record
   (`state="tombstone"`, `reclaimed=True`), and bridge owner are reclaimed.
   A worker terminal code of `EXPIRED_SESSION` or `CANCELLED` is accepted only
   when the worker tombstone's first `monotonic_terminated_at` is at or after
   the copied original core hard expiry, the same core record retains
   `invalid_reason="session-hard-expiry"`, and the real monotonic clock is past
   both the original hard expiry and the record's current hard expiry. These
   worker/core monotonic values are compared only within this shared host
   process; the test makes no cross-host timestamp claim. This accounts for the
   bridge's hard-expiry notice path, which calls
   `WorkerHandler.invalidate_for_authorization()` and therefore records
   `CANCELLED`; it rejects a worker cancellation that happened before expiry,
   even if a later core sweep marks the record expired. The call observer
   remains installed through the whole expiry/quarantine interval and requires
   one Open, no Step, and no Renew, Cancel, Close, or SessionStatus RPC, so
   retries cannot go uncounted. The
   coordinator and service remain fenced/retained in-process because no runtime
   recovery hook is part of this test. Teardown always attempts the original
   bounded coordinator close, even if expiry proof fails. It disposes the local
   model only after hard expiry, worker-side reclamation, coordinator retirement,
   no active compute, and exact-`True` model close are confirmed. If any proof or
   close is unconfirmed, the test keeps a strong reference to the pipeline in a
   finite process-local cleanup registry until the test process exits; it does
   not report cleanup success or clear the runtime restart fence. A model close
   result other than exact `True`, including `False`, a non-boolean result, an
   exception or timeout, follows this retained-owner path. This is not evidence
   of in-process coordinator recovery.
2. **Lost mutating reply.** The test lets one real worker-1 `Step` complete
   through TLS and records only its sequence, KV positions and allocated byte
   counts. It then raises `EXECUTION_FAILED` before the coordinator receives
   that real response. The test requires one Step attempt on worker 1, no Step
   on workers 2 or 3, no retry, no token output, and a failed terminal result
   with an empty token list. It also requires confirmed worker session/KV,
   present worker core binding records with `state="tombstone"` and
   `reclaimed=True`, zero active worker authorizations, transport, coordinator
   and capture cleanup.

The partial-Open case requires the internal failed request state and retained
unknown-Open fence. The consumer may receive one failed terminal event with
`cleanup_complete=false`, but delivery is not guaranteed by the runtime, so the
test does not require receipt of that event. It never fabricates a terminal
result.

The focused stdlib fixture test compiles the production `Authorizer.sweep`,
`SessionBindings.poll`/`mark_reclaimed`, bridge sweep/notice/reconcile methods,
and `WorkerHandler.invalidate_for_authorization`/`_terminate` bodies into a
small source probe. It verifies the hard-expiry reason and resulting
`CANCELLED` terminal without importing protobuf, gRPC, or a model. The real
pipeline case still provides the integration oracle; the source probe is not
network or model evidence. A negative source probe also runs the production
worker invalidation at monotonic 9.5, then the actual core expiry/reclamation
at 10.25 for a 10.0 hard expiry; the oracle rejects that earlier worker
termination despite the later reclaimed core tombstone.

Both injections are at a test-only caller boundary **after a successful RPC**.
They are not socket disconnections, WAN-loss experiments, or separate-device
evidence. The first case deliberately retains the unknown lease fence until
physical expiry and does not replay Open or reconnect to continue the session.

## Running and evidence boundary

With the offline Linux model artifacts and dependencies prepared, require the
tests with:

```sh
STEAMBOAT_SECURE_PIPELINE_TESTS=1 \
STEAMBOAT_ARTIFACT_DIR=/artifacts \
STEAMBOAT_REFERENCE_DIR=/reference \
python -m unittest discover -s tests/security -p 'test_secure_pipeline_faults.py' -v
```

When the opt-in is enabled, missing artifacts or dependencies are errors and
the inherited opt-in skip gate no longer skips these cases. Each test creates
its own temporary credentials, full-model reference and three-worker cohort,
so run them serially. The established one-token and capture matrix are rerun as part of
each inherited test before its fault is injected. Parent execution is required
for Linux Docker evidence; no local model or Docker run is claimed here.

The ignored local diagnostic helper
`.lab/participant-network/diagnose_secure_baseline.py` runs only the inherited
mutating-Step baseline case. It accepts `--cohorts N` for 1 through 5 fresh
three-worker cohorts (default 1), stops at the first failing case, and enforces
one 240-second watchdog across the batch. Each case emits at most 256 sanitized
scalar events. In its child process only, a logging filter suppresses asyncio's
standard slow-callback message template that renders a `Task` representation;
this prevents debug logging from exposing task-held logits. It does not change
asyncio debug settings, test code, or production behavior. This is an explicit
diagnostic variable, and diagnostic output is not acceptance evidence.

These tests do not establish C1a/C1 acceptance, separate-device execution,
WAN fault behavior, performance, GPU speed, pooled-memory fit, or automatic
recovery from an ambiguous mutation. The partial-Open case specifically
records the current retained restart fence; a trusted runtime maintenance or
restart integration remains necessary to reclaim that in-process ownership.
