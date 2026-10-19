# Secure pipeline correctness matrix

This page defines one opt-in, one-laptop correctness test for the unfinished C1
integration. It is not a C1a/C1 acceptance result and does not change phase
status. The existing [participant contracts](PARTICIPANT_CONTRACTS.md) and
[secure transport guide](PARTICIPANT_SECURE_TRANSPORT.md) remain normative for
identity, grants, TLS, bindings and failure behavior.

## Test boundary

`tests/security/test_secure_pipeline.py` exercises one noncapture control and a
three-case capture matrix through the same resident real secure runtime.
`tests/security/test_secure_pipeline_lifecycle.py` subclasses that test-only
harness and adds lifecycle cases below, so each invocation still creates only
one real identity cohort, one complete-model reference, and one supervised
coordinator model:

1. Three `StageExecutor` instances load the fixed `[0,3)`, `[3,6)`, and `[6,8)`
   artifact assignments into three actual `WorkerHandler`s.
2. Each handler is wrapped by `SecureWorkerRuntimeBridge` and an actual core
   `Authorizer`. Worker calls use generated `steamboat.v1.Request` protobufs.
3. Three fixed numeric worker peers use normal mTLS, C0 expected-leaf
   verification, and the default owned `SecureConnector`. The coordinator wraps
   those clients in `BootstrapWorkerClient` with finite Describe-only
   capabilities.
4. Authenticated worker `Describe` calls prewarm those outbound channels
   sequentially before `Coordinator.start()` performs readiness probes. This
   respects the shared maximum of two outbound pending handshakes without
   changing the connection budget or adding retries.
5. A fourth real mTLS listener runs `SecureCoordinatorService` around
   `CoordinatorService`, the actual `Coordinator`, and the supervised
   `CoordinatorModel` subclass. `ConsumerContextFactory` builds the server-side
   context from the actual consumer `Authorization` for the admitted Generate.
6. A consumer `SecureCoordinatorClient` sends only synthetic token IDs. The
   one-token noncapture control checks its greedy output against the same-stack
   pinned complete model. Capture cases use prompt lengths 1, 128 and 1024; each
   supplies eight identical forced continuation tokens and requests nine output
   positions. Every received last-position logit vector is compared with the
   corresponding row from a local CPU float32/eager complete-model reference
   using `atol=1e-3, rtol=0`. Full reference-prefill logits stay local; only the
   supported last-position vector crosses the wire.

Each Generate uses a fresh typed consumer request context and receives a fresh
typed worker session ID. The checks cover token/terminal ordering, forced-input
feedback, positions after the prompt, output token counts, `cleanup_complete`,
worker KV/session reclamation, capture reservation release, and the shared
transport connection/pending budget. The signed authority snapshot is not
refreshed during any request, and the client does not retry a Generate.

## Lifecycle extensions

The lifecycle subclass runs after the original one-token control and 27-vector
matrix while the same authenticated mTLS pipeline remains resident. Its public
synthetic prompts use the fixed formula
`3+((i*37+offset)%(32000-3))`, with token values in `[3, 31999]`. Offsets are
fixed in the test: 23 for the 17-token greedy case; 37 and 41 for concurrent
prompts of lengths 5 and 11; 53 for the 1,151-token exact-boundary prompt; 59
and 61 for the over-boundary input checks of lengths 1,152 and 1,153; and 83
for the identical one-token inputs used by the eight-request capacity case.
Every supported request satisfies `prompt_length + new_tokens <= 1152`.

The additional authenticated model cases are:

1. Four unforced output tokens are compared with iterative greedy feedback from
   the pinned complete Hugging Face model.
2. Two unequal prompt lengths run concurrently. Each sends three identical
   forced feedback inputs, captures four last-position vectors, and compares
   each vector with a separate full-model reference computed from that request's
   exact forced-input sequence (`atol=1e-3`, `rtol=0`).
3. A 1,151-token prompt plus one output token exercises the exact 1,152-position
   limit and compares the single captured last row. Inputs of 1,153 tokens and
   1,152 tokens plus two outputs are rejected by the secure client validator
   before tensor allocation or RPC admission. This is client-boundary evidence,
   not a raw malformed-server-request test.
4. Eight distinct authenticated capture requests with identical one-token input
   are held at the return boundary of the first real worker stage computation.
   The test checks eight active captures, coordinator requests and worker
   sessions per stage, the in-flight first-stage KV cache, and the shared
   connection budget. A ninth capture request must return
   `CAPACITY_EXHAUSTED` without another coordinator submit or session. The gate
   then releases the real result, and all eight requests must finish with unique
   typed request/session IDs and complete cleanup.

The lifecycle additions are pending parent execution against the refreshed
Linux candidate. The parent result below covers only the original 27-vector
matrix, not these new cases.

The four listeners reserve one connection slot each. The three worker clients
and the consumer coordinator client reserve three slots each, so one shared
`NodeConnectionBudget(max_connections=16, max_pending=4)` accounts for all 16
static slots. The test also checks that all pending-handshake reservations drain.
This in-process shared budget is a local harness arrangement, not a cross-device
or cross-process enforcement claim.

Fixture cleanup ownership is registered as resources are created. Partial
identity fixture construction attempts to remove its private temporary
directory; listener, bridge, handler, raw/wrapped client, model, and
acceptor-directory cleanup is attempted in reverse dependency order. Teardown
continues after individual failures, checks final connection and capture
reservations, and reports teardown errors together with any primary assertion
or RPC failure.

The owner passes an explicit `CaptureBudget` configured for vocabulary 32,000,
the coordinator's actual 16-slot output queue, eight active captures, and a 1 GiB
logical pool. This is reservation accounting, not a measured RSS bound.

## Credentials and local inputs

The opt-in fixture creates fresh ECDSA P-256 identities using the actual offline
invitation/enrollment and signed-snapshot APIs. It uses current wall and
monotonic clocks, separate cohort CA, invitation-signing and snapshot-signing
keys, short-lived role leaves, `127.0.0.1` IP SANs, and distinct worker account,
device, boot and assignment identities. Generated private keys are written only
under a mode-0700 temporary directory as mode-0600 files on Linux. The CA key is
not passed to a participant component. The signed snapshot/grants use the
allowed 300-second lifetime and stay unchanged throughout the test.

Set `STEAMBOAT_SECURE_PIPELINE_TESTS=1` to require the case. It reads the already
prepared artifact directory in `STEAMBOAT_ARTIFACT_DIR` and the pinned complete
reference in `STEAMBOAT_REFERENCE_DIR`; it performs no download or artifact
write. Once opted in, missing paths or dependencies are test errors, not skips.
Torch intra-op and inter-op threads are capped at two. With the opt-in disabled,
each inherited model case records an explicit skip. Required validation enables
the opt-in and rejects every skip.

The [local evidence report](experiments/2026-10-17-participant-c1a-local.md)
records exact source/image/log identities. Parent Linux runs passed the one-token
greedy control and all 27 captured last-position vectors for patterned prompts
of lengths 1, 128 and 1024, with eight forced continuation inputs per prompt,
`atol=1e-3`, and `rtol=0`. The expanded lifecycle test subsequently passed in
isolation, including a four-token greedy continuation, unequal concurrent
requests, context boundaries, and eight captures with a rejected ninth request.
A consolidated run failed cleanup; an observational diagnostic then failed an
earlier clock check. These failures remain part of the record. The current
capacity-marker and cleanup changes still require consolidated validation.

Invocation inside the prepared offline environment:

```sh
STEAMBOAT_SECURE_PIPELINE_TESTS=1 \
STEAMBOAT_ARTIFACT_DIR=/artifacts \
STEAMBOAT_REFERENCE_DIR=/reference \
python -m unittest discover -s tests/security -p 'test_secure_pipeline*.py' -v
```

## Runtime API composition

The test uses the following existing constructors without changing runtime or
security source:

- `SecureWorkerRuntimeBridge(core_authorizer, worker_handler)` supplies the
  request-bound incoming authorizer, handler adapter and expiry watcher to
  `create_secure_worker_server`.
- `OutboundAuthorizer` is configured per fixed host target with the generated
  `Request` type, exact `TrustedRequestContext` type, and explicit bootstrap
  permission. `create_bootstrap_context(max_describes=2)` covers the test's
  prewarm plus the coordinator's startup probe.
- `Coordinator` receives the three bootstrap wrappers and the actual supervised
  model. The secure coordinator server receives the actual core `Authorizer`,
  `AuthorizationWatcher`, and `ConsumerContextFactory`.
- For Generate, the secure server calls
  `create_with_deadline(authorization, payload, absolute_deadline=request_deadline)`
  with its receive-time monotonic deadline. The factory preserves that cap
  through validation and the one-use context commit; its legacy two-argument
  call remains for direct callers without a server receive-time deadline.
- The consumer adapter creates a one-use `ConsumerRequestContext` for Generate;
  `SecureCoordinatorClient.generate(..., trusted_request_context=...)` sends it
  through the fixed peer and does not retry an ambiguous request.

The receive-time deadline remains capped through context construction and
admission. These same-host checks establish only their recorded authenticated
path and numerical results. They do not establish separate-device execution,
GPU speed, throughput, physically pooled memory, production enrollment or C1
acceptance. The [reply-loss cases](PARTICIPANT_SECURE_FAULTS.md) add actual TLS
caller-boundary fault injections; their Linux validation is pending. Actual
socket disconnection, restart/boot invalidation and the separate-device C1b
lifecycle gate need their own evidence. C1a remains unfinished until the current
local repairs, review and consolidated checks pass.
