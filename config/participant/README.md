# Participant C0 contracts (v1)

These are **declarations, not a network/security implementation or a phase pass**.
`v1/boundaries.json` supplies normative role, trust, identity, lifecycle, resource
and evidence semantics. Parent-owned decisions and phase records require separate
review. The existing M0–M5 runtime and Petals controls are not changed.

## Files and validation

- `v1/contracts.schema.json`: versioned **custom closed-type dialect**, not JSON
  Schema and not compatible with generic JSON Schema validators. `contract_schema.py`
  implements only `const`, `enum`, `bool`, bounded `int`, bounded/patterned `string`,
  `nullable`, `object`, `list` and named type references. Every object property is
  required; unknown properties, versions, types and booleans used as integers fail.
  JSON is UTF-8, at most 1 MiB; duplicate keys, nonfinite constants and exponent
  overflow fail. Explicit iterative parsed-document traversal enforces depth <=64,
  independently of the interpreter's JSON recursion limit. Schema/type traversal
  is also bounded. No new packages or runtime imports are needed.
- `examples/local-c1a-c2a.json`: contract-only, synthetic single-physical-pool local
  consumer/host/personal-coordinator declaration, with separate daemon, coordinator
  and three worker process boots (raw 32 lowercase hex digits).
  Linux amd64, CPU float32/eager, exact tiny model/tokenizer and existing runtime
  lock. Personal orchestration is separately enabled and owns input/output weights.
- `examples/outbound-c2b.json`: later **trusted terminating** gateway profile, mTLS
  on both legs and bounded outbound channel. Not opaque end-to-end encryption.
- `examples/all-roles-off.json`: default disabled roles, remote candidate route
  and daemon-only reservation. No execution or hosting is enabled by loading it.
- `examples/session-operation.json`: synthetic Step identity/binding declaration;
  not a serialized RPC or credential. Cross-binding checks compare all declared
  principals, worker boot, route, assignment/binding version, credential epoch and
  compatibility digest. Consumer-only, host-only and coordinator-only contexts are
  supported. Personal coordination remains restricted to the consumer's account,
  not its daemon/process boot or its physical device.
- `examples/experiment-awaiting-hardware.json`: no actual hardware/image/source
  freeze; named external dependencies remain open. Local C0 gate is contract review
  and tests only. `frozen_for_trials` additionally needs complete actual inventory,
  artifact manifest/source/image/config pins, UTC freeze time, confirmed required
  dependencies and executing devices on at least two distinct physical hosts.
  Unused inventory cannot satisfy that requirement. Use
  `validate_experiment_binding` / `--participant` to bind the freeze to its config.
- `examples/c0-evidence-template.json`: all checks **not run**; never a fabricated
  execution report. Evidence is restricted to C0 declaration validation, not a
  C1/C2/network/security pass. Actual checks require exact source, exit and report hash.
- `fixtures/negative.json`: named mutation fixtures with expected rejection rules;
  tested alongside systematic bool/float, missing/unknown-property and binding cases.

From repository root, using an available Python 3.11+ (stdlib only):

```text
python -B scripts/check_participant_contracts.py
python -B -m unittest discover -s tests -p "test_participant*.py" -v
python -B scripts/check_participant_contracts.py --validate config/participant/examples/local-c1a-c2a.json
python -B scripts/check_participant_contracts.py --validate config/participant/examples/session-operation.json --participant config/participant/examples/local-c1a-c2a.json
```

Default checker runs discoverable contract tests, rejects zero tests/skips/failures,
and checks the unchanged runtime limits/lock without importing PyTorch. The source
tree supplies schemas; this is not a packaged SDK or a deployed validator service.
`validate_document` checks structure and cross-field semantics; `validate_binding`
and `validate_experiment_binding` add declared cross-document checks, **not live
authorization, certificate verification, sequence enforcement or inventory proof**.

Optional isolated validation recipe, for the parent to run when scheduled:

```text
docker build --platform linux/amd64 -f config/participant/Dockerfile.validation -t steamboat-participant-contracts .
docker run --rm --network none --cpus 1 --memory 256m steamboat-participant-contracts
```

The validation Dockerfile reuses the exact digest-pinned Python 3.12.15 base and
installs no dependencies; no new dependency lock is needed. It copies the candidate
snapshot using the existing `.dockerignore`, including docs/link targets so the
parent can independently run release checks without Git. This recipe is not an
assertion that a container was built or run. Native stdlib checks do not validate
the selected Linux execution stack. Keep generated output under `.lab/`.

## Limits and truthfulness

All IDs, certificate hashes, DNS `.invalid` endpoints, capacities and leases in
examples are public/synthetic and unusable as credentials. There is no enrollment,
TLS, transport, daemon, download, registry, revocation or resource enforcement here.
`status=contract_only`, `policy.enforcement=unimplemented_contract_only`, public
enrollment/credits off and no phase/security/hardware claims are deliberate strict
constants. Future executable/evidence versions must be reviewed, not silently
enabled by editing those constants.

Null `artifact_manifest_sha256` is explicit unfinished preparation, permitted only
in contract examples/unfrozen templates; trial freezes require the actual prepared
manifest. The existing runtime verifies all source/tokenizer/artifact hashes offline;
the two source hashes in the compatibility identity are not a replacement for it.
Null memory telemetry declares unavailable state, not zero usage or usable capacity.
Even measured arithmetic is not execution fit. Each physical pool counts **all**
local reservations plus simultaneous loading peaks; weights/KV/temp/runtime and
connection/queue buffers are distinct. Local complete-model reference cost is
included in examples. Remote host policies/route inventory must be separately
frozen and reviewed by their actual owners before trials.

Only the unchanged fixed `[0,3) / [3,6) / [6,8)` partitions are supported here;
variable stage placement, GPUs, other precisions, compression, recovery and public
operators require new reviewed contracts/gates. Remote all-prefill-logit collection
is not declared or implemented. Only last-position JSON float32 vocabulary vectors
fit the selected contract. No limit in these files raises an M0–M5 ceiling.

## Selected security and wire declarations

The runtime lock identity is the SHA-256 of the exact UTF-8/LF bytes checked into
Git. `.gitattributes` enforces LF checkout bytes for `*.lock` on every platform.
The existing CPU dependency lock's Git content is unchanged. Do not substitute
the hash of a CRLF working copy: Linux source checkouts and participant images
must agree on the same artifact identity.

Typed IDs use `acct_/dev_/req_/ses_/route_/op_/asg_` plus 32 lowercase hex digits;
boots are raw 32 lowercase hex digits. Stage assignments are distinct `asg_` IDs.
Attempt is exactly 1: no mutation retries, replay or recovery. Personal coordinator
account/device matches the local owner when enabled; its process boot must differ
from the daemon and every worker. Each stable device maps to exactly one account.

TLS minimum is 1.2. Credentials last <=900000 ms and begin renewal 300000 ms before
expiry. Authorization snapshot lifetime <=300000 ms, refresh <=30000 ms and expiry
check <=5000 ms are distinct fields with refresh-before-expiry relations. Rotation
drains old bindings, then uses a new credential epoch and fresh sessions. None of
these declaration checks verifies certificates or implements authentication.

Management is AF_UNIX, same UID plus per-daemon-boot token, at most four local
connections, never TCP. Total TLS connections, including pending handshakes, are
capped at 16, two per peer, with at most four pending handshakes and a five-second
handshake timeout. Local Unix management has a separate allocation; all sockets
are included in conservative descriptor budgeting. Three stage channels plus
control, gateway, `client_tls_channels` and pending handshake allocations must fit;
client stream capacity is
`client_tls_channels * streams_per_connection`.

The nested synthetic `SessionOperation` is not a serialized secure envelope.
Its coordinator maps to the authenticated personal-coordinator actor, consumer
account to tenant, worker device to target, worker boot to payload boot, and stage
assignment to `assignment_id`. Request/session/route/epoch/attempt/operation IDs
map to the flat `steamboat-binding-bin` JSON metadata specified by the parent-owned
participant contract; `binding_version=1` is separate from control/inference
versions. Lease/payload hashes here are synthetic declarations, not bearer leases
or activation bytes. C1a must check authenticated context and stored ownership;
C0 adds no carrier encoder, TLS listener or live-session authorization.

Last-position logit messages reserve at least `32000*32 +4096 =1028096` bytes,
including a 4096-byte token metadata envelope, and remain within 1 MiB. Coordinator
communication reservations additionally include
`active_sessions * (output_queue_tokens + 2) * logit_message_bytes` for validation
capture buffering and two producer/write slots per active session, on top of
in-flight, queued and ordinary output buffers. Different device roles must
declare distinct certificate hashes; C1a additionally verifies actual role keys.
