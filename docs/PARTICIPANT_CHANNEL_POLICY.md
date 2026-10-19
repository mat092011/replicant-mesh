# C2 operator channel policy primitive

Status: bounded policy primitive only. This document describes the module in
`steamboat_security.channel_policy`; it does not claim a C2 channel or gateway
authorization path has been integrated or passed an acceptance gate.

The policy is a short-lived, operator-signed permission for a trusted
terminating gateway to bind an authenticated coordinator route to a specific
worker channel. The gateway can read and modify traffic on both TLS hops. A
valid policy is not participant enrollment, a C1 grant, certificate revocation
status, host readiness, proof of coordinator possession at the worker, or
end-to-end prompt privacy. The signing key is a dedicated operator policy key,
separate from gateway, worker, and CA keys. It is not distributed to gateway or
worker participants.

## Encoding and limits

`sign_channel_policy(payload, private_key_pem)` validates the closed v1 schema
and returns canonical UTF-8 JSON containing exactly `payload` and a base64
DER `signature`. The signature is ECDSA P-256/SHA-256 over
`b"steamboat-channel-policy-v1\0" + canonical_json(payload)`. Signatures use
canonical base64 and low-S DER. The entire envelope is limited to 64 KiB.
Verification rejects duplicate JSON keys, non-finite values, noncanonical
bytes, unknown or missing fields, noncanonical signature encodings, and
oversized input.

The payload has exactly these top-level fields:

```json
{"version":1,"revision":1,"issued_at":1000,"expires_at":1100,"gateways":[],"workers":[],"routes":[]}
```

The policy lifetime is positive and at most 300 seconds. There may be at most
4 gateways, 8 workers, and 32 routes. Lists are sorted and unique. Every
gateway record contains exactly `gateway_id`, `serial`, `certificate_sha256`,
`public_key_sha256`, `not_before`, `not_after`, `endpoint_host`, and
`endpoint_port`. Gateway IDs use the channel certificate gateway identity
grammar. Endpoint hosts are fixed canonical lowercase DNS names or canonical
IPv4/IPv6 literals; wildcards and URLs are rejected. Ports are 1–65535.

Every worker record contains exactly `account_id`, `device_id`, `host_serial`,
`host_credential_epoch`, `host_certificate_sha256`, `worker_boot_id`,
`assignment_id`, `model_id`, `channel_serial`, `channel_certificate_sha256`,
`channel_public_key_sha256`, `not_before`, `not_after`, and `gateway_id`.
Every route record contains exactly `gateway_id`, `account_id`, `device_id`,
`actor_serial`, `actor_credential_epoch`, `actor_certificate_sha256`,
`coordinator_boot_id`, `tenant_account_id`, `target_device_id`,
`worker_boot_id`, `assignment_id`, `model_id`, and `methods`.

All serials are positive canonical lowercase hexadecimal of at most 40
characters. Typed account/device/assignment IDs and boot IDs use the existing
strict v1 grammars. Hashes and model IDs are lowercase 64-character hex.
Channel/gateway validity is at most 900 seconds and must cover the policy's
entire issued-to-expiry interval. Each route must name an exact worker and its
gateway, account, assignment, and model. The tenant must equal the actor
account. Methods are a nonempty sorted subset of the existing worker RPC
method names. Gateway/worker public keys cannot reuse the policy signing key.

## Store API and liveness

`ChannelPolicyStore(verification_key_pem, *, clock, minimum_revision=None,
minimum_policy_digest=None, durable_commit=None, require_durable=True)` pins an
operator P-256 verification key and requires the core `Clock` type. Production
construction requires a synchronous durable callback; tests can explicitly
set `require_durable=False`, but installation still requires a callback. The
callback receives `(encoded_envelope, revision, canonical_payload_sha256)` and
must synchronously return `None`. It runs under the store's bounded serialized
install operation, before publication. Re-entry, exceptions, awaitables, or
other return values fail closed and latch the store unusable. The callback
must itself have a bounded completion contract and durable high-water behavior;
this module does not implement persistence or restart recovery.

`install(encoded)` verifies and validates before publishing an immutable
`ChannelPolicyView`. Revision rollback and same-revision content equivocation
are rejected. The configured revision/digest pair is an additional bootstrap
fence. Reinstalling the exact same signed payload is idempotent and does not
call the durable hook or extend its original monotonic deadline. A new
revision must pass durable commit before it becomes visible; the store samples
the clock again afterward and refuses publication if policy authority expired
during the callback.

`current()` resamples the supplied `Clock` and fails when the policy's wall or
monotonic expiry has passed. The view provides `gateway(id)`,
`worker(device_id, worker_boot_id)`, and exact-field `route(...)` lookup. Views
contain frozen mappings and tuples and do not expose the mutable input payload.
Consumers must call `current()` on every authorization/liveness check rather
than retaining a view as continuing authority.

## Integration still required

This primitive does not authenticate TLS, compare an actual upstream gateway
or selected worker channel to the policy, validate C1 current credentials and
grants, establish loaded host readiness, create a gateway delegation, bind
stream generation/sequence replay state, enforce request deadlines, or
invalidate sessions on stream loss. The C2 coordinator/gateway/worker path must
wire those checks through admission, live authorization, and completion while
preserving the C1 direct-peer API. The terminating gateway remains a trusted
traffic endpoint. No C2 phase approval or channel acceptance gate follows from
the primitive or its unit tests.
