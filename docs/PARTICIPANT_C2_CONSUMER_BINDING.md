# C2 consumer identity binding

`steamboat_security.root_c2_consumer.load_c2_consumer_binding` binds a
protected local C1 `consumer` certificate and key to the exact consumer
`RoleLaunchSpec` in the freshly validated C2 selected root. Its explicit,
closed `native_posix_root_c2_consumer_v1` header pins the selected roots,
identity and launch epochs, model scope, role keypair and opaque runtime
configuration. The consumer model scope is checked against the consumer's
currently active grants in the selected signed policy.

The returned `C2ConsumerRuntimeBinding` reuses the guarded C2 policy lifecycle
and the same caller-owned `RootGenerationStore` and `Clock`. Exposed identity,
TLS material, launch spec and opaque bytes are guarded on every access. It
retains observed policy, credential and grant deadline floors, supports exact
same-head compare-and-swap reconciliation across bindings, and invalidates
once on a durable trust, storage or protected-file failure. Bounded synchronous
teardown callbacks run outside the binding lock; they do not prove cleanup.

This profile uses the selected C1 consumer role certificate and key. It does
not define a consumer-stream certificate. Any gateway certificate, channel CA,
endpoint, channel policy and route pin checks remain separate egress-adapter
requirements. Protected runtime bytes are opaque and supply no peer path or
command. This binding does not create an SDK session, load or validate weights,
start a process, contact a gateway, consume a launch claim, or report READY.
Consumers need no PyTorch, model download or assigned worker weights at this
identity-binding layer. No inference or connector readiness is established.

Focused contract checks:

```powershell
$env:PYTHONPATH = 'src'
uv run python -Xutf8 -B -m unittest tests.security.test_root_c2_consumer -v
```

The protected selected-store integration cases require the supported native
POSIX parent. A portable run on another platform skips those cases; it is not
evidence that the protected RootGenerationStore integration passed.
