# C2 host runtime settings

`parse_c2_host_settings` accepts only canonical JSON bytes for the closed
`native_posix_c2_host_runtime_v1` schema, bounded to 16 KiB. It rejects duplicate
keys, non-integer numeric values, unknown fields, malformed or noncanonical
paths, invalid P-256 catalog points, and noncanonical/private gateway keys. Its
result is a frozen value tree with an immutable component-allocation mapping.

The settings contain locators and pins for offline artifacts, a signed channel
policy store, its initial policy and gateway CA, plus the traffic ledger's state
path, allocation identity and clock-domain label. Parsing does not open any
declared path, load model artifacts, build a gateway, or start a listener. The
artifact allocation declarations do not prove selected manifest policy or
resource availability; a future runtime assembler must narrow them against the
selected signed C2 scope and perform bounded protected-material reads and hash
checks.

`load_c2_host_settings(binding)` requires the exact selected
`C2HostRuntimeBinding`, obtains its opaque runtime bytes through the guarded
`runtime_configuration_bytes` accessor, parses them, and rechecks binding
liveness before returning. The returned settings remain inert declarations, not
TLS authority, endpoint authority, startup, admission, or readiness evidence.
Future endpoint selection must come only from a verified signed channel policy;
there is no raw endpoint, module, callback, command, or clock override here.

Focused portable parser checks:

```text
python -m unittest tests.connector.test_c2_host_settings
```

The parser tests use generated public P-256 material and synthetic locators.
They do not test native persistent policy/traffic stores, referenced file
integrity, C2 consumer/host startup, TLS, gateway readiness, or artifact loading.
