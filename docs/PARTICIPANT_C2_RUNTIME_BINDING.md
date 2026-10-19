# C2 host-group runtime binding

`steamboat_security.root_c2_runtime.load_c2_host_runtime_binding` is a protected
loader prerequisite for a selected C2 host group. It checks the C2 activation
selection, canonical host header, parent credential, signed operator group
policy, component channel certificate/key pairs, and current signed policy
grants. It returns inert per-component identities and TLS material. Each
identity and material accessor calls the binding's liveness guard.

The C2 header uses the separate `native_posix_root_c2_host_group_v1` profile.
Its closed `component_paths` map replaces the singular C1 assignment field.
The protected header hash is pinned by the selected host launch specification;
the signed scope is obtained from the C2 selected activation manifest and must
match the operator-signed policy byte for byte after canonicalization. Runtime
configuration remains opaque and bounded to 16 KiB.

The signed group policy lifetime is at most 300 seconds. This binding expires
when that original policy deadline or any channel certificate deadline is
reached. Rechecking a file cannot extend either deadline; use a cold restart
with a newly selected group policy. A long-running group refresh protocol has
not been designed.

Callers must invoke `assert_live()` before each admission and during periodic
sweeps. Policy updates go through `install_policy()`, which persists the signed
head through the same `RootGenerationStore` while rechecking immutable group
material. Bounded synchronous subscribers receive a one-time invalidation
notification; they do not prove that component owners actually stopped.
Transport adapters that enforce these calls and tear down every component owner
are future integration work. This module does not activate a
process, expose readiness, consume claims, prove catalog contents, or authorize
direct use of an unguarded `LocalIdentity`.

Validation:

```powershell
$env:PYTHONPATH = 'src'
& '<configured-python>' -Xutf8 -B -m unittest tests.security.test_root_c2_runtime -v
```

The portable checks validate closed format and real operator signatures.
Protected-file loading requires POSIX no-follow support and must be verified
with the repository's native POSIX suite; Windows test runs do not establish
that storage integration.
