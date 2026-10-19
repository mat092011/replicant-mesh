# C2 coordinator runtime settings

`parse_c2_coordinator_settings` validates bounded canonical JSON for the closed
`native_posix_c2_coordinator_runtime_v1` profile. It validates the exact
assignment identity and digest fields, checks that the assignment's catalog
public-key digest matches the declared uncompressed P-256 point, and reuses the
host runtime parser's gateway and traffic field validation. Results are frozen
inert values.

These assignment and catalog anchors are declared by the selected coordinator
runtime settings. The current selected coordinator launch specification does
not itself carry those assignment/catalog anchors; the settings parser does not
claim that it does. A future adapter must compare these declarations against
its actual verified artifact pin before loading. Parsing does not read artifact,
policy, CA, or traffic-state paths, load a model, create a channel, or start a
process. Endpoints must come only from a verified signed channel policy; this
schema accepts no raw endpoint, module, command, or clock override.

`load_c2_coordinator_settings(binding)` requires the exact selected
`C2CoordinatorRuntimeBinding`, obtains its opaque bytes through the existing
guarded `runtime_configuration` property, parses them, then rechecks liveness.
The returned settings do not confer role, startup, network, admission, or READY
authority.

Focused portable parser tests:

```text
python -m unittest tests.connector.test_c2_coordinator_settings
```

Tests use synthetic locators and generated keys. They do not validate a signed
catalog or assignment, referenced file integrity, native stores, coordinator
startup, TLS, or readiness.
