# C2 coordinator runtime settings

`parse_c2_coordinator_settings` validates bounded canonical JSON for the closed
`native_posix_c2_coordinator_runtime_v1` profile. It validates the exact
assignment identity and digest fields, checks that the assignment's catalog
public-key digest matches the declared uncompressed P-256 point, and reuses the
host runtime parser's gateway and traffic field validation. It also requires
the exact logical component set `worker-1`, `worker-2`, and `worker-3`; each
entry pins a device ID, worker boot ID, assignment ID, and host-certificate
path/SHA-256 locator. Device IDs may repeat across different boots, while each
device/boot pair and each worker assignment must be unique. The fixed consumer
listener declaration reuses the runtime's canonical numeric IPv4 listener
validator, requires a nonzero explicit port and sorted allowlist, and bounds
the listener ID, one-or-two connection slots, and acceptor directory. Results
are frozen inert values.

These assignment and catalog anchors are declared by the selected coordinator
runtime settings. The current selected coordinator launch specification does
not itself carry those assignment/catalog anchors; the settings parser does not
claim that it does. A future adapter must compare these declarations against
its actual verified artifact pin before loading. Worker certificate locators
and the consumer-listener declaration are likewise inert selected-runtime
declarations: they do not authenticate certificates, authorize listeners, or
establish a TLS connection. A future factory must compare each opened
certificate against its pinned bytes and the selected signed policy and
assignment before use. Parsing does not read artifact, policy, certificate, or
traffic-state paths, load a model, create a channel, or start a process. Worker
outbound endpoints must come only from verified signed channel policy; this
schema accepts no raw worker endpoint, module, command, or clock override.

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
