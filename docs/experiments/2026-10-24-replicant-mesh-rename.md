# Replicant Mesh rename validation

Date: 2026-10-24. The maintainer selected **Replicant Mesh** and explicitly
requested a direct commit to `main`. The starting main commit was `2a63036`.

**Follow-up:** the maintainer subsequently completed the hosting rename. See the
[CI repair and hosting verification record](2026-10-24-ci-secret-scan.md) for the
resolved history-scan findings and current repository links. The blocked hosting
attempt and scan results below describe the initial rename work.

## Scope

Renamed the Python package to `replicant_mesh`, environment prefix to
`REPLICANT_MESH_`, RPC namespace to `replicant.mesh.v1`, and local Docker
images/projects/scripts to Replicant Mesh names. Updated current documentation,
tests and module commands. Historical experiment JSON, source-freeze records,
image digests, numerical results and source commits remain unchanged. Dated
Markdown records now identify their historical context. See the
[migration guide](../RENAMING.md).

The desired repository name is `mat092011/replicant-mesh`. GitHub rejected the
name/description update with HTTP 403 (`Resource not accessible by integration`),
so hosting remains at `mat092011/steamboat_net`. Live links and clone instructions
retain that working address. Private-reporting verification now resolves the
live repository name by stable ID, with a regression test for name changes.
The owner-side settings step is documented in the migration guide.

## Executed checks

- `python -S scripts/run_fast_tests.py`: **83 tests passed, zero skips** after
  the security-verifier update.
- `python scripts/check_release.py`, both Compose configuration checks and
  `git diff --cached --check`: passed.
- Regenerated `worker_pb2.py` using `grpcio-tools==1.84.0` (Protobuf Python
  generator 7.35.1). Compared old/new descriptors after normalizing names: field
  numbers, types and methods are unchanged; only file/package/type names changed.
- Built the hash-locked CPU image, verified eager prefill/cached decode and
  absence of Petals dependencies. Tested image ID:
  `sha256:8e07643002bfc5203bd009861198f8600315d2b97d7ee6f1161fec550825d472`.
  The managed environment required a temporary, uncommitted build-file variant
  mounting the system CA for pip; dependency versions/hashes were unchanged.
- Prepared fresh model/artifact volumes with the pinned checkpoint. The
  artifact fingerprint is `33aec5e084dc12cef677821fcc8ca55a00f74298531f1a97d499658e6930254d`.
- `docker compose -f compose.pytorch.yaml run --rm --no-deps tests`:
  **263 tests passed, zero skips**, including protocol, numerical, coordinator,
  process-failure and model integration checks. The later security-verifier
  change and its new test were checked by the 83-test host suite above.
- Started all three workers and the coordinator under their renamed Compose
  project; all health checks passed. Service validation passed **144 numerical
  comparisons**. A six-request pipeline smoke at concurrency three with 128 input
  tokens and eight output tokens per request completed successfully.
- Verified GitHub private reporting is enabled at the actual hosting URL;
  no advisory or message was submitted.
- Pinned Gitleaks 8.30.1 found no candidate-source findings and no findings in
  `main` history. An additional all-local-ref scan reported 12 existing findings
  in the separate `feature/participant-network` history. They were not changed
  or suppressed by this rename; this is not an all-branch clean-scan claim.

## Environment-specific failed attempt

The first multi-container coordinator startup failed because the managed
environment's injected HTTP proxy intercepted gRPC to Docker service names.
The first service check consequently failed with `NOT_READY` and zero comparisons.
A direct RPC diagnostic confirmed an unreachable proxy address. A temporary,
uncommitted Compose overlay set `no_grpc_proxy` only for the private lab's worker,
coordinator and loopback names. Outbound HTTP/HTTPS proxy settings were retained.
With that overlay, startup, the 144-comparison gate and the smoke passed. No
runtime assertions or deadlines were relaxed. Failed and successful raw reports
remain in ignored `.lab/pytorch-results/`.

These are colocated CPU correctness/smoke checks. No separate-device, GPU, WAN,
performance, credit-system or broader research-phase completion is claimed.
