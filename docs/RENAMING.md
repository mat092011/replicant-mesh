# Migrating to Replicant Mesh

On 2026-10-24 the project was renamed from Steamboat Net to **Replicant Mesh**.
The planned repository name is `mat092011/replicant-mesh`. Its current address is
[mat092011/steamboat_net](https://github.com/mat092011/steamboat_net); the hosting
rename remains pending because the connected integration cannot change repository settings.
This is a coordinated source/runtime rename. All clients, workers and coordinators
must be upgraded together; the old Python imports, environment variables and RPC
service paths are not compatibility aliases.

## Name mapping

| Surface | Previous name | Current name |
| --- | --- | --- |
| Project | Steamboat Net / `steamboat_net` | Replicant Mesh |
| GitHub repository | `mat092011/steamboat_net` | `mat092011/replicant-mesh` (hosting rename pending) |
| Python package and module commands | `steamboat_runtime` | `replicant_mesh` |
| Runtime environment prefix | `STEAMBOAT_` | `REPLICANT_MESH_` |
| Worker RPC service | `steamboat.v1.Worker` | `replicant.mesh.v1.Worker` |
| Coordinator RPC service | `steamboat.v1.Coordinator` | `replicant.mesh.v1.Coordinator` |
| Owned-runtime Compose project | `steamboat-pytorch-m1` | `replicant-mesh-pytorch-m1` |
| Owned-runtime image | `steamboat-pytorch:cpu` | `replicant-mesh-pytorch:cpu` |
| Legacy Petals Compose project/image | `steamboat-net-lab` / `steamboat-net-lab:cpu` | `replicant-mesh-lab` / `replicant-mesh-lab:cpu` |
| Legacy private DHT prefix | `steamboat-local-v1` | `replicant-mesh-local-v1` |
| Image environment verifier | `/opt/steamboat/verify_environment.py` | `/opt/replicant-mesh/verify_environment.py` |

For example, `STEAMBOAT_ARTIFACT_DIR` becomes `REPLICANT_MESH_ARTIFACT_DIR`, and
`STEAMBOAT_PROTOCOL_TESTS` becomes `REPLICANT_MESH_PROTOCOL_TESTS`. Apply the same
prefix change to reference/snapshot paths, report destinations and process,
coordinator and service test flags in local scripts or shell configuration.
The root `.env.example` still configures the optional Petals model selection;
model identifiers, revisions, dependency locks and numerical tolerances are unchanged.

## Upgrade an existing lab

1. Finish active requests. If network shaping was enabled, perform and verify
   the existing scripts' documented network reset **before** updating the checkout.
2. Stop the old lab using its explicit project name. Run only the commands for
   the labs you actually started. These commands preserve prepared volumes:

   ```powershell
   docker compose -p steamboat-pytorch-m1 -f compose.pytorch.yaml down
   docker compose -p steamboat-net-lab -f compose.yaml down
   ```

3. Pull `main` using a clean checkout and the existing remote:

   ```powershell
   git switch main
   git pull --ff-only origin main
   ```

   A local checkout directory can keep its existing name or be renamed to
   `replicant-mesh` after leaving that directory. New clones use the new name.
   After the hosting rename below, update the remote to its new address:

   ```powershell
   git remote set-url origin https://github.com/mat092011/replicant-mesh.git
   ```

4. Update custom imports, module commands, environment variables and RPC clients
   using the table above. Rebuild every service from the same checkout. Prepare
   the new project's volumes and run the gate before starting the lab:

   ```powershell
   docker compose -f compose.pytorch.yaml build prepare
   docker compose -f compose.pytorch.yaml run --rm prepare
   docker compose -f compose.pytorch.yaml run --rm tests
   ```

5. Follow the [README quick start](../README.md#run-the-private-lab) to start the
   workers/coordinator and validate the service. Use the new project names with
   the experiment and network-profile scripts.

Compose scopes named volumes and networks by project. The renamed projects use
fresh volumes; old cache/artifact/peer-state volumes are left intact. Preparation
downloads and verifies the pinned checkpoint again. Copying or deleting old
volumes is not part of this migration. Do not run mixed old/new services or reuse
an old experiment continuation plan with the renamed source: source fingerprints,
Compose hashes and image identities change, so start a new run and retain the
earlier evidence separately.

## Complete the GitHub hosting rename

The API rejected the repository name/description update with HTTP 403
(`Resource not accessible by integration`). Source writes are available, but
repository-settings changes are not available to this connection. The owner can
finish this step in [repository settings](https://github.com/mat092011/steamboat_net/settings):
set **Repository name** to `replicant-mesh` and select **Rename**. Set the About
description to “Replicant Mesh: cooperative LLM inference across consumer devices,
pooling memory and spare compute. Experimental research prototype.”

Once the server rename succeeds, replace the transitional old-slug links and
clone URL in README/SECURITY with the new address and mark this hosting step
complete. GitHub's security-setting verifier follows the live name automatically.

## Historical records

Reports under [experiments](experiments/README.md) describe runs performed before
the rename. Their recorded image tags, paths, hashes, source commits and raw JSON
remain historical evidence. Markdown reports are labeled accordingly and links
to the repository use its current hosting URL. Older source paths can be
inspected at the source commits recorded in those reports. A new image tag does
not establish equivalence to a historical image digest or repeat a performance
measurement. The rename does not complete any research phase.

The full name **Replicant Mesh** distinguishes this project from other projects
using “Replicant.” Preliminary exact-name web and GitHub searches found no obvious
software-project collision; domains, registry names and trademarks were not cleared
or reserved. No package, container registry release or domain is created by this rename.
