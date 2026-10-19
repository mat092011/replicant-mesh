# Participant artifact assignments (C2.3 local slice)

## Status and scope

This document describes a bounded local implementation slice, not completion or
acceptance of C2.3, C2a, or any later phase. The catalog verifier, local artifact
installer, and assigned-artifact loader are not yet wired to the participant
daemon, worker service, or network coordinator. Installing files does not make a
role ready, authenticate a peer, or establish that remote revocation succeeded.
The parent-run Linux checks for these local components are recorded in the
[2026-10-17 validation report](experiments/2026-10-17-participant-c2a-local.md);
they do not change this integration boundary or phase status.
The existing v1 `load_manifest`, `StageExecutor`, and
`CoordinatorModel.from_artifacts` validation paths remain unchanged.
The parent contract remains [normative](PARTICIPANT_CONTRACTS.md), with the
decision recorded in [decision 0001](decisions/0001-participant-contracts.md).

The only accepted model package is the C0-pinned TinyLlama v1 CPU package:
`Maykeye/TinyLLama-v0` at revision
`298338802ab94432b917bcce11382aa151aee50f`, Linux amd64, Python 3.12.15,
Torch 2.14.1+cpu, Transformers 5.19.0, gRPC 1.84.0, Protobuf 7.36.2,
float32/eager/no compression, and the C0 GitLF runtime-lock SHA-256
`0d893300099241375c9ef032268e162ff6ef46fe93cce1bbe6457bfd01545434`. The
catalog rejects other model, source, component, range, or runtime identities.
Native Windows, AMD, GPU, other models, precision changes, and arbitrary code
are unsupported. No `trust_remote_code` path is allowed.

## Signed formats and trust

Catalog and assignment envelopes are canonical bounded JSON with exact v1
fields, duplicate-key/non-finite/unknown-field rejection, and distinct
domain-separated messages. Both use the pinned catalog root and
`ecdsa-p256-sha256-raw-low-s-v1`: a 64-byte big-endian `r || s` signature,
P-256, SHA-256, and low-S encoding. Public points are parsed by
`cryptography`'s P-256 implementation and signatures are verified with its
ECDSA API; no handwritten curve or signature arithmetic is used. The key ID is
SHA-256 of the uncompressed SEC1 public point. Deployment must provide the
approved root key out of band and pin `cryptography==50.0.2` from a
hash-verified package source. Test signing keys are synthetic and are not
deployment trust roots.

Catalog lifetime is at most 30 days. An assignment is bound to one `acct_`,
`dev_`, role, component, catalog revision and digest, and global manifest
fingerprint; its expiry cannot exceed the catalog expiry. The persistent local
high-water mark rejects catalog rollback and same-revision equivocation. Root
key replacement or state migration is not implemented and requires an explicit
owner-controlled migration; there is no public enrollment or automatic trust
bootstrap.

| Assignment role | Downloaded files | Local scope |
| --- | --- | --- |
| `consumer` | None | Never installs or loads model weights. |
| `host` | Global runtime manifest, pinned config, and exactly one of `worker-1`, `worker-2`, or `worker-3` safetensors | One assigned contiguous worker shard and its layer cache. |
| `coordinator` | Global runtime manifest, pinned config, coordinator safetensors, and the pinned tokenizer/source files | Embeddings, norm/head, and offline tokenizer; no worker shard weights. |

The current local retriever accepts only fixed filenames from an approved local
artifact-store directory owned by the same UID with mode 0700; source files must
be same-UID regular files and not group/world writable. There is no HTTPS
implementation, arbitrary URL fetching, redirect handling, peer-supplied
source, or public distribution service. The actual catalog operator,
signing-key custody, assignment issuer,
terms, approved distribution route, and revocation process remain external
dependencies (DEP-03); human owners are unassigned. Synthetic fixtures do not
resolve those dependencies.

## Installation and loading bounds

The installation root is owner-owned/private (0700); metadata and artifacts are
owner-owned regular files (0600), accessed with no-follow/open-directory
primitives. Staging is private and is committed only after every selected file
has the signed exact size and SHA-256. Linux publication uses
`renameat2(RENAME_NOREPLACE)` with the opened installation-root directory
descriptor; there is no replace-capable fallback. If a final path appears in
the publication race, the destination and marker are left untouched, staging is
cleaned, and the persisted reservation remains charged. Recovery refuses to
remove that ambiguous final directory or release its reservation automatically;
operator reconciliation is not implemented here.
Unexpected files, symlinks, unsafe paths, malformed state, signature/hash
mismatch, expiry, rollback, quota exhaustion, or incomplete retrieval fail
closed. Cleanup is confined to recorded installer-owned paths. Interrupted
staging can be cleaned; an ambiguous final directory is preserved and causes
recovery to stop rather than deleting it automatically.

If final publication succeeds but writing the committed state fails, the result
is uncertain: the installer preserves the published directory and does not
attempt a second state write or delete files that may already be referenced.
Before metadata replacement, the persisted reservation remains charged and
restart refuses automatic recovery while that final directory exists. After
replacement, the installation record accounts for the directory and the active
role pointer may already have changed. The previous installation remains on
disk, but its active pointer is not guaranteed to remain selected. Manual
reconciliation is not implemented.

The enforced code bounds are 32 MiB per file, 64 MiB per selected package
(including signed documents and a fixed 64 KiB metadata reserve), 64 KiB per
retrieval chunk, at most 512 chunks per maximum-size file, and a 300-second
install deadline. The caller must set a disk ceiling; at least 16 MiB is
reserved as free-space headroom. Existing installations and in-progress
reservations both count against the ceiling, so a replacement must fit beside
the prior installation until commit/removal. There are at most eight recorded
installations and eight recorded staging reservations. Install attempts
serialize on a cross-process file lock with a maximum five-second acquisition
timeout. Regular-file readers open with no-follow and nonblocking flags before
checking the descriptor type, so a FIFO is rejected without waiting for a
writer. Deadlines are checked between local reads/chunks and writes; they are
not a hard interrupt for a blocked read, write, fsync, or other filesystem
operation, especially on a pathological or network filesystem, and they do not
interrupt a stalled process.

Install/replace does not remove the previous installation. Removal requires an
inactive role and an explicit `compute_stopped=True` caller assertion; that
assertion is not independently verified by this slice. Remote assignment
revocation is not implied. The assigned-artifact adapter re-verifies the signed
catalog/assignment, role file scope, selected-file hashes, runtime lock, pinned
config, complete global v1 manifest structure/fingerprint, and catalog-to-
manifest component inventory before loading. It also checks actual Linux/amd64,
CPython 3.12.15 and installed distribution metadata for Torch 2.14.1+cpu,
Transformers 5.19.0, safetensors 0.8.0, gRPC 1.84.0 and Protobuf 7.36.2 before
importing Torch. Once imported, the Torch module version must match and CUDA/HIP
builds or available CUDA are rejected before safetensors materialization. These
metadata checks do not import Torch on consumer, catalog, or installer paths.
The adapter loads only the assigned safetensors after validating its header;
the unchanged full-inventory v1 loader remains strict and rejects these partial
role installations.

Signed expiry checks rely on the host's trusted wall clock. An explicit `now`
passed to `open_view` is only the initial validation snapshot; later checks use
the advancing installer wall clock, including a fresh catalog/assignment
validation immediately before tensor materialization. Clock rollback protection
and C1 secure-clock integration remain pending; no arbitrary expiry tolerance
is applied.

The adapter can construct existing `LayerStage`/`LayerCache` objects for a host
shard or the existing coordinator `InputOutput` plus local tokenizer. It does
not weaken whole-inventory checks in the existing runtime, register a running
worker, connect a coordinator to remote stages, or assert resource/auth
readiness. Assigned loaders and the parent daemon/network integration remain
separate gates.

## Threat model and limits

The verifier trusts the externally pinned catalog root and the owner account
that controls the private installation directory and local artifact store. A
valid signature binds metadata to a trusted issuer; it does not prove that the
issuer is honest, that the model is safe, that a host executes correctly, or
that a remote operator has revoked an assignment. Local owner/root compromise,
malicious same-UID processes, signing-key compromise, denial of service, and
model-side-channel exposure are not prevented here. The slice downloads no
consumer weights and does not log prompts, tokens, leases, or payloads, but
worker owners can observe computations assigned to their machine; encrypted
transport would not hide computation from them. Use only public or synthetic
prompts in experiments. There is no public-insecure lab mode.

## Validation matrix

`tests/connector/test_artifacts.py` covers cryptography-backed signatures and
wrong-root, wrong-curve, invalid-point, altered/high-S, and cross-domain
signature negatives; strict
JSON/schema/version/expiry/revision/model/runtime/hash/size/range binding;
role scope; interrupted retrieval after a recorded positive partial write;
corruption, quota, path/symlink handling, rollback, concurrent installs,
before- and after-replacement commit failures, descriptor-count checks retaining
failure tracebacks, positive-write ENOSPC, an atomic publication-race collision,
and safe recovery. It also checks expiry after simulated hashing/runtime delay,
runtime guards on cache construction, and has an opt-in assigned-loader numerical comparison and
negative checks for corrupt assigned files, complete-v1-inventory rejection,
and loading only the assigned shard or coordinator file. The numerical test
uses the existing pinned read-only model artifacts, bounded scratch, and forced
token continuations against the same-stack reference. It must not download or
copy model weights into Git or a host model cache. Runtime metadata mismatch
tests assert failure before Torch import; the consumer/catalog/installer import
test uses a fresh subprocess so earlier model tests cannot pollute `sys.modules`.

Run the lightweight suite with:

```text
PYTHONPATH=src python -m unittest tests.connector.test_artifacts tests.connector.test_validation_client -v
```

On non-Linux hosts the Linux openat, `O_NOFOLLOW`, and `flock` installer cases
are skipped; the parent-run Linux results are linked below. The model comparison is also opt-in and skipped unless
the parent provides `STEAMBOAT_ASSIGNED_TEST_SOURCE` (read-only artifacts) and
`STEAMBOAT_ASSIGNED_TEST_SCRATCH` (bounded writable scratch). The parent-run
[Linux validation report](experiments/2026-10-17-participant-c2a-local.md)
records 58 combined artifact/connector tests with no skips, including the
assigned-only comparison of three host shards plus the coordinator against the
same-stack reference. This validates the local verifier, installer, and loader
paths only; it does not establish daemon wiring, secure admission, a live worker
service, or a real network route.

## Remaining dependencies

- DEP-03: an approved catalog/assignment operator, pinned production root
  custody/rotation, assignment issuance, distribution terms, and a revocation
  route; accountable human operators remain unassigned.
- C2.3 network retrieval: an approved bounded retriever and its actual address,
  hostname/TLS, redirect, response-size, timeout, and authorization policy.
- C2a integration: connect installation/loading to authenticated daemon state,
  readiness, resource enforcement, and supervised role lifecycle.
- Integration validation: the parent-run Linux report records skip-free installer,
  publication-race, runtime-identity, import-isolation and assigned-loader checks.
  Secure role startup, daemon lifecycle, live authorization/revocation and network
  retrieval remain separate work; these local results do not satisfy those gates.
- Research inputs: separate inventoried physical hosts, real operator access,
  routes, and measured budgets remain pending; same-host arithmetic or synthetic
  fixtures do not satisfy those requirements.

No phase evidence or status is changed here; parent owns integration, evidence,
and acceptance.
