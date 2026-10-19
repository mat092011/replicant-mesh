# Local participant artifact and connector validation

Date: 2026-10-17. **Status: bounded local Linux validation only.** This record
does not pass C2a, C2.3, C2, or any research gate. It records parent-run checks
of the offline artifact verifier/installer, assigned-artifact loader, and
standard-library connector foundation. The tested source candidate predates this
documentation update.

## Environment and commands

The parent ran the tests in Linux/amd64 Docker containers with networking
disabled. The artifact image used CPython 3.12.15 and the pinned CPU runtime;
Compose capped it at 2 CPUs, 6 GiB memory, and 256 processes, with a read-only
root, dropped capabilities, offline model inputs, and bounded temporary storage.
Its separate hash-pinned artifact-security lock adds `cryptography==50.0.2`,
`cffi==2.1.1`, and `pycparser==3.11`. The connector foundation image used
CPython 3.12.15, `python -S`, 1 CPU, 256 MiB memory, and 64 processes. These are
container limits, not measured peak memory or evidence that runtime role limits
are enforced.

Parent-executed build and run commands, from retained command records:

```sh
docker compose -p steamboat-c2a-artifacts-20261017 -f compose.participant-artifacts.yaml build artifacts
docker compose -p steamboat-c2a-artifacts-20261017 -f compose.participant-artifacts.yaml run --rm artifacts
docker compose -p steamboat-c2a-foundation-20261017 -f compose.participant-connector.yaml build connector
docker compose -p steamboat-c2a-foundation-20261017 -f compose.participant-connector.yaml run --rm connector
```

| Run | Result | Retained parent log and SHA-256 |
| --- | --- | --- |
| Artifact, assigned-loader, and connector suite | 58 passed, 0 skipped | `.lab/participant-network/results/c2a-artifacts/artifacts-test-1792258722536.log` — `36500ab9e4f7e79abed7a8cc7f6ce97f5574fee236dd2328d77bba678dfd01a9` |
| Connector standard-library foundation | 23 passed, 0 skipped | `.lab/participant-network/results/c2a-foundation/connector-test-1792258835562.log` — `c974ec1fcc4f47c6deacc300dcbb7c2e2585517453e6a13ec392822f7a92e66c` |

The 23 foundation tests overlap the 58-test run; the counts are not additive.
The artifact run used read-only model artifacts and bounded scratch supplied by
the parent. It tests signed catalog/assignment validation, strict parsing and
scoping, installer storage and failure cases, runtime/import guards, connector
checks, and the assigned-loader integration case. The consumer/foundation path
remains standard-library-only; artifact signature verification uses the
separate pinned dependency.

## Assigned-only numerical check

The opt-in model test installed and loaded only the signed files for each of the
three host assignments, then loaded the coordinator assignment. In one process,
it compared the assigned-component path with the existing v1 `PipelineModel`
loaded from the complete original artifact inventory. The pinned TinyLlama CPU
stack was `Maykeye/TinyLLama-v0`, revision
`298338802ab94432b917bcce11382aa151aee50f`, float32/eager, PyTorch 2.14.1+cpu,
Transformers 5.19.0, safetensors 0.8.0, gRPC 1.84.0 and Protobuf 7.36.2;
compression was unchanged (none). The forced input
sequence was `[[1, 17, 19], [23], [31]]`; logits were checked with
`atol=1e-3, rtol=0`. This is a bounded same-stack correctness check, not a
performance, memory-fit, GPU, separate-device, or live-service result.

## Candidate provenance and retained history

The parent source proof checked 193 candidate files with zero mismatches and
recorded source-manifest digest
`ff467f9ca57856c7fb643ac9d9b279b9befa766e7abf9f5c059acf9e303c90dc`. Its proof
log SHA-256 is
`fad10c17344757889ad12b6994aad652cbc17c0a0cffa76ed1bb11105b06f2af`. The tested
artifact and minimal-foundation image digests were respectively
`sha256:bc7fa57d96c8db5a8ee43a10849365529f1833293c77e0b2348c134fda20aad9` and
`sha256:56d0a35772faf503a09b5108de1a2300233a62cf536f4fdb25a6716444b3af1f`.
These source/image proofs predate this documentation change; they do not attest
to a later source revision or make a source-publication claim.

An earlier focused run is retained at
`.lab/participant-network/results/c2a-artifacts/artifacts-required-18-1792253187136.log`.
It ran 18 tests and failed one interrupted-replacement test because its fake
retriever yielded the file as one chunk, so the intended interruption was never
reached. The fixture was changed to yield 8-byte chunks; the corrected suite
subsequently passed, and the model case passed in the earlier model-enabled run.
The initial failure remains part of the evidence history.

Earlier source reviews also found issues in expiry refresh after lock/load,
iterator/descriptor cleanup, expiry checks before new cache creation,
valid-assignment wrong-domain rejection, and uncertain state after a
post-replacement directory-fsync failure. The candidate was corrected with
regression coverage for those cases. The latest parent review reported no
remaining material source findings in its bounded three-file fix scope.
Header-malformation model cases still replace
`_verify_unlocked`, so they are not full signed-install end-to-end evidence; the
separate `open_view` tamper case does exercise end-to-end assigned-file hash
rejection.

## Limits and next dependencies

The artifact retriever accepts a local approved artifact-store directory; there
is no HTTPS retriever, redirect/hostname policy, public issuer/operator, or
production key custody. The installer and loader are not wired into the
participant daemon, worker/coordinator services, real role backend, readiness,
live authorization/revocation, or an outbound route. Shared resource records
and container caps do not prove physical memory or CPU enforcement. No GPU,
memory-fit, cost, WAN, multi-device, or separate-device inference result follows
from these tests.

C0 remains the only passed/published participant-network phase. C1–C9 remain
planned, C2a/C2.3 are not accepted, and all P0–P8 research statuses remain
unchanged.
