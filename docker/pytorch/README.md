# Independent PyTorch CPU environment

This image supports the owned runtime. It has no Petals, Hivemind, or
bitsandbytes dependency. The historical `docker/Dockerfile` keeps its separate
Petals dependency stack. The pinned target is **CPython 3.12 / Linux amd64**; other Python
versions and architectures need their own resolution and numerical validation.

The selected runtime is PyTorch `2.14.1+cpu`, Transformers `5.19.0`, gRPC
`1.84.0`, and Protobuf `7.36.2`. `requirements.lock` fixes all 38 resolved
application packages to exact wheel URLs and SHA256 hashes. Builds use
`--require-hashes`, binary wheels only, and no package index. `requirements.in`
records the top-level choices for intentional future updates. The build tool
`pip` is supplied by the immutable Python base image.

The Python `3.12.15-slim-bookworm` **linux/amd64 manifest digest** is
`sha256:2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d`.
M5 installs Debian's `iproute2` package for container-local `tc` shaping. The tested
package version is captured in experiment evidence; this OS tooling layer uses
the Debian package repository and is separate from the hash-locked Python stack.

From the repository root:

```powershell
docker build --platform linux/amd64 -f docker/pytorch/Dockerfile -t replicant-mesh-pytorch:cpu .
docker run --rm --network none replicant-mesh-pytorch:cpu python /opt/replicant-mesh/verify_environment.py
```

The build runs `pip check` and an offline random-weight Llama eager-attention
prefill/cached-decode smoke test. It also checks that the legacy dependency
modules are absent and the PyTorch build is CPU-only. Model equivalence tests
are separate: this environment check cannot establish partition correctness.
Weights are downloaded/prepared at runtime, not baked into the image.

The M0–M5 Compose lab uses its own project, cache and artifact volumes. Run the
following services sequentially; `prepare` is the only one with internet access.
Tests and comparisons mount the prepared weights read-only and run with
`network_mode: none`, two CPUs and a 6 GiB memory limit per invocation.
The separate worker/coordinator services use an internal network with no published
ports. The thin benchmark mounts only its results directory. See the
[M5 lab guide](../../docs/PYTORCH_LAB.md) for service budgets and network experiments.

```powershell
docker compose -f compose.pytorch.yaml build prepare
docker compose -f compose.pytorch.yaml run --rm prepare
docker compose -f compose.pytorch.yaml run --rm tests
docker compose -f compose.pytorch.yaml run --rm benchmark
```

`benchmark` defaults to the pre-run numerical check. To collect a short,
single-process smoke benchmark after that check passes:

```powershell
docker compose -f compose.pytorch.yaml run --rm benchmark python -m lab.benchmark bench --backend pytorch --mode pipeline --requests 3 --concurrency 1 --prompt-tokens 128 --new-tokens 8 --label m1-in-process
```

The test service also enables M2's codec/state checks and M3's queue, admission,
and process-fault tests. These run within the test container using loopback RPC.
For the three supervised containers and their remote numerical comparison, follow
[the worker guide](../../docs/PYTORCH_WORKERS.md). They share an internal Docker
network and publish no ports; workers each have two CPUs and a 3 GiB limit.
M4 also enables coordinator lifecycle/model tests. Its `coordinator-check` service
compares 1/3/8 concurrent requests and verifies compute overlap; see the
[coordinator guide](../../docs/PYTORCH_COORDINATOR.md).

The matching complete-model control uses `--mode local`. Both use the same
locked new stack and CPU budget. These are in-process M1 runs; they provide no
network or independent-worker performance evidence. Do not run the two controls
simultaneously on the shared laptop. Reports are written to ignored
`.lab/pytorch-results/`; tests default to a unique timestamped JSON file (override
the directory or use an unused JSON filename through `REPLICANT_MESH_TEST_REPORT`).
The original `compose.yaml` and its volumes remain
independent. There is no `NET_ADMIN`, Docker socket mount, or exposed port here.

To build only the dependency environment while developing source files, add
`--target dependencies` and use a different tag such as
`replicant-mesh-pytorch:dependencies`. Bind the repository to `/app` for development;
`PYTHONPATH` already includes `/app/src` and `/app`. Model cache paths are
`/cache/huggingface` and `/cache/huggingface/hub`; prepared slices can be mounted
at `/artifacts`. `PYTHONDONTWRITEBYTECODE=1` avoids cache writes into source mounts.

## Intentional lock updates

Run these PowerShell commands from the repository root after editing
`requirements.in`. This re-resolves transitive versions; inspect the resulting
diff and repeat environment and numerical gates before accepting the change.
Keep the raw resolver report under ignored `.lab/`.

```powershell
New-Item -ItemType Directory -Force .lab/pytorch-env | Out-Null
$runtimeBase = 'python:3.12.15-slim-bookworm@sha256:2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d'
$runtimeMount = "type=bind,source=$($PWD.Path),target=/work"
docker run --rm --platform linux/amd64 --mount $runtimeMount $runtimeBase python -m pip install --dry-run --ignore-installed --only-binary=:all: --report /work/.lab/pytorch-env/resolution.json -r /work/docker/pytorch/requirements.in
if ($LASTEXITCODE -ne 0) { throw 'Dependency resolution failed' }
docker run --rm --platform linux/amd64 --mount $runtimeMount $runtimeBase python /work/docker/pytorch/lock_from_report.py /work/.lab/pytorch-env/resolution.json /work/docker/pytorch/requirements.lock
if ($LASTEXITCODE -ne 0) { throw 'Lock rendering failed' }
```

Version and API choices were checked against the primary distributions on
2026-10-14: [official PyTorch CPU wheels](https://download.pytorch.org/whl/cpu/torch/),
[Transformers 5.19.0](https://pypi.org/project/transformers/5.19.0/),
[gRPC 1.84.0](https://pypi.org/project/grpcio/1.84.0/),
[Protobuf 7.36.2](https://pypi.org/project/protobuf/7.36.2/), and the
[pinned Llama adapter source](https://github.com/huggingface/transformers/blob/v5.19.0/src/transformers/models/llama/modeling_llama.py).
The source uses explicit `past_key_values`, absolute `position_ids`, shared
rotary position embeddings, and a cache indexed by each attention layer's
`layer_idx`; the owned adapter must preserve these semantics.
