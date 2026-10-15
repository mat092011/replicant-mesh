# PyTorch runtime: first implementation slice

The M0/M1 slice of [the implementation plan](PYTORCH_PIPELINE_PLAN.md) is runnable.
It prepares verified model shards and proves three sequential Llama partitions
against a complete model on the same new software stack. All stages execute in
one process. [M2 protocol/lifecycle](PYTORCH_PROTOCOL.md) is also implemented as a
separate worker handler and binary transport with lease expiry. The direct M1
benchmark path described here remains sequential. Separate worker services and
supervision are available in [M3](PYTORCH_WORKERS.md). Scheduling
and network simulation for this backend remain M4–M5 work.

## Run

Use Docker Desktop with its Linux engine, Linux amd64, and at least 6 GiB available
to the test container. Run from the repository root in PowerShell:

```powershell
docker compose -f compose.pytorch.yaml build prepare
docker compose -f compose.pytorch.yaml run --rm prepare
docker compose -f compose.pytorch.yaml run --rm tests
docker compose -f compose.pytorch.yaml run --rm benchmark
```

These commands were executed successfully on 2026-10-14; see the
[validation report](experiments/2026-10-14-pytorch-m1.md). The preparation job alone
uses the network. It downloads seven public files at the exact checkpoint revision,
verifies their frozen SHA256 hashes, converts BF16 source weights to float32 and
writes four safetensors artifacts plus `modelmanifest.json`. Reusing an existing
artifact directory verifies it; incomplete or corrupted directories fail explicitly.
Use a new output directory after changing the manifest contract.

The project `steamboat-pytorch-m1` owns separate model-cache and artifact volumes.
Tests and comparisons mount both read-only with networking disabled. Each process
has two CPUs, two Torch threads, a 6 GiB container memory limit and no public ports.
Reports go to ignored `.lab/pytorch-results/` with unique names. The test JSON is
numerical observations; use the test process exit status to establish suite success.
Without explicit artifact/reference environment paths, model integration tests
skip; the Compose `tests` service supplies both so missing artifacts cause failure.

`benchmark` defaults to a short correctness check. After it passes, exercise the
existing runner with the new backend:

```powershell
docker compose -f compose.pytorch.yaml run --rm benchmark python -m lab.benchmark bench --backend pytorch --mode pipeline --requests 3 --concurrency 3 --prompt-tokens 128 --new-tokens 8 --label m1-cli-smoke
docker compose -f compose.pytorch.yaml run --rm benchmark python -m lab.benchmark bench --backend pytorch --mode local --requests 3 --concurrency 1 --prompt-tokens 128 --new-tokens 8 --label m1-cli-control
```

These are runner smoke checks with different concurrency, not a performance
comparison. The pipeline serializes whole steps under one lock. Threaded clients
exercise independent sessions but do not demonstrate stage overlap. Use identical
workloads/resources and the later measurement protocol before drawing conclusions.

The original `compose.yaml` remains the Petals lab. Existing benchmark invocations
default to `--backend petals`; the new image has no Petals, Hivemind or bitsandbytes.
Run each backend in its own image. See [dependency details](../docker/pytorch/README.md)
for the pinned base digest, 38-package hash lock, environment checks and updates.

## Components and session contract

`Maykeye/TinyLLama-v0` and its tokenizer are fixed at revision
`298338802ab94432b917bcce11382aa151aee50f`. Only CPU float32, eager attention,
unpadded batch size one, and `[batch, sequence, hidden]` activations are supported.

| Component | Resident model parameters | Parameter count |
| --- | --- | ---: |
| Coordinator input/output | Embeddings, final normalization, output projection | 4,096,064 |
| Worker 1 partition | Global layers `[0,3)` | 196,992 |
| Worker 2 partition | Global layers `[3,6)` | 196,992 |
| Worker 3 partition | Global layers `[6,8)` | 131,328 |

The small model places about 89% of its parameters in the coordinator. This
checkpoint is useful for checking mechanics, not demonstrating pooled memory.
The eight legacy `rotary_emb.inv_freq` checkpoint buffers are checked against the
pinned configuration and omitted explicitly; current Transformers derives them.
Unknown weights or missing learned parameters are rejected.

`steamboat_runtime.interfaces.InferenceSession` defines `step`, `close`, `position`,
`diagnostics` and context-manager cleanup. `PipelineModel.open_session(max_length)`
reserves a context budget and generates an opaque local session ID. `step` accepts
CPU int64 token IDs shaped `[1,T]`; it returns last-position logits by default or
all input-position logits with `return_all_logits=True`.

Each stage owns a separate KV cache for every session, keyed by global layer
number. Absolute positions and an explicit causal mask retain the entire committed
prefix. A step advances the session position only after all stages and the head
succeed. Invalid IDs/shapes/context bounds are rejected before mutation. A compute
failure closes the affected session because earlier layers may already have
advanced; another session remains usable. Close is idempotent.

Diagnostics expose logical lengths, reserved positions, live cache tensor bytes
and active sessions. Reservations are accounting limits, not preallocated tensors.
Caches grow as tokens arrive. Counts exclude allocator overhead, temporary attention
buffers, process RSS and loading peaks. Closing releases references to live KV
tensors; it does not promise that the allocator returns all memory to the OS.

## Resource contract

This table describes the original direct M1 adapter. M2 adds protocol/lifecycle
enforcement; [M3's service guide](PYTORCH_WORKERS.md) describes the implemented
worker memory quotas, stage queues and independent process deadlines.

| Bound | Value | Enforcement in M1 |
| --- | --- | --- |
| Active sessions | 8 | Excess open rejected |
| Input positions per session | 1,152 | Reservation and every step checked |
| Reserved positions per stage | 12,288 | Admission accounting checked |
| Cache budget per stage | 16 MiB | Configuration proves all admitted reservations fit |
| Planned worker memory | 3 GiB | Configuration checks weights/cache; no worker process yet |
| Active compute | 1 | One lock serializes the entire pipeline |
| Stage/admission/output queues | 8 / 32 / 16 | Declared for M2–M4; no queues yet |
| Admission/request/RPC timeouts | 30 / 300 / 30 seconds | Declared for M2–M4 |
| Idle lease/check/renew | 120 / 5 / 30 seconds | Declared for M2–M4 |
| Compute cancellation grace | 15 seconds | Declared for later worker supervisor |
| Tensor message ceiling | 1 MiB | Configuration checks shape budget; no transport yet |

At eight full 1,152-position sessions, the three-layer partitions each require
14,155,776 KV tensor bytes and the two-layer partition requires 9,437,184 bytes.
The configuration rejects insufficient reservations and unsupported layer coverage,
model identity, architecture, precision, tensor ownership and artifact hashes.

Tests compare every prefill-position logit for 1/128/1,024-token prompts followed
by eight identical forced tokens, plus independent greedy generation, unequal
interleaved sessions, 1,152-position boundaries, eight-session admission, parameter
ownership, invalid input and injected compute failure. The frozen acceptance
tolerance remains `atol=1e-3, rtol=0`; observed errors are recorded separately.

To remove only this project's stopped containers/network while retaining caches:

```powershell
docker compose -f compose.pytorch.yaml down
```
