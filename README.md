# steamboat_net

A research project exploring cooperative LLM inference across consumer devices
connected over the internet.

The idea is to pool GPU memory and spare compute so participants can access models
or inference capacity beyond their own machines. A later contribution system will
test whether credits earned by serving accepted work can be exchanged for personal
inference.

The first experiment splits a fixed model into consecutive groups of layers,
validates its outputs, and measures latency and throughput on local and internet
connections. Multiple independent requests can occupy different pipeline stages
at once; faster generation for one user must be demonstrated separately.

## Status

The owned PyTorch runtime runs three fixed layer partitions in separate supervised
containers, with per-session KV caches, bounded FIFO queues and no Petals dependency.
The binary protocol checks activations, positions and worker identities. The process
supervisor replaces stuck workers and invalidates their old sessions.
See the [worker guide](docs/PYTORCH_WORKERS.md) and
[M3 validation results](docs/experiments/2026-10-15-pytorch-m3.md).

M4 adds a bounded coordinator that streams tokens and overlaps independent requests
across stages. Concurrent requests match the complete-model reference, and a trace
verifies actual worker compute overlap on this laptop. See the
[coordinator guide](docs/PYTORCH_COORDINATOR.md) and
[M4 validation results](docs/experiments/2026-10-15-pytorch-m4.md).
M5 adds a standalone coordinator service, a thin benchmark client and measured
Docker network simulation. Its lab gate passes; the full performance sweep remains
incomplete. See the [network lab guide](docs/PYTORCH_LAB.md) and
[M5 results](docs/experiments/2026-10-16-pytorch-m5.md).
Follow-on tools [audit saved experiments](docs/PYTORCH_EXPERIMENT_ANALYSIS.md)
and [prepare memory-capacity budgets](docs/PYTORCH_CAPACITY.md). They support the
broader research plan without claiming a pooled-GPU demonstration.

A CPU container lab now defines three Petals workers, a private discovery service,
and a client on one laptop. It includes a complete-model reference, correctness
checks, and a benchmark runner. Packet shaping can simulate delay, bandwidth
limits, jitter, and loss between containers.

The first [local smoke experiment](docs/experiments/2026-10-13-local-lab.md)
passed correctness checks and completed 58 benchmark requests without failures,
including simulated WAN conditions and eight concurrent sessions. Containers share
the laptop's CPU and RAM; this tests pipeline mechanics and network sensitivity.
Separate consumer GPUs, pooled-memory benefits, and credits remain future work.

## Run the local experiment

Follow [the PyTorch network lab guide](docs/PYTORCH_LAB.md) for launch, correctness
checks, benchmarks and network reset. The checkpoint is the tiny real transformer
`Maykeye/TinyLLama-v0`. The historical [Petals lab guide](docs/LOCAL_LAB.md)
also describes an optional `bigscience/bloom-560m` configuration.

## Project documents

- [PyTorch runtime guide](docs/PYTORCH_RUNTIME.md): run the independent CPU image,
  prepare verified shards, test numerical parity and inspect session limits.
- [PyTorch protocol guide](docs/PYTORCH_PROTOCOL.md): binary messages, worker
  sessions, cancellation, deadlines and loopback transport checks.
- [PyTorch worker guide](docs/PYTORCH_WORKERS.md): three private worker containers,
  bounded queues, process supervision and remote numerical checks.
- [PyTorch coordinator guide](docs/PYTORCH_COORDINATOR.md): admission, concurrent
  scheduling, streamed tokens, cancellation and compute-overlap evidence.
- [PyTorch network lab guide](docs/PYTORCH_LAB.md): standalone coordinator,
  remote benchmark, measured network profiles and reproducible experiments.
- [PyTorch pipeline implementation plan](docs/PYTORCH_PIPELINE_PLAN.md): fixed
  workers, session protocol, coordinator scheduling, and reusable lab comparisons.
- [Container lab guide](docs/LOCAL_LAB.md): setup, simulation commands, and limits.
- [Multiphase research and implementation plan](docs/PLAN.md): experiments,
  deliverables, acceptance gates, benchmarks, and the path toward decentralization.
- [Agent guidance](AGENTS.md): technical principles and repository workflow.
