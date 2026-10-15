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

The remote validation driver calls the three stages sequentially and compares
logits with the complete model. The next milestone is the coordinator scheduler
that overlaps independent requests across stages. Network-performance experiments
for this runtime follow in M5.

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

Follow [the container lab guide](docs/LOCAL_LAB.md) for prerequisites, launch,
correctness checks, benchmarks, and cleanup. The default checkpoint is the tiny
real transformer `Maykeye/TinyLLama-v0`; the guide also describes an optional
`bigscience/bloom-560m` configuration.

## Project documents

- [PyTorch runtime guide](docs/PYTORCH_RUNTIME.md): run the independent CPU image,
  prepare verified shards, test numerical parity and inspect session limits.
- [PyTorch protocol guide](docs/PYTORCH_PROTOCOL.md): binary messages, worker
  sessions, cancellation, deadlines and loopback transport checks.
- [PyTorch worker guide](docs/PYTORCH_WORKERS.md): three private worker containers,
  bounded queues, process supervision and remote numerical checks.
- [PyTorch pipeline implementation plan](docs/PYTORCH_PIPELINE_PLAN.md): fixed
  workers, session protocol, coordinator scheduling, and reusable lab comparisons.
- [Container lab guide](docs/LOCAL_LAB.md): setup, simulation commands, and limits.
- [Multiphase research and implementation plan](docs/PLAN.md): experiments,
  deliverables, acceptance gates, benchmarks, and the path toward decentralization.
- [Agent guidance](AGENTS.md): technical principles and repository workflow.
