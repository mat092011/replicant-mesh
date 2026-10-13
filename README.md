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

- [Container lab guide](docs/LOCAL_LAB.md): setup, simulation commands, and limits.
- [Multiphase research and implementation plan](docs/PLAN.md): experiments,
  deliverables, acceptance gates, benchmarks, and the path toward decentralization.
- [Agent guidance](AGENTS.md): technical principles and repository workflow.
