# steamboat_net

A research project exploring cooperative LLM inference across consumer devices
connected over the internet.

The idea is to pool GPU memory and spare compute so participants can access models
or inference capacity beyond their own machines. A later contribution system will
test whether credits earned by serving accepted work can be exchanged for personal
inference.

The first experiment will split a fixed model into consecutive groups of layers,
validate its outputs, and measure latency and throughput on local and internet
connections. Multiple independent requests can occupy different pipeline stages
at once; faster generation for one user must be demonstrated separately.

## Status

Planning only. No inference runtime, benchmark results, or credit system has been
implemented yet.

## Project documents

- [Multiphase research and implementation plan](docs/PLAN.md): experiments,
  deliverables, acceptance gates, benchmarks, and the path toward decentralization.
- [Agent guidance](AGENTS.md): technical principles and repository workflow.
