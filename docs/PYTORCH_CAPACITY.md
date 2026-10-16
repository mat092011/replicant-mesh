# Capacity inventory and explicit memory-fit planning

`lab.device_inventory` records local CPU, RAM, and supported NVIDIA GPU
observations, then checks caller-supplied memory budgets against device
capacities. It does not choose a model, infer memory from the tiny checkpoint,
measure model loading, or establish that a model can execute successfully.

Run the inventory snapshot from the repository root:

```powershell
python -m lab.device_inventory inventory
```

The output includes an observation time in UTC, OS release and architecture,
CPU name and logical count, total and currently available physical RAM where the
OS exposes it, and NVIDIA name, total/free VRAM, and driver version when
`nvidia-smi` works. It excludes hostnames, IP addresses, and serial numbers. Free
memory is a time-sensitive snapshot. When the GPU vendor or telemetry is
unsupported or unavailable, GPU status is `unknown`; the tool does not estimate
free VRAM. The current implementation has no AMD telemetry path.

The planner consumes JSON with a model, revision, and precision identifier;
usable capacity and a `capacity_basis` for each device; the RAM/VRAM `memory_kind`;
an explicit device index for the coordinator and each worker; and one component
budget for each placement. Every component declares weight bytes, KV-cache bytes,
temporary headroom, ownership, and whether the budget is measured, estimated, or
configured. Coordinator ownership must cover input embeddings, final norm, and
output head. A tied embedding/output matrix can be represented once by one
component whose `owns` list names both roles.

The default layer map is `[0,3)`, `[3,6)`, `[6,8)`. For another model, set
`total_layers` and `layer_ranges`; the three ordered worker ranges must cover the
layer indices exactly once. All byte budgets must come from explicit model and
workload evidence or be clearly labeled estimates/configuration. In particular,
include the intended precision, maximum cache workload, and measured temporary
memory headroom. Do not extrapolate from the prototype model.
Configuring a different layer map here changes only the arithmetic planner;
the inference runtime still supports its pinned eight-layer CPU prototype.

Run the supplied example with:

```powershell
python -m lab.device_inventory plan configs/pytorch-capacity-example.json
```

That example uses the repository's pinned tiny-model identity but arbitrary
synthetic byte counts. They exist only to exercise the arithmetic and are not
observations of that model, the local machine, or any GPU. The output retains
budget and capacity evidence labels, and states that it is arithmetic rather than
execution evidence.

The planner separates three questions. `single_device_fit` compares the entire
component budget against one device when all assigned components use one memory
kind. It is a conservative whole-budget control and assumes the declared devices
are comparable capacity pools. If assigned components span RAM and VRAM, the
field is `null` because a single physical device can have both pools and this
inventory does not map those pools to physical-device identities;
`whole_budget_single_pool_fit` preserves the stricter arithmetic check. The
`aggregate_capacity_fit` result sums capacities only within RAM or VRAM, never
across those independent pools. `assigned_stage_fit` checks the sum of all
placements assigned to each specific device, so colocated stages cannot each
pass separately while exceeding their shared capacity.

Each capacity entry must describe a distinct usable pool. Do not enter the same
physical RAM once per container, or count shared/unified RAM as both RAM and VRAM.
This tool cannot detect aliases between caller-supplied pools. The laptop's
integrated-GPU memory has not been measured by this inventory path.

Passing any planner result does not prove startup, loading-peak fit, steady-state
fit, or useful inference. Before a P4 model choice, replace every synthetic,
estimated, or configured capacity with measurements from the actual participating
devices; measure component weights, peak loading and execution headroom, and KV
cache use for the selected workload; then run numerical and runtime checks. A
model is a P4 candidate only when the same pinned configuration fails to fit on
each participating device alone, fits across the assigned workers with measured
headroom, and passes execution checks. This guide makes no P4 completion claim.
