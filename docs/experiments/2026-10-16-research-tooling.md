# P3 analysis and P4 preparation tools

Date: 2026-10-16. This extends the completed M0–M5 runtime implementation with
evidence-review and capacity-planning tools. It does not complete the P3 or P4
research gates. The user confirmed that only the current laptop is available.

The [experiment auditor](../PYTORCH_EXPERIMENT_ANALYSIS.md) distinguishes executed,
interrupted, plan-only and invalid runs, checks selected configuration/repetition
coverage, retains failed attempts and reset errors, and separates runtime images.
The [capacity tool](../PYTORCH_CAPACITY.md) inventories supported local hardware
and checks explicit weights, caches and temporary headroom against assigned
capacity. It includes coordinator memory and collocated stages, separates memory
kinds and preserves whether input budgets are measured, estimated or configured.

## Verification

```powershell
python -m unittest tests.test_device_inventory tests.test_experiment_audit -v
python -m lab.device_inventory inventory
python -m lab.device_inventory plan configs/pytorch-capacity-example.json
```

All **25 focused tests passed** (14 inventory/planner, 11 audit). The inventory and
synthetic planner CLI commands ran successfully. Tests cover tied-weight ownership,
missing coordinator budgets, cache/headroom costs, collocated-stage overflow,
mixed memory kinds, configurable contiguous layer coverage, unknown GPU telemetry,
underfilled runs, missing/corrupt evidence, mixed images and failed cleanup.
The example's arbitrary byte counts are configuration, not model measurements.
Legacy-image discovery also passed **100 tests with 145 opt-in tests skipped**
(245 discovered, 1.854 seconds), confirming that the new standard-library tools
remain compatible with the historical test environment. Documentation links and
`git diff --check` passed.

The [sanitized inventory](2026-10-16-device-inventory.json) records Windows 11,
an AMD Ryzen AI 9 HX 370 with 24 logical CPUs, 33,413,771,264 bytes of visible
physical RAM and 15,799,058,432 bytes available at that instant. It was collected
while the lab was running. Free memory is time-sensitive. NVIDIA telemetry was
unavailable; GPU capacity remains unknown. The CPU description names integrated
Radeon graphics, but this does not establish usable VRAM or runtime compatibility.

Read-only audits of real retained M5 evidence correctly identify:

- The six-case smoke run, including all cases and verified resets.
- Three underfilled repetitions with 63 completions and 137 failures each,
  retained as an interrupted run with 411 capacity failures in total.
- The 144-case full matrix as plan-only, not measured performance.
- A 102-completion run whose matrix stopped after reset-wrapper failure,
  preserving successful request metrics and failed cleanup separately.
- The final three-repetition LAN run as complete for its selected configuration,
  with 306 completions, zero failures and verified resets. When all historical
  runs are audited together, duplicate repetition labels stay visible; the
  auditor does not silently select only favorable runs.

## Remaining research work

P3 still needs the full prescribed performance matrix, resource-matched controls,
and real-link/device measurements before claiming an operating envelope. The
auditor checks selected plans; passing a LAN subset cannot complete that gate.

P4 needs measured participating GPU/device capacities, a suitable pinned model,
runtime support for that hardware/model, numerical validation, loading/steady-state
memory measurements and a same-model offloading comparison. With one laptop and
unmeasured GPU memory, no pooled-GPU demonstration or P4 completion is claimed.
The inventory/planner is a prerequisite, not a substitute for those experiments.

P5 recovery, P6 credits, P7 pilot and P8 decentralization remain downstream work
in [PLAN.md](../PLAN.md). Their research gates are unchanged.
