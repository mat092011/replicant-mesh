# Audit saved network experiments

`lab.experiment_audit` reads preserved M5 experiment directories without changing
their evidence. It checks the frozen plan against observed benchmark files,
request counts, repetitions, failures, runtime images and network-reset records.
The tool uses Python's standard library and does not start Docker or inference.

```powershell
python -m lab.experiment_audit --output .lab/pytorch-results/audit.json .lab/pytorch-results/RUN_DIRECTORY
# Multiple runs can be inspected together; image identities remain separate:
python -m lab.experiment_audit --output .lab/pytorch-results/comparison.json .lab/pytorch-results/RUN_A .lab/pytorch-results/RUN_B
python -m unittest tests.test_experiment_audit -v
```

Replace the directory placeholders with real runner outputs. The destination
must not already exist. Invalid or missing evidence appears in the audit rather
than being replaced with an invented success. The CLI successfully writing an
audit is not an experiment passing: inspect its issues, coverage, completion
targets, failures and reset state.

The audit distinguishes plan-only, interrupted, executed and invalid directories.
Smoke plans must have the six prescribed cases. Full plans must include three
repetitions for each selected configuration, targeting at least 100 completed
requests and no more than 200 attempts per repetition. Those checks concern the
selected plan; a passing LAN subset does not establish coverage of the entire
48-configuration matrix.

Reset evidence must contain verified root `noqueue` for all four inference
services. A successful benchmark with failed cleanup remains visibly different
from a completely successful experiment. Missing, corrupt and conflicting
evidence stays explicit, including runs with successful requests but a later
validation error.

Repetition comparisons group the same workload/network configuration and image
identity. Different or unknown images are not silently pooled. Duplicate
repetition numbers remain visible. Metrics include per-run TTFT and inter-token
percentiles, completed-output throughput and min/mean/max/range across repetitions.
The mean of per-run percentiles is not a percentile of all request samples.
Failed and underfilled runs remain in the output and must not be silently omitted
when interpreting those summaries.

This is a P3 evidence-review tool. It does not validate real-link performance,
clock synchronization, thermal conditions, energy, resource-matched efficiency,
or a pooled-memory benefit. Its `research_gate_complete` field remains false.
