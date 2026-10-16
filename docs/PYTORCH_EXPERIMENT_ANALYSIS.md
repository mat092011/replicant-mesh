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
It is file-based: an active run without its final summary also appears as
`interrupted`. Check the detached job's exit marker and process state before
deciding that execution stopped; the audit does not inspect running processes.
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

## Immutable continuation and duration estimates

Use `python -m lab.experiment_continue PARENT --output NEW_DIRECTORY` to create a
new continuation plan. The parent directory and its original frozen plan remain
unchanged. The child records parent plan/evidence hashes and the original indices
of unfinished cases. A case is omitted only when its saved workload, request
policy, completion target, successful outcome and full per-target reset evidence
agree. Failed or interrupted repetitions are attempted again as distinct child
records; their earlier attempts remain in the parent and must accompany reports.
This is experiment continuation, not inference-session replay.

New runner plans pin the source fingerprint, Git commit, Compose file hash and
resolved runtime image digest. Execute a generated child using
`scripts/Invoke-PytorchExperiment.ps1 -Mode Full -FrozenPlanPath NEW_DIRECTORY/plan.json`.
The runner creates another exclusive execution directory, checks parent evidence,
source/configuration and runtime compatibility, and re-runs the correctness gate.
It never appends into the parent or child plan directory. Old M5 plans without
these compatibility fields cannot be continued safely; start a separately labelled
experiment instead. Do not retrofit provenance into historical evidence.
Pipeline and matched-control runners hold one exclusive lab lock throughout
execution and cleanup, preventing concurrent runners from changing network state.
An interrupted process releases the lock; retained evidence still requires review.

To freeze a bounded subset without launching it, use the runner's `-PlanOnly`
and optional `-ExpectedImage sha256:...` arguments. Create a continuation of that
plan-only directory to execute it. `python -m lab.experiment_continue PARENT
--estimate --observations HISTORICAL_RUN` prints a dry-run estimate. Additional
`--observations` arguments are allowed. Only compatible source, Compose, image and
workload observations supply numerical estimates. Unknown profiles remain unknown;
historical measurements from other images may inform a separately labelled rough
planning budget but are not silently pooled. Estimates cover benchmark wall time,
excluding gate, warm-up, network probes, reset and recovery. Observed min/max is a
sample range, not a confidence interval or an upper bound on failed runs.

The runner also saves per-case cgroup CPU counters and current memory around the
benchmark command. Counter differences include warm-up and command overhead; they
are not CPU time isolated to the client's timed interval. Memory peaks continue
to be scoped to the lifetime of each container.

This is a P3 evidence-review tool. It does not validate real-link performance,
clock synchronization, thermal conditions, energy, resource-matched efficiency,
or a pooled-memory benefit. Its `research_gate_complete` field remains false.
