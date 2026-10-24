# Contributing

Replicant Mesh is an experimental inference-systems project available as a public
source preview. Start with the [README](README.md),
[research plan](docs/PLAN.md) and [development roadmap](docs/ROADMAP.md).
The maintainer reviews scope and merges changes; no release/support cadence or
public service is promised.

## Useful first contributions

- Reproduce the documented CPU lab and record the environment, commands, outcomes
  and any failures. Report skips separately from passing model checks.
- Improve documentation, setup diagnostics and compact experiment summaries.
- Add meaningful protocol/lifecycle regressions or audit missing experimental
  coverage. Keep measurements and implementation tests separate.

Discuss new models, GPU backends, transport changes, batching, topology changes,
recovery or credits before implementation. These affect experimental variables
and require a scoped acceptance gate. Do not assume planned work is supported.

## Development and checks

The supported runtime environment is the pinned Linux amd64 CPU container, not
an unversioned host installation. Follow the [environment guide](docker/pytorch/README.md)
and [lab commands](docs/PYTORCH_LAB.md). Rebuild the runtime image after changing
source: normal lab services run the image's source snapshot.

For code changes, run focused checks and the appropriate container integration
gate. Model/protocol/scheduler changes need same-stack forced-token logit
comparisons, isolation and cleanup checks before performance measurements.
The Compose `tests` service configures artifacts and integration flags; record
which checks actually ran and any skips. See the [protocol source guide](src/replicant_mesh/protocol/README.md)
before regenerating bindings.

For documentation-only changes, check local links and consistency and run:

```powershell
git diff --check
```

Application/model tests are not required for documentation-only changes.
The source and secret-scanning workflows are in `.github/workflows/ci.yml`;
the artifact-dependent CPU gate is a separate manual workflow. Run the same
source checks locally with Python 3.12 and Git on PATH:

```powershell
python scripts/check_release.py
python -S scripts/run_fast_tests.py
python scripts/scan_secrets.py
```

The fast suite targets Linux; use the documented Linux container for it on
Windows. It loads the dependency-free cases explicitly and fails on skips.
The opt-in model/process cases belong to the full runtime gate. Scanner binaries
are pinned and SHA256-verified; reports stay under ignored `.lab/release/` and
are redacted. Only five exact public model/tokenizer identities are allowlisted;
do not add broad path or rule exclusions to hide findings. A local run does not
establish that a hosted GitHub workflow ran.

## Changes and experiment reports

Keep a contribution focused. Explain the problem, resulting behavior, validation,
and remaining limitations. Include actual commands and results, not proposed
commands described as successful runs. Update the relevant guide and
`docs/PLAN.md` when implementation evidence or phase status changes.

Before collecting performance results, freeze model/tokenizer revisions, runtime
image, precision, attention, workload, resource ceilings, network conditions,
repetitions and acceptance criteria. Retain failed attempts and state exclusions.
Report client-observed first-token/inter-token latency separately from aggregate
completed-output throughput, with prefill, startup and recovery distinguished.
Clock comparisons across hosts require measured alignment uncertainty.

Same-host containers and synthetic memory budgets do not demonstrate pooled-GPU
benefits or real internet performance. Preserve the Petals baseline and keep
its older dependencies distinct from owned-runtime measurements.

## Data, security and provenance

Keep weights, caches, credentials, private prompts and large raw traces out of
Git. Use public/synthetic workloads and compact sanitized summaries. Do not
expose the unauthenticated lab to public networks. Follow [SECURITY.md](SECURITY.md)
for the GitHub reporting plan and current private-repository limitation. Do not
post credentials, private data or sensitive exploit details in a public issue.

Identify the origin and license of copied or adapted material and preserve
required notices. The [third-party review](docs/THIRD_PARTY.md) also applies to
model artifacts, tokenizer files and container distributions.

Project contributions are intended to be submitted under
[Apache-2.0](LICENSE), unless explicitly agreed otherwise, consistent with
section 5 of that license. Submit only work you have the right to contribute;
do not add an employer's or another contributor's work without authority. No
copyright assignment or additional contributor agreement is introduced here.
