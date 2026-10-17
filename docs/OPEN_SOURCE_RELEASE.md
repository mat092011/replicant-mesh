# Open-source release readiness

Review date: 2026-10-17. Target: an experimental **source-only research preview**,
with local artifact preparation and no hosted inference service. This document
does not authorize publication. No release tag, push, registry upload or
repository visibility change is part of this preparation.

## Review outcome

The source-only technical preparation now includes ownership attestation,
installed dependency/OS inventories, model/tokenizer provenance, pinned/redacted
secret scanning, CI definitions and a clean local-clone reproduction. See the
[validation report](experiments/2026-10-17-release-readiness.md). Hosted workflow
execution and an externally available GitHub reporting route remain pending;
the repository is still private and no changes have been pushed.

| Area | State after preparation | Evidence / next action |
| --- | --- | --- |
| Project license | Added: Apache-2.0, selected by maintainer | [LICENSE](../LICENSE); third-party rights are reviewed separately |
| Public introduction | Improved | [README](../README.md): scope, topology, measured findings, setup and limits |
| Contributor workflow | Added | [CONTRIBUTING](../CONTRIBUTING.md); maintainer review and actual check expectations |
| Development priorities | Added; proposed work | [Roadmap](ROADMAP.md), subordinate to the [research gates](PLAN.md) |
| Model/dependency provenance | Source-preview technical review recorded | [Review](THIRD_PARTY.md), [notices](../THIRD_PARTY_NOTICES.md), exact installed inventories; binary/model distributions remain excluded |
| Sensitive files and history | Dedicated scan passed with reviewed exact exceptions | Gitleaks 8.30.1; ten fetched/ref/reflog commits plus intended source; positive detection/redaction control passed |
| Reproduction | Clean local clone/candidate overlay and fresh model volumes passed | Same laptop, independent Compose project/image; full tests, remote parity, smoke and cleanup recorded |
| CI | Implemented and local commands validated; hosted execution pending | [Source workflow](../.github/workflows/ci.yml), [manual runtime gate](../.github/workflows/runtime.yml); no push/dispatch performed |
| Security reporting | Policy/tool implemented; unavailable under private visibility | [SECURITY.md](../SECURITY.md); no email required, GitHub route must be enabled and verified at approved publication |
| Packaging | Container workflow exists | No package/registry release verified in this review; defer distribution support claims |
| Release governance | Decision pending | Maintainer approves exact commit, remaining limitations, version and publication destination |

These are proposed project release gates, not a claim that every research
prototype must meet the same requirements. A public source preview would still
be a private-lab runtime, not an invitation to expose unauthenticated RPC.

## Initial documentation-review checks

- Inspected all tracked paths, both Compose configurations and pinned/runtime
  documentation. No `.github` CI configuration, root LICENSE, CONTRIBUTING.md
  or SECURITY.md existed at the start.
- Checked tracked paths for model/checkpoint files, private-key files and a
  tracked `.env`; none matched the inspected filename patterns.
- Inspected blob sizes across reachable Git history. The largest observed blob
  was the 260,054-byte M5 JSON summary, not a model checkpoint or large raw trace.
- Searched all 10 commits reachable from current local refs for private-key
  headers, GitHub token patterns and AWS access-key-ID patterns. No file versions
  matched those patterns. Checked the current tracked tree for common personal
  home-directory/contact/embedded-URL-credential patterns; none matched.
- Retrieved the canonical Apache-2.0 text and reviewed the pinned model card's
  license metadata and Petals' pinned upstream license. Detailed third-party
  review remains outstanding.
- Checked 156 local links across 26 Markdown files, with no missing targets;
  checked changed-file whitespace and `git diff --check`. README measurement
  values match the existing P3 report. The LICENSE text matches the canonical
  Apache text after normalizing line endings and final whitespace.

That initial pass did not include a dedicated scanner or new Docker/model runs.
The implementation follow-up below and linked report supersede those limitations
where actual checks are recorded. No scanner proves the absence of every
credential or private datum; remote refs not fetched, unreachable objects and
local ignored caches are not claimed as published-source coverage.

## Implementation follow-up

`scripts/check_release.py` checks intended source paths, binary/size limits,
whitespace and local Markdown targets. `scripts/run_fast_tests.py` runs the
dependency-free Linux cases explicitly and fails on skips. Both Compose files
and the mocked per-target network-reset checks pass locally.

`scripts/scan_secrets.py` downloads only the pinned Gitleaks archive, verifies its
SHA256, checks a synthetic detection/redaction control, and scans all local refs
and reflogs plus a copy of tracked/unignored candidate files. It traverses up to
three archive levels and five decoding levels without a file-size cutoff.
Fetched remote branches/tags are included. Initial generic-key findings were
reviewed as five public checkpoint/tokenizer identifiers; `.gitleaks.toml` allows
only those exact values. No project path-wide exclusions, fingerprint suppression or
inline allow comments hide findings. Full redacted outputs remain ignored.

`scripts/reproduce_release.py` creates a fresh local clone of HEAD, overlays the
uncommitted candidate and verifies its source digest. Unique Compose project,
image and model/artifact volumes avoid the historical lab. Build cache is
allowed and recorded; fresh weights are prepared and verified. Tests, service
parity, a six-request smoke and project-scoped cleanup are retained. It creates
no commits, branches or releases. Independent-person/device reproduction remains
future evidence, not a claim from this local run.

`scripts/verify_security_reporting.py` verifies the actual GitHub setting and
optionally enables it only for an already public repository. The live repository
metadata is private; its reporting endpoint returned 404. The tool therefore
reports an explicit blocked state rather than claiming a functioning channel.
The maintainer declined an email contact, so the GitHub-only policy remains
gated until a later publication instruction. No report/message was submitted.

## Required before publication

- [x] Select a license for original project code/documentation and add its text.
- [x] Document the actual architecture, reproduction path and negative findings.
- [x] Add contribution guidance and a prioritized development roadmap.
- [x] Record original-code ownership attestation, source-preview third-party
  review, tokenizer provenance and applicable notices/inventories.
- [x] Run a pinned dedicated scanner over fetched/ref/reflog history and intended
  source; retain reviewed false positives and redacted evidence. Re-scan the
  eventual release commit/ref set before publishing it.
- [x] Reproduce the candidate in a clean local clone with isolated model volumes;
  retain failed runs and record full tests, numerical gate, smoke and cleanup.
- [x] Add source/security CI and a separate manual artifact-dependent runtime
  workflow; validate their commands locally.
- [ ] Run the new workflows on GitHub after a later authorized push. Hosted runner
  behavior is not established by local validation.
- [ ] Investigate the retained intermittent one-second gRPC transport-test
  failure before claiming stable CI; the final suite and three focused runs
  passed without changing its assertion or timeout.
- [ ] At approved public visibility, enable and verify GitHub private reporting;
  the no-email policy/tool exists but the external route is not yet available.
- [ ] Review the complete diff and evidence; select an experimental version and
  write release notes naming supported setup and untested configurations.
- [ ] Obtain the maintainer's later instruction to publish the reviewed commit.

## Proposed first release contents

Include source, protocol schema/generated binding, tests, pinned configurations,
lab scripts, guides and compact sanitized result summaries. Include the project
license and the third-party notices required for those contents. Keep model
weights, prepared artifacts, caches, credentials and raw local runs outside Git.

Defer package registries, public container images and model-artifact bundles until
their installation/support and distribution obligations are reviewed. A Git tag
or version number does not complete any research gate.

## Next implementation slices

1. Review the concrete local changes and retained evidence, including initial
   failures. No source or binary publication has occurred.
2. When authorized, commit/push the reviewed candidate and inspect hosted CI.
3. Only after a separate publication decision, configure the GitHub private
   reporting route and read back its enabled status before announcing a release.
4. Obtain an independent reproducer/device when available and continue the
   measured roadmap. Do not turn local reproduction into separate-device claims.

The [roadmap](ROADMAP.md) then progresses from reproduction to separate-device
correctness, network measurements and pooled-memory evidence before credits.
