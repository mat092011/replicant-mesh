# Open-source release readiness

Review/publication date: 2026-10-17. Scope: an experimental **source-only research
preview**, with local artifact preparation and no hosted inference service.
The maintainer subsequently authorized committing, pushing and making the
repository public. See the [publication record](experiments/2026-10-17-publication.md).
No registry upload or versioned release tag is part of this source preview.

## Review outcome

The source-only technical preparation now includes ownership attestation,
installed dependency/OS inventories, model/tokenizer provenance, pinned/redacted
secret scanning, CI definitions and a clean local-clone reproduction. See the
[validation report](experiments/2026-10-17-release-readiness.md). The source is now
public, both hosted workflows passed, and GitHub private reporting is enabled
and verified. Hosted runtime evidence is tracked in the publication record;
the existing intermittent transport-test failure remains disclosed.

| Area | State after preparation | Evidence / next action |
| --- | --- | --- |
| Project license | Added: Apache-2.0, selected by maintainer | [LICENSE](../LICENSE); third-party rights are reviewed separately |
| Public introduction | Improved | [README](../README.md): scope, topology, measured findings, setup and limits |
| Contributor workflow | Added | [CONTRIBUTING](../CONTRIBUTING.md); maintainer review and actual check expectations |
| Development priorities | Added; proposed work | [Roadmap](ROADMAP.md), subordinate to the [research gates](PLAN.md) |
| Model/dependency provenance | Source-preview technical review recorded | [Review](THIRD_PARTY.md), [notices](../THIRD_PARTY_NOTICES.md), exact installed inventories; binary/model distributions remain excluded |
| Sensitive files and history | Dedicated scan passed with reviewed exact exceptions | Gitleaks 8.30.1; ten fetched/ref/reflog commits plus intended source; positive detection/redaction control passed |
| Reproduction | Clean local clone/candidate overlay and fresh model volumes passed | Same laptop, independent Compose project/image; full tests, remote parity, smoke and cleanup recorded |
| CI | Source/security jobs and CPU runtime gate passed on GitHub | [Source workflow](../.github/workflows/ci.yml), [manual runtime gate](../.github/workflows/runtime.yml); run evidence in publication record |
| Security reporting | Enabled and read back as verified on the public repository | [SECURITY.md](../SECURITY.md); GitHub-only reporting, no email required |
| Packaging | Container workflow exists | No package/registry release verified in this review; defer distribution support claims |
| Release governance | Maintainer authorized commit/push/public visibility | Source preview only; no package/image/model distribution or version tag |

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
optionally enables it only for an already public repository. During preparation,
private visibility produced a blocked result. After authorized publication the
setting was enabled and read back as true. The GitHub-only policy requires no
published email address. No report/message was submitted.

## Publication checklist

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
- [x] Push the new workflows and verify hosted source/security checks.
- [x] Review the completed hosted CPU gate and its recorded outcome in the
  publication evidence; one passing run does not establish test stability.
- [ ] Investigate the retained intermittent one-second gRPC transport-test
  failure before claiming stable CI; the final suite and three focused runs
  passed without changing its assertion or timeout.
- [x] Enable and read back GitHub private reporting at public visibility;
  use the verified no-email route in SECURITY.md.
- [x] Review the source-preview diff/evidence and preserve supported/untested
  setup in README and reports. No experimental version tag is selected here.
- [x] Obtain the maintainer's explicit commit/push/publication instruction.

## Proposed first release contents

Include source, protocol schema/generated binding, tests, pinned configurations,
lab scripts, guides and compact sanitized result summaries. Include the project
license and the third-party notices required for those contents. Keep model
weights, prepared artifacts, caches, credentials and raw local runs outside Git.

Defer package registries, public container images and model-artifact bundles until
their installation/support and distribution obligations are reviewed. A Git tag
or version number does not complete any research gate.

## Next implementation slices

1. Review hosted runtime results and retained failures; investigate transport-test
   intermittency before claiming stable CI.
2. Keep the verified private reporting setting and security policy current.
3. Review any future binary/model distribution and versioning separately.
4. Obtain an independent reproducer/device when available and continue the
   measured roadmap. Do not turn local reproduction into separate-device claims.

The [roadmap](ROADMAP.md) then progresses from reproduction to separate-device
correctness, network measurements and pooled-memory evidence before credits.
