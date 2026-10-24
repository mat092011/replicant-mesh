# Repairing the all-history secret scan

Date: 2026-10-24. The failed [Source checks run](https://github.com/mat092011/replicant-mesh/actions/runs/40090835049)
passed its `source` job and failed its `secrets` job. Gitleaks reported 12 history
findings and zero candidate-source findings.

## Cause and review

The workflow checks out every branch with `fetch-depth: 0`; the scanner traverses
all local refs and reflogs. Main's scanner configuration knew the five public
model/tokenizer artifact identities, but lacked the exact synthetic-marker
exceptions already reviewed on `feature/participant-network` in commit
`b39b30ca1dd3fb2eff47fba47e27ddbc7e18e29e`.

Every finding's committed source line was checked. All finding commits were
outside main's ancestry. The entire set maps to three public, noncredential values:

| Exact matched value | Occurrences | Source meaning |
| --- | --- | --- |
| `lease_0123456789` | 5 | Fixed lease identifier in protocol test replies |
| `lease_mux_0123456789` | 5 | Fixed lease identifier in gateway test replies |
| `ec.SECP256R1` | 2 | Public cryptography class used to validate ECDSA P-256 keys |

The fix carries those three exact values into main's Gitleaks secret-value
allowlist. Each expression is anchored at both ends; the class name's dot is
escaped. Default rules, all-ref/full-history scanning, redaction, archive/decode
depth, disabled inline allows and the existing positive control are retained.
No directory, branch, commit or finding fingerprint is excluded. The scanner's
summary text now describes the expanded reviewed-value list accurately.

## Validation

- Pinned Gitleaks 8.30.1 scanned 346 local-ref/reflog commits after fetching both
  remote branches: zero history findings and zero candidate-source findings.
- The scanner's synthetic GitHub-token detection/redaction control passed.
- An additional temporary control directory tested the three exact values and
  six near-matches formed by prepending or appending `x`. The exact values were
  allowed; all six near-matches and a synthetic GitHub credential were detected
  and redacted. The control directory was removed; no fixture credential is
  committed.
- The fast suite passed 83 tests with zero skips; source/local-link, Compose
  configuration and whitespace checks passed. No inference/runtime code changed,
  so numerical/performance experiments were not repeated for this repair.

## Completed hosting rename

The maintainer completed the GitHub repository rename. Metadata queried by stable
ID `1416538470` reports `mat092011/replicant-mesh`. Current clone/security links,
the research plan and the migration guide now reflect that completed state.
Private vulnerability reporting was verified as enabled at the renamed address;
no report or message was submitted.
