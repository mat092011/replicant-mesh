# C0 lock identity portability correction, 2026-10-17

The [original C0 record](2026-10-17-participant-c0.md) describes its actual
Windows-working-tree Docker snapshot. Hosted
[Source checks](https://github.com/mat092011/steamboat_net/actions/runs/39040905715)
then found that its declared lock fingerprint used CRLF bytes, while a Linux
Git checkout contained LF. This follow-up corrects that portability defect;
it adds no participant runtime or later-phase completion.

`*.lock text eol=lf` now fixes checkout bytes across platforms. The exact committed
CPU lock SHA-256 is
`0d893300099241375c9ef032268e162ff6ef46fe93cce1bbe6457bfd01545434`.
The CPU lock's Git blob, package versions and wheel hashes are unchanged. The
declarations/examples now pin those exact LF bytes, and the derived synthetic
operation compatibility fingerprint was regenerated. The raw-byte lock test
remains strict; no newline normalization was added to that assertion.

The parent reviewed the entire correction and reran validation using staged
Git tree `d90246b76ac6d8c21aab520f99733b8b0ca22039`. `git archive --format=tar`
produced SHA-256
`1abca0600731d4c32fca03bce4e2b534aef2c94e91abc5facf67131eea5a63c2`;
Python `tarfile.extractall(filter='data')` extracted the snapshot. This supplies
the same LF Git source bytes used by Linux CI.

The [C0 Compose commands](../PARTICIPANT_CONTRACTS.md#run-the-c0-checks) were run
against that snapshot using project `steamboat-c0-portability-20261017`: build
`model-tests` and `contracts`; run `contracts`, `documents`, `runtime-tests`,
the exact dependency-free `python -S` fast command in the original record,
and `smoke`. Every final command exited 0. Model/tokenizer, float32/eager,
tolerance, read-only artifacts and CPU/RAM/network limits remain unchanged.

| Check | Actual final result | Retained log SHA-256 |
| --- | --- | --- |
| Contracts | 45 tests, zero skips | `06bae9a887a8af210b505e16ecf153f967a2398be7606566fdf192b953bbdc6f` |
| Full offline runtime | 308 tests, zero skips | `b49c4d84733e003e7b2099a1a072902fceb8edb26d16c885e3248f16c03f0490` |
| Fast CI command | 127 tests, zero skips | `3f6c96ee0bad20aca0b046f5753f09325997b05fcdede809d63debf217618fde` |
| CPU smoke | Eight comparisons, zero final sessions/cache/reservations | `9947bb8b3c486c9a95cced54781c6ae6278259b19c3c6ee051f0ba1619e5dd28` |
| Baked declaration source | 159 files, zero byte mismatches | `a4b06e16bb2ffdb83c7802e782443a57790c7812087615f393b322d88e4b5ccb` |
| Baked runtime source | 92 files, zero byte mismatches | `39d4e67429f5bbe11378a54d991ea12c90ba66e7431bc1bf1f97ac6a8ced0921` |

Actual runtime image:
`sha256:ce0e8c70ffa1b23f44a9bd4b3fac749e54aa9fff65c7aa3d09734d594d139bf1`;
copied-source manifest:
`75ea584055e772a98174a16e5bc7babd99eab04b5c0781bb851ffc98a30112d4`.
Declaration image:
`sha256:d3ddacf7c8599fc88578ff01b367f4e718a76cf42e2dc6ca170c8a3efcaf9fb8`;
complete source manifest:
`089236949acd1e8ada625348cc8a5fc022d08877b39e7034a42ce3ddfc968011`.
This evidence/status-only documentation was added afterwards; the document
image was rebuilt/checked before publication.

The initial correction missed the derived operation fingerprint: 45 contract
tests reported one failure and seven errors; the full suite also failed those
cases. Both attempts, the hosted failure and every final command/log are retained
under ignored `.lab/participant-network/results/c0-portability/` and `c0-final1/`.
No failure was discarded or reclassified as passing. The parent reads back the
published commit and its hosted CI result in the execution journal.

No GPU, real route or performance study ran. C1–C9 and P0–P8 limits are unchanged.
