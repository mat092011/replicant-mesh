# Participant C0 contract gate, 2026-10-17

**Decision: C0 passed. C1–C9 and all P0–P8 research gates remain incomplete.**
The parent accepted C0.1–C0.5 after independent contract review, corrections,
rebuilt Docker validation and the existing CPU controls. This permits local
C1a/C2a and CPU C4a work. It provides no deployed authentication, connector,
remote-device, GPU, pooled-memory, performance or participant-benefit evidence.

## Scope and review

The [decision](../decisions/0001-participant-contracts.md) and
[normative specification](../PARTICIPANT_CONTRACTS.md) define independently
disabled consumer/host/personal-coordinator roles, trusted authorities, typed
identities, scoped session ownership, transport and credential lifecycle,
shared resource reservations, stop/removal behavior and explicit dependencies.
[Versioned declarations](../../config/participant/README.md), six examples,
118 negative mutation fixtures and a dependency-free checker make the static
boundary executable. The closed-type dialect is explicitly proprietary to this
checker; it does not claim general JSON Schema compatibility or live enforcement.

Independent review found and corrected role/context admission gaps, device/account
aliasing, unused-host experiment acceptance, connection/capture accounting and
rotation wording. Every fresh v1 request has new IDs and `route_epoch=1`;
credential rotation advances the role credential epoch after draining. No live
route replacement or mutating replay is introduced. Final independent review
reported no material ambiguity preventing C1a/C2a. The parent retains acceptance
and publication responsibility.

Coordination used the installed Codex app-server 0.163.0-alpha.10.2, local stdio,
the inspected generated protocol, initialize/initialized and thread/turn APIs.
Worker IDs, exact requests and failures remain in the ignored execution journal.
After the model-routing instruction, correction work explicitly selected
`gpt-6-luna`; the independent acceptance reviewer used the main configured
`gpt-6.1-sol`. No approval/security setting was changed.

## Frozen validation environment

One Windows laptop ran Docker Desktop 4.95.0 / Linux engine 29.8.2, amd64, with
24 logical CPUs and 16,299,233,280 bytes available to Docker. Containers are one
physical machine. No GPU execution or network shaping was used.

- Base: CPython 3.12.15 slim Bookworm, digest
  `sha256:2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d`.
- CPU lock: `docker/pytorch/requirements.lock`, SHA-256
  `ec074730911798d0d08bd56fcd24f00db53d14dbe13e2be4e031150a52b82be3`.
  PyTorch 2.14.1+cpu, Transformers 5.19.0, gRPC 1.84.0, Protobuf 7.36.2,
  safetensors 0.8.0; Petals is absent from this environment.
- Model and tokenizer: `Maykeye/TinyLLama-v0`, revision
  `298338802ab94432b917bcce11382aa151aee50f`, verified existing artifacts,
  float32, eager attention, no compression, fixed `[0,3)/[3,6)/[6,8)` stages,
  coordinator-owned embeddings/norm/head. Public deterministic token fixtures;
  numerical tolerance `atol=1e-3, rtol=0`.
- Unique project `steamboat-c0-20261017`; no external network or published ports,
  dropped capabilities, no-new-privileges, read-only image and artifact/cache
  volumes. Declaration/doc checks: 1 CPU, 256 MiB. CPU controls: 2 CPUs, 6 GiB.
  Full discovery copies baked source into a bounded 128 MiB test-only tmpfs;
  [Compose](../../compose.participant-contracts.yaml) records all limits.

The final executable validation image was
`steamboat-participant-runtime:cpu-c0-v1`, ID
`sha256:55c9287aa87d8d3e2cc07382acf229dbb14a8d4d903c955b8308c35a26e77d5e`.
Its 92 copied source/configuration/lock files matched candidate bytes exactly;
their ordered SHA-256 manifest digest was
`e483744b726e284eb417a06112e146ce401eec01e0828248c518657b853f6594`.
The declaration test image ID was
`sha256:aea358bbf6ac17f8849ba2d4e56f358e5e248ab2dfb1474a57e1d224f3695d77`;
all 157 baked files matched the pre-evidence candidate snapshot, digest
`dc75c4d85b82cbbcf5a09dec101a14845f563e182ab2b506c39180f26ad2bf0e`.
These identify the actual tested working snapshot, rather than its earlier
scratch checkpoint. This report and status-only documentation were added after
execution; the document image was rebuilt and checked again before publication.

## Commands and outcomes

Executed from the isolated C0 candidate, using the checked-in Compose file:

```powershell
docker compose -p steamboat-c0-20261017 -f compose.participant-contracts.yaml build model-tests
docker compose -p steamboat-c0-20261017 -f compose.participant-contracts.yaml build contracts
docker compose -p steamboat-c0-20261017 -f compose.participant-contracts.yaml run --rm contracts
docker compose -p steamboat-c0-20261017 -f compose.participant-contracts.yaml run --rm documents
docker compose -p steamboat-c0-20261017 -f compose.participant-contracts.yaml run --rm runtime-tests
docker compose -p steamboat-c0-20261017 -f compose.participant-contracts.yaml run --rm runtime-tests python -S -c "import os,shutil,runpy; shutil.copytree('/app','/test-app',dirs_exist_ok=True); os.chdir('/test-app'); runpy.run_path('/test-app/scripts/run_fast_tests.py',run_name='__main__')"
docker compose -p steamboat-c0-20261017 -f compose.participant-contracts.yaml run --rm smoke
```

Every final command exited 0. Exact timestamped command records and raw logs are
retained under ignored `.lab/participant-network/results/c0-final1/`.

Final document/source checks covered 158 files, 37 Markdown files and 256 local
links with zero errors; `git diff --check` passed. The repository's pinned
Gitleaks 8.30.1 scan passed its detection/redaction control and found zero secrets
in all local refs/reflogs or the intended 158-file source snapshot. Raw scanner
reports remain ignored.

| Check | Actual result | Retained final log SHA-256 |
| --- | --- | --- |
| Contract suite | 45 tests, zero skips; all 118 invalid mutations rejected | `ae19241bb079b181e5fb95d34ec072abdec2ba9203f8a8a74f5bdf7cd057a697` |
| Full offline runtime suite | 308 tests, zero skips; model, protocol, worker processes, coordinator and service gates enabled | `c5e296cb159b2976caa080846b6720a13bfec073df2b08721f560a62e90d79eb` |
| Dependency-free CI command | 127 tests, zero skips, run with `python -S` | `80009b2a5109899d1fb8184556ae489d310669d50fc0f1d31917bd450ae2b176` |
| Existing CPU smoke | Eight last-position logit comparisons; session-limit rejection, cancellation and zero final caches/reservations | `522bb5a810fc0e93caca23bb28bcf8e54f960077bb0e0cda662faade1186b31c` |
| Baked runtime source comparison | 92 files, zero mismatches | `298885bf829e7b7029a5b9e145a59d7ee2eb0535fe06e527f7544f69cece3a79` |
| Baked declaration snapshot comparison | 157 files, zero mismatches | `586d864d7e0c82be25ae3d26e2763aeb14b7327c9b2f45d57813cdfdbd7e59d6` |

The full suite includes the ten real-model tests, every-position prefill controls,
identical forced continuations, unequal interleaving, context/cache cleanup and
failure isolation. The separate smoke is serialized in-process inference; neither
test timing nor same-host process tests establish speedup or separate devices.
The unchanged private Petals path was preserved and was not rerun for C0.

## Failed attempts and limitations

- The first Docker build hit a transient Docker context metadata file lock;
  an identical retry succeeded. Both records remain retained.
- The initial Docker contract suite ran 31 tests with one failure: deeply nested
  JSON parsed on Python 3.12 without the expected recursion error. Explicit
  iterative depth validation and regression cases corrected this; final tests
  retain the original acceptance boundary.
- The first full candidate suite ran 308 tests with 18 errors: the runtime image
  omitted the lock at the tested path, and 17 existing audit tests needed writable
  temporary directories beside source. The unchanged lock is now copied into the
  image; only full discovery receives the bounded baked-source scratch copy.
  The failed log SHA-256 is
  `6336e3e565990bb9f4fca7aefa136630c2219c3464107fbfcff27b7fd76684f5`.
- The PATH CLI rejected the configured model. The installed app-bundled binary
  worked after capability inspection. Some completed sessions could not resume
  due to an active-writer error; fresh actual app-server reviewer sessions were
  recorded without bypassing locks or approval settings. A Luna worker initially
  stopped based on its generic model-family description; catalog and explicit
  thread/turn model selection confirmed Luna before its correction turn.

These are implementation/correctness checks, not a performance study. A limited
synthetic local gRPC leaf-pinning feasibility probe informed the contract; it does
not pass authentication/admission enforcement. No C1a security gate has run.
The [dependency register](../PARTICIPANT_CONTRACTS.md#dependency-register) still
requires operators, a second physical execution device, approved real routes,
gateway custody/budgets, supported GPU access and later participants. Experiment
templates remain unfrozen placeholders until those actual values are supplied.
No unfinished parent phase is authorized for publication by a local sub-gate.
