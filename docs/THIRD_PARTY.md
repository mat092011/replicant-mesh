# Third-party licensing and artifact provenance

Review date: 2026-10-17. Technical review covers this source-only preview,
installed dependency/OS inventories and model/tokenizer provenance. Image,
wheel, dataset and model-bundle redistribution remain outside this scope.

## Project license decision

The maintainer selected **Apache-2.0** to allow commercial use and proprietary
reuse. The canonical license is in [LICENSE](../LICENSE); it applies to this
project's code and documentation except for third-party material under its own
terms. Contributor grants cover only rights the contributors can grant.

[Apache's authoritative text](https://www.apache.org/licenses/LICENSE-2.0)
permits source/binary redistribution subject to its conditions. It requires a
license copy, preservation of applicable attribution notices, notices of changed
files, and preservation of applicable NOTICE content when supplied. Its patent
grant is limited to covered contributor claims, and trademarks are excluded.
It does not require all downstream modifications to be published.

The project license does not automatically cover dependencies, downloaded model
weights, tokenizer files, training datasets or their upstream components.
Source releases, runtime images and prepared weight shards have different
contents and need distribution-specific review.

## Evidence reviewed

| Material | Pinned identity / source | Finding | Remaining work |
| --- | --- | --- | --- |
| Tiny model | `Maykeye/TinyLLama-v0`, revision `298338802ab94432b917bcce11382aa151aee50f` | Pinned card declares Apache-2.0; attribution is in [third-party notices](../THIRD_PARTY_NOTICES.md) | Artifacts remain excluded from source distribution |
| Tokenizer | Same pinned model snapshot | Binary SHA256 matches OpenLLaMA 3B revision `141067009124b9c0aea62c76b3eb952174864057`, whose card declares Apache-2.0 | JSON conversions remain identified by the TinyLLama hashes; no claim of identical upstream conversion files |
| Optional Petals baseline | `22afba627a7eb4fcfe9418c49472c6a51334b8ac` | Pinned upstream LICENSE is MIT | Preserve upstream copyright/license notices in distributions containing it; review its transitive dependencies separately |
| Owned runtime Python dependencies | [Installed inventory](third_party/dependencies-owned.json) | 38 locked application packages match installed versions; pip is a separate base tool; 165 installed notice files fingerprinted | Source-only scope; preserve complete native/bundled notices before image/wheel distribution |
| Historical baseline dependencies | [Installed inventory](third_party/dependencies-legacy.json) | 68 packages and 100 notice files recorded from the actual preserved Petals image | Rebuilds may resolve differently; review the actual distributed image |
| Container base and OS packages | Both installed inventories | 112 owned-stack and 172 legacy OS packages recorded with available copyright-file hashes | OS/copyleft obligations remain separate from the Apache project license |
| Generated Protobuf binding | [Generation record](../src/replicant_mesh/protocol/README.md) | Compiler/runtime identities and regeneration command are recorded | Review generated/runtime material alongside the distribution inventory |

Primary sources inspected on the review date:

- [Pinned TinyLLama model card](https://huggingface.co/Maykeye/TinyLLama-v0/blob/298338802ab94432b917bcce11382aa151aee50f/README.md)
  and [revision metadata](https://huggingface.co/api/models/Maykeye/TinyLLama-v0/revision/298338802ab94432b917bcce11382aa151aee50f).
- [Pinned Petals MIT license](https://github.com/bigscience-workshop/petals/blob/22afba627a7eb4fcfe9418c49472c6a51334b8ac/LICENSE).
- [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

## Ownership and source-preview decision

The local and fetched repository history contains ten commits attributed to
`mat092011`. On 2026-10-17 the maintainer explicitly confirmed authority to
license the project's original code under Apache-2.0, including employer and
collaborator rights. This is a maintainer attestation, not independent proof of
authorship from Git identities alone. No copyright assignment is introduced.

The reviewed adapter imports Transformers layer implementations; its cache,
partition, protocol and scheduling code remain in this repository. The generated
Protobuf binding records its compiler and schema. No framework source tree,
wheel, model weights or training dataset is included in the intended source
preview. The Petals MIT text is preserved in
[third_party/petals-LICENSE.txt](../third_party/petals-LICENSE.txt).

The metadata review identifies MIT/BSD/Apache/ISC/PSF terms plus the additional
MPL-2.0, CNRI-Python and bundled native terms described in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). Missing wheel metadata for
SentencePiece/Tokenizers was checked against pinned upstream license files;
this does not flatten their native dependencies into one license.

The source-preview ownership/provenance review is recorded, with third-party
software kept separate under its own terms. This is not a blanket compatibility
certification for later binary/model distributions. Re-run the inventory when
changing locks/images and review newly copied/adapted source explicitly.

## Reproduce the inventory

Run `scripts/audit_dependencies.py` inside the exact image under review with the
repository mounted at `/review`, passing `--output` and `--notices-output` paths
under `/review/.lab/release/licenses/`. Select `--stack legacy` for the preserved
baseline. The script records all installed packages, available notice hashes,
direct source metadata, lock-version mismatches and Debian package versions.
Full extracted notice text remains ignored; compact inventories live under
`docs/third_party/` for inclusion in the source preview.

To repeat the owned-image inventory from the repository root with the current
image name (the historical inventory predates the [rename](RENAMING.md)):

```powershell
docker.exe run --rm --network none --mount "type=bind,source=$PWD,target=/review" --entrypoint python replicant-mesh-pytorch:cpu /review/scripts/audit_dependencies.py --output /review/.lab/release/licenses/owned.json --notices-output /review/.lab/release/licenses/owned-notices.json
```

For the baseline, use image `replicant-mesh-lab:cpu`, add `--stack legacy`,
and write `legacy.json` / `legacy-notices.json` in the same ignored directory.
Inspect image IDs before repeating these commands; tags alone do not establish
that a later inventory describes the same historical image.

Before any later redistribution beyond this source preview:

1. Reconfirm authority for newly added/copied/adapted contributions.
2. Review exact dependency licenses and flag any distribution constraints.
   Do not infer licensing from a hash, package name or public download URL.
3. Complete the model/tokenizer provenance record and document attribution.
   Keep weights, caches, prepared shards and datasets outside the source release.
4. Add any required third-party license texts/attributions and applicable
   NOTICE material after identifying what is actually included. Do not invent
   copyright holders or imply an incomplete inventory is clearance.

The existing preparation manifest hashes seven configuration/weight/tokenizer
files; it does not currently preserve the upstream model card or license text
as an artifact-provenance bundle. Adding that record requires an explicit
preparation-contract change and checks. Before distributing prepared artifacts,
preserve the relevant upstream terms and notices alongside them.

Publishing runtime images or model shards is outside this source-preview scope.
Review their full dependency/OS/artifact contents before a later distribution;
installing a dependency separately does not relicense it under Apache-2.0.
