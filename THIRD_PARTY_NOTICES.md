# Third-party notices

This source-only research preview uses third-party software through imports,
dependencies and runtime downloads. Those components retain their own terms;
Apache-2.0 applies to the project's original code/documentation, not automatically
to installed packages, native libraries, models, tokenizers or datasets.

## Model and tokenizer

`Maykeye/TinyLLama-v0` revision
`298338802ab94432b917bcce11382aa151aee50f` declares Apache-2.0 in its
[model card](https://huggingface.co/Maykeye/TinyLLama-v0/blob/298338802ab94432b917bcce11382aa151aee50f/README.md).
It credits the TinyStories work and identifies the OpenLLaMA 3B tokenizer.
No training dataset is included in this repository.

The downloaded `tokenizer.model` SHA256
`ab1b681ec7fc02fed5edd3026687d7a692a918c4dd8e150ca2e3994a6229843b`
matches OpenLLaMA 3B revision `141067009124b9c0aea62c76b3eb952174864057`.
The [OpenLLaMA card](https://huggingface.co/openlm-research/open_llama_3b/blob/141067009124b9c0aea62c76b3eb952174864057/README.md)
declares Apache-2.0 for its framework and weights. The match establishes the
binary tokenizer's provenance; it does not assert that every JSON tokenizer
conversion was copied unchanged from that snapshot. The project's pinned hashes
identify the exact TinyLLama tokenizer files used for numerical checks.

Weights and tokenizer artifacts are prepared locally and are excluded from the
source preview. Preserve upstream terms/notices alongside any later redistributed
model bundle; the current preparation manifest alone is not a notice bundle.

## Software

- The optional Petals baseline uses revision
  `22afba627a7eb4fcfe9418c49472c6a51334b8ac`, copyright 2022 Petals authors and
  collaborators, under its [preserved MIT license](third_party/petals-LICENSE.txt).
- The owned runtime imports PyTorch, Transformers, gRPC/Protobuf, Safetensors,
  Hugging Face Hub, NumPy and SentencePiece. Exact versions, declared terms,
  source URLs where recorded, and installed notice hashes appear in the
  [owned inventory](docs/third_party/dependencies-owned.json).
- The optional historical baseline has a separate
  [installed inventory](docs/third_party/dependencies-legacy.json). It is not
  covered by the owned runtime's wheel lock.
- SentencePiece 0.2.1 uses the upstream
  [Apache-2.0 license](https://github.com/google/sentencepiece/blob/31646a467d2051eb904e0b45de3a73e91fe1c1e3/LICENSE).
  Tokenizers 0.23.3 uses the upstream
  [Apache-2.0 license](https://github.com/huggingface/tokenizers/blob/301277072263fb3830eb66eec7e47adadf76f1dc/LICENSE).
  These sources supplement incomplete installed wheel license metadata.

Some installed components have additional terms: tqdm and legacy certifi include
MPL-2.0; regex includes CNRI-Python; PyTorch/NumPy bundle native code with several
licenses. These are separate dependencies, not copied wholesale into this source
preview. Redistributing modified covered files, wheels or a container image
requires the applicable notices/source obligations, not just this list.

Debian/OS packages are inventoried separately in the same JSON records. Public
image, wheel, dataset and model-bundle distribution remain outside this release
scope. The [review](docs/THIRD_PARTY.md) states the evidence and limits.

## Release tooling

The scanner is [Gitleaks 8.30.1](https://github.com/gitleaks/gitleaks/tree/v8.30.1),
under MIT; platform archives are downloaded locally and SHA256-verified rather
than included in Git. The workflows reference MIT-licensed GitHub Actions
Checkout 7.0.1, Setup Python 7.0.0 and Upload Artifact 7.0.2 at full commit SHAs.
These tool references do not include their implementation source or binaries in
this source preview.
