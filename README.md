# Cyber MoE Datasets

A reproducible dataset preparation repository for **Qwen3-30B-A3B**, BF16,
Apple M3 Ultra (96 GB), MLX-LM and MLX-FUN. No pruning, training, model-weight
loading, teacher inference, publication or dataset commands are performed.

Development and dataset validation run on **Windows** in this workspace. All MLX
model inference, saliency collection, pruning and model evaluation run later on
the **Apple M3 Ultra**. GitHub transfers reviewed code and small approved exports;
the Mac checks out a pinned validated commit. No remote or push is configured yet.
See [Mac deployment](docs/MAC_DEPLOYMENT.md) and
[Windows publication workflow](docs/WINDOWS_WORKFLOW.md).

The current portable candidate is `data/releases/mitre-pilot-v0.2`: 432 canonical
records, 132 calibration exports, 187 training, 21 validation and 43 evaluation.
Exact official Qwen reference-tokenizer validation passed on Windows without
weights or MLX. Installed Mac tokenizer matching and calibration remain pending.

```sh
uv sync --locked
uv run cyber-data verify-release data/releases/mitre-pilot-v0.2
```

The first release proves the engineering workflow. It does **not** claim a
production-ready 512-example cybersecurity calibration corpus.

## Setup and reproduce

Python 3.12 and uv are recommended. On Apple Silicon, use this separate environment;
do not reinstall or modify your working MLX-FUN environment.

```sh
uv sync --locked
uv run cyber-data inspect
uv run cyber-data download mitre_attack data/raw/enterprise-attack-17.1.json
uv run cyber-data build --config configs/calibration.yaml --output outputs/pilot
uv run cyber-data validate outputs/pilot/canonical.jsonl
uv run cyber-data report outputs/pilot/canonical.jsonl
uv run cyber-data export outputs/pilot/canonical.jsonl outputs/reexport/train.jsonl --kind train --preview
uv run pytest -q
uv run ruff check .
```

Commands run from the repository root. `uv.lock` pins the environment. The pinned
MITRE download is checksum-verified and refuses to replace different local data.
All generated datasets, raw downloads, review records and research checkouts are
ignored by Git. Original CC0 fixtures and specifically packaged, approved MITRE
exports under `data/releases/` are eligible for Git. Reviews and raw payloads stay local.

For an entirely offline CI demonstration:

```sh
uv run cyber-data build --config configs/fixtures.yaml --output outputs/fixtures
```

For exact tokenization, install the optional tokenizer dependencies and supply the
directory of your **actual installed** Qwen3-30B-A3B tokenizer and `config.json`:

```sh
uv sync --locked --extra tokenizer
uv run --extra tokenizer cyber-data build --config configs/calibration.yaml --output outputs/tokenized --model /path/to/installed/Qwen3-30B-A3B
```

Make a copy of the configuration and set `mode: production` to require exact token
counts. Preview mode keeps counts null and labels length filtering unverified.
It never substitutes character estimates for Qwen tokens. The model configuration
must identify `qwen3_moe`; tokenization uses local files with remote code disabled.
The manifest records model configuration/tokenizer hashes, without loading weights.
Set `QWEN_MODEL_PATH` to enable the optional tokenizer integration test.

## Workflow and artifacts

The pipeline validates source approval and metadata, ingests pinned STIX or local
canonical JSONL, validates conversations and tool arguments, quarantines possible
PII/secrets, counts tokens when possible, rejects whole over-length records, groups
connected scenarios/documents/duplicates, assigns seeded partitions, samples the
calibration mixture without replacement, and exports datasets and reports.

Each build writes canonical records, calibration JSONL, training and validation
JSONL, evaluation JSONL, expert-training metadata, quarantine/length rejection
files, source manifest, quality report and leakage report. MITRE outputs carry its
full license. Each export has a metadata sidecar retaining row-level provenance
and licensing. The finetuning directory supplies stock `train.jsonl` and
`valid.jsonl` filenames. Canonical records retain provenance and reference answers; evaluation
exports remove the final assistant answer from the prompt.

Calibration measures routing on representative inputs; training learns supported
answers; evaluation remains held out. Recovery training uses the training partition,
never calibration or evaluation. Domain metadata supports future expert experiments;
it does not identify trainable experts or prove a routing strategy.

The experimental calibration targets are SOC 192, security reasoning 128, tool
workflows 96, general reasoning/coding 64, and structured/evidence fidelity 32.
Shortfalls and category token totals are reported. There is no filler generation.

## Sources and MLX-FUN

See [source catalog](docs/SOURCE_CATALOG.md), [governance](docs/DATA_GOVERNANCE.md),
[dataset card](docs/DATASET_CARD.md), and [experiment protocol](docs/EXPERIMENT_PROTOCOL.md).
Only pinned MITRE and original synthetic fixtures are approved initially. Splunk
BOTS arrives as pre-indexed Splunk buckets, not JSONL. Export events through Splunk
and preserve investigation IDs; validated Q&A requires a separate reviewer.
REAP recipes are methodology references, not redistribution permission for their
upstream sources. CyberSecEval is reserved exclusively for independent evaluation.

The reviewed upstream MLX-FUN commit is
`c5d0cbb0a962bb72c781aff2fe5e158507bf5745` (reported package version 0.1.0).
Its `src/mlx_fun/data.py::_tokenize_entry` accepts `messages`,
`prompt`/`completion`, or `content`, in that order. Chat rendering calls
`apply_chat_template(tokenize=True, add_generation_prompt=False)` and ignores
top-level tool schemas. Tool calibration is therefore pre-rendered into `content`
using the local tokenizer with tools. Without that tokenizer those calibration
records are explicitly deferred. Training keeps `messages` and `tools`.
Actual MLX-LM training execution remains unverified.

Check your installed MLX-FUN loader before using exports:

```sh
uv run cyber-data check-mlx /path/to/mlx_fun/src/mlx_fun/data.py outputs/pilot/calibration/data.jsonl
```

The check executes only the reviewed function whose AST hash matches the stored
contract, using a spy tokenizer; it cannot confirm MLX or Qwen model behavior.
Changed loader code fails closed and needs review. On the Mac, after exact
tokenization and installed-version review, upstream documents this collector command:

```sh
mlx-fun collect --model /path/to/model --dataset outputs/tokenized/calibration/data.jsonl --output saliency.npz --max-samples 512 --max-tokens 2048 --seed 42
```

This is documentation for the next phase; collection is not run in this task.
Its token limit must be at least the dataset's validated maximum, since upstream
otherwise slices tokens and could break evidence or tool exchanges. Pre-rendered
tool text also needs a real-tokenizer round-trip check before collection.

## Tested scope and limitations

Development took place on Windows; MLX, MLX-FUN, transformers and the model were
absent at initial inspection. The optional tokenizer dependencies and pinned
official tokenizer files have since been added locally; no weights were acquired.
No planning PDF was attached. The original real-data pilot
uses 80 active MITRE attack-pattern records from Enterprise 17.1, pinned by commit
and SHA256. Answers are deterministic field extraction, not inferred incident
attributions or human-validated SOC reasoning. This narrow pilot is not a balanced
corpus, nor an independent benchmark.

Tests cover malformed input, registry approval, schema/content integrity, provenance,
tool exchange integrity, deterministic generation/sampling/splits, document and
scenario grouping, exact/near duplicates, benchmark reference checks, privacy
flags, length rejection, separate exports, and offline end-to-end builds.
CI requires neither network datasets nor the 30B model. Exact tokenizer integration
is optional. Benchmark references are not bundled; reports state when contamination
checking is unavailable. Near-duplicate checks use pairwise normalized prompt
5-gram Jaccard at 0.85: suitable for the pilot, quadratic at scale and unable to
guarantee semantic decontamination. Privacy detection is heuristic and requires review.

Next: verify installed tokenizer/MLX-FUN contracts on the Mac, acquire and review
BOTS investigation exports, add source-specific tool/general adapters after license
approval, freeze benchmark references, and expand the corpus toward 512 genuinely
validated calibration records. Pruning, recovery and selective expert routing
experiments are later phases.
