# Windows dataset development → Apple Silicon deployment

Windows owns source acquisition, dataset engineering, exact tokenizer checks,
quality reports, exports and release packaging. The M3 Ultra owns all MLX model
execution. No Windows step loads model weights, imports MLX, collects saliency,
runs inference, prunes experts or fine-tunes the model.

The candidate release is `data/releases/mitre-pilot-v0.2`: 432 canonical examples,
132 calibration exports, 187 training, 21 validation and 43 evaluation records.
The canonical calibration partition contains 181 records; seeded sampling selects
100 technique/tactic extractions and 32 grounded detection reports. Its remaining
49 records stay reserved for calibration, never move to training or evaluation.
This is a narrow MITRE pilot, not a completed 512-example SOC calibration corpus.

Windows reference tokenization uses **Qwen/Qwen3-30B-A3B** revision
`ad44e777bcd18fa416d9da3bd8f70d33ebb85d39`, with no weight files downloaded.
Mac installed-tokenizer equivalence and every MLX run below are **pending** until
executed on the Mac. Do not assume your installed tokenizer matches the reference.

## Clone and select a validated version

The remote and commit are not yet configured. After an authorized Windows push and
successful CI, replace both placeholders with the actual repository URL and the
validated full commit SHA. Use an immutable commit, not a floating branch:

```sh
git clone <GITHUB_REPOSITORY_URL> trimming_dataset
cd trimming_dataset
git fetch --tags
git checkout --detach <VALIDATED_FULL_COMMIT_SHA>
git rev-parse HEAD
uv sync --locked --extra tokenizer
```

Python 3.12 and uv are needed for the dataset verifier. This `.venv` is independent
of your working MLX-FUN environment. Do not reinstall MLX, MLX-LM or MLX-FUN.
CI is configured for Windows, Linux and macOS, but remote CI results are pending
until the repository is pushed. The optional tokenizer extra needs Jinja2; it
does not require PyTorch, TensorFlow, MLX or model weights.

## Verify transferred files and traceability

```sh
uv run cyber-data verify-release data/releases/mitre-pilot-v0.2
(cd data/releases/mitre-pilot-v0.2 && shasum -a 256 -c SHA256SUMS)
uv run cyber-data validate data/releases/mitre-pilot-v0.2/canonical.jsonl
```

`verify-release` checks the exact file inventory, SHA256 hashes, UTF-8/LF bytes,
source provenance, export-to-canonical rows, smoke subset, and split isolation.
The root MITRE license accompanies all exported files. Checksums detect transfer
damage; trust the pinned reviewed Git commit as the release identity. Benchmark
reference contamination checks are still unavailable, not passed.

## Verify the installed tokenizer and calibration JSONL

Use the actual local BF16 Qwen3-30B-A3B model directory. Only its configuration and
tokenizer files are read; this command does not load model weights:

```sh
QWEN_MODEL=/absolute/path/to/installed/Qwen3-30B-A3B
uv run --extra tokenizer cyber-data validate-tokenizer \
  data/releases/mitre-pilot-v0.2/canonical.jsonl \
  --model "$QWEN_MODEL" \
  --reference data/releases/mitre-pilot-v0.2/tokenizer_validation.json
uv run --extra tokenizer cyber-data validate-calibration \
  data/releases/mitre-pilot-v0.2/calibration/data.jsonl \
  --model "$QWEN_MODEL" --max-tokens 2048
uv run --extra tokenizer cyber-data validate-calibration \
  data/releases/mitre-pilot-v0.2/calibration/smoke.jsonl \
  --model "$QWEN_MODEL" --max-tokens 2048
```

The reference check requires identical token sequences and chat-template identity.
Stop if it fails; review any installed template modifications on Windows and issue
a new validated release. It must not be bypassed by merely increasing a token cap.
The loader must receive records that fit its limit, because upstream otherwise
truncates tokens. Neither preparation nor smoke export truncates examples.

## Verify installed MLX-FUN

Activate the **existing working MLX-FUN environment**, not this dataset `.venv`.
These are read-only version and location checks, not model execution:

```sh
command -v mlx-fun
python -c 'from importlib.metadata import version; print("mlx-fun", version("mlx-fun")); print("mlx-lm", version("mlx-lm"))'
python -c 'from importlib.util import find_spec; from pathlib import Path; print(Path(find_spec("mlx_fun").origin).parent / "data.py")'
mlx-fun collect --help
```

For an editable installation, also record the repository commit:

```sh
git -C /path/to/installed/mlx_fun rev-parse HEAD
```

Run the dataset verifier with the loader path printed above (the explicit `uv run`
uses the separate dataset environment and does not reinstall the working toolkit):

```sh
uv run cyber-data check-mlx /actual/installed/mlx_fun/data.py \
  data/releases/mitre-pilot-v0.2/calibration/data.jsonl
```

The inspected applicable upstream commit is
`c5d0cbb0a962bb72c781aff2fe5e158507bf5745`, reporting package version `0.1.0`.
Version strings alone are insufficient. The reviewed tokenization function's AST
must match; changed code fails closed for review. Its CLI defines `--model`,
`--dataset`, `--output`, `--max-samples`, `--max-tokens`, `--text-key`, and `--seed`.
The commands below use only those verified options. If installed code/help differs,
stop and review the installed collector before executing them. No invented flags
or automatic toolkit upgrades are needed.

## Four-sample calibration smoke test — Mac only

After all checks above pass, keep the existing MLX-FUN environment active. Point
`QWEN_MODEL` at the local BF16 target model. Create a fresh experiment directory
**outside** the dataset repository; preserve each run's toolkit versions and commit:

```sh
QWEN_MODEL=/absolute/path/to/installed/Qwen3-30B-A3B
EXPERIMENT_DIR="$HOME/cyber-moe-experiments/mitre-pilot-v0.2-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EXPERIMENT_DIR"
git rev-parse HEAD > "$EXPERIMENT_DIR/dataset_commit.txt"
cp data/releases/mitre-pilot-v0.2/release_manifest.json "$EXPERIMENT_DIR/"
python -c 'from importlib.metadata import version; print("mlx-fun", version("mlx-fun")); print("mlx-lm", version("mlx-lm"))' > "$EXPERIMENT_DIR/toolkit_versions.txt"
mlx-fun collect \
  --model "$QWEN_MODEL" \
  --dataset data/releases/mitre-pilot-v0.2/calibration/smoke.jsonl \
  --output "$EXPERIMENT_DIR/smoke_saliency.npz" \
  --max-samples 4 --max-tokens 2048 --seed 42 \
  > "$EXPERIMENT_DIR/smoke.log" 2>&1
test -s "$EXPERIMENT_DIR/smoke_saliency.npz"
```

Inspect the log for successful processing of all four examples, absence of
truncation, valid model/adapter loading and acceptable memory use. Output existence
alone does not establish valid saliency. Do not claim Mac validation from the
Windows format-contract test. No pruning is included in this handoff.

## Full calibration — Mac only, after smoke validation

The current release has **132**, not 512, calibration records. Use its published
count and preserve the seeded sample ordering:

```sh
mlx-fun collect \
  --model "$QWEN_MODEL" \
  --dataset data/releases/mitre-pilot-v0.2/calibration/data.jsonl \
  --output "$EXPERIMENT_DIR/full_saliency.npz" \
  --max-samples 132 --max-tokens 2048 --seed 42 \
  > "$EXPERIMENT_DIR/full.log" 2>&1
test -s "$EXPERIMENT_DIR/full_saliency.npz"
```

Keep saliency, logs and later model outputs in the experiment directory. The Git
dataset repository excludes `.npz` and all model-weight formats. Never use training,
validation, or held-out evaluation JSONL as calibration input. Future LoRA data is
under `finetuning/train.jsonl` and `finetuning/valid.jsonl`; domain metadata for
selective expert experiments is under `expert_training/`, with expert selection
explicitly unvalidated. Held-out evaluation records are under `evaluation/`.
