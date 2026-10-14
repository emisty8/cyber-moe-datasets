# Windows preparation and GitHub publication

Work in `D:\ITS\trimming_dataset`; do not create another project. This repository
does not execute MLX or load the model on Windows. The tokenizer is independently
usable through transformers and Jinja2 without MLX/PyTorch or 30B weights.

## Reproduce the portable candidate

```powershell
uv sync --locked --extra tokenizer
uv run --extra tokenizer cyber-data acquire-tokenizer
uv run --extra tokenizer cyber-data download mitre_attack data/raw/enterprise-attack-17.1.json
uv run --extra tokenizer cyber-data build --config configs/portable.yaml --output outputs/rebuilt --model data/tokenizers/qwen3-30b-a3b
uv run --extra tokenizer cyber-data validate-tokenizer outputs/rebuilt/canonical.jsonl --model data/tokenizers/qwen3-30b-a3b --output outputs/rebuilt/tokenizer_validation.json
uv run --extra tokenizer cyber-data validate-calibration outputs/rebuilt/calibration/data.jsonl --model data/tokenizers/qwen3-30b-a3b
uv run --extra tokenizer cyber-data verify-release data/releases/mitre-pilot-v0.2
$env:QWEN_MODEL_PATH = 'data/tokenizers/qwen3-30b-a3b'
uv run --extra tokenizer pytest -q
uv run --extra tokenizer ruff check .
```

The acquisition command downloads only six explicitly allowed files from the
pinned official Qwen revision. It records their hashes locally. Reference hashes
are included in the release tokenizer report. On later acquisition it refuses to
replace mismatching local files. No secrets, Hugging Face token or model weights
are needed. Mac-installed files still need the reference-equivalence check.

Configuration paths are repository-relative. JSONL and manifests use UTF-8 and LF;
`.gitattributes` preserves this on checkout. Source/implementation checksums use
portable POSIX names. The frozen pilot scenario map preserves the original split
assignments when extending the corpus. Newly introduced connected groups that
would bridge existing incompatible partitions are rejected and reported locally.
No prior held-out examples are reassigned for a larger calibration quota.

The packaged release has a complete checksum inventory, row-level export lineage,
source manifest, exact token counts/hashes, quality/leakage reports, four-sample
smoke export and MITRE license. Use `release` only for a **new** immutable version:

```powershell
uv run --extra tokenizer cyber-data release outputs/rebuilt data/releases/<NEW_RELEASE_ID>
```

Existing releases are never overwritten by that command. Failed packaging uses a
temporary staging directory and leaves no partially published destination.

## Git review and local commit

The initial workflow initialized this repository locally. At the Task B audit,
`main` contains commit `c5427dc`, `dataset-mitre-v0.2` is present, and `origin` is
`https://github.com/emisty8/cyber-moe-datasets.git`. Task B works on
`feature/bots-mcp-pipeline`; no automatic commit, tag or push is performed. Review
the Task B diff first; the commands below describe the original v0.2 publication flow:

```powershell
git status --short
uv run cyber-data audit-publication
git check-ignore data/raw/enterprise-attack-17.1.json data/tokenizers/qwen3-30b-a3b/tokenizer.json outputs/portable/quarantine.jsonl
git add .gitattributes .gitignore .python-version pyproject.toml uv.lock README.md .github configs schemas src scripts tests docs data/fixtures data/manifests data/releases/mitre-pilot-v0.2
git diff --cached --stat
git diff --cached --check
uv run cyber-data audit-publication
git commit -m "Prepare validated Windows datasets and Apple Silicon handoff"
git tag -a dataset-mitre-v0.2 -m "Windows tokenizer-validated MITRE pilot; Mac validation pending"
git rev-parse HEAD
```

`git add`/commit/tag are recommended commands, not actions already performed.
Confirm that the Git identity is configured before committing. Audit the actual
staged diff for secrets and rights decisions; scanners are not a replacement for
review. `audit-publication` also rejects forbidden files even if previously staged
or force-added, unlike `.gitignore` alone.

Eligible files: source package, scripts, configs, schemas, uv lockfile, tests,
cross-platform CI, documentation/licenses, original synthetic fixtures, public
metadata and the small approved MITRE release. Excluded: raw/research/local sources,
privacy quarantines, length/partition rejections, tokenizer payloads, environments,
API keys/private certificates, model weights, saliency arrays and logs.

## Configure remote; push only after explicit authorization

Replace the URL with the actual destination. Configuring the remote is separate
from authorizing a push. Once the user explicitly authorizes the push:

```powershell
git remote add origin https://github.com/<OWNER>/<REPOSITORY>.git
git remote -v
git push -u origin main
git push origin dataset-mitre-v0.2
```

If `origin` already exists, inspect it and resolve the destination before changing
it. Wait for Windows/Linux/macOS CI to pass, then give the Mac the full validated
commit SHA. The Mac uses [MAC_DEPLOYMENT.md](MAC_DEPLOYMENT.md). Remote CI and Mac
model execution are pending until actually performed.

## Remaining coverage

The calibration target is still short by 380: SOC 192, security reasoning 28,
tool workflows 96, general reasoning/coding 64. The structured-output target of 32
is met with source-grounded detection reports, not invented incident answers.
MITRE reporting copies documented fields; it does not prove incident reasoning.
BOTS requires a Splunk export and reviewed investigation answers. Salesforce xLAM
is gated (HTTP 401 at the pinned data URL without credentials); rights/terms review
and user-provided approved acquisition remain pending. REAP is a reference recipe,
not a blanket license to its upstream datasets. Benchmark reference data is absent.

Next dataset milestone: a reviewed BOTS investigation export adapter and enough
independent, validated SOC cases to address the 192-example calibration gap,
while freezing the evaluation benchmark reference set. Review public tool/general
datasets under their own pinned licenses before adding them.
