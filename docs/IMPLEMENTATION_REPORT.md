# Implementation report — October 14, 2026

Historical report for the initial preview implementation. The current portable
candidate and Windows validation results are documented in
[WINDOWS_VALIDATION.md](WINDOWS_VALIDATION.md).

Created a standalone typed Python package with uv lockfile, strict canonical and
export schemas, reviewed source registry, pinned downloads, MITRE STIX ingestion,
canonical JSONL ingestion, privacy quarantine, local tokenizer integration,
connected-group deterministic splits, exact/near duplicate checks, benchmark
reference checking, seeded calibration sampling, independent exports, row-level
lineage sidecars, machine-readable reports, documentation and Windows/Linux CI.
No existing source files were present or overwritten. No model environment was
modified and no training, pruning, collection or GitHub push was performed.

| Inventory | Calibration export | Train | Validation | Evaluation | Rights |
|---|---:|---:|---:|---:|---|
| MITRE 17.1, 78 retained records | 35 | 32 | 5 | 6 | MITRE terms/attribution preserved |
| Original synthetic fixtures, 20 records | 4 | 5 | 5 | 5 | CC0; tests only |

Two of the 80 selected MITRE records were quarantined for IPv4 review flags.
All retained MITRE tasks are grounded technique/name/tactic extraction. Fixture
calibration contains five assigned examples, but one tool example is deferred
until exact tokenizer rendering is available. Other sources are researched registry
candidates and have zero ingested examples. Calibration shortfall is **477 of 512**:
SOC 192, security reasoning 93, tool workflows 96, general 64, structured 32.

Validation: **45 passed, 0 failed, 1 skipped** (local Qwen tokenizer integration).
Ruff passed. Public canonical/calibration/evaluation JSON Schemas validated all
real pilot records. Connected scenario/document and duplicate split checks passed;
benchmark-reference checks remain unavailable. A second real-data build reproduced
all **27 artifacts byte-for-byte**, including reports and lineage sidecars.
The offline fixture end-to-end test also checks deterministic output reproduction.

MLX-FUN's upstream commit `c5d0cbb0a962bb72c781aff2fe5e158507bf5745` was inspected.
The exact reviewed `_tokenize_entry` function accepted all 35 exported calibration
records using a contract-spy tokenizer. Loader SHA256:
`fcf561444da0d52c170017a257b1d0f12555657e66b9a0e291e504f6d4336be2`.
Chat uses messages; tool calibration requires pre-rendered content because upstream
does not pass tool schemas to its chat template. Exact tool rendering is checked
for a token-preserving round trip when a tokenizer is available. Installed Mac
version compatibility, MLX execution and real tokenizer behavior remain unverified.

Reproduce from the repository root:

```sh
uv sync --locked
uv run cyber-data inspect
uv run cyber-data download mitre_attack data/raw/enterprise-attack-17.1.json
uv run cyber-data build --config configs/calibration.yaml --output outputs/pilot
uv run cyber-data validate outputs/pilot/canonical.jsonl
uv run cyber-data export outputs/pilot/canonical.jsonl outputs/reexport/train.jsonl --kind train --preview
uv run pytest -q
uv run ruff check .
```

See README for the offline fixture command, exact local tokenizer setup, installed
MLX-FUN check and next-phase collector command. The machine-readable evidence
snapshot is `data/manifests/pilot_summary.json`; current build outputs are under
`outputs/pilot` and `outputs/fixtures`, ignored by Git.

Limitations: preview token counts are unknown; sequence filtering is unverified;
the pilot is narrow field extraction; BOTS buckets require Splunk extraction and
answer review; candidate adapters are not implemented; held-out benchmark data is
not downloaded; pairwise lexical duplicate checks do not prove semantic isolation.
GitHub Actions is configured but was not run remotely.

Highest priority: verify the installed Mac tokenizer/collector contract, then
acquire and review BOTS SOC investigation exports to address the 192-example SOC
gap. Freeze external benchmark references before broadening the corpus. Synthetic
fixtures must stay outside the production calibration corpus.
