# Windows validation — October 14, 2026

The development workspace is `D:\ITS\trimming_dataset`; all current dataset
engineering and quality checks ran on Windows with Python 3.12.10 and uv 0.12.23.
No MLX import/model execution, expert collection, inference, pruning or fine-tuning
was performed. No 30B weights were downloaded. Git is initialized on `main` with
no remote, commit, tag or push.

## Validation evidence

| Check | Result |
|---|---|
| Full Windows tests, tokenizer-only integration enabled | 67 passed, 0 failed, 0 skipped |
| Local CI command simulation, no optional tokenizer dependency | 65 passed, 0 failed, 2 integration skips |
| Ruff | Passed |
| Exact official Qwen chat/token round trips | Passed for all 432 release canonical records |
| Tool schemas, arguments and complete tool exchanges | Passed; 20 synthetic fixture records independently rendered, including four tool exchanges |
| Real-tokenizer fixture calibration exporter | Passed; all five fixture calibration records exported without truncation |
| Source-to-output traceability | Passed for every export row and sidecar |
| Partition isolation | Passed; scenarios, source documents, exact/near duplicate groups isolated |
| Prior split preservation | Original 78 retained pilot records keep their assignments |
| Deterministic release rebuild | All 20 release files byte-identical |
| UTF-8/LF and relative POSIX release paths | Passed |
| Pinned MLX-FUN format contract | All 132 calibration exports accepted |
| Git-visible path, size and strong-credential-pattern audit | Passed |
| Benchmark-reference decontamination | Unavailable; reference dataset not acquired |
| Remote GitHub Actions | Configured for Windows/Linux/macOS; execution pending |
| Installed Mac tokenizer and MLX-FUN compatibility | Pending |
| Mac four-sample smoke/full calibration | Pending |

No imported record was truncated. Two IPv4-flagged records were quarantined, and
14 newly introduced records that bridged incompatible frozen partitions were
rejected. Their contents remain in ignored local output directories. Their IDs
and counts appear in the public quality report without exposing rejected contents.
No filler or duplicate calibration examples were generated to meet quotas.

## Dataset inventory

`data/releases/mitre-pilot-v0.2` contains 20 files totaling **3,484,415 bytes**.
It carries the full MITRE license, source revision/checksum, experiment config,
tokenizer validation report, row-level lineage and SHA256 inventory.

| Partition | Canonical assignment | Exported records |
|---|---:|---:|
| Calibration | 181 | 132 |
| Training | 187 | 187 |
| Validation | 21 | 21 |
| Held-out evaluation | 43 | 43 |
| Total canonical | 432 | Separate exports; do not sum duplicate formats |

Calibration selects 100 technique/tactic extraction examples and 32 documented
detection-guidance reports. The 49 unselected calibration records remain reserved
for calibration. Training is also exported with domain metadata for future
selective-expert experiments; expert selection is unvalidated.

Calibration category tokens: security reasoning **40,952** and structured reports
**14,402**, totaling **55,354**. All canonical records have exact token counts;
the canonical corpus totals 185,217 tokens. All fit the configured 2048-token cap.
This is source-grounded field extraction/reporting, not validated SOC incident
reasoning or an independent benchmark. Synthetic fixtures are kept separate.

The official tokenizer reference is `Qwen/Qwen3-30B-A3B` revision
`ad44e777bcd18fa416d9da3bd8f70d33ebb85d39`. Only tokenizer/config/license files
were acquired, under an explicit file allowlist. Their checksums are recorded in
`data/manifests/qwen_tokenizer_source.json`. No special tokens or expert counts
were guessed. Exact matching to the Mac installation is required before collection.

MLX-FUN contract inspection uses upstream commit
`c5d0cbb0a962bb72c781aff2fe5e158507bf5745`. Its reviewed tokenization function
accepted the calibration JSONL with a spy tokenizer, and an independent real
Qwen-tokenizer check verified sequence lengths. This proves Windows format and
tokenizer preparation, not installed Mac execution.

## Publication and handoff

Git-eligible: package/scripts, configs/schemas, uv lockfile, tests, cross-platform
CI, documentation/licenses, original CC0 fixtures, public metadata and the approved
MITRE release. Excluded: `.venv`, raw/research/local data, tokenizer payloads,
quarantine and rejected examples, logs, model weights, archives, credentials and
saliency. `.gitignore` is reinforced by a Git-visible-file audit, including
force-added or already tracked forbidden files. Secret scanning is heuristic and
does not replace staged-diff review.

Reproduction and exact staging/commit/tag/remote commands are in
[WINDOWS_WORKFLOW.md](WINDOWS_WORKFLOW.md). Mac clone, checksum, installed tokenizer
and MLX-FUN checks, four-sample calibration smoke test, full 132-sample collection
and external saliency storage are in [MAC_DEPLOYMENT.md](MAC_DEPLOYMENT.md).
No push is authorized or performed. The final commit SHA and remote URL must be
supplied after the user configures and authorizes publication and CI succeeds.

Remaining 512-target gaps: SOC **192**, security reasoning **28**, tool workflows
**96**, general reasoning/coding **64**, structured output **0**: total **380**.
BOTS needs Splunk-exported events and reviewed answers. Salesforce xLAM data is
gated and returned HTTP 401 without credentials; it remains unapproved/un-ingested.
REAP upstream data needs independent rights, quality and revision review. Public
benchmark references remain unavailable.

Next milestone: implement a reviewed BOTS export adapter and build independent SOC
cases with validated answers, while freezing a held-out benchmark reference set.
