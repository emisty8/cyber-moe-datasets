# Task B report - October 14, 2026

Development branch: `feature/bots-mcp-pipeline`, based on the existing validated
repository and configured `origin`. No commit, tag or push was made for this task.
No model inference, MLX execution, expert collection, pruning or training occurred.
No Splunk software or large BOTS archive was installed/downloaded.

## Implementation

Added local native Splunk CSV/JSON/REST-result export adapters, typed event/review
contracts, explicit investigation annotations, evidence-bound analyst approval,
local review queues, conservative field/count/timeline answer validation, and
shared-native-event splitting across source revisions. Canonical optional fields
preserve the existing schema and old content hashes. Unreviewed SOC answers cannot
enter calibration, training or evaluation. Source approval is separate from answer
approval. Invalid fields, false counts, stale reviews, unsupported conclusions,
malformed/preview rows and conflicting native identifiers fail validation.

Added versioned MCP tool packs, faithful name/parameter conversion, input/output
schema checks, explicit error envelopes, tool-call/result linkage, schema-bound
review checks for future real traces, and a constrained read-only SPL subset with
observed fields, explicit index/sourcetype scope and a bounded time window. Remote
JSON Schema references are rejected; no commands or tool requests are executed.

Added original CC0 fixtures, fixture/review build configurations, JSON Schemas,
cross-platform CI steps and acquisition/review/MCP documentation. Publication audits
reject unreviewed or real raw SOC artifacts outside approved local-only handling.
Artifact IO blocks writes to the frozen MITRE release.

## Inventory and readiness

| Inventory | Records | Actual Qwen tokens | Production contribution |
|---|---:|---:|---:|
| Existing frozen MITRE canonical release | 432 | 185,217 | Existing release retained |
| New synthetic SOC cases | 10 over 18 test events | 10,385 | 0 |
| New synthetic MCP traces | 7 | 3,486 | 0 |
| Genuine reviewed BOTS/SOC cases | 0 | 0 | 0 |

The new fixture pilot totals **17 records / 13,871 tokens**. Its partition inventory
is calibration 5, training 5, validation 4 and evaluation 3. The calibration fixture
export contains 3 SOC and 2 MCP records, totaling **4,377 tokens** (SOC 3,440; MCP
937). Maximum fixture length is **1,661**, below the 2048-token cap; no record was
truncated or length-rejected. No fixture contributes to production quotas.

Outputs in ignored `outputs/soc_fixture_pilot/`: canonical records, calibration,
LoRA training/validation, independent evaluation, expert metadata, lineage sidecars,
quality/leakage reports, source manifest, review/quarantine/rejection queues and
exact-tokenizer validation. The review queue is empty for these authored fixtures;
tests exercise pending real-case routing using clearly unit-only simulated inputs.

MCP schema: `synthetic-splunk-fixture-only`, `fixture-v1.0.0`, identity
`eee9f010c8bda9661d271d52e9e4122db20ecd4cd21983c7b590fc9dd7296f9f`.
All seven fixture traces validate against it. Actual production MCP schemas, result
formats, permissions and live compatibility remain **unverified**.

## Validation

- Audited baseline: all **67** previously reported tests passed.
- Expanded Windows suite with tokenizer integration: **116 passed, 0 failed, 0 skipped**.
- Earlier base-dependency CI simulation: **113 passed, 0 failed, 3 integration skips**.
  Final rerun with the integration tokenizer path unset gave the same result; optional
  tokenizer dependencies were still installed during that final rerun.
- Ruff, Git whitespace checks and publication audits passed.
- All new canonical/calibration/evaluation records passed their public JSON Schemas.
- All **23** fixture pilot artifacts reproduced byte-for-byte across two builds.
- All **20** frozen MITRE release files match `dataset-mitre-v0.2` byte-for-byte;
  release checksum/traceability checks passed and Git shows no release file changes.
- Pinned MLX-FUN input-format checks accepted all five calibration fixtures;
  independent Qwen tokenization checked their actual collector lengths.
- Remote CI, Mac model execution, production MCP integration and benchmark-reference
  contamination checking remain pending/unavailable.

Machine-readable evidence is under `data/manifests/task_b_*.json`. These snapshots
contain metadata/checksums and synthetic inventory, not real raw BOTS events.

## Gaps and manual review

Production calibration remains the existing 132 MITRE examples, short of 512 by
**380**: SOC 192, security reasoning 28, MCP/tools 96, general/coding 64, structured
0. Synthetic test coverage does not reduce any of those shortfalls.

No local approved Splunk installation/export was found in PATH, common installation
locations, running process names or workspace data. The official BOTS metadata was
inspected; its archive checksum is recorded as **published**, not locally verified.
Source licensing/third-party archive notices still need approval. Regex PII/secret
screening is heuristic and does not identify every account/person identifier.

Required next inputs: an approved bounded BOTS event export with original native
locators/raw evidence and checksums; actual observed field inventory; source rights
decision; case questions and evidence-supported analyst review; and the real MCP
`tools/list` snapshot/version plus approved recorded tool results. Human review
must assess causal/attack conclusions; automated checks only prove supported facts
and enforce documented review bindings. Benchmark reference material is still absent.

Suggested next release: **`dataset-soc-v0.3`**, after genuinely reviewed BOTS cases
exist and source/MCP/publication decisions are approved. No such production release
is claimed or tagged now. The highest-priority next action is exporting and reviewing
one real BOTS investigation end to end using [SOC_PIPELINE.md](SOC_PIPELINE.md).

Mac transfer continues through an explicitly authorized Git push and pinned
validated commit; [MAC_DEPLOYMENT.md](MAC_DEPLOYMENT.md) keeps all model execution
on Apple Silicon. Only code, schemas, metadata and synthetic test fixtures are
Git-ready for Task B. Raw BOTS exports, reviewer details and unreviewed examples
remain local-only. Do not calibrate the production model on fixture datasets.

## Final continuation audit

Completed on Windows on October 14, 2026, after the interrupted session. Confirmed
branch `feature/bots-mcp-pipeline`, HEAD `c5427dc930cc2b8b4c4e5e7ffee6f4b9bbdc5559`,
and an empty Git index. The existing implementation was preserved; this continuation
changed only this report among publication files. No new features were added.

Fresh checks:

- `uv sync --locked --extra tokenizer` succeeded with the existing lockfile.
- Complete suite: **116 passed in 21.02 seconds**, no failures or skips, with
  `QWEN_MODEL_PATH=data/tokenizers/qwen3-30b-a3b`.
- Integration path unset: **113 passed, 3 skipped in 11.83 seconds**. This is a local
  Windows check, not evidence that remote Linux/macOS CI has run.
- Ruff, Git whitespace and publication audit passed. Publication audit inspected
  102 Git-visible files, including the unrelated editor settings; no remote contact.
- Baseline and SOC CI-style fixture builds passed without selecting a tokenizer.
  Tool calibration was explicitly deferred in those preview builds.
- Two fresh exact-tokenizer builds under ignored `outputs/task_b_final_audit/first`
  and `second`, including independently generated tokenizer reports, reproduced
  **all 23 files byte-for-byte** and matched every prior pilot checksum.
- Canonical validation/leakage, public canonical/calibration/evaluation schemas,
  source payload hashes, native evidence identity, and every export lineage sidecar
  passed. All 18 source events are preserved; no shared event crosses partitions.
  All generated files are UTF-8 without BOM, with LF and repository-relative paths.
- Exact Qwen chat-template/tool-argument checks passed for all 17 records. All five
  calibration collector inputs passed exact length validation (641, 1661, 1138,
  438, 499 tokens) and the pinned MLX-FUN static input contract. No MLX was imported
  or executed by these checks; no model weights were loaded.
- The frozen release verifier checked 19 manifest-listed payloads. Independently,
  **all 20 files, including the release manifest**, were read directly from
  `dataset-mitre-v0.2` with `git show` and compared with working-tree bytes. There
  were no extra/missing release files and no release diff.
- All 10 SOC cases and 7 MCP traces retain `provenance.synthetic: true` and
  `verification_status: synthetic`. SOC review status remains `synthetic_fixture`;
  MCP schema identity is explicitly synthetic. Production contribution remains **0**.
- Nothing is staged: therefore no customer data, weights, credentials, restricted
  raw sources or generated experiment outputs are staged. Ignore rules cover local
  exports, raw archives, tokenizers, models, saliency and generated outputs. The
  credential scanner is heuristic, not an exhaustive proof about arbitrary secrets.

Fresh local evidence: `outputs/task_b_final_audit/audit.json` and its two build trees.
These are ignored and must not be committed. Existing publication manifests remain
consistent with the fresh checks. The only unrelated Git-visible file is the
untracked `.vscode/settings.json`; it was left untouched and is excluded below.
Benchmark-reference contamination, real MCP server compatibility, remote CI and
actual Mac validation remain pending. The production MITRE shortfall remains 380.

## Exact input contract for a real BOTS pilot

Supply these local files; do not supply the pre-indexed TGZ to the adapter:

1. `data/local/bots/events.csv` (or `.json` / `.jsonl`), at most **64 MiB**, UTF-8.
   Each event must contain nonempty **string** values for `_time`, `index`,
   `sourcetype`, `host`, `source`, `_raw`, `_bkt`, `_cd`. Preserve original locator
   values and raw evidence. `_time` accepts timezone-bearing ISO-8601 or finite
   epoch seconds as a string. Extracted fields may preserve JSON multivalue types.
   CSV must have exactly the manifest's field names (column order may differ).
   JSON must be an array or `{"results": [...]}`; JSONL accepts native row objects
   or final `{"preview": false, "result": {...}}` wrappers. Additional fields must
   be declared in the inventory. Duplicate keys, nonfinite numbers, preview results,
   missing native fields and conflicting locators are rejected. BOM/CRLF input is
   tolerated; generated exports use UTF-8/LF.
2. `data/local/bots/export_manifest.json`, following
   `schemas/splunk_export_manifest.schema.json`. Required keys: `source_id`,
   `source_version`, `source_dataset`, `source_url`, `license`, `synthetic`, `format`,
   `payload_sha256`, `field_inventory`, `export_query`, `splunk_version`, `exported_at`.
   For real BOTS also include `archive_md5`. Use `source_id: botsv3`,
   `source_version: botsv3@5f556f8b4c4ce0bd7498e642fdb52801e89bee0f`, dataset `botsv3`,
   the official source URL, registry-matching license, `synthetic: false`, actual
   export format/version/query/time and SHA256 of the exact exported bytes.
   Inventory must contain all eight native fields and every exported extracted
   field. BOTS requires archive MD5 `d7ccca99a01cff070dff3c139cdc10eb`; recording
   that value is an operator attestation, not an automatic archive verification.
3. `data/local/bots/investigations.json`, a JSON array of objects following
   `schemas/soc_investigation.schema.json`. Required keys: `scenario_id`,
   `document_id`, `workflow`, `question`, `event_ids`. Optional `required_fields`
   defaults to `[]`, `difficulty` to `intermediate`, `split` to `unassigned`.
   Each cited event ID is the compact, sorted JSON string containing the original
   `_bkt`, `_cd`, `index` values; it is not a row number or fabricated identifier.
   Allowed workflows and partitions are enumerated in that schema.
4. Later, a local reviewed source registry and `reviews.json` keyed by scenario ID,
   following `schemas/soc_review.schema.json`. Source approval and evidence/answer-
   bound analyst approval are both required before a real case reaches any export.
   Pending candidates are inspection/review material, not training or gold answers.

Candidate ingestion (does not approve the source or answer):

```powershell
uv run --extra tokenizer cyber-data ingest-splunk data/local/bots/events.csv --manifest data/local/bots/export_manifest.json --cases data/local/bots/investigations.json --source-id botsv3 --output data/local/bots/candidates.jsonl
```

## Bounded acquisition milestone

1. Use an existing authorized BOTS v3 Splunk lab; resolve archive rights and verify
   the original archive checksum. No lab or real export is currently available here.
2. Choose one observed authentication or process investigation: one host, selected
   actual sourcetypes, a 30-60 minute interval, initially 100-500 native events.
   Export the eight native fields plus only observed fields needed for the question.
   Use an explicit result cap, check the total count, and narrow or subdivide the
   time window if the cap is reached; preserve complete evidence for each case.
3. Save the exact query, version/add-ons, field inventory, timestamp and payload
   checksum locally. Inspect sensitive fields; keep original raw evidence off Git.
4. Annotate one evidence-grounded case, ingest a pending candidate, and have an
   analyst verify cited values/counts/chronology and any attack conclusion against
   the raw events. Bind the approved answer and evidence hashes, and approve source
   rights independently in a local registry.
5. Build with the existing review configuration and exact tokenizer; require schema,
   privacy, evidence, length, partition and reproducibility checks to pass. Keep
   overlapping cases together. Then acquire independent investigations for the
   remaining splits. Do not fill quota gaps by copying the first case.

Success criterion: one genuinely reviewed BOTS investigation through the existing
pipeline, with traceable source bytes and zero unsupported claims. A larger SOC
release and real MCP traces require subsequent source/server/publication review.

## Exact pending Task B files and recommended commit

The following PowerShell array is the complete **38-file** pending Task B scope:
15 tracked modifications and 23 new files. It excludes `.vscode/settings.json`,
the frozen release and all ignored local/generated artifacts. Nothing has been
staged or committed by this audit. Inspect the staged diff before committing.

```powershell
$taskBFiles = @(
    ".github/workflows/tests.yml"
    "README.md"
    "configs/mcp/synthetic-splunk-v1.json"
    "configs/soc_fixtures.yaml"
    "configs/soc_review.yaml"
    "configs/sources.yaml"
    "data/fixtures/soc/events.jsonl"
    "data/fixtures/soc/export_manifest.json"
    "data/fixtures/soc/investigations.json"
    "data/fixtures/soc/mcp.jsonl"
    "data/manifests/bots_source_inspection.json"
    "data/manifests/task_b_frozen_release_audit.json"
    "data/manifests/task_b_pilot_summary.json"
    "docs/BOTS_ACQUISITION.md"
    "docs/MAC_DEPLOYMENT.md"
    "docs/SOC_PIPELINE.md"
    "docs/SPLUNK_MCP_DATASETS.md"
    "docs/TASK_B_REPORT.md"
    "docs/WINDOWS_WORKFLOW.md"
    "schemas/canonical_sample.schema.json"
    "schemas/mcp_tool_pack.schema.json"
    "schemas/soc_investigation.schema.json"
    "schemas/soc_review.schema.json"
    "schemas/splunk_export_manifest.schema.json"
    "scripts/generate_soc_fixtures.py"
    "src/cyber_moe_datasets/cli.py"
    "src/cyber_moe_datasets/exporters/__init__.py"
    "src/cyber_moe_datasets/ingestion/splunk.py"
    "src/cyber_moe_datasets/io.py"
    "src/cyber_moe_datasets/mcp.py"
    "src/cyber_moe_datasets/models.py"
    "src/cyber_moe_datasets/pipeline.py"
    "src/cyber_moe_datasets/publication.py"
    "src/cyber_moe_datasets/soc_models.py"
    "src/cyber_moe_datasets/splitting/__init__.py"
    "src/cyber_moe_datasets/tokenization.py"
    "src/cyber_moe_datasets/validation/__init__.py"
    "tests/test_soc.py"
)
git add -- $taskBFiles
git diff --cached --stat
git diff --cached --check
uv run --extra tokenizer cyber-data audit-publication
git commit -m "Add evidence-reviewed Splunk and MCP pipeline with synthetic fixtures"
```

No push command is recommended or executed here. Mac handoff remains
[MAC_DEPLOYMENT.md](MAC_DEPLOYMENT.md), selecting a validated pinned commit after
an explicitly authorized push. Actual Mac calibration is pending.
