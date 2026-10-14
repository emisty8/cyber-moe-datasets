# SOC investigation preparation and review

The pipeline retains the existing canonical schema, adding optional typed `events`,
`review` and `mcp_schema` fields. Existing MITRE records and their content hashes
remain readable. The frozen `data/releases/mitre-pilot-v0.2` is unchanged and guarded
against writes through artifact IO. This task creates no production SOC release.

`ingestion/splunk.py` reads only local CSV/JSON exports; it cannot read Splunk buckets,
execute SPL, install software or contact a server. See [acquisition](BOTS_ACQUISITION.md).
Each event preserves its native locator, dataset/revision, original timestamp,
index, sourcetype, host, source, raw evidence and observed extracted fields.
`event_id` is the canonical serialization of the original `index/_bkt/_cd` tuple,
not a newly invented source ID. An internal hash links those same native locators
across derived questions and documents.

Native event grouping uses dataset identity and the original locator, independently
of documentation/source revisions. A revision change cannot move the same event
into another partition. Contradictory raw evidence for one locator is rejected.

## Case annotation and candidates

Create an array of investigation annotations following
`schemas/soc_investigation.schema.json`. Each annotation supplies the original
reviewed case/document IDs, workflow, question, cited native event IDs, required
observed fields, difficulty and optional frozen partition. Choose from authentication,
login correlation, PowerShell, Windows events, Sysmon, network, DNS, CloudTrail,
timeline and security reporting. Case labels do not establish an attack verdict.

Generate candidates locally:

```powershell
uv run cyber-data ingest-splunk data/local/bots/events.csv --manifest data/local/bots/export_manifest.json --cases data/local/bots/investigations.json --source-id botsv3 --output data/local/bots/candidates.jsonl
```

No source approval is needed to **inspect** candidates. They remain unverified,
with `expected_answer: null` and no assistant gold response. The review object stores
a proposed structured answer consisting of counts, chronological references and
the explicitly required observed fields. It never invents causal relationships,
techniques, extracted fields, maliciousness or missing evidence. All commands/log
text in evidence remain inert data.

## Review and approval

Review each case against its original export and raw evidence. The review schema
requires status, reviewer identity, timezone-bearing review timestamp, rationale,
evidence hash and answer hash for approval. The evidence hash binds every cited
event and extracted field; a change invalidates the review. The answer hash binds
the exact proposed-answer string using the package's canonical `checksum()` helper.

Store approved reviews in a local JSON object keyed by scenario ID, with review
objects conforming to `schemas/soc_review.schema.json`. Copy the evidence hash from
the generated candidate's review. Compute `checksum(answer_string)` after approving
the answer, not before editing it. Keep reviewer information local.

The supported answer structure is `{"assessment": ..., "claims": [...]}`.
Claims cite explicit event IDs and may contain an exact event count, an observed
field/value, or an ordered timestamp timeline. Counts, fields, values and ordering
are checked against source evidence. Unknown fields and unsupported claims fail.
`confirmed_attack` requires documented analyst approval and an evidence-based
rationale; software cannot independently prove that an analyst's conclusion is
correct. Free-form inferential claims need a future reviewed rubric and are
currently rejected. Treat login success or a PowerShell process as an observation,
not proof of compromise.

Approve the source revision/license separately in a **local** reviewed registry.
Even an approved reviewer answer cannot become verified training data while the
source is unapproved. Re-ingest with `--reviews data/local/bots/reviews.json` and the
reviewed registry. Never mark synthetic fixtures as real or human-reviewed data.

For end-to-end preparation, use a copy of `configs/soc_review.yaml`, pointing at
the actual local files and local reviewed registry. `review_unverified: true`
permits normalization of unapproved Splunk exports into a local review queue;
it does not approve them or expose them to calibration/training/evaluation.

```powershell
uv run --extra tokenizer cyber-data build --config configs/soc_review.yaml --output outputs/bots-review --model data/tokenizers/qwen3-30b-a3b
```

Missing input files are expected until a real export is supplied. Unverified cases
are stored only in `review_queue.jsonl`; privacy flags go to `quarantine.jsonl`.
Verified cases have complete canonical records and separate calibration, training,
validation, evaluation and expert-metadata exports with provenance sidecars. Length
filtering rejects whole cases and never discards individual tool/evidence fragments.

Scenarios, source documents, shared native events and exact/near duplicates form
connected split groups. Overlapping investigations must remain in one partition,
even if their scenario labels differ. Conflicting frozen assignments fail or reject
new additions under the existing frozen-sample policy. Benchmark reference matches
by text **or shared native event** are held out; without references, the report
explicitly states that benchmark checking is unavailable.

## Synthetic pilot and reproduction

```powershell
uv run python scripts/generate_soc_fixtures.py
uv run cyber-data build --config configs/soc_fixtures.yaml --output outputs/soc-fixture-preview
uv run --extra tokenizer cyber-data build --config configs/soc_fixtures.yaml --output outputs/soc_fixture_pilot --model data/tokenizers/qwen3-30b-a3b
uv run cyber-data validate outputs/soc_fixture_pilot/canonical.jsonl
uv run --extra tokenizer cyber-data validate-calibration outputs/soc_fixture_pilot/calibration/data.jsonl --model data/tokenizers/qwen3-30b-a3b
```

These are **10 synthetic SOC cases over 18 fabricated test events plus 7 synthetic
MCP traces**, originally authored for tests under CC0. They are not BOTS events and
contribute **zero genuinely verified production SOC samples**. The pilot covers
all ten workflows with factual field extraction, chronology and conservative
reporting. It does not implement or validate real maliciousness classifiers.
Production quota shortfalls are reported separately so fixtures never fill quotas.

Without a tokenizer, tool calibration is deferred rather than emitted incorrectly.
With the pinned reference tokenizer, all 17 cases fit the 2048-token cap. The fixture
pilot includes a review-queue file, empty because synthetic cases have fixture answers;
unit tests exercise actual pending-review routing with test-only simulated inputs.
