# Dataset card: engineering pilot v0.1

This section describes the original preview. The current portable **v0.2** expands
the scope to 240 active MITRE techniques plus their documented detection guidance.
It retains 432 measured, source-grounded records after two privacy quarantines and
14 rejected partition-conflicting additions. The calibration export selects 132
unique records, with no synthetic filler. See [current validation](WINDOWS_VALIDATION.md)
for inventory, tokenizer identity, readiness and limitations. All source/license
and interpretation limits below continue to apply.

Target: Qwen3-30B-A3B; no architectural expert counts or special tokens assumed.
Purpose: validate a reproducible preparation pipeline before calibration/training.

Real source: MITRE Enterprise ATT&CK 17.1 at commit
`c2494b29dd268c46a5d0ea0990553e4327cd2253`.
Raw SHA256: `0d1c347a4d584cf7e11ef46556c33b7689341443bf86299188d46c307274323b`.
The MITRE license and attribution accompany each pilot build. Deterministic
questions ask for record IDs, names and listed tactics. Answers copy source fields;
they are not expert-validated incident mappings. Active attack-pattern objects
include techniques and sub-techniques; revoked/deprecated entries are excluded.
Tactics are copied from kill-chain phases. No detection recommendations are invented.

The initial selection is the first 80 eligible sorted STIX IDs. This has selection
bias and proves format/lineage, not coverage or calibration quality. Privacy
quarantine and token filtering can reduce the retained inventory. The generated
quality report provides actual counts and all target shortfalls. Token counts are
null in preview mode. Local held-out MITRE extraction examples are not CyberSecEval.

Test source: 20 original CC0 synthetic examples, including four full tool exchanges.
Fixtures carry explicit synthetic provenance and fixed partitions. Tool calibration
without a real tokenizer is deferred. These records must not be represented as
real SOC logs or a validated production corpus.

Potential risks: duplicated underlying ATT&CK facts across sources, public-source
memorization, narrow extraction task coverage, heuristic privacy checks, lexical
decontamination blind spots and changing upstream license conditions. See generated
reports and [governance](DATA_GOVERNANCE.md). No model performance claims are made.
