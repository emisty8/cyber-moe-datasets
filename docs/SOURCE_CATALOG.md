# Source research and decisions

Research performed October 14, 2026. Registry approval is conservative; do not infer
that all candidates are suitable or actively maintained from their public availability.

| Source | Observed distribution / rights | Decision |
|---|---|---|
| [Splunk BOTS v3](https://github.com/splunk/botsv3) | 320.1 MB pre-indexed Splunk archive; repository CC0 | Pending extraction, archive rights review and answer validation |
| [MITRE STIX](https://github.com/mitre-attack/attack-stix-data) | Versioned STIX 2.1 collections; MITRE attribution/terms | Pinned Enterprise 17.1 approved for grounded extraction and documented detection reporting |
| [Cerebras REAP](https://github.com/CerebrasResearch/reap) | Reference code and multi-source calibration recipe | Methodology only; upstream rights separate |
| [CyberSecEval](https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks) | Benchmark suite, including SOC tasks; custom Purple Llama license | Evaluation-only; selected files and revision await review |
| [Salesforce APIGen/xLAM](https://huggingface.co/datasets/Salesforce/xlam-function-calling-60k) | Gated synthetic JSON, CC-BY-4.0 card | Revision pinned; data URL returned HTTP 401 without credentials; terms acceptance, acquisition and adapter pending |
| [SWE-smith trajectories](https://huggingface.co/datasets/SWE-bench/SWE-smith-trajectories) | Tool trajectories in Parquet; MIT card | Embedded repository licenses and grouping need review |
| [Mixture-of-Thoughts](https://huggingface.co/datasets/open-r1/Mixture-of-Thoughts) | Generated reasoning traces; subset-specific provenance | Unapproved; no inferred blanket redistribution rights |
| [Evol-CodeAlpaca](https://huggingface.co/datasets/theblackcat102/evol-codealpaca-v1) | General coding candidate in REAP recipe | Unapproved, rights chain unresolved |
| [SambaNova AttackQA](https://huggingface.co/datasets/sambanovasystems/attackqa) | Official card cites MITRE origin and AttackQA paper, Apache-2.0 plus MITRE notice | Promising defensive reasoning candidate; overlap, revision and label review pending |
| [CyberSecurity-1M](https://huggingface.co/datasets/WhitzardAgent/CyberSecurity-1M) | Aggregated third-party content, Apache claim with noncommercial/no redistribution gate | No automatic ingestion; conflicting conditions unresolved |

REAP's published recipe mixes 4096 general coding, 12288 reasoning, 4096 single-turn
tools and 4096 agentic examples with maximum length 16384. It provides a useful
diversity starting point, not evidence that this project's 512 mixture is optimal.
REAP observes router-weighted expert activations; this project prepares examples
only and neither estimates expert saliency nor changes expert parameters.

BOTS ingestion cannot read Splunk index buckets as events. Install the documented
matching Splunk/add-on versions separately, export selected search results as JSON,
retain `_raw`, timestamps, query, host/source/sourcetype and investigation lineage,
and convert to canonical records with proposed answers marked unverified until
review. This repository accepts reviewed canonical exports but does not implement
a Splunk server connector or claim tested BOTS extraction.

Benchmark data has not been downloaded. Supply canonical held-out references via
the configuration's `benchmark_references` path or `validate --benchmark-references`.
Use the official harness for scoring in a later phase; the export pipeline itself
does not evaluate model responses.
