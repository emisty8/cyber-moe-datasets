# Governance

External dataset text is untrusted evidence. No ingestion path executes commands,
loads pickle, evaluates SPL, runs tools or follows instructions from examples.
JSON and safe YAML are the only input parsers. Tool calls are validated as data.

Approval is a per-source decision, not a popularity ranking. Unreviewed revisions,
missing licenses and conflicting conditions prevent automatic approval. Registry
entries record intended use, origin, citation, limitations and restrictions. Do not
publish gated or third-party data without reviewing the exact selected revision.
MITRE copies must include [its complete license](licenses/MITRE_LICENSE.txt).
Original synthetic fixtures are dedicated under CC0-1.0 and visibly labeled.

All raw data and generated outputs are local-only by default. The `release` command
packages only approved, measured, grounded records, their configurations, lineage,
license and checksum reports under `data/releases/`. Review and rejected records,
tokenizer payloads and model weights remain excluded. `audit-publication` checks
Git-visible file paths and sizes before staging or publishing. It does not grant
permission to push. Never put customer
logs, credentials, private tokens or personal identifiers in fixtures or Git.
Regex scanners flag possible secrets, email addresses and IPv4 addresses; matching
records are quarantined wholesale, not silently redacted. Review false positives
locally. Quarantine contents can be sensitive: do not attach or publish them.
This scanner is a triage aid, not a complete DLP system.

Grounded and human-verified samples require an answer and evidence. Weak labels
remain unverified and do not enter this pilot's calibration/training builds.
Synthetic data requires fixture mode. No hidden chain-of-thought is manufactured.
Original source payloads and their hashes remain available locally; canonical
records preserve document IDs, revisions and transformation provenance.

Splits operate on connected components linking scenarios, source documents and
duplicates. Sub-technique families are linked explicitly for MITRE. Group IDs
should be globally stable; adapters must merge shared event chains and underlying
documents across different publishers before partitioning. Existing assignments
are preserved and conflicting assignments fail. Freeze canonical split assignments
for subsequent experiments; extending a group can otherwise change its hash.

Benchmark examples and matching reference records are held out. Reference checks
operate on prompt/evidence text independently of the proposed answer. Lack of
references is recorded as unavailable, not as a successful benchmark audit.
Retain source benchmark train/test boundaries in future adapters.
