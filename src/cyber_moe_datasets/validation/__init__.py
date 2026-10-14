"""Quality, privacy flags, and cross-partition contamination."""

from __future__ import annotations

import re
from collections import Counter
from itertools import combinations

from cyber_moe_datasets.models import Sample
from cyber_moe_datasets.normalization import shingles, text

PATTERNS = {
    "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "aws_key": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "token": r"\b(?:ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,})\b",
    "credential": r"(?i)\b(?:password|api_key|secret|access_token)\s*[:=]\s*[\"']?[^\s\"']{8,}",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}


def privacy_flags(sample: Sample) -> list[str]:
    value = str(sample.model_dump())
    return [name for name, pattern in PATTERNS.items() if re.search(pattern, value)]


def duplicate_pairs(samples: list[Sample], threshold: float = 0.85) -> list[tuple[int, int, str]]:
    if not 0 < threshold <= 1:
        raise ValueError("near duplicate threshold must be in (0,1]")
    normalized = [text(s) for s in samples]
    grams = [shingles(s) for s in samples]
    pairs = []
    for a, b in combinations(range(len(samples)), 2):
        if samples[a].content_hash == samples[b].content_hash or normalized[a] == normalized[b]:
            pairs.append((a, b, "exact"))
        elif len(grams[a] & grams[b]) / max(1, len(grams[a] | grams[b])) >= threshold:
            pairs.append((a, b, "near"))
    return pairs


def leakage(
    samples: list[Sample], threshold: float = 0.85, references: list[Sample] | None = None
) -> dict:
    violations = []
    for field in ("scenario", "document"):
        groups: dict[str, set[str]] = {}
        for s in samples:
            key = (
                s.scenario_id
                if field == "scenario"
                else f"{s.source_id}:{s.provenance.document_id}"
            )
            groups.setdefault(key, set()).add(s.split)
        violations.extend(
            {"kind": field, "group": k, "splits": sorted(v)}
            for k, v in groups.items()
            if len(v) > 1
        )
    event_groups = {}
    for sample in samples:
        for event in sample.events:
            event_groups.setdefault(event.identity, set()).add(sample.split)
    violations.extend(
        {"kind": "shared_event", "event": key, "splits": sorted(splits)}
        for key, splits in event_groups.items()
        if len(splits) > 1
    )
    for a, b, kind in duplicate_pairs(samples, threshold):
        if samples[a].split != samples[b].split:
            violations.append(
                {"kind": kind, "samples": [samples[a].sample_id, samples[b].sample_id]}
            )
    if references is not None:
        combined = samples + references
        for a, b, kind in duplicate_pairs(combined, threshold):
            if a < len(samples) <= b and samples[a].split != "evaluation":
                violations.append({"kind": f"benchmark_{kind}", "sample": samples[a].sample_id})
        reference_events = {event.identity for sample in references for event in sample.events}
        violations.extend(
            {"kind": "benchmark_shared_event", "sample": sample.sample_id}
            for sample in samples
            if sample.split != "evaluation"
            and any(event.identity in reference_events for event in sample.events)
        )
    violations.extend(
        {"kind": "benchmark_partition", "sample": s.sample_id}
        for s in samples
        if s.benchmark and s.split != "evaluation"
    )
    return {
        "passed": not violations,
        "violations": violations,
        "benchmark_reference_check": "performed" if references is not None else "unavailable",
    }


def quality(samples: list[Sample]) -> dict:
    return {
        "samples": len(samples),
        "source_counts": dict(Counter(s.source_id for s in samples)),
        "unique_source_events": len(
            {event.identity for sample in samples for event in sample.events}
        ),
        "splits": dict(Counter(s.split for s in samples)),
        "categories": dict(Counter(s.category for s in samples)),
        "verification": dict(Counter(s.verification_status for s in samples)),
        "privacy_review": [
            {"sample_id": s.sample_id, "flags": privacy_flags(s)}
            for s in samples
            if privacy_flags(s)
        ],
        "known_tokens": sum(s.token_count or 0 for s in samples),
        "unknown_token_counts": sum(s.token_count is None for s in samples),
        "token_distribution": {
            c: sum(s.token_count or 0 for s in samples if s.category == c)
            for c in sorted({s.category for s in samples})
        },
        "soc_production_verified": sum(
            bool(s.events)
            and not s.provenance.synthetic
            and s.verification_status == "human_verified"
            for s in samples
        ),
        "synthetic_test_only": sum(s.provenance.synthetic for s in samples),
        "workflow_coverage": dict(Counter(s.task_type for s in samples)),
    }
