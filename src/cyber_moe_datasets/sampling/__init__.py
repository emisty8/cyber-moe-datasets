"""Deterministic sampling without replacement; shortfalls are explicit."""

import hashlib

from cyber_moe_datasets.models import Sample
from cyber_moe_datasets.validation import duplicate_pairs


def select(samples: list[Sample], targets: dict[str, int], seed: int) -> tuple[list[Sample], dict]:
    if any(not isinstance(n, int) or n < 0 for n in targets.values()):
        raise ValueError("targets must be nonnegative integers")
    chosen = []
    shortfalls = {}
    seen = set()
    for category, target in targets.items():
        pool = sorted(
            (s for s in samples if s.split == "calibration" and s.category == category),
            key=lambda s: hashlib.sha256(f"{seed}:{s.sample_id}".encode()).hexdigest(),
        )
        unique = []
        blocked = {b for _, b, _ in duplicate_pairs(pool)}
        for index, s in enumerate(pool):
            if index in blocked:
                continue
            if s.content_hash not in seen:
                unique.append(s)
                seen.add(s.content_hash)
        selected = unique[:target]
        chosen.extend(selected)
        shortfalls[category] = {
            "target": target,
            "available": len(unique),
            "selected": len(selected),
            "shortfall": max(0, target - len(selected)),
        }
    return chosen, shortfalls
