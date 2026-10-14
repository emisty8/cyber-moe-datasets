"""Stable connected-component grouping before partition assignment."""

from __future__ import annotations

import hashlib

from cyber_moe_datasets.models import Sample
from cyber_moe_datasets.validation import duplicate_pairs


class PartitionConflict(ValueError):
    def __init__(self, sample_ids: list[str]):
        super().__init__("incompatible fixed partitions in connected group")
        self.sample_ids = sample_ids


def partition(
    samples: list[Sample],
    seed: int = 42,
    threshold: float = 0.85,
    ratios: dict[str, float] | None = None,
) -> list[Sample]:
    ratios = ratios or {"calibration": 0.4, "train": 0.4, "validation": 0.1, "evaluation": 0.1}
    if (
        set(ratios) != {"calibration", "train", "validation", "evaluation"}
        or any(v < 0 for v in ratios.values())
        or abs(sum(ratios.values()) - 1) > 1e-8
    ):
        raise ValueError("invalid split ratios")
    if len({s.sample_id for s in samples}) != len(samples):
        raise ValueError("duplicate sample IDs")
    samples = sorted(samples, key=lambda s: s.sample_id)
    parent = list(range(len(samples)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a: int, b: int) -> None:
        parent[find(b)] = find(a)

    for key_fn in (lambda s: s.scenario_id, lambda s: f"{s.source_id}:{s.provenance.document_id}"):
        owners = {}
        for i, sample in enumerate(samples):
            key = key_fn(sample)
            if key in owners:
                union(i, owners[key])
            owners[key] = i
    for a, b, _ in duplicate_pairs(samples, threshold):
        union(a, b)
    event_owners = {}
    event_contents = {}
    for i, sample in enumerate(samples):
        for event in sample.events:
            content = event.model_dump(exclude={"source_version"})
            if event.identity in event_contents and content != event_contents[event.identity]:
                raise ValueError("conflicting source evidence for the same native event")
            if event.identity in event_owners:
                union(i, event_owners[event.identity])
            event_owners[event.identity] = i
            event_contents[event.identity] = content
    groups: dict[int, list[int]] = {}
    for i in range(len(samples)):
        groups.setdefault(find(i), []).append(i)
    for indices in groups.values():
        fixed = {samples[i].split for i in indices if samples[i].split != "unassigned"}
        if any(samples[i].benchmark for i in indices):
            fixed.add("evaluation")
        if len(fixed) > 1:
            raise PartitionConflict([samples[i].sample_id for i in indices])
        key = "|".join(samples[i].sample_id for i in indices)
        fraction = int(hashlib.sha256(f"{seed}:{key}".encode()).hexdigest()[:16], 16) / 2**64
        chosen = "evaluation"
        cumulative = 0.0
        for name in ("calibration", "train", "validation", "evaluation"):
            cumulative += ratios[name]
            if fraction < cumulative:
                chosen = name
                break
        chosen = next(iter(fixed)) if fixed else chosen
        for i in indices:
            samples[i] = Sample.model_validate({**samples[i].model_dump(), "split": chosen})
    return samples
