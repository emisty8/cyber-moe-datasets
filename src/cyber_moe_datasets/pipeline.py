"""Reproducible build, quarantine, partitioning, and report artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

from cyber_moe_datasets.exporters import export, write_jsonl
from cyber_moe_datasets.ingestion import ingest_stix, read_jsonl
from cyber_moe_datasets.io import text_hash, write_json, write_text
from cyber_moe_datasets.models import Sample, digest
from cyber_moe_datasets.sampling import select
from cyber_moe_datasets.sources import registry
from cyber_moe_datasets.splitting import PartitionConflict, partition
from cyber_moe_datasets.tokenization import load_tokenizer, measure
from cyber_moe_datasets.validation import leakage, privacy_flags, quality


def build(config_path: Path, output: Path, model: Path | None = None) -> dict:
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if config.get("length_policy") != "reject_whole_sample":
        raise ValueError("only whole-sample length rejection is supported")
    if config.get("mode") not in {"preview", "production", "fixture"}:
        raise ValueError("invalid build mode")
    sources = registry(Path(config["registry"]))
    tokenizer = load_tokenizer(model) if model else None
    if tokenizer is None and config["mode"] == "production":
        raise ValueError("production build requires local Qwen tokenizer")
    samples = []
    inputs = []
    for item in config["inputs"]:
        if item["format"] not in {"stix", "canonical"}:
            raise ValueError("unsupported source input format")
        source = sources[item["source_id"]]
        if not source.approved:
            raise ValueError("unapproved source")
        path = Path(item["path"])
        inputs.append(
            {
                "source_id": source.source_id,
                "path": path.as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
        rows = (
            ingest_stix(path, source, item.get("limit", 80), item.get("reporting", False))
            if item["format"] == "stix"
            else read_jsonl(path)
        )
        for sample in rows:
            if (
                sample.source_id != source.source_id
                or sample.source_version != source.revision
                or sample.license != source.license
            ):
                raise ValueError("record source metadata disagrees with registry")
            if sample.provenance.synthetic and config["mode"] != "fixture":
                raise ValueError("synthetic records require fixture mode")
            if not sample.benchmark and sample.verification_status == "unverified":
                raise ValueError("unverified records cannot enter the validated pilot")
        samples.extend(rows)
    references = None
    if config.get("benchmark_references"):
        references = read_jsonl(Path(config["benchmark_references"]))
    quarantined = [s for s in samples if privacy_flags(s)]
    clean = [s for s in samples if not privacy_flags(s)]
    rejected = []
    if tokenizer:
        measured = [measure(s, tokenizer) for s in clean]
        rejected = [
            s for s in measured if not config["min_tokens"] <= s.token_count <= config["max_tokens"]
        ]
        clean = [
            s for s in measured if config["min_tokens"] <= s.token_count <= config["max_tokens"]
        ]
    # Preserve benchmark matches in held-out evaluation before assigning groups.
    if references is not None:
        from cyber_moe_datasets.validation import duplicate_pairs

        for a, b, _ in duplicate_pairs(clean + references, config["near_duplicate_threshold"]):
            if a < len(clean) <= b:
                clean[a] = Sample.model_validate({**clean[a].model_dump(), "split": "evaluation"})
    assigned = freeze_assignments(clean, config)
    conflict_rejections = []
    preserved = (
        set(json.loads(Path(config["frozen_sample_ids"]).read_text(encoding="utf-8")))
        if config.get("frozen_sample_ids")
        else set()
    )
    while True:
        try:
            split = partition(
                assigned, config["seed"], config["near_duplicate_threshold"], config["split_ratios"]
            )
            break
        except PartitionConflict as exc:
            if not preserved:
                raise
            rejected_ids = set(exc.sample_ids) - preserved
            if not rejected_ids:
                raise
            conflict_rejections.extend(s for s in assigned if s.sample_id in rejected_ids)
            assigned = [s for s in assigned if s.sample_id not in rejected_ids]
    for sample in split:
        if sample.split not in sources[sample.source_id].intended_use:
            raise ValueError("assigned partition is outside source intended use")
    report = leakage(split, config["near_duplicate_threshold"], references)
    if not report["passed"]:
        raise ValueError("cross-split leakage detected")
    calibration, shortfalls = select(split, config["targets"], config["seed"])
    tool_render_pending = [s for s in calibration if s.tools and tokenizer is None]
    if tool_render_pending:
        calibration = [s for s in calibration if not s.tools]
        for category in {s.category for s in tool_render_pending}:
            count = sum(s.category == category for s in tool_render_pending)
            shortfalls[category]["selected"] -= count
            shortfalls[category]["shortfall"] += count
            shortfalls[category]["pending_tokenizer_render"] = count
    exportable = [s for s in split if s.split != "calibration"] + calibration
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "canonical.jsonl", [s.model_dump() for s in split])
    # Review records remain local-only and may contain sensitive data.
    write_jsonl(output / "quarantine.jsonl", [s.model_dump() for s in quarantined])
    write_jsonl(output / "length_rejections.jsonl", [s.model_dump() for s in rejected])
    write_jsonl(
        output / "partition_rejections.jsonl", [s.model_dump() for s in conflict_rejections]
    )
    for kind in ("calibration", "train", "validation", "evaluation", "expert_training"):
        export(
            exportable,
            output / kind / "data.jsonl",
            kind,
            tokenizer=tokenizer,
            max_tokens=config["max_tokens"],
            allow_unmeasured=config["mode"] != "production",
        )
    for kind, filename in (("train", "train.jsonl"), ("validation", "valid.jsonl")):
        export(
            exportable,
            output / "finetuning" / filename,
            kind,
            tokenizer=tokenizer,
            max_tokens=config["max_tokens"],
            allow_unmeasured=config["mode"] != "production",
        )
    result = {
        **quality(split),
        "mode": config["mode"],
        "calibration_targets": shortfalls,
        "quarantined": len(quarantined),
        "quarantine_review": [
            {"sample_id": s.sample_id, "flags": privacy_flags(s)} for s in quarantined
        ],
        "length_rejected": len(rejected),
        "partition_conflict_rejected": len(conflict_rejections),
        "partition_conflict_sample_ids": sorted(s.sample_id for s in conflict_rejections),
        "tokenizer_verified": tokenizer is not None,
        "length_filter_verified": tokenizer is not None,
        "calibration_samples": len(calibration),
        "calibration_token_distribution": {
            category: sum(s.token_count or 0 for s in calibration if s.category == category)
            for category in sorted(config["targets"])
        },
        "leakage": report,
    }
    manifest = {
        "pipeline_version": "0.1.0",
        "uv_lock_sha256": hashlib.sha256(Path("uv.lock").read_bytes()).hexdigest(),
        "implementation_sha256": digest(
            {
                p.relative_to(Path(__file__).parent).as_posix(): text_hash(p)
                for p in sorted(Path(__file__).parent.rglob("*.py"))
            }
        ),
        "config": config,
        "config_sha256": digest(config),
        "inputs": inputs,
        "sources": [sources[i].model_dump() for i in sorted({s.source_id for s in samples})],
        "model": model.name if model else None,
        "model_files": (
            {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(model.glob("*"))
                if p.is_file() and (p.suffix in {".json", ".jinja"} or p.name == "tokenizer.model")
            }
            if model
            else {}
        ),
        "outputs": {
            p.relative_to(output).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.rglob("*"))
            if p.is_file() and (p.suffix == ".jsonl" or p.name.endswith(".metadata.json"))
        },
    }
    for name, document in (
        ("quality_report.json", result),
        ("leakage_report.json", report),
        ("source_manifest.json", manifest),
    ):
        write_json(output / name, document)
    license_path = Path("docs/licenses/MITRE_LICENSE.txt")
    if any(s.source_id == "mitre_attack" for s in samples) and license_path.exists():
        write_text(output / "MITRE_LICENSE.txt", license_path.read_text(encoding="utf-8"))
    return result


def freeze_assignments(samples: list[Sample], config: dict) -> list[Sample]:
    if not config.get("frozen_partitions"):
        return samples
    mapping = json.loads(Path(config["frozen_partitions"]).read_text(encoding="utf-8"))
    result = []
    for sample in samples:
        chosen = mapping.get(sample.scenario_id)
        if chosen:
            if sample.split not in {"unassigned", chosen}:
                raise ValueError("frozen partition conflict")
            sample = Sample.model_validate({**sample.model_dump(), "split": chosen})
        result.append(sample)
    return result
