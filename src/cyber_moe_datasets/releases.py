"""Approved, small portable dataset releases with traceability and checksums."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from cyber_moe_datasets.exporters import write_jsonl
from cyber_moe_datasets.ingestion import read_jsonl
from cyber_moe_datasets.io import write_json, write_text
from cyber_moe_datasets.models import CalibrationRecord, EvaluationRecord
from cyber_moe_datasets.sources import registry
from cyber_moe_datasets.validation import leakage, privacy_flags

EXPORTS = {
    "calibration/data.jsonl": "calibration",
    "finetuning/train.jsonl": "train",
    "finetuning/valid.jsonl": "validation",
    "expert_training/data.jsonl": "train",
    "evaluation/data.jsonl": "evaluation",
}


def relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value or ":" in value or not value:
        raise ValueError("release paths must be relative POSIX paths")
    return path


def _rows(path: Path) -> list[dict]:
    payload = path.read_bytes()
    if b"\r" in payload or payload.startswith(b"\xef\xbb\xbf"):
        raise ValueError("release requires UTF-8 without BOM and LF line endings")
    if payload and not payload.endswith(b"\n"):
        raise ValueError("JSONL must end in LF")
    return [json.loads(line) for line in payload.decode("utf-8").splitlines()]


def traceability(root: Path) -> dict:
    samples = read_jsonl(root / "canonical.jsonl")
    index = {sample.sample_id: sample for sample in samples}
    if len(index) != len(samples) or not leakage(samples)["passed"]:
        raise ValueError("duplicate IDs or split leakage in release")
    if any(privacy_flags(sample) or sample.provenance.synthetic for sample in samples):
        raise ValueError("release contains privacy flags or synthetic records")
    manifest = json.loads((root / "source_manifest.json").read_text(encoding="utf-8"))
    sources = {source["source_id"]: source for source in manifest["sources"]}
    inputs = {(row["source_id"], row["sha256"]) for row in manifest["inputs"]}
    for row in manifest["inputs"]:
        relative_path(row["path"])
    for field in ("registry", "benchmark_references", "frozen_partitions", "frozen_sample_ids"):
        if manifest["config"].get(field):
            relative_path(manifest["config"][field])
    for row in manifest["config"]["inputs"]:
        relative_path(row["path"])
    for sample in samples:
        source = sources[sample.source_id]
        if (
            not source["approved"]
            or source["revision"] != sample.source_version
            or source["license"] != sample.license
        ):
            raise ValueError("unapproved or inconsistent release provenance")
        if (sample.source_id, sample.provenance.raw_sha256) not in inputs:
            raise ValueError("sample cannot be traced to an input checksum")
        if source.get("sha256") != sample.provenance.raw_sha256:
            raise ValueError("release source checksum mismatch")
        if sample.token_count is None or sample.verification_status not in {
            "source_grounded",
            "human_verified",
        }:
            raise ValueError("release requires measured, grounded samples")
    counts = {}
    exports = {**EXPORTS}
    if (root / "calibration/smoke.jsonl").exists():
        exports["calibration/smoke.jsonl"] = "calibration"
    calibration_ids = set()
    for filename, split in exports.items():
        path = root / filename
        rows = _rows(path)
        metadata = json.loads(path.with_suffix(".metadata.json").read_text(encoding="utf-8"))
        if len(rows) != len(metadata["records"]):
            raise ValueError("row/lineage count mismatch")
        ids = []
        for number, (row, lineage) in enumerate(zip(rows, metadata["records"])):
            sample = index[lineage["sample_id"]]
            ids.append(sample.sample_id)
            if sample.split != split or lineage["row"] != number:
                raise ValueError("export partition or row index mismatch")
            for field in (
                "source_id",
                "source_version",
                "license",
                "verification_status",
                "content_hash",
                "token_count",
                "token_method",
            ):
                if lineage[field] != getattr(sample, field):
                    raise ValueError("export metadata changed canonical provenance")
            if lineage["provenance"] != sample.provenance.model_dump():
                raise ValueError("export provenance mismatch")
            messages = [m.model_dump(exclude_defaults=True) for m in sample.messages]
            if split == "calibration":
                CalibrationRecord.model_validate(row)
                if sample.tools:
                    if set(row) != {"content"}:
                        raise ValueError("tool calibration must be pre-rendered")
                elif row != {"messages": messages}:
                    raise ValueError("calibration content differs from canonical source")
            elif split == "evaluation":
                EvaluationRecord.model_validate(row)
                expected = {
                    "sample_id": sample.sample_id,
                    "messages": messages[:-1],
                    "expected_answer": sample.expected_answer,
                    "evidence_references": sample.evidence_references,
                    "tools": sample.tools,
                }
                if row != expected:
                    raise ValueError("evaluation prompt/answer trace mismatch")
            else:
                if row["messages"] != messages or row.get("tools", []) != sample.tools:
                    raise ValueError("training content differs from canonical source")
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate exported sample")
        if filename == "calibration/data.jsonl":
            calibration_ids = set(ids)
        if filename == "calibration/smoke.jsonl" and (
            len(ids) != 4 or not set(ids) <= calibration_ids
        ):
            raise ValueError("smoke test must contain four calibration samples")
        if split != "calibration" and set(ids) != {
            s.sample_id for s in samples if s.split == split
        }:
            raise ValueError("export omits assigned records")
        counts[filename] = len(rows)
    return {
        "passed": True,
        "canonical_samples": len(samples),
        "exports": counts,
        "leakage": leakage(samples),
    }


def package_release(build: Path, destination: Path, source_registry: Path) -> dict:
    from tempfile import TemporaryDirectory

    if destination.exists():
        raise ValueError("release destination exists; use a new immutable release directory")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".release-stage-", dir=destination.parent) as stage:
        candidate = Path(stage) / destination.name
        result = _package_release(build, candidate, source_registry)
        candidate.rename(destination)
    return result


def _package_release(build: Path, destination: Path, source_registry: Path) -> dict:
    if destination.exists():
        raise ValueError("release destination exists; use a new immutable release directory")
    sources = registry(source_registry)
    canonical = read_jsonl(build / "canonical.jsonl")
    if not canonical or any(not sources[s.source_id].approved for s in canonical):
        raise ValueError("empty or unapproved release")
    for sample in canonical:
        source = sources[sample.source_id]
        if (
            source.revision != sample.source_version
            or source.license != sample.license
            or source.sha256 != sample.provenance.raw_sha256
        ):
            raise ValueError("release disagrees with reviewed source registry")
    tokenizer_report = build / "tokenizer_validation.json"
    if not tokenizer_report.exists():
        raise ValueError("release requires exact tokenizer validation report")
    token_validation = json.loads(tokenizer_report.read_text(encoding="utf-8"))
    if not token_validation["passed"] or token_validation["over_limit"]:
        raise ValueError("release tokenizer/sequence length validation failed")
    if {r["sample_id"]: r["token_count"] for r in token_validation["records"]} != {
        s.sample_id: s.token_count for s in canonical
    }:
        raise ValueError("tokenizer report does not match canonical records")
    traceability(build)
    files = [
        "canonical.jsonl",
        "source_manifest.json",
        "quality_report.json",
        "leakage_report.json",
        "MITRE_LICENSE.txt",
    ]
    for name in EXPORTS:
        files.extend([name, str(PurePosixPath(name).with_suffix(".metadata.json"))])
    for name in files:
        relative_path(name)
        write_text(destination / name, (build / name).read_text(encoding="utf-8"))
    data_path = destination / "calibration/data.jsonl"
    rows = _rows(data_path)
    if len(rows) < 4:
        raise ValueError("release requires at least four calibration records")
    write_jsonl(destination / "calibration/smoke.jsonl", rows[:4])
    metadata = json.loads(data_path.with_suffix(".metadata.json").read_text(encoding="utf-8"))
    metadata["records"] = metadata["records"][:4]
    write_json(destination / "calibration/smoke.metadata.json", metadata)
    validation = traceability(destination)
    write_json(
        destination / "tokenizer_validation.json",
        json.loads(tokenizer_report.read_text(encoding="utf-8")),
    )
    # Original build checksums include excluded review artifacts; publication gets its own inventory.
    source_manifest_path = destination / "source_manifest.json"
    source_manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
    source_manifest["outputs"] = {
        p.relative_to(destination).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(destination.rglob("*"))
        if p.is_file() and p.suffix == ".jsonl"
    }
    write_json(source_manifest_path, source_manifest)
    entries = {
        p.relative_to(destination).as_posix(): {
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            "bytes": p.stat().st_size,
        }
        for p in sorted(destination.rglob("*"))
        if p.is_file()
    }
    if sum(entry["bytes"] for entry in entries.values()) > 10 * 1024 * 1024:
        raise ValueError("approved pilot release exceeds 10 MiB publication budget")
    manifest = {
        "release": destination.name,
        "readiness": "windows_tokenizer_validated; mac_pending",
        "validation": validation,
        "files": entries,
        "excluded": [
            "raw sources",
            "quarantine",
            "length rejections",
            "model weights",
            "tokenizer payloads",
            "saliency",
        ],
    }
    write_json(destination / "release_manifest.json", manifest)
    sums = "".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(destination).as_posix()}\n"
        for p in sorted(destination.rglob("*"))
        if p.is_file()
    )
    write_text(destination / "SHA256SUMS", sums)
    return verify_release(destination)


def verify_release(root: Path) -> dict:
    manifest = json.loads((root / "release_manifest.json").read_text(encoding="utf-8"))
    expected = {}
    for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        checksum, name = line.split("  ", 1)
        relative_path(name)
        if name in expected or len(checksum) != 64:
            raise ValueError("invalid checksum inventory")
        expected[name] = checksum
    actual_files = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    if actual_files != set(expected) | {"SHA256SUMS"}:
        raise ValueError("unlisted or missing release file")
    if set(expected) != set(manifest["files"]) | {"release_manifest.json"}:
        raise ValueError("manifest/checksum file inventory mismatch")
    for name, checksum in expected.items():
        path = root / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
            raise ValueError(f"release checksum mismatch: {name}")
        if name != "release_manifest.json" and manifest["files"][name]["sha256"] != checksum:
            raise ValueError("manifest checksum mismatch")
        if b"\r" in path.read_bytes():
            raise ValueError("release contains non-LF line endings")
        path.read_bytes().decode("utf-8")
    return {
        "checksums": "passed",
        "files_checked": len(expected),
        "traceability": traceability(root),
        "mac_validation": "pending",
    }
