"""Source approval and immutable downloads."""

from __future__ import annotations

import hashlib
import re
import urllib.request
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field

from cyber_moe_datasets.models import StrictModel


class Source(StrictModel):
    source_id: str
    official_url: str
    dataset_name: str
    publisher: str
    revision: str
    license: str
    restrictions: str
    format: str
    download_method: str
    intended_use: list[str]
    category: str
    trust_level: Literal["official", "candidate", "fixture"]
    approved: bool = False
    citation: str
    limitations: list[str]
    download_url: str | None = None
    sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


def registry(path: Path) -> dict[str, Source]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    sources = [Source.model_validate(row) for row in doc["sources"]]
    result = {s.source_id: s for s in sources}
    if len(result) != len(sources):
        raise ValueError("duplicate source identifiers")
    for source in sources:
        for name in (
            "source_id",
            "official_url",
            "dataset_name",
            "publisher",
            "revision",
            "license",
            "restrictions",
            "format",
            "download_method",
            "category",
            "citation",
        ):
            if not getattr(source, name).strip():
                raise ValueError(f"source metadata field is empty: {name}")
        if not set(source.intended_use).issubset(
            {"calibration", "train", "validation", "evaluation"}
        ):
            raise ValueError("unsupported intended use")
        if not source.official_url.startswith(("https://", "fixture://")):
            raise ValueError("invalid official URL")
        if source.approved and (source.license == "unknown" or source.revision == "unreviewed"):
            raise ValueError("approved sources require a reviewed license and revision")
        if source.source_id == "cyberseceval" and source.intended_use != ["evaluation"]:
            raise ValueError("CyberSecEval must be evaluation-only")
    return result


def download(source: Source, destination: Path) -> Path:
    if not source.approved or not source.download_url or not source.sha256:
        raise ValueError("download requires approval, pinned URL and SHA256")
    if not source.download_url.startswith("https://") or not re.search(
        r"/[a-f0-9]{40}/", source.download_url
    ):
        raise ValueError("download URL must contain an immutable commit")
    if destination.exists():
        if hashlib.sha256(destination.read_bytes()).hexdigest() != source.sha256:
            raise ValueError("existing source checksum mismatch; refusing overwrite")
        return destination
    with urllib.request.urlopen(source.download_url, timeout=60) as response:
        payload = response.read(64 * 1024 * 1024 + 1)
    if len(payload) > 64 * 1024 * 1024:
        raise ValueError("source exceeds 64 MiB download limit")
    if hashlib.sha256(payload).hexdigest() != source.sha256:
        raise ValueError("download checksum mismatch")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    return destination
