"""Acquire only pinned public tokenizer/config files; never model weights."""

import hashlib
import json
import urllib.request
from pathlib import Path

from cyber_moe_datasets.io import write_json

REPOSITORY = "Qwen/Qwen3-30B-A3B"
REVISION = "ad44e777bcd18fa416d9da3bd8f70d33ebb85d39"
FILES = (
    "config.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "merges.txt",
    "vocab.json",
    "LICENSE",
)


def acquire(destination: Path) -> dict:
    manifest_path = destination / "tokenizer_source.json"
    previous = (
        json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else None
    )
    hashes = {}
    for name in FILES:
        path = destination / name
        if path.exists():
            if not previous or previous.get("revision") != REVISION:
                raise ValueError("existing tokenizer files have no matching acquisition manifest")
            payload = path.read_bytes()
            if hashlib.sha256(payload).hexdigest() != previous["files"][name]:
                raise ValueError("existing tokenizer checksum mismatch; refusing overwrite")
        else:
            url = f"https://huggingface.co/{REPOSITORY}/resolve/{REVISION}/{name}"
            with urllib.request.urlopen(url, timeout=60) as response:
                payload = response.read(32 * 1024 * 1024 + 1)
            if len(payload) > 32 * 1024 * 1024:
                raise ValueError("tokenizer file exceeds size limit")
            destination.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        hashes[name] = hashlib.sha256(payload).hexdigest()
        write_json(manifest_path, {"repository": REPOSITORY, "revision": REVISION, "files": hashes})
    result = {
        "repository": REPOSITORY,
        "revision": REVISION,
        "files": hashes,
        "purpose": "tokenizer-only reference validation; Mac installation match pending",
    }
    write_json(manifest_path, result)
    return result
