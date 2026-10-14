"""Portable UTF-8/LF artifact IO."""

import json
from pathlib import Path


def write_text(path: Path, content: str) -> None:
    frozen = (Path.cwd() / "data/releases/mitre-pilot-v0.2").resolve()
    if path.resolve().is_relative_to(frozen):
        raise ValueError("the frozen MITRE v0.2 release cannot be overwritten")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content.replace("\r\n", "\n"))


def write_json(path: Path, content: dict) -> None:
    write_text(
        path,
        json.dumps(content, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )


def text_hash(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
