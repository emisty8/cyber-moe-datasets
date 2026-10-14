"""Audit Git-visible files without staging, committing, contacting a remote or pushing."""

import hashlib
import json
import re
import subprocess
from pathlib import Path


def audit(root: Path = Path(".")) -> dict:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    files = sorted(set(name for name in result.stdout.decode("utf-8").split("\0") if name))
    blocked = []
    for name in files:
        path = root / name
        if not path.is_file() or path.is_symlink():
            blocked.append({"file": name, "reason": "missing staged file or unsupported path"})
            continue
        forbidden_prefixes = (
            "outputs/",
            "data/raw/",
            "data/research/",
            "data/local/",
            "data/tokenizers/",
            "models/",
            "saliency/",
        )
        forbidden_suffixes = {
            ".safetensors",
            ".gguf",
            ".npz",
            ".bin",
            ".pt",
            ".pth",
            ".pkl",
            ".pickle",
            ".key",
            ".pem",
            ".tgz",
            ".zip",
        }
        if (
            name.startswith(forbidden_prefixes)
            or path.suffix in forbidden_suffixes
            or path.name.startswith(".env")
        ):
            blocked.append({"file": name, "reason": "local-only, restricted or binary artifact"})
        elif path.stat().st_size > 5 * 1024 * 1024:
            blocked.append({"file": name, "reason": "exceeds 5 MiB publication limit"})
        elif re.search(
            rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bghp_[A-Za-z0-9]{20,}\b|\bsk-[A-Za-z0-9]{20,}\b",
            path.read_bytes(),
        ):
            blocked.append(
                {"file": name, "reason": "possible credential or private key; inspect locally"}
            )
        if path.suffix == ".jsonl":
            if not name.startswith(("data/fixtures/", "data/releases/")):
                blocked.append(
                    {"file": name, "reason": "dataset JSONL outside approved publication locations"}
                )
                continue
            try:
                rows = [
                    json.loads(line)
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line
                ]
                if name.startswith("data/fixtures/"):
                    if all(
                        row.get("provenance", {}).get("synthetic") is True
                        and row.get("verification_status") == "synthetic"
                        for row in rows
                    ):
                        pass
                    else:
                        metadata = path.parent / "export_manifest.json"
                        manifest = json.loads(metadata.read_text(encoding="utf-8"))
                        if (
                            not manifest.get("synthetic")
                            or manifest.get("payload_sha256")
                            != hashlib.sha256(path.read_bytes()).hexdigest()
                        ):
                            raise ValueError(
                                "non-synthetic raw export cannot be published as a fixture"
                            )
                if any(
                    row.get("events") and not row.get("provenance", {}).get("synthetic")
                    for row in rows
                ):
                    raise ValueError("real SOC evidence publication is not authorized by Task B")
            except (ValueError, KeyError, OSError, TypeError):
                blocked.append({"file": name, "reason": "unreviewed or real raw dataset artifact"})
    release_parent = root / "data/releases"
    if release_parent.exists():
        from cyber_moe_datasets.releases import verify_release

        for release in sorted(release_parent.iterdir()):
            if release.is_dir():
                verify_release(release)
    if blocked:
        raise ValueError(f"Git publication audit rejected files: {blocked}")
    return {
        "passed": True,
        "git_visible_files": len(files),
        "total_bytes": sum((root / name).stat().st_size for name in files),
        "secrets_scan": "strong credential patterns checked in Git-visible files; release samples privacy checked separately",
        "remote_contacted": False,
    }
