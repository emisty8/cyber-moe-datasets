"""Small explicit CLI; errors never log the contents of sensitive records."""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
from pathlib import Path

from cyber_moe_datasets.exporters import export
from cyber_moe_datasets.ingestion import read_jsonl
from cyber_moe_datasets.pipeline import build
from cyber_moe_datasets.sources import download, registry
from cyber_moe_datasets.validation import leakage, quality


def main() -> None:
    parser = argparse.ArgumentParser(prog="cyber-data")
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--registry", type=Path, default=Path("configs/sources.yaml"))
    fetch = commands.add_parser("download")
    fetch.add_argument("source_id")
    fetch.add_argument("destination", type=Path)
    fetch.add_argument("--registry", type=Path, default=Path("configs/sources.yaml"))
    builder = commands.add_parser("build")
    builder.add_argument("--config", type=Path, default=Path("configs/calibration.yaml"))
    builder.add_argument("--output", type=Path, default=Path("outputs/pilot"))
    builder.add_argument("--model", type=Path)
    for command in ("validate", "report"):
        validator = commands.add_parser(command)
        validator.add_argument("path", type=Path)
        validator.add_argument("--benchmark-references", type=Path)
    exporter = commands.add_parser("export")
    exporter.add_argument("path", type=Path)
    exporter.add_argument("output", type=Path)
    exporter.add_argument(
        "--kind",
        required=True,
        choices=["calibration", "train", "validation", "evaluation", "expert_training"],
    )
    exporter.add_argument("--preview", action="store_true")
    exporter.add_argument("--model", type=Path)
    compat = commands.add_parser("check-mlx")
    compat.add_argument("loader", type=Path, help="installed or pinned upstream mlx_fun/data.py")
    compat.add_argument("dataset", type=Path)
    acquire = commands.add_parser("acquire-tokenizer")
    acquire.add_argument("--output", type=Path, default=Path("data/tokenizers/qwen3-30b-a3b"))
    tokens = commands.add_parser("validate-tokenizer")
    tokens.add_argument("dataset", type=Path)
    tokens.add_argument(
        "--model", type=Path, required=True, help="tokenizer/config directory; no weights needed"
    )
    tokens.add_argument("--output", type=Path)
    tokens.add_argument("--reference", type=Path)
    tokens.add_argument("--max-tokens", type=int, default=2048)
    calibration = commands.add_parser("validate-calibration")
    calibration.add_argument("dataset", type=Path)
    calibration.add_argument("--model", type=Path, required=True)
    calibration.add_argument("--max-tokens", type=int, default=2048)
    release = commands.add_parser("release")
    release.add_argument("build", type=Path)
    release.add_argument("destination", type=Path)
    release.add_argument("--registry", type=Path, default=Path("configs/sources.yaml"))
    verify = commands.add_parser("verify-release")
    verify.add_argument("path", type=Path)
    commands.add_parser("audit-publication")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO, format='{"level":"%(levelname)s","event":"%(message)s"}'
    )
    try:
        if args.command == "inspect":
            sources = registry(args.registry)
            result = {
                "sources": [s.model_dump() for s in sources.values()],
                "warnings": [
                    {"source_id": s.source_id, "reason": "not approved or unpinned"}
                    for s in sources.values()
                    if not s.approved or s.revision == "unreviewed"
                ],
                "dependencies": {
                    x: importlib.util.find_spec(x) is not None
                    for x in ("mlx", "mlx_fun", "transformers")
                },
            }
        elif args.command == "download":
            result = {
                "path": str(download(registry(args.registry)[args.source_id], args.destination))
            }
        elif args.command == "build":
            result = build(args.config, args.output, args.model)
        elif args.command == "acquire-tokenizer":
            from cyber_moe_datasets.tokenizer_source import acquire

            result = acquire(args.output)
        elif args.command == "validate-tokenizer":
            from cyber_moe_datasets.io import write_json
            from cyber_moe_datasets.tokenization import validate_tokenizer

            result = validate_tokenizer(read_jsonl(args.dataset), args.model, args.max_tokens)
            if args.reference:
                reference = json.loads(args.reference.read_text(encoding="utf-8"))
                if (
                    result["records"] != reference["records"]
                    or result["chat_template_sha256"] != reference["chat_template_sha256"]
                ):
                    raise ValueError(
                        "installed tokenizer differs from validated release tokenization"
                    )
                result["mac_installed_tokenizer_match"] = (
                    "matched supplied reference; execution platform not inferred"
                )
            if args.output:
                write_json(args.output, result)
        elif args.command == "validate-calibration":
            from cyber_moe_datasets.tokenization import validate_calibration

            result = validate_calibration(args.dataset, args.model, args.max_tokens)
        elif args.command == "release":
            from cyber_moe_datasets.releases import package_release

            result = package_release(args.build, args.destination, args.registry)
        elif args.command == "verify-release":
            from cyber_moe_datasets.releases import verify_release

            result = verify_release(args.path)
        elif args.command == "audit-publication":
            from cyber_moe_datasets.publication import audit

            result = audit()
        elif args.command in {"validate", "report", "export"}:
            samples = read_jsonl(args.path)
            refs = (
                read_jsonl(args.benchmark_references)
                if getattr(args, "benchmark_references", None)
                else None
            )
            checked = leakage(samples, references=refs)
            if not checked["passed"]:
                raise ValueError("dataset leakage detected")
            result = {**quality(samples), "leakage": checked}
            if args.command == "export":
                from cyber_moe_datasets.tokenization import load_tokenizer, measure

                tokenizer = load_tokenizer(args.model) if args.model else None
                if tokenizer:
                    samples = [measure(s, tokenizer) for s in samples]
                export(
                    samples,
                    args.output,
                    args.kind,
                    allow_unmeasured=args.preview,
                    tokenizer=tokenizer,
                )
                result = {"output": str(args.output)}
        else:
            from cyber_moe_datasets.compatibility import check_loader

            result = check_loader(args.loader, args.dataset)
        print(json.dumps(result, indent=2, sort_keys=True))
    except (ValueError, RuntimeError, OSError, KeyError, TypeError) as exc:
        logging.error("operation_failed:%s", type(exc).__name__)
        parser.exit(2, f"{exc}\n")


if __name__ == "__main__":
    main()
