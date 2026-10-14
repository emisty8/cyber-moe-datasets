"""Separate exports with fail-closed production requirements."""

from __future__ import annotations

import json
from pathlib import Path

from cyber_moe_datasets.io import write_json, write_text
from cyber_moe_datasets.models import CalibrationRecord, EvaluationRecord, Sample
from cyber_moe_datasets.tokenization import render


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    write_text(
        temporary,
        "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows),
    )
    temporary.replace(path)


def export(
    samples: list[Sample],
    path: Path,
    kind: str,
    *,
    tokenizer=None,
    max_tokens: int = 2048,
    allow_unmeasured: bool = False,
) -> None:
    if kind not in {"calibration", "train", "validation", "evaluation", "expert_training"}:
        raise ValueError("unknown export kind")
    split = "train" if kind == "expert_training" else kind
    selected = [s for s in samples if s.split == split]
    rows = []
    for sample in selected:
        if sample.verification_status == "unverified" and kind != "evaluation":
            raise ValueError("unverified sample cannot enter calibration or supervised exports")
        if sample.token_count is None and not allow_unmeasured:
            raise ValueError("exact tokenizer measurement required; use preview mode explicitly")
        if sample.token_count is not None and sample.token_count > max_tokens:
            raise ValueError("over-length record: whole-record rejection only")
        if sample.provenance.synthetic and not allow_unmeasured:
            raise ValueError("synthetic samples require explicit preview export")
        messages = [m.model_dump(exclude_defaults=True) for m in sample.messages]
        if kind == "calibration":
            # Upstream loader drops top-level tools when rendering chat messages.
            if sample.tools:
                if tokenizer is None:
                    raise ValueError("tool calibration requires exact tokenizer pre-rendering")
                row = {"content": render(sample, tokenizer, tokenize=False)}
                encoded = tokenizer.encode(row["content"])
                if encoded != render(sample, tokenizer, tokenize=True):
                    raise ValueError("tool text round-trip changes tokens under collector encoding")
                if len(encoded) > max_tokens:
                    raise ValueError("pre-rendered tool record exceeds collector token limit")
            else:
                row = {"messages": messages}
            CalibrationRecord.model_validate(row)
        elif kind == "evaluation":
            # Reference answer is separate; do not leak it into the model prompt.
            row = {
                "sample_id": sample.sample_id,
                "messages": messages[:-1] if messages[-1]["role"] == "assistant" else messages,
                "expected_answer": sample.expected_answer,
                "evidence_references": sample.evidence_references,
                "tools": sample.tools,
            }
            EvaluationRecord.model_validate(row)
        else:
            if sample.expected_answer is None or sample.verification_status == "unverified":
                raise ValueError("supervised export requires a supported answer")
            if (
                messages[-1]["role"] != "assistant"
                or messages[-1].get("content") != sample.expected_answer
            ):
                raise ValueError("supervised answer must match the final assistant message")
            row = {"messages": messages}
            if sample.tools:
                row["tools"] = sample.tools
            if kind == "expert_training":
                row["metadata"] = {
                    "sample_id": sample.sample_id,
                    "domain": sample.security_domain,
                    "task_type": sample.task_type,
                    "expert_selection": "unvalidated",
                }
        rows.append(row)
    write_jsonl(path, rows)
    lineage = {
        "kind": kind,
        "preview": allow_unmeasured,
        "records": [
            {
                "row": index,
                "sample_id": sample.sample_id,
                "source_id": sample.source_id,
                "source_version": sample.source_version,
                "license": sample.license,
                "verification_status": sample.verification_status,
                "provenance": sample.provenance.model_dump(),
                "content_hash": sample.content_hash,
                "token_count": sample.token_count,
                "token_method": sample.token_method,
            }
            for index, sample in enumerate(selected)
        ],
    }
    write_json(path.with_suffix(".metadata.json"), lineage)
    if any(sample.source_id == "mitre_attack" for sample in selected):
        license_path = Path("docs/licenses/MITRE_LICENSE.txt")
        if not license_path.exists():
            raise ValueError("MITRE export requires the complete bundled license")
        write_text(path.parent / "MITRE_LICENSE.txt", license_path.read_text(encoding="utf-8"))
