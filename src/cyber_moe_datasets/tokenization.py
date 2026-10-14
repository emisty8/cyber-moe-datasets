"""Local tokenizer only; exact template, no hardcoded special tokens."""

import json
from pathlib import Path

from cyber_moe_datasets.models import Sample


def load_tokenizer(model: Path):
    if not model.is_dir():
        raise ValueError("local model directory not found")
    config = json.loads((model / "config.json").read_text(encoding="utf-8"))
    if config.get("model_type") != "qwen3_moe":
        raise ValueError("expected local Qwen3 MoE model configuration")
    try:
        from transformers import AutoTokenizer
    except ImportError as exc:
        raise RuntimeError("install the tokenizer extra; model weights are never loaded") from exc
    tokenizer = AutoTokenizer.from_pretrained(model, local_files_only=True, trust_remote_code=False)
    if not tokenizer.chat_template:
        raise ValueError("installed tokenizer has no chat template")
    return tokenizer


def render(sample: Sample, tokenizer, tokenize: bool = True):
    kwargs = {"tools": sample.tools} if sample.tools else {}
    return tokenizer.apply_chat_template(
        [m.model_dump(exclude_defaults=True) for m in sample.messages],
        tokenize=tokenize,
        add_generation_prompt=False,
        **kwargs,
    )


def measure(sample: Sample, tokenizer) -> Sample:
    return Sample.model_validate(
        {
            **sample.model_dump(),
            "token_count": len(render(sample, tokenizer)),
            "token_method": "local_qwen_chat_template",
        }
    )


def validate_tokenizer(samples: list[Sample], model: Path, max_tokens: int = 2048) -> dict:
    import hashlib

    from cyber_moe_datasets.models import digest

    tokenizer = load_tokenizer(model)
    records = []
    for sample in samples:
        sample = Sample.model_validate(sample.model_dump())
        rendered = render(sample, tokenizer, tokenize=False)
        tokens = render(sample, tokenizer)
        if tokens != render(sample, tokenizer) or tokenizer.encode(rendered) != tokens:
            raise ValueError(f"non-deterministic or changed token round-trip: {sample.sample_id}")
        for message in sample.messages:
            if message.content.strip() and message.content.strip() not in rendered:
                raise ValueError(f"chat template removes message content: {sample.sample_id}")
            for call in message.tool_calls:
                if call.function.name not in rendered:
                    raise ValueError("chat template removes tool call")
                # Validate JSON serialization against the actual rendered template.
                expected = {"name": call.function.name, "arguments": call.function.arguments}
                decoder = json.JSONDecoder()
                objects = []
                for offset, character in enumerate(rendered):
                    if character == "{":
                        try:
                            objects.append(decoder.raw_decode(rendered[offset:])[0])
                        except ValueError:
                            pass
                if not any(digest(expected) == digest(value) for value in objects):
                    raise ValueError(
                        f"tool arguments lost during serialization: {sample.sample_id}"
                    )
        records.append(
            {
                "sample_id": sample.sample_id,
                "token_count": len(tokens),
                "token_ids_sha256": digest(tokens),
                "over_limit": len(tokens) > max_tokens,
            }
        )
    files = {
        name: hashlib.sha256((model / name).read_bytes()).hexdigest()
        for name in (
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
            "chat_template.jinja",
        )
        if (model / name).exists()
    }
    return {
        "passed": True,
        "records_checked": len(records),
        "records": records,
        "over_limit": sum(r["over_limit"] for r in records),
        "max_tokens": max_tokens,
        "files": files,
        "chat_template_sha256": digest(tokenizer.chat_template),
        "model_weights_loaded": False,
        "mlx_executed": False,
        "mac_installed_tokenizer_match": "pending",
        "reference_source": (
            json.loads((model / "tokenizer_source.json").read_text(encoding="utf-8"))
            if (model / "tokenizer_source.json").exists()
            else None
        ),
    }


def validate_calibration(path: Path, model: Path, max_tokens: int = 2048) -> dict:
    from cyber_moe_datasets.models import CalibrationRecord

    tokenizer = load_tokenizer(model)
    counts = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            record = json.loads(line)
            CalibrationRecord.model_validate(record)
            if "messages" in record:
                tokens = tokenizer.apply_chat_template(
                    record["messages"], tokenize=True, add_generation_prompt=False
                )
            else:
                tokens = tokenizer.encode(record["content"])
            if not 0 < len(tokens) <= max_tokens:
                raise ValueError(
                    f"empty or over-length calibration line {number}; collector would truncate"
                )
            counts.append(len(tokens))
    if not counts:
        raise ValueError("empty calibration export")
    return {
        "passed": True,
        "records_checked": len(counts),
        "max_sample_tokens": max(counts),
        "token_counts": counts,
        "limit": max_tokens,
        "model_weights_loaded": False,
        "mlx_executed": False,
    }
