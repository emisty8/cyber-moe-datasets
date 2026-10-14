import json
from pathlib import Path

import pytest
import yaml

from cyber_moe_datasets.exporters import export
from cyber_moe_datasets.ingestion import read_jsonl
from cyber_moe_datasets.models import Message, Provenance, Sample, digest
from cyber_moe_datasets.pipeline import build
from cyber_moe_datasets.sampling import select
from cyber_moe_datasets.sources import download, registry
from cyber_moe_datasets.splitting import partition
from cyber_moe_datasets.tokenization import load_tokenizer, measure
from cyber_moe_datasets.validation import duplicate_pairs, leakage, privacy_flags


def sample(index=0, **updates):
    prompts = [
        "Count failed authentication events on the server.",
        "Identify TLS certificate expiration dates from inventory.",
        "Summarize firewall egress rules for the staging network.",
        "Describe backup retention requirements for compliance.",
    ]
    base = dict(
        sample_id=f"fixture-{index}",
        source_id="fixture",
        source_version="1",
        scenario_id=f"scenario-{index}",
        task_type="fixture",
        security_domain="soc",
        category="soc",
        messages=[
            Message(role="user", content=prompts[index % 4]),
            Message(role="assistant", content="Fixture answer"),
        ],
        expected_answer="Fixture answer",
        evidence_references=["fixture://evidence"],
        license="CC0-1.0",
        verification_status="synthetic",
        provenance=Provenance(
            document_id=f"doc-{index}",
            source_url="fixture://local",
            raw_sha256=digest(index),
            transformation="test fixture",
            synthetic=True,
        ),
    )
    base.update(updates)
    return Sample(**base)


def test_registry():
    assert registry(Path("configs/sources.yaml"))["mitre_attack"].approved


def test_registry_duplicate(tmp_path):
    doc = yaml.safe_load(Path("configs/sources.yaml").read_text())
    doc["sources"].append(doc["sources"][0])
    p = tmp_path / "sources.yaml"
    p.write_text(yaml.safe_dump(doc))
    with pytest.raises(ValueError, match="duplicate"):
        registry(p)


def test_download_approval(tmp_path):
    with pytest.raises(ValueError, match="approval"):
        download(registry(Path("configs/sources.yaml"))["botsv3"], tmp_path / "data")


def test_hash_tampering():
    row = sample().model_dump()
    row["messages"][0]["content"] = "Tampered evidence"
    with pytest.raises(ValueError, match="hash"):
        Sample.model_validate(row)


def test_schema_extra_field():
    with pytest.raises(ValueError):
        sample(unknown=True)


def test_synthetic_label():
    with pytest.raises(ValueError, match="synthetic"):
        sample(verification_status="human_verified")


def test_gold_requires_evidence():
    row = sample().model_dump()
    row["provenance"]["synthetic"] = False
    row["verification_status"] = "source_grounded"
    row["evidence_references"] = []
    with pytest.raises(ValueError, match="evidence"):
        Sample.model_validate(row)


def test_malformed_json(tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text('{"messages":')
    with pytest.raises(ValueError, match="line 1"):
        read_jsonl(p)


def test_exact_answer_independent():
    a = sample()
    b = sample(
        1,
        messages=[
            Message(role="user", content=a.messages[0].content),
            Message(role="assistant", content="Other answer"),
        ],
    )
    assert duplicate_pairs([a, b])[0][2] == "exact"


def test_near_duplicate():
    a = sample(messages=[Message(role="user", content=" ".join(f"word{i}" for i in range(100)))])
    b = sample(1, messages=[Message(role="user", content=a.messages[0].content + " extra")])
    assert duplicate_pairs([a, b])[0][2] == "near"


def test_scenario_grouping():
    rows = [sample(0), sample(1, scenario_id="scenario-0"), sample(2)]
    split = partition(rows)
    assert split[0].split == split[1].split
    assert leakage(split)["passed"]


def test_document_grouping():
    a, b = sample(0), sample(1)
    b.provenance.document_id = a.provenance.document_id
    split = partition([a, b])
    assert split[0].split == split[1].split


def test_transitive_grouping():
    a, b, c = sample(0), sample(1, scenario_id="scenario-0"), sample(2)
    c.provenance.document_id = b.provenance.document_id
    assert len({s.split for s in partition([a, b, c])}) == 1


def test_order_independent_split():
    rows = [sample(i) for i in range(4)]
    assert [s.model_dump() for s in partition(rows)] == [
        s.model_dump() for s in partition(rows[::-1])
    ]


def test_fixed_split_conflict():
    with pytest.raises(ValueError, match="incompatible"):
        partition(
            [sample(0, split="train"), sample(1, scenario_id="scenario-0", split="evaluation")]
        )


def test_leakage_detected():
    result = leakage(
        [sample(0, split="train"), sample(1, split="evaluation", scenario_id="scenario-0")]
    )
    assert not result["passed"]


def test_benchmark_locked():
    assert partition([sample(benchmark=True)])[0].split == "evaluation"
    with pytest.raises(ValueError, match="benchmark"):
        sample(benchmark=True, split="train")


def test_benchmark_reference_contamination():
    assert not leakage([sample(split="train")], references=[sample(benchmark=True)])["passed"]


def test_sampling_no_filler():
    rows = [sample(0, split="calibration"), sample(1, split="calibration")]
    a, report = select(rows, {"soc": 192}, 42)
    b, _ = select(rows[::-1], {"soc": 192}, 42)
    assert [s.sample_id for s in a] == [s.sample_id for s in b]
    assert report["soc"]["shortfall"] == 190


@pytest.mark.parametrize(
    "content,flag",
    [
        ("password=supersecret123", "credential"),
        ("person@example.com", "email"),
        ("AKIA" + "A" * 16, "aws_key"),
    ],
)
def test_privacy(content, flag):
    assert flag in privacy_flags(sample(messages=[Message(role="user", content=content)]))


def test_tokenizer_missing_path(tmp_path):
    with pytest.raises(ValueError, match="directory"):
        load_tokenizer(tmp_path / "absent")


def test_token_measurement_template_contract():
    class Tokenizer:
        def apply_chat_template(self, messages, **kwargs):
            assert kwargs == {"tokenize": True, "add_generation_prompt": False}
            return [10, 20, 30]

    assert measure(sample(), Tokenizer()).token_count == 3


def test_exports_and_provenance(tmp_path):
    a = sample(split="calibration", token_count=12, token_method="test")
    export([a], tmp_path / "cal.jsonl", "calibration", allow_unmeasured=True)
    assert set(json.loads((tmp_path / "cal.jsonl").read_text())) == {"messages"}
    assert a.provenance.raw_sha256 == digest(0)
    lineage = json.loads((tmp_path / "cal.metadata.json").read_text())
    assert lineage["records"][0]["provenance"]["raw_sha256"] == a.provenance.raw_sha256
    assert lineage["records"][0]["license"] == a.license


def test_export_refuses_unknown_length(tmp_path):
    with pytest.raises(ValueError, match="measurement"):
        export([sample(split="calibration")], tmp_path / "cal.jsonl", "calibration")


def test_overlength_never_truncated(tmp_path):
    with pytest.raises(ValueError, match="whole-record"):
        export(
            [sample(split="calibration", token_count=3000)], tmp_path / "cal.jsonl", "calibration"
        )


def test_evaluation_answer_removed(tmp_path):
    export(
        [sample(split="evaluation", token_count=20)],
        tmp_path / "eval.jsonl",
        "evaluation",
        allow_unmeasured=True,
    )
    row = json.loads((tmp_path / "eval.jsonl").read_text())
    assert row["messages"][-1]["role"] == "user"
    assert row["expected_answer"] == "Fixture answer"


def test_orphan_tool_result():
    with pytest.raises(ValueError, match="orphan"):
        sample(messages=[Message(role="tool", content="result", tool_call_id="missing")])


def test_fixture_end_to_end(tmp_path):
    result = build(Path("configs/fixtures.yaml"), tmp_path / "first")
    build(Path("configs/fixtures.yaml"), tmp_path / "second")
    assert result["leakage"]["passed"]
    for p in (tmp_path / "first").rglob("*.jsonl"):
        assert (
            p.read_bytes() == (tmp_path / "second" / p.relative_to(tmp_path / "first")).read_bytes()
        )


def test_production_requires_tokenizer(tmp_path):
    config = yaml.safe_load(Path("configs/calibration.yaml").read_text())
    config["mode"] = "production"
    p = tmp_path / "production.yaml"
    p.write_text(yaml.safe_dump(config))
    with pytest.raises(ValueError, match="tokenizer"):
        build(p, tmp_path / "output")


def test_public_json_schema():
    from jsonschema import validate

    validate(
        sample().model_dump(), json.loads(Path("schemas/canonical_sample.schema.json").read_text())
    )


@pytest.mark.integration
def test_local_qwen_tokenizer():
    import os

    path = os.environ.get("QWEN_MODEL_PATH")
    if not path:
        pytest.skip("set QWEN_MODEL_PATH and install tokenizer extra")
    assert measure(sample(), load_tokenizer(Path(path))).token_count > 0
