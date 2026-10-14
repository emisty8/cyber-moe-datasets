import json
import shutil
from pathlib import Path

import pytest

from cyber_moe_datasets.exporters import write_jsonl
from cyber_moe_datasets.io import text_hash
from cyber_moe_datasets.pipeline import freeze_assignments
from cyber_moe_datasets.releases import package_release, relative_path, traceability, verify_release
from cyber_moe_datasets.tokenization import validate_calibration, validate_tokenizer

RELEASE = Path("data/releases/mitre-pilot-v0.2")


def test_utf8_lf_jsonl(tmp_path):
    p = tmp_path / "data.jsonl"
    write_jsonl(p, [{"text": "évidence"}])
    assert b"\r" not in p.read_bytes()
    assert p.read_bytes().endswith(b"\n")
    assert json.loads(p.read_bytes().decode("utf-8"))["text"] == "évidence"


def test_implementation_hash_platform_independent(tmp_path):
    a, b = tmp_path / "windows.py", tmp_path / "unix.py"
    a.write_bytes(b"hello\r\nworld\r\n")
    b.write_bytes(b"hello\nworld\n")
    assert text_hash(a) == text_hash(b)


@pytest.mark.parametrize(
    "value", ["D:\\data\\sample.jsonl", "../secret", "/tmp/file", "a\\b", "C:/data"]
)
def test_release_rejects_platform_paths(value):
    with pytest.raises(ValueError, match="relative"):
        relative_path(value)


def test_relative_posix_path():
    assert str(relative_path("calibration/data.jsonl")) == "calibration/data.jsonl"


def test_release_checksums_and_traceability():
    result = verify_release(RELEASE)
    assert result["checksums"] == "passed"
    assert result["traceability"]["canonical_samples"] > 78
    assert result["traceability"]["exports"]["calibration/smoke.jsonl"] == 4
    assert result["mac_validation"] == "pending"


def test_release_checksum_tamper(tmp_path):
    clone = tmp_path / "release"
    shutil.copytree(RELEASE, clone)
    p = clone / "calibration/data.jsonl"
    p.write_bytes(p.read_bytes() + b"{}\n")
    with pytest.raises(ValueError, match="checksum"):
        verify_release(clone)


def test_unlisted_publication_file(tmp_path):
    clone = tmp_path / "release"
    shutil.copytree(RELEASE, clone)
    (clone / "customer.log").write_text("private")
    with pytest.raises(ValueError, match="unlisted"):
        verify_release(clone)


def test_release_has_no_review_records_or_weights():
    names = {p.name for p in RELEASE.rglob("*") if p.is_file()}
    assert not names & {
        "quarantine.jsonl",
        "length_rejections.jsonl",
        "partition_rejections.jsonl",
        "tokenizer.json",
    }
    assert not any(p.suffix in {".safetensors", ".gguf", ".npz"} for p in RELEASE.rglob("*"))


def test_export_content_tamper_traceability(tmp_path):
    clone = tmp_path / "release"
    shutil.copytree(RELEASE, clone)
    p = clone / "finetuning/train.jsonl"
    rows = [json.loads(line) for line in p.read_text().splitlines()]
    rows[0]["messages"][0]["content"] = "changed evidence"
    write_jsonl(p, rows)
    with pytest.raises(ValueError, match="differs"):
        traceability(clone)


def test_failed_release_does_not_leave_partial_directory(tmp_path):
    build = tmp_path / "invalid-build"
    build.mkdir()
    write_jsonl(build / "canonical.jsonl", [])
    destination = tmp_path / "release"
    with pytest.raises(ValueError):
        package_release(build, destination, Path("configs/sources.yaml"))
    assert not destination.exists()


def test_frozen_scenarios_preserve_baseline():
    from cyber_moe_datasets.ingestion import read_jsonl

    rows = read_jsonl(RELEASE / "canonical.jsonl")
    mapping = json.loads(Path("data/manifests/frozen_pilot_partitions.json").read_text())
    assert all(s.split == mapping[s.scenario_id] for s in rows if s.scenario_id in mapping)
    assert freeze_assignments(rows, {}) == rows


def test_reporting_answer_is_source_grounded():
    from cyber_moe_datasets.ingestion import read_jsonl

    rows = read_jsonl(RELEASE / "canonical.jsonl")
    reports = [s for s in rows if s.task_type == "evidence_grounded_detection_report"]
    assert reports
    for sample in reports:
        answer = json.loads(sample.expected_answer)
        assert answer["detection_guidance"]
        assert sample.expected_answer in sample.messages[0].content
        assert sample.verification_status == "source_grounded"


def test_new_bridge_rejected_without_reassigning_old_splits(tmp_path):
    from cyber_moe_datasets.fixtures import fixtures
    from cyber_moe_datasets.models import Sample
    from cyber_moe_datasets.pipeline import build

    original = fixtures()[:2]
    bridge = original[0].model_dump()
    bridge.update(sample_id="new-bridge", content_hash="")
    bridge["messages"][0]["content"] = "New scenario bridge document"
    bridge["provenance"]["document_id"] = original[1].provenance.document_id
    rows = original + [Sample.model_validate(bridge)]
    input_path = tmp_path / "rows.jsonl"
    write_jsonl(input_path, [s.model_dump() for s in rows])
    freeze = tmp_path / "freeze.json"
    freeze.write_text(json.dumps({s.scenario_id: s.split for s in original}))
    ids = tmp_path / "ids.json"
    ids.write_text(json.dumps([s.sample_id for s in original]))
    config = json.loads(Path("configs/fixtures.yaml").read_text())
    config["inputs"][0]["path"] = str(input_path)
    config.update(frozen_partitions=str(freeze), frozen_sample_ids=str(ids))
    p = tmp_path / "config.yaml"
    p.write_text(json.dumps(config))
    report = build(p, tmp_path / "output")
    assert report["partition_conflict_rejected"] == 1
    assert report["partition_conflict_sample_ids"] == ["new-bridge"]
    from cyber_moe_datasets.ingestion import read_jsonl

    retained = read_jsonl(tmp_path / "output/canonical.jsonl")
    assert {s.sample_id: s.split for s in retained} == {s.sample_id: s.split for s in original}


def test_ci_configures_all_platforms():
    import yaml

    workflow = yaml.safe_load(Path(".github/workflows/tests.yml").read_text())
    assert set(workflow["jobs"]["test"]["strategy"]["matrix"]["os"]) == {
        "ubuntu-latest",
        "windows-latest",
        "macos-latest",
    }


def test_git_publication_audit_blocks_forced_weights(tmp_path):
    import subprocess

    from cyber_moe_datasets.publication import audit

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "model.safetensors").write_bytes(b"not real weights")
    subprocess.run(["git", "add", "model.safetensors"], cwd=tmp_path, check=True)
    with pytest.raises(ValueError, match="rejected"):
        audit(tmp_path)


def test_git_publication_audit_blocks_key_in_source(tmp_path):
    import subprocess

    from cyber_moe_datasets.publication import audit

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "settings.py").write_text('KEY = "' + "AKIA" + "A" * 16 + '"\n')
    with pytest.raises(ValueError, match="credential"):
        audit(tmp_path)


@pytest.mark.integration
def test_reference_tokenizer_release_and_tool_round_trips():
    import os

    from cyber_moe_datasets.fixtures import fixtures
    from cyber_moe_datasets.ingestion import read_jsonl

    model = os.environ.get("QWEN_MODEL_PATH")
    if not model:
        pytest.skip("set QWEN_MODEL_PATH for tokenizer-only integration")
    result = validate_tokenizer(fixtures(), Path(model))
    assert result["passed"] and result["records_checked"] == 20
    records = read_jsonl(RELEASE / "canonical.jsonl")
    actual = validate_tokenizer(records, Path(model))
    expected = json.loads((RELEASE / "tokenizer_validation.json").read_text())
    assert actual["records"] == expected["records"]
    assert validate_calibration(RELEASE / "calibration/data.jsonl", Path(model))["passed"]
    with pytest.raises(ValueError, match="truncate"):
        validate_calibration(RELEASE / "calibration/data.jsonl", Path(model), max_tokens=1)
