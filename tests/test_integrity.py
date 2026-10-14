import hashlib
import json
import sys
from pathlib import Path

import pytest
import yaml

from cyber_moe_datasets.compatibility import check_loader
from cyber_moe_datasets.exporters import export
from cyber_moe_datasets.fixtures import fixtures
from cyber_moe_datasets.ingestion import ingest_stix
from cyber_moe_datasets.models import Sample
from cyber_moe_datasets.pipeline import build
from cyber_moe_datasets.sources import download, registry
from cyber_moe_datasets.tokenization import load_tokenizer


def tool_sample():
    return next(s for s in fixtures() if s.tools)


def test_fixture_generation_deterministic():
    assert [s.model_dump() for s in fixtures()] == [s.model_dump() for s in fixtures()]


def test_tool_schema_arguments_invalid():
    row = tool_sample().model_dump()
    row["content_hash"] = ""
    row["messages"][1]["tool_calls"][0]["function"]["arguments"] = {"asset": 123}
    with pytest.raises(ValueError, match="tool arguments"):
        Sample.model_validate(row)


def test_tool_result_missing():
    row = tool_sample().model_dump()
    row["content_hash"] = ""
    row["messages"] = row["messages"][:2]
    with pytest.raises(ValueError, match="missing tool result"):
        Sample.model_validate(row)


def test_unknown_tool():
    row = tool_sample().model_dump()
    row["content_hash"] = ""
    row["messages"][1]["tool_calls"][0]["function"]["name"] = "execute_unknown"
    with pytest.raises(ValueError, match="unknown tool"):
        Sample.model_validate(row)


def test_tool_calibration_deferred(tmp_path):
    with pytest.raises(ValueError, match="pre-rendering"):
        export([tool_sample()], tmp_path / "tool.jsonl", "calibration", allow_unmeasured=True)


def test_tool_calibration_renders_schema(tmp_path):
    class Tokenizer:
        def apply_chat_template(self, messages, **kwargs):
            assert kwargs["tools"][0]["function"]["name"] == "lookup_inventory"
            return [1, 2, 3] if kwargs["tokenize"] else "rendered with tools"

        def encode(self, content):
            return [1, 2, 3]

    export(
        [tool_sample()],
        tmp_path / "tool.jsonl",
        "calibration",
        tokenizer=Tokenizer(),
        allow_unmeasured=True,
    )
    assert json.loads((tmp_path / "tool.jsonl").read_text()) == {"content": "rendered with tools"}


def test_missing_optional_dependency(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text('{"model_type":"qwen3_moe"}')
    monkeypatch.setitem(sys.modules, "transformers", None)
    with pytest.raises(RuntimeError, match="tokenizer extra"):
        load_tokenizer(tmp_path)


def test_wrong_model_configuration(tmp_path):
    (tmp_path / "config.json").write_text('{"model_type":"qwen3_5_moe"}')
    with pytest.raises(ValueError, match="Qwen3"):
        load_tokenizer(tmp_path)


def test_stix_checksum_rejected(tmp_path):
    source = registry(Path("configs/sources.yaml"))["mitre_attack"]
    p = tmp_path / "bad.json"
    p.write_text('{"type":"bundle","objects":[]}')
    with pytest.raises(ValueError, match="checksum"):
        ingest_stix(p, source)


def test_stix_adapter_no_inferred_answers(tmp_path):
    source = registry(Path("configs/sources.yaml"))["mitre_attack"]
    obj = {
        "type": "attack-pattern",
        "id": "attack-pattern--fixture",
        "name": "Fixture behavior",
        "description": "Evidence description",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "T9999.001",
                "url": "https://example.org/record",
            }
        ],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}],
    }
    p = tmp_path / "bundle.json"
    p.write_text(
        json.dumps({"type": "bundle", "objects": [obj, {**obj, "id": "revoked", "revoked": True}]})
    )
    source.sha256 = hashlib.sha256(p.read_bytes()).hexdigest()
    rows = ingest_stix(p, source)
    assert len(rows) == 1
    assert rows[0].scenario_id == "attack:T9999"
    assert json.loads(rows[0].expected_answer)["tactics"] == ["discovery"]
    assert rows[0].provenance.raw_sha256 == source.sha256


def test_download_checksum_and_existing_protection(tmp_path, monkeypatch):
    source = registry(Path("configs/sources.yaml"))["mitre_attack"]
    payload = b"test download"
    source.sha256 = hashlib.sha256(payload).hexdigest()

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            return payload

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: Response())
    p = tmp_path / "download.json"
    assert download(source, p).read_bytes() == payload
    p.write_bytes(b"existing work")
    with pytest.raises(ValueError, match="refusing overwrite"):
        download(source, p)
    assert p.read_bytes() == b"existing work"


def test_privacy_quarantine_preserves_evidence(tmp_path):
    config = yaml.safe_load(Path("configs/fixtures.yaml").read_text())
    row = fixtures()[0].model_dump()
    row["content_hash"] = ""
    row["messages"][0]["content"] = "password=confidential123"
    p = tmp_path / "samples.jsonl"
    p.write_text(json.dumps(row) + "\n")
    config["inputs"][0]["path"] = str(p)
    c = tmp_path / "config.yaml"
    c.write_text(yaml.safe_dump(config))
    result = build(c, tmp_path / "output")
    assert result["quarantined"] == 1
    assert result["samples"] == 0
    retained = json.loads((tmp_path / "output/quarantine.jsonl").read_text())
    assert retained["messages"][0]["content"] == row["messages"][0]["content"]


def test_changed_mlx_contract_fails_closed(tmp_path):
    loader = tmp_path / "data.py"
    loader.write_text(
        "def _tokenize_entry(obj, tokenizer, text_key, max_tokens):\n    return [1]\n"
    )
    dataset = tmp_path / "cal.jsonl"
    dataset.write_text('{"content":"test"}\n')
    with pytest.raises(ValueError, match="changed"):
        check_loader(loader, dataset)
