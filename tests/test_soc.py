import csv
import hashlib
import json
from pathlib import Path

import pytest

from cyber_moe_datasets.exporters import export, write_jsonl
from cyber_moe_datasets.ingestion.splunk import (
    ExportManifest,
    Investigation,
    construct,
    read_events,
)
from cyber_moe_datasets.mcp import load_pack, safe_spl, validate_pack_sample, validate_spl
from cyber_moe_datasets.models import Sample
from cyber_moe_datasets.pipeline import build
from cyber_moe_datasets.soc_models import Review, checksum, evidence_hash, validate_answer
from cyber_moe_datasets.sources import registry
from cyber_moe_datasets.splitting import partition
from cyber_moe_datasets.validation import leakage, privacy_flags

ROOT = Path("data/fixtures/soc")


def context():
    source = registry(Path("configs/sources.yaml"))["soc_fixture"]
    manifest = ExportManifest.model_validate(
        json.loads((ROOT / "export_manifest.json").read_text())
    )
    events = read_events(ROOT / "events.jsonl", manifest, source)
    cases = [
        Investigation.model_validate(row)
        for row in json.loads((ROOT / "investigations.json").read_text())
    ]
    return source, manifest, events, cases


def samples():
    source, manifest, events, cases = context()
    return construct(events, manifest, cases, {}, source.approved)


def real_context():
    source, manifest, events, cases = context()
    source = source.model_copy(update={"trust_level": "official", "approved": True})
    manifest = manifest.model_copy(update={"synthetic": False})
    return source, manifest, events, cases


def test_soc_all_workflows_deterministic():
    first, second = samples(), samples()
    assert [s.model_dump() for s in first] == [s.model_dump() for s in second]
    assert len(first) == 10 and len({s.task_type for s in first}) == 10
    assert all(s.provenance.synthetic and s.verification_status == "synthetic" for s in first)


def test_native_metadata_preserved():
    _, manifest, events, _ = context()
    original = json.loads((ROOT / "events.jsonl").read_text().splitlines()[0])
    event = events[0]
    assert event.raw == original["_raw"] and event.timestamp == original["_time"]
    assert event.host == original["host"]
    assert json.loads(event.event_id) == {key: original[key] for key in ("index", "_bkt", "_cd")}
    assert samples()[0].provenance.raw_sha256 == manifest.payload_sha256


def test_native_raw_is_an_observed_field():
    source, manifest, events, cases = context()
    cases[0].required_fields = ["_raw"]
    row = construct(events, manifest, cases[:1], {}, source.approved)[0]
    assert any(claim.get("field") == "_raw" for claim in json.loads(row.expected_answer)["claims"])


def test_metadata_contradiction_rejected():
    from cyber_moe_datasets.soc_models import EventEvidence

    row = context()[2][0].model_dump()
    row["fields"]["host"] = "different-host"
    with pytest.raises(ValueError, match="metadata differs"):
        EventEvidence.model_validate(row)


def test_boolean_source_value_cannot_be_replaced_with_integer():
    event = context()[2][0].model_copy(deep=True)
    event.fields["unit_boolean"] = True
    answer = {
        "assessment": "observations_only",
        "claims": [
            {
                "kind": "observed_field",
                "event_ids": [event.event_id],
                "field": "unit_boolean",
                "value": 1,
            }
        ],
    }
    with pytest.raises(ValueError, match="unsupported field value"):
        validate_answer(json.dumps(answer), [event])


def test_rendered_tool_argument_types_must_be_preserved(tmp_path, monkeypatch):
    from cyber_moe_datasets.ingestion import read_jsonl
    from cyber_moe_datasets.tokenization import validate_tokenizer

    original = next(
        row for row in read_jsonl(ROOT / "mcp.jsonl") if row.task_type == "bounded_search"
    )
    row = original.model_dump()
    row["messages"][1]["tool_calls"][0]["function"]["arguments"]["limit"] = 1
    row["content_hash"] = ""
    sample = Sample.model_validate(row)
    corrupted = sample.messages[1].tool_calls[0].function.model_dump()
    corrupted["arguments"]["limit"] = True

    class Tokenizer:
        chat_template = "unit-test-template"

        def apply_chat_template(self, messages, **kwargs):
            return (
                [1]
                if kwargs["tokenize"]
                else "\n".join(m.content for m in sample.messages) + json.dumps(corrupted)
            )

        def encode(self, text):
            return [1]

    monkeypatch.setattr("cyber_moe_datasets.tokenization.load_tokenizer", lambda path: Tokenizer())
    with pytest.raises(ValueError, match="tool arguments lost"):
        validate_tokenizer([sample], tmp_path)


def adapted_file(tmp_path, rows, manifest, format="jsonl"):
    p = tmp_path / "events.jsonl"
    if format == "jsonl":
        write_jsonl(p, rows)
    else:
        p.write_text(json.dumps(rows), encoding="utf-8")
    manifest = manifest.model_copy(
        update={"format": format, "payload_sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
    )
    return p, manifest


@pytest.mark.parametrize("field", ["_cd", "_bkt", "_raw", "_time", "host", "index"])
def test_missing_native_values_never_invented(tmp_path, field):
    source, manifest, _, _ = context()
    row = json.loads((ROOT / "events.jsonl").read_text().splitlines()[0])
    del row[field]
    p, manifest = adapted_file(tmp_path, [row], manifest)
    with pytest.raises(ValueError, match="no values will be invented"):
        read_events(p, manifest, source)


def test_checksum_mismatch():
    source, manifest, _, _ = context()
    manifest.payload_sha256 = "0" * 64
    with pytest.raises(ValueError, match="checksum"):
        read_events(ROOT / "events.jsonl", manifest, source)


def test_preview_results_rejected(tmp_path):
    source, manifest, _, _ = context()
    row = json.loads((ROOT / "events.jsonl").read_text().splitlines()[0])
    p, manifest = adapted_file(tmp_path, [{"result": row, "preview": True}], manifest)
    with pytest.raises(ValueError, match="preview"):
        read_events(p, manifest, source)


@pytest.mark.parametrize("envelope", ["array", "results", "rest-jsonl"])
def test_native_json_export_formats(tmp_path, envelope):
    source, manifest, expected, _ = context()
    rows = [json.loads(line) for line in (ROOT / "events.jsonl").read_text().splitlines()]
    document = (
        rows
        if envelope == "array"
        else {"results": rows}
        if envelope == "results"
        else [{"result": row, "preview": False} for row in rows]
    )
    p, manifest = adapted_file(
        tmp_path, document, manifest, "jsonl" if envelope == "rest-jsonl" else "json"
    )
    assert read_events(p, manifest, source) == expected


def test_csv_round_trip(tmp_path):
    source, manifest, expected, _ = context()
    rows = [json.loads(line) for line in (ROOT / "events.jsonl").read_text().splitlines()]
    p = tmp_path / "events.csv"
    with p.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=manifest.field_inventory)
        writer.writeheader()
        writer.writerows(rows)
    manifest = manifest.model_copy(
        update={"format": "csv", "payload_sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
    )
    actual = read_events(p, manifest, source)
    assert [(e.native_id, e.raw, e.timestamp) for e in actual] == [
        (e.native_id, e.raw, e.timestamp) for e in expected
    ]


def test_timestamp_requires_timezone(tmp_path):
    source, manifest, _, _ = context()
    row = json.loads((ROOT / "events.jsonl").read_text().splitlines()[0])
    row["_time"] = "2020-01-01T00:00:00"
    p, manifest = adapted_file(tmp_path, [row], manifest)
    with pytest.raises(ValueError, match="timezone"):
        read_events(p, manifest, source)


def test_conflicting_native_event_rejected(tmp_path):
    source, manifest, _, _ = context()
    row = json.loads((ROOT / "events.jsonl").read_text().splitlines()[0])
    other = {**row, "_raw": "changed raw evidence"}
    p, manifest = adapted_file(tmp_path, [row, other], manifest)
    with pytest.raises(ValueError, match="conflicting"):
        read_events(p, manifest, source)


def test_missing_scenario_event():
    source, manifest, events, cases = context()
    cases[0].event_ids = ["invented"]
    with pytest.raises(ValueError, match="missing"):
        construct(events, manifest, cases, {}, source.approved)


def test_missing_field_cannot_be_used():
    source, manifest, events, cases = context()
    cases[0].required_fields = ["ImaginarySplunkField"]
    with pytest.raises(ValueError, match="invented"):
        construct(events, manifest, cases, {}, source.approved)


def test_real_candidates_have_no_gold_answer():
    source, manifest, events, cases = real_context()
    rows = construct(events, manifest, cases, {}, source.approved)
    assert all(s.expected_answer is None and s.verification_status == "unverified" for s in rows)
    assert all(s.review.status == "pending" and len(s.messages) == 1 for s in rows)


def approved_review(row):
    return Review(
        status="approved",
        reviewer="unit-test-reviewer",
        reviewed_at="2020-02-02T00:00:00Z",
        rationale="Unit test only: checked event count and chronology against supplied test evidence.",
        evidence_hash=evidence_hash(row.events),
        proposed_answer=row.review.proposed_answer,
        answer_hash=checksum(row.review.proposed_answer),
    )


def test_documented_review_promotion_and_stale_rejection():
    source, manifest, events, cases = real_context()
    candidate = construct(events, manifest, cases[:1], {}, True)[0]
    review = approved_review(candidate)
    verified = construct(events, manifest, cases[:1], {candidate.scenario_id: review}, True)[0]
    assert verified.verification_status == "human_verified"
    review.evidence_hash = "0" * 64
    with pytest.raises(ValueError, match="stale"):
        construct(events, manifest, cases[:1], {candidate.scenario_id: review}, True)


def test_unapproved_source_cannot_promote_review():
    _, manifest, events, cases = real_context()
    candidate = construct(events, manifest, cases[:1], {}, False)[0]
    reviewed = construct(
        events, manifest, cases[:1], {candidate.scenario_id: approved_review(candidate)}, False
    )[0]
    assert reviewed.verification_status == "unverified" and reviewed.expected_answer is None


def test_unsupported_confirmation_and_false_counts():
    row = samples()[0]
    answer = json.loads(row.expected_answer)
    answer["assessment"] = "confirmed_attack"
    with pytest.raises(ValueError, match="confirmation"):
        validate_answer(json.dumps(answer), row.events)
    answer["assessment"] = "observations_only"
    answer["claims"][0]["value"] = 99
    with pytest.raises(ValueError, match="count"):
        validate_answer(json.dumps(answer), row.events)


def test_field_claim_requires_exact_source_value():
    row = samples()[0]
    answer = {
        "assessment": "observations_only",
        "claims": [
            {
                "kind": "observed_field",
                "event_ids": [row.events[0].event_id],
                "field": "ImaginarySplunkField",
                "value": "bad",
            }
        ],
    }
    with pytest.raises(ValueError, match="invented"):
        validate_answer(json.dumps(answer), row.events)


def test_shared_event_groups_different_scenarios():
    a = samples()[0]
    b = a.model_copy(deep=True)
    b.sample_id = "another-derived-question"
    b.scenario_id = "different-investigation-label"
    b.provenance.document_id = "different-document"
    b.split = "unassigned"
    # Different wording ensures this test checks shared native evidence, not duplicate text.
    b.messages[0].content = "A completely different question about a reused event chain"
    b.content_hash = ""
    b = Sample.model_validate(b.model_dump())
    assert len({s.split for s in partition([a, b])}) == 1
    b.split = "evaluation"
    assert not leakage([a, b])["passed"]
    assert not leakage([a], references=[b])["passed"]


def test_shared_event_stays_isolated_across_source_revisions():
    a = samples()[0]
    row = a.model_dump()
    row.update(
        sample_id="same-events-new-revision",
        source_id="second-export",
        source_version="fixture-soc-v2",
        scenario_id="new-scenario-label",
        split="unassigned",
        content_hash="",
    )
    for event in row["events"]:
        event["source_version"] = row["source_version"]
    from cyber_moe_datasets.soc_models import EventEvidence

    row["review"]["evidence_hash"] = evidence_hash(
        [EventEvidence.model_validate(e) for e in row["events"]]
    )
    b = Sample.model_validate(row)
    assert len({s.split for s in partition([a, b])}) == 1
    b.split = "evaluation"
    assert any(v["kind"] == "shared_event" for v in leakage([a, b])["violations"])


def test_unverified_soc_not_exported_even_as_evaluation(tmp_path):
    source, manifest, events, cases = real_context()
    row = construct(events, manifest, cases[:1], {}, True)[0]
    row.split = "evaluation"
    with pytest.raises(ValueError, match="review queue"):
        export([row], tmp_path / "eval.jsonl", "evaluation", allow_unmeasured=True)


def test_mcp_fixtures_and_schema_version():
    from cyber_moe_datasets.ingestion import read_jsonl

    pack = load_pack(Path("configs/mcp/synthetic-splunk-v1.json"))
    rows = read_jsonl(ROOT / "mcp.jsonl")
    assert len(rows) == 7 and all(row.mcp_schema.synthetic for row in rows)
    for row in rows:
        validate_pack_sample(row, pack)
    pack.schema_version = "changed-version"
    with pytest.raises(ValueError, match="identity"):
        validate_pack_sample(rows[0], pack)


@pytest.mark.parametrize(
    "query",
    [
        "index=* | delete",
        'index="synthetic_soc" | outputlookup secret',
        'index="synthetic_soc" [| rest /services]',
    ],
)
def test_unsafe_spl_rejected(query):
    with pytest.raises(ValueError, match="subset"):
        validate_spl(query, {"_time", "host"})


def test_bounded_spl_and_unknown_fields():
    query = safe_spl(
        "synthetic_soc",
        "wineventlog",
        "2020-01-01T00:00:00Z",
        "2020-01-02T00:00:00Z",
        ["host", "_time"],
        {"host", "_time"},
    )
    validate_spl(query, {"host", "_time"})
    with pytest.raises(ValueError, match="observed"):
        safe_spl("synthetic_soc", "wineventlog", "1", "2", ["imaginary"], {"host"})
    with pytest.raises(ValueError, match="time window"):
        safe_spl("synthetic_soc", "wineventlog", "1", "90000", ["host"], {"host"})


def test_synthetic_secret_is_still_flagged():
    row = samples()[0].model_copy(deep=True)
    row.events[0].raw += " password=syntheticsecret123"
    assert "credential" in privacy_flags(row)


def test_soc_end_to_end_no_model_and_repeatable(tmp_path):
    first = build(Path("configs/soc_fixtures.yaml"), tmp_path / "first")
    build(Path("configs/soc_fixtures.yaml"), tmp_path / "second")
    assert first["soc_production_verified"] == 0 and first["synthetic_test_only"] == 17
    assert first["production_calibration_samples"] == 0
    assert first["production_target_shortfalls"]["soc"] == 192
    assert first["leakage"]["passed"]
    assert (tmp_path / "first/review_queue.jsonl").exists()
    for path in (tmp_path / "first").rglob("*.jsonl"):
        assert (
            path.read_bytes()
            == (tmp_path / "second" / path.relative_to(tmp_path / "first")).read_bytes()
        )
        assert b"\r" not in path.read_bytes()


def test_pending_cases_go_to_review_queue(tmp_path):
    source, manifest, events, cases = real_context()
    candidates = construct(events, manifest, cases, {}, False)
    from cyber_moe_datasets.io import write_json

    source.approved = False
    # Use the real-export route to exercise unapproved ingestion, without claiming unit data is real BOTS.
    rows = [json.loads(line) for line in (ROOT / "events.jsonl").read_text().splitlines()]
    payload, manifest = adapted_file(tmp_path, rows, manifest)
    manifest_path = tmp_path / "manifest.json"
    write_json(manifest_path, manifest.model_dump())
    registry_path = tmp_path / "registry.json"
    write_json(registry_path, {"sources": [source.model_dump()]})
    case_path = tmp_path / "cases.json"
    case_path.write_text(json.dumps([case.model_dump() for case in cases]))
    config = json.loads(Path("configs/soc_fixtures.yaml").read_text())
    config.update(mode="preview", registry=str(registry_path), mcp_schemas=[])
    config["inputs"] = [
        {
            "source_id": source.source_id,
            "path": str(payload),
            "format": "splunk_export",
            "manifest": str(manifest_path),
            "cases": str(case_path),
        }
    ]
    p = tmp_path / "config.json"
    write_json(p, config)
    report = build(p, tmp_path / "output")
    assert report["review_queue_samples"] == len(candidates) == 10
    assert report["samples"] == 0 and report["production_calibration_samples"] == 0
    assert (tmp_path / "output/evaluation/data.jsonl").read_bytes() == b""


def test_review_hash_tampering():
    source, manifest, events, cases = real_context()
    row = construct(events, manifest, cases[:1], {}, True)[0]
    review = approved_review(row).model_dump()
    review["proposed_answer"] = "changed answer"
    with pytest.raises(ValueError, match="answer hash"):
        Review.model_validate(review)


def test_mcp_mutating_query_and_invalid_argument_rejected():
    from cyber_moe_datasets.ingestion import read_jsonl

    pack = load_pack(Path("configs/mcp/synthetic-splunk-v1.json"))
    row = next(s for s in read_jsonl(ROOT / "mcp.jsonl") if s.task_type == "bounded_search")
    bad = row.model_dump()
    bad["content_hash"] = ""
    bad["messages"][1]["tool_calls"][0]["function"]["arguments"]["query"] = "index=* | delete"
    with pytest.raises(ValueError, match="subset"):
        validate_pack_sample(Sample.model_validate(bad), pack)
    bad["messages"][1]["tool_calls"][0]["function"]["arguments"]["limit"] = 10000
    with pytest.raises(ValueError, match="arguments"):
        Sample.model_validate(bad)


def test_mcp_wrong_output_and_unsupported_conclusion():
    from cyber_moe_datasets.ingestion import read_jsonl

    pack = load_pack(Path("configs/mcp/synthetic-splunk-v1.json"))
    row = next(s for s in read_jsonl(ROOT / "mcp.jsonl") if s.task_type == "empty_result")
    wrong = row.model_dump()
    wrong["content_hash"] = ""
    envelope = json.loads(wrong["messages"][2]["content"])
    envelope["content"][0]["text"] = json.dumps({"results": [], "truncated": True})
    wrong["messages"][2]["content"] = json.dumps(envelope)
    with pytest.raises(ValueError, match="output"):
        validate_pack_sample(Sample.model_validate(wrong), pack)
    wrong = row.model_dump()
    wrong["content_hash"] = ""
    answer = json.loads(wrong["expected_answer"])
    answer["attack_status"] = "confirmed_attack"
    wrong["expected_answer"] = json.dumps(answer)
    wrong["messages"][-1]["content"] = wrong["expected_answer"]
    with pytest.raises(ValueError, match="confirmed"):
        validate_pack_sample(Sample.model_validate(wrong), pack)


def test_remote_schema_references_rejected():
    from cyber_moe_datasets.mcp import MCPToolPack

    data = json.loads(Path("configs/mcp/synthetic-splunk-v1.json").read_text())
    data["tools"][0]["inputSchema"] = {"$ref": "https://example.invalid/remote-schema.json"}
    with pytest.raises(ValueError, match="external"):
        MCPToolPack.model_validate(data)


def test_frozen_release_write_blocked():
    with pytest.raises(ValueError, match="frozen"):
        write_jsonl(Path("data/releases/mitre-pilot-v0.2/calibration/data.jsonl"), [])


def test_real_mcp_review_binding_rejects_schema_changes():
    # Unit-only simulated recorded trace, never emitted as real dataset content.
    from cyber_moe_datasets.ingestion import read_jsonl

    pack = load_pack(Path("configs/mcp/synthetic-splunk-v1.json"))
    original = read_jsonl(ROOT / "mcp.jsonl")[0]
    pack.synthetic = False
    pack.server_id = "unit-test-recorded-server"
    row = original.model_dump()
    row.update(
        content_hash="",
        expected_answer=None,
        verification_status="unverified",
        source_id="unit-test-recorded-source",
        mcp_schema=pack.reference().model_dump(),
    )
    row["provenance"]["synthetic"] = False
    row["messages"] = row["messages"][:-1]
    candidate = Sample.model_validate(row)
    answer = original.expected_answer
    review = Review(
        status="approved",
        reviewer="unit-test-only",
        reviewed_at="2020-02-02T00:00:00Z",
        rationale="Unit test of trace binding, not real production review.",
        evidence_hash=candidate.review_binding(),
        proposed_answer=answer,
        answer_hash=checksum(answer),
    )
    row.update(
        content_hash="",
        expected_answer=answer,
        verification_status="human_verified",
        review=review.model_dump(),
    )
    row["messages"].append({"role": "assistant", "content": answer})
    Sample.model_validate(row)
    row["mcp_schema"]["schema_version"] = "different-schema-version"
    row["content_hash"] = ""
    with pytest.raises(ValueError, match="MCP review"):
        Sample.model_validate(row)


@pytest.mark.parametrize(
    "text", ['{"host":"first","host":"second"}', '{"value":NaN}', '{"value":Infinity}']
)
def test_malformed_json_values_rejected(text):
    from cyber_moe_datasets.ingestion.splunk import parse_json

    with pytest.raises(ValueError):
        parse_json(text)


def test_raw_export_cannot_be_published_as_fixture(tmp_path):
    import subprocess

    from cyber_moe_datasets.publication import audit

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    p = tmp_path / "data/fixtures/events.jsonl"
    write_jsonl(p, [{"_raw": "unreviewed real event"}])
    with pytest.raises(ValueError, match="unreviewed"):
        audit(tmp_path)


@pytest.mark.integration
def test_soc_fixture_exact_tokens_and_tool_export(tmp_path):
    import os

    path = os.environ.get("QWEN_MODEL_PATH")
    if not path:
        pytest.skip("set QWEN_MODEL_PATH for tokenizer-only SOC integration")
    report = build(Path("configs/soc_fixtures.yaml"), tmp_path / "pilot", Path(path))
    assert report["unknown_token_counts"] == 0 and report["length_rejected"] == 0
    assert report["samples"] == 17 and report["known_tokens"] > 0
    assert report["production_calibration_samples"] == 0
    assert report["calibration_token_distribution"]["tool_workflow"] > 0
