"""Reproduce original CC0 synthetic SOC/MCP test artifacts; no real BOTS data."""

import hashlib
import json
from pathlib import Path

from cyber_moe_datasets.exporters import write_jsonl
from cyber_moe_datasets.ingestion.splunk import METADATA, WORKFLOWS
from cyber_moe_datasets.io import write_json
from cyber_moe_datasets.mcp import load_pack, safe_spl
from cyber_moe_datasets.models import Message, Provenance, Sample
from cyber_moe_datasets.soc_models import checksum

ROOT = Path("data/fixtures/soc")
QUESTIONS = {
    "authentication": "Report the observed account, login event codes and chronology from this synthetic authentication evidence.",
    "login_correlation": "Correlate the recorded failed and successful login codes for the shared synthetic account using native event references and timestamps.",
    "powershell": "Inspect the synthetic PowerShell process image and command line without executing it. Report the recorded fields; suspicion does not prove an attack.",
    "windows_event": "Extract the recorded Windows event code and process name from this synthetic Windows Event Log evidence.",
    "sysmon": "Report the synthetic Sysmon event code and process image, keeping the interpretation limited to supplied fields.",
    "network": "Investigate the recorded byte counts and transport fields in this synthetic network traffic evidence.",
    "dns": "Inspect the recorded query and record type in this synthetic DNS anomaly exercise; do not infer maliciousness.",
    "cloudtrail": "Report the CloudTrail event name and identity type present in this synthetic AWS evidence.",
    "timeline": "Build a source-referenced chronology for these synthetic Windows events, preserving their event codes and accounts.",
    "security_reporting": "Create a structured, source-grounded report of these synthetic cloud events without asserting compromise.",
}


def generate():
    events = []
    cases = []
    fields = set(METADATA)
    # These symbolic values and locators are deliberately synthetic, not BOTS facts.
    details = [
        ("wineventlog", {"EventCode": "4625", "Account_Name": "fixture-user"}, 2),
        ("wineventlog", {"EventCode": "4624", "Account_Name": "fixture-user"}, 3),
        (
            "xmlwineventlog:microsoft-windows-sysmon/operational",
            {
                "Image": "powershell.exe",
                "CommandLine": "powershell -NoProfile Write-Output fixture",
            },
            1,
        ),
        ("wineventlog", {"EventCode": "4688", "New_Process_Name": "fixture-process.exe"}, 1),
        (
            "xmlwineventlog:microsoft-windows-sysmon/operational",
            {"EventCode": "1", "Image": "fixture-agent.exe"},
            1,
        ),
        ("stream:tcp", {"bytes": "2048", "transport": "tcp"}, 2),
        ("stream:dns", {"query": "fixture-domain.invalid", "record_type": "TXT"}, 2),
        ("aws:cloudtrail", {"eventName": "ConsoleLogin", "userIdentity.type": "IAMUser"}, 1),
        ("wineventlog", {"EventCode": "4624", "Account_Name": "fixture-timeline"}, 3),
        ("aws:cloudtrail", {"eventName": "ListBuckets", "readOnly": "true"}, 2),
    ]
    partitions = ["calibration", "train", "validation", "evaluation"]
    for i, (workflow, (sourcetype, extra, count)) in enumerate(zip(WORKFLOWS, details)):
        ids = []
        fields.update(extra)
        for offset in range(count):
            values = dict(extra)
            if workflow == "login_correlation":
                values["EventCode"] = "4625" if offset < 2 else "4624"
            row = {
                "_time": f"2020-01-{i + 1:02d}T12:0{offset}:00Z",
                "index": "synthetic_soc",
                "sourcetype": sourcetype,
                "host": f"fixture-host-{i}",
                "source": "fixture-source",
                "_bkt": f"synthetic_soc~fixture-bucket-{i}",
                "_cd": f"fixture:{offset}",
                "_raw": json.dumps(values, sort_keys=True),
                **values,
            }
            native = {key: row[key] for key in ("index", "_bkt", "_cd")}
            ids.append(json.dumps(native, sort_keys=True, separators=(",", ":")))
            events.append(row)
        cases.append(
            {
                "scenario_id": f"synthetic-soc:{workflow}",
                "document_id": f"fixture-case:{workflow}",
                "workflow": workflow,
                "question": QUESTIONS[workflow]
                + " Include counts, chronology and relevant recorded fields; leave attack status unconfirmed.",
                "event_ids": ids,
                "required_fields": sorted(extra),
                "difficulty": "intermediate",
                "split": partitions[i % 4],
            }
        )
    write_jsonl(ROOT / "events.jsonl", events)
    manifest = {
        "source_id": "soc_fixture",
        "source_version": "fixture-soc-v1",
        "source_dataset": "original-synthetic-soc",
        "source_url": "fixture://soc",
        "license": "CC0-1.0",
        "synthetic": True,
        "format": "jsonl",
        "payload_sha256": hashlib.sha256((ROOT / "events.jsonl").read_bytes()).hexdigest(),
        "field_inventory": sorted(fields),
        "export_query": "not executed; original synthetic events",
        "splunk_version": "not applicable; no Splunk used",
        "exported_at": "2020-02-01T00:00:00Z",
    }
    write_json(ROOT / "export_manifest.json", manifest)
    from cyber_moe_datasets.io import write_text

    write_text(ROOT / "investigations.json", json.dumps(cases, indent=2, sort_keys=True) + "\n")
    pack = load_pack(Path("configs/mcp/synthetic-splunk-v1.json"))
    tools = pack.openai_tools()
    reference = pack.reference()
    inventory = set(manifest["field_inventory"])
    query = safe_spl(
        "synthetic_soc",
        "wineventlog",
        "2020-01-01T00:00:00Z",
        "2020-01-02T00:00:00Z",
        ["_time", "host", "EventCode"],
        inventory,
    )
    workflows = [
        ("discover_indexes", "fixture_indexes", {}, {"indexes": ["synthetic_soc"]}, False),
        (
            "discover_sourcetypes",
            "fixture_sourcetypes",
            {"index": "synthetic_soc"},
            {"sourcetypes": ["wineventlog"]},
            False,
        ),
        (
            "bounded_search",
            "fixture_search",
            {"query": query, "limit": 10},
            {"results": [{"EventCode": "4625"}], "truncated": False},
            False,
        ),
        (
            "empty_result",
            "fixture_search",
            {"query": query, "limit": 10},
            {"results": [], "truncated": False},
            False,
        ),
        (
            "failed_result",
            "fixture_search",
            {"query": query, "limit": 10},
            {"message": "synthetic timeout"},
            True,
        ),
        (
            "correlation",
            "fixture_search",
            {"query": query, "limit": 10},
            {"results": [{"EventCode": "4625"}, {"EventCode": "4624"}], "truncated": False},
            False,
        ),
        (
            "structured_tool_report",
            "fixture_search",
            {"query": query, "limit": 10},
            {"results": [{"EventCode": "4624"}], "truncated": False},
            False,
        ),
    ]
    samples = []
    for i, (workflow, name, args, result, failed) in enumerate(workflows):
        answer = json.dumps(
            {
                "tool_status": "failed"
                if failed
                else "empty"
                if result.get("results") == []
                else "returned",
                "attack_status": "unconfirmed",
                "observed_result": result,
            },
            sort_keys=True,
        )
        envelope = {
            "content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
            "isError": failed,
        }
        messages = [
            Message(
                role="user",
                content=f"Synthetic MCP {workflow} exercise: use only the supplied fixture tools and keep the result bounded. No production server is contacted.",
            ),
            Message(
                role="assistant",
                tool_calls=[
                    {"id": f"fixture-call-{i}", "function": {"name": name, "arguments": args}}
                ],
            ),
            Message(
                role="tool",
                tool_call_id=f"fixture-call-{i}",
                content=json.dumps(envelope, sort_keys=True),
            ),
            Message(role="assistant", content=answer),
        ]
        samples.append(
            Sample(
                sample_id=f"synthetic-mcp:{workflow}",
                source_id="mcp_fixture",
                source_version="fixture-mcp-v1",
                scenario_id=f"synthetic-mcp-case:{workflow}",
                task_type=workflow,
                security_domain="splunk_mcp",
                category="tool_workflow",
                messages=messages,
                tools=tools,
                mcp_schema=reference,
                expected_answer=answer,
                evidence_references=[f"fixture://mcp/result/{i}"],
                verification_status="synthetic",
                license="CC0-1.0",
                split=partitions[i % 4],
                provenance=Provenance(
                    document_id=f"fixture-mcp-trace:{i}",
                    source_url="fixture://mcp",
                    raw_sha256=checksum([m.model_dump() for m in messages]),
                    transformation="original synthetic MCP trace; no server called",
                    synthetic=True,
                ),
            )
        )
    write_jsonl(ROOT / "mcp.jsonl", [sample.model_dump() for sample in samples])
    return {
        "events": len(events),
        "soc_cases": len(cases),
        "mcp_samples": len(samples),
        "production_samples": 0,
    }


if __name__ == "__main__":
    print(json.dumps(generate(), sort_keys=True))
