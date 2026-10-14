"""Original synthetic test scenarios. Never mixed into real-data builds."""

from cyber_moe_datasets.models import Message, Provenance, Sample, digest


def fixtures() -> list[Sample]:
    cases = [
        ("soc", "How many failures are shown? Evidence: failure, failure, success.", "2"),
        ("soc", "Which event occurs first? Evidence: login 09:00; logout 10:00.", "login"),
        (
            "security_reasoning",
            "Does an absent log prove no attack occurred?",
            "No; collection gaps may exist.",
        ),
        ("general", "Return Python for summing a list of integers.", "sum(values)"),
        ("structured", "Return JSON with status equal to reviewed.", '{"status":"reviewed"}'),
        ("soc", "Extract the reported outcome: audit says access denied.", "access denied"),
        (
            "security_reasoning",
            "Is a technique attribution supported without behavior evidence?",
            "No.",
        ),
        ("general", "Calculate the number of minutes in two hours.", "120"),
        ("structured", "Format an empty evidence array in JSON.", '{"evidence":[]}'),
        ("soc", "Inventory lists workstation and server. Count assets.", "2"),
        (
            "security_reasoning",
            "Explain the purpose of least privilege.",
            "Limit access to required capabilities.",
        ),
        ("general", "Sort these integers ascending: 8, 2, 5.", "2, 5, 8"),
        (
            "structured",
            "Emit JSON with severity low and confidence unknown.",
            '{"severity":"low","confidence":"unknown"}',
        ),
        (
            "soc",
            "An alert lacks endpoint telemetry. What evidence should be requested?",
            "Endpoint telemetry for the alert interval.",
        ),
        ("security_reasoning", "Why preserve evidence checksums?", "To detect evidence changes."),
        ("general", "Which Python structure provides unique elements?", "set"),
    ]
    samples = []
    splits = ["calibration", "train", "validation", "evaluation"]
    for i, (category, prompt, answer) in enumerate(cases):
        samples.append(
            Sample(
                sample_id=f"synthetic:{i}",
                source_id="fixture",
                source_version="1",
                scenario_id=f"synthetic-scenario:{i}",
                task_type="synthetic_contract_test",
                security_domain=category,
                category=category,
                messages=[
                    Message(role="user", content=prompt),
                    Message(role="assistant", content=answer),
                ],
                expected_answer=answer,
                evidence_references=[f"fixture://case/{i}"],
                license="CC0-1.0",
                verification_status="synthetic",
                split=splits[i % 4],
                provenance=Provenance(
                    document_id=f"synthetic-doc:{i}",
                    source_url=f"fixture://case/{i}",
                    raw_sha256=digest([prompt, answer]),
                    synthetic=True,
                    transformation="original hand-authored synthetic fixture",
                ),
            )
        )
    # Full tool exchanges, with fixed fixture partitions for predictable offline CI.
    for i, split in enumerate(splits):
        tool = {
            "type": "function",
            "function": {
                "name": "lookup_inventory",
                "description": "Read an offline synthetic inventory record",
                "parameters": {
                    "type": "object",
                    "properties": {"asset": {"type": "string"}},
                    "required": ["asset"],
                    "additionalProperties": False,
                },
            },
        }
        record = samples[i].model_dump()
        record.update(
            sample_id=f"synthetic-tool:{i}",
            scenario_id=f"synthetic-tool-scenario:{i}",
            category="tool_workflow",
            task_type="tool_exchange",
            split=split,
            expected_answer=f"Asset {i} is managed.",
            tools=[tool],
            content_hash="",
            messages=[
                {"role": "user", "content": f"Look up synthetic asset number {i}."},
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": f"call{i}",
                            "type": "function",
                            "function": {
                                "name": "lookup_inventory",
                                "arguments": {"asset": f"asset-{i}"},
                            },
                        }
                    ],
                },
                {
                    "role": "tool",
                    "tool_call_id": f"call{i}",
                    "content": f'{{"asset":"asset-{i}","managed":true}}',
                },
                {"role": "assistant", "content": f"Asset {i} is managed."},
            ],
        )
        record["provenance"].update(
            document_id=f"synthetic-tool-doc:{i}", raw_sha256=digest(record["messages"])
        )
        samples.append(Sample.model_validate(record))
    return samples
