"""Versioned MCP schema adapters and a conservative, offline SPL subset."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from pydantic import Field, model_validator

from cyber_moe_datasets.models import Sample, ensure_local_schema
from cyber_moe_datasets.soc_models import Contract, MCPReference, checksum, timestamp_key


class MCPTool(Contract):
    name: str = Field(min_length=1)
    description: str
    inputSchema: dict[str, Any]
    outputSchema: dict[str, Any] | None = None
    annotations: dict[str, Any] = Field(default_factory=dict)


class SearchPolicy(Contract):
    query_argument: str
    field_inventory: list[str]
    indexes: list[str]
    sourcetypes: list[str]


class MCPToolPack(Contract):
    server_id: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)
    source_url: str = Field(min_length=1)
    synthetic: bool
    tools: list[MCPTool] = Field(min_length=1)
    search_policies: dict[str, SearchPolicy] = Field(default_factory=dict)

    @model_validator(mode="after")
    def schemas(self):
        if len({tool.name for tool in self.tools}) != len(self.tools):
            raise ValueError("duplicate MCP tool name")
        if not set(self.search_policies) <= {tool.name for tool in self.tools}:
            raise ValueError("query policy references an undeclared tool")
        for tool in self.tools:
            for schema in (tool.inputSchema, tool.outputSchema):
                if schema is not None:
                    ensure_local_schema(schema)
                    Draft202012Validator.check_schema(schema)
        return self

    def openai_tools(self) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.inputSchema,
                },
            }
            for tool in self.tools
        ]

    def reference(self) -> MCPReference:
        return MCPReference(
            server_id=self.server_id,
            schema_version=self.schema_version,
            schema_sha256=checksum(self.model_dump()),
            synthetic=self.synthetic,
        )


def load_pack(path: Path) -> MCPToolPack:
    return MCPToolPack.model_validate(json.loads(path.read_text(encoding="utf-8")))


def validate_pack_sample(sample: Sample, pack: MCPToolPack) -> None:
    if sample.mcp_schema != pack.reference() or sample.tools != pack.openai_tools():
        raise ValueError("MCP schema identity or tool declarations differ from the versioned pack")
    Sample.model_validate(sample.model_dump())
    declared = {tool.name: tool for tool in pack.tools}
    calls = {}
    if sample.expected_answer:
        try:
            answer = json.loads(sample.expected_answer)
        except ValueError:
            answer = None
        if isinstance(answer, dict) and answer.get("attack_status") in {
            "confirmed",
            "confirmed_attack",
        }:
            if sample.review is None or sample.review.status != "approved":
                raise ValueError("MCP results alone do not justify confirmed attack status")
    for message in sample.messages:
        for call in message.tool_calls:
            if call.function.name in pack.search_policies:
                policy = pack.search_policies[call.function.name]
                query = call.function.arguments.get(policy.query_argument)
                if not isinstance(query, str):
                    raise ValueError("MCP search query argument missing")
                validate_spl(query, set(policy.field_inventory))
                if not any(
                    query.startswith(f'index="{index}" ') for index in policy.indexes
                ) or not any(
                    f' sourcetype="{sourcetype}" ' in query for sourcetype in policy.sourcetypes
                ):
                    raise ValueError("MCP query exceeds approved index/sourcetype scope")
        calls.update({call.id: call.function.name for call in message.tool_calls})
        if message.role == "tool":
            result = json.loads(message.content)
            if set(result) != {"content", "isError"} or type(result["isError"]) is not bool:
                raise ValueError(
                    "tool result must preserve the explicit MCP content/isError envelope"
                )
            if not isinstance(result["content"], list) or any(
                not isinstance(block, dict)
                or block.get("type") != "text"
                or not isinstance(block.get("text"), str)
                for block in result["content"]
            ):
                raise ValueError("fixture/adapter supports MCP text content blocks only")
            schema = declared[calls[message.tool_call_id]].outputSchema
            if schema is not None and not result["isError"]:
                if len(result["content"]) != 1:
                    raise ValueError("structured MCP output requires one JSON text block")
                try:
                    Draft202012Validator(schema).validate(json.loads(result["content"][0]["text"]))
                except ValidationError as exc:
                    raise ValueError("MCP tool output violates the versioned schema") from exc


def safe_spl(
    index: str, sourcetype: str, earliest: str, latest: str, fields: list[str], inventory: set[str]
) -> str:
    if not fields or len(fields) != len(set(fields)) or not set(fields) <= inventory:
        raise ValueError("SPL fields must be observed, unique and explicitly selected")
    atom = re.compile(r"^[A-Za-z0-9_:/.-]+$")
    if (
        not atom.fullmatch(index)
        or not atom.fullmatch(sourcetype)
        or any(not atom.fullmatch(f) for f in fields)
    ):
        raise ValueError("unsafe index, sourcetype or field selector")
    start, end = timestamp_key(earliest), timestamp_key(latest)
    if not 0 < end - start <= 86400:
        raise ValueError("SPL requires an explicit positive time window of at most 24 hours")
    return (
        f'index="{index}" sourcetype="{sourcetype}" earliest={start} latest={end}'
        + " | fields "
        + " ".join(sorted(fields))
        + " | sort _time"
    )


def validate_spl(query: str, inventory: set[str]) -> None:
    pattern = r'^index="([A-Za-z0-9_:/.-]+)" sourcetype="([A-Za-z0-9_:/.-]+)" earliest=([0-9.]+) latest=([0-9.]+) \| fields ([A-Za-z0-9_:/ .-]+) \| sort _time$'
    match = re.fullmatch(pattern, query)
    if not match:
        raise ValueError("SPL is outside the conservative read-only generated subset")
    index, sourcetype, start, end, fields = match.groups()
    if safe_spl(index, sourcetype, start, end, fields.split(), inventory) != query:
        raise ValueError("noncanonical or unsafe SPL")
