"""Strict canonical contracts and conversation integrity."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError
from pydantic import BaseModel, ConfigDict, Field, model_validator

Split = Literal["unassigned", "calibration", "train", "validation", "evaluation"]


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class FunctionCall(StrictModel):
    name: str = Field(min_length=1)
    arguments: dict[str, Any]


class ToolCall(StrictModel):
    id: str = Field(min_length=1)
    type: Literal["function"] = "function"
    function: FunctionCall


class Message(StrictModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_call_id: str | None = None


class Provenance(StrictModel):
    document_id: str = Field(min_length=1)
    source_url: str = Field(min_length=1)
    raw_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    transformation: str = Field(min_length=1)
    synthetic: bool = False


class Sample(StrictModel):
    sample_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    source_version: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    task_type: str = Field(min_length=1)
    security_domain: str = Field(min_length=1)
    difficulty: Literal["basic", "intermediate", "advanced"] = "basic"
    category: Literal["soc", "security_reasoning", "tool_workflow", "general", "structured"]
    messages: list[Message] = Field(min_length=1)
    expected_answer: str | None = None
    evidence_references: list[str] = Field(default_factory=list)
    attack_technique_ids: list[str] = Field(default_factory=list)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    provenance: Provenance
    license: str = Field(min_length=1)
    verification_status: Literal["source_grounded", "human_verified", "unverified", "synthetic"]
    split: Split = "unassigned"
    token_count: int | None = Field(default=None, ge=1)
    token_method: str = "unavailable"
    content_hash: str = ""
    benchmark: bool = False

    def content(self) -> dict[str, Any]:
        return {
            "messages": [m.model_dump(exclude_defaults=True) for m in self.messages],
            "tools": self.tools,
            "expected_answer": self.expected_answer,
        }

    @model_validator(mode="after")
    def integrity(self) -> Sample:
        actual = digest(self.content())
        if self.content_hash and self.content_hash != actual:
            raise ValueError("content_hash mismatch")
        self.content_hash = actual
        if self.provenance.synthetic != (self.verification_status == "synthetic"):
            raise ValueError("synthetic provenance/status mismatch")
        if self.verification_status in {"source_grounded", "human_verified"}:
            if not self.evidence_references or not self.expected_answer:
                raise ValueError("verified answers require evidence")
        if self.benchmark and self.split not in {"unassigned", "evaluation"}:
            raise ValueError("benchmark must remain evaluation-only")
        pending: set[str] = set()
        seen: set[str] = set()
        schemas = {}
        for tool in self.tools:
            if tool.get("type") != "function" or not isinstance(tool.get("function"), dict):
                raise ValueError("invalid tool schema")
            fn = tool["function"]
            if not fn.get("name") or fn["name"] in schemas:
                raise ValueError("invalid or duplicate tool name")
            schema = fn.get("parameters", {})
            try:
                Draft202012Validator.check_schema(schema)
            except SchemaError as exc:
                raise ValueError("invalid tool parameter schema") from exc
            schemas[fn["name"]] = schema
        for message in self.messages:
            if pending and message.role != "tool":
                raise ValueError("tool calls must be followed by their results")
            if message.tool_calls and message.role != "assistant":
                raise ValueError("only assistant may call tools")
            for call in message.tool_calls:
                if call.id in seen or call.function.name not in schemas:
                    raise ValueError("duplicate call ID or unknown tool")
                try:
                    Draft202012Validator(schemas[call.function.name]).validate(
                        call.function.arguments
                    )
                except ValidationError as exc:
                    raise ValueError("tool arguments do not match the declared schema") from exc
                pending.add(call.id)
                seen.add(call.id)
            if message.role == "tool":
                if message.tool_call_id not in pending:
                    raise ValueError("orphan tool result")
                pending.remove(message.tool_call_id)
            elif message.tool_call_id is not None:
                raise ValueError("tool_call_id requires tool role")
        if pending:
            raise ValueError("missing tool result")
        return self


class CalibrationRecord(StrictModel):
    messages: list[Message] | None = None
    content: str | None = None

    @model_validator(mode="after")
    def exactly_one(self):
        if (self.messages is None) == (self.content is None):
            raise ValueError("calibration requires exactly one format")
        if self.messages == [] or self.content == "":
            raise ValueError("empty calibration record")
        return self


class EvaluationRecord(StrictModel):
    sample_id: str
    messages: list[Message]
    expected_answer: str | None
    evidence_references: list[str]
    tools: list[dict[str, Any]]
