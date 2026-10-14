"""Strict canonical contracts and conversation integrity."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError
from pydantic import BaseModel, ConfigDict, Field, model_validator

from cyber_moe_datasets.soc_models import (
    EventEvidence,
    MCPReference,
    Review,
    checksum,
    evidence_hash,
    validate_answer,
)

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
    events: list[EventEvidence] = Field(default_factory=list)
    review: Review | None = None
    mcp_schema: MCPReference | None = None

    def review_binding(self) -> str | None:
        trace = (
            checksum(
                {
                    "schema": self.mcp_schema.model_dump(),
                    "messages": [
                        m.model_dump(exclude_defaults=True)
                        for m in self.messages
                        if m.role != "assistant" or m.tool_calls
                    ],
                }
            )
            if self.mcp_schema
            else None
        )
        if self.events and trace:
            return checksum(
                {
                    "events": evidence_hash(self.events),
                    "tool_trace": trace,
                    "schema_sha256": self.mcp_schema.schema_sha256,
                }
            )
        return evidence_hash(self.events) if self.events else trace

    def content(self) -> dict[str, Any]:
        content = {
            "messages": [m.model_dump(exclude_defaults=True) for m in self.messages],
            "tools": self.tools,
            "expected_answer": self.expected_answer,
        }
        if self.events:
            content["events"] = [event.model_dump() for event in self.events]
        if self.mcp_schema:
            content["mcp_schema"] = self.mcp_schema.model_dump()
        return content

    @model_validator(mode="after")
    def integrity(self) -> Sample:
        if self.events:
            if len({e.identity for e in self.events}) != len(self.events):
                raise ValueError("duplicate native event evidence")
            if any(e.source_version != self.source_version for e in self.events):
                raise ValueError("event source revision mismatch")
            if self.review is None or self.review.evidence_hash != self.review_binding():
                raise ValueError("SOC review is missing or bound to different evidence")
            if self.provenance.synthetic and self.review.status != "synthetic_fixture":
                raise ValueError("synthetic SOC records require synthetic fixture review status")
            if not self.provenance.synthetic and self.review.status == "synthetic_fixture":
                raise ValueError("real evidence cannot have a synthetic review")
            if self.verification_status == "human_verified" and self.review.status != "approved":
                raise ValueError("verified SOC sample requires documented review")
            if not self.provenance.synthetic and self.verification_status == "source_grounded":
                raise ValueError("real SOC answers require analyst review, not automatic promotion")
            if self.expected_answer is not None:
                if self.review.proposed_answer != self.expected_answer:
                    raise ValueError("answer differs from documented review")
                validate_answer(self.expected_answer, self.events, self.review.status == "approved")
            if self.verification_status == "unverified" and self.expected_answer is not None:
                raise ValueError("unverified SOC candidate must not contain a gold answer")
            if not self.evidence_references:
                raise ValueError("SOC sample requires evidence references")
        if self.mcp_schema and self.mcp_schema.synthetic != self.provenance.synthetic:
            raise ValueError("MCP schema synthetic status mismatch")
        if (
            self.mcp_schema
            and not self.provenance.synthetic
            and self.verification_status in {"human_verified", "source_grounded"}
        ):
            if (
                self.verification_status != "human_verified"
                or self.review is None
                or self.review.status != "approved"
            ):
                raise ValueError("real MCP answers require documented analyst review")
            binding = self.review_binding()
            if (
                self.review.evidence_hash != binding
                or self.review.proposed_answer != self.expected_answer
            ):
                raise ValueError("MCP review is bound to different tool evidence or answer")
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
            ensure_local_schema(schema)
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


def ensure_local_schema(value: Any) -> None:
    if isinstance(value, dict):
        for key in ("$ref", "$dynamicRef", "$recursiveRef"):
            if key in value and (not isinstance(value[key], str) or not value[key].startswith("#")):
                raise ValueError("external JSON Schema references are forbidden")
        for child in value.values():
            ensure_local_schema(child)
    elif isinstance(value, list):
        for child in value:
            ensure_local_schema(child)


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
