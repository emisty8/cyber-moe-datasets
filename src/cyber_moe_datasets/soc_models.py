"""Evidence/review contracts shared by SOC and MCP, independent of model execution."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def checksum(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def timestamp_key(value: str) -> Decimal:
    try:
        number = Decimal(value)
        if not number.is_finite():
            raise ValueError("timestamp must be finite")
        datetime.fromtimestamp(float(number), timezone.utc)
        return number
    except InvalidOperation:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timestamps require an explicit timezone")
        return Decimal(str(parsed.timestamp()))


class EventEvidence(Contract):
    # Native Splunk locators are preserved, never generated from row numbers.
    event_id: str = Field(min_length=1)
    native_id: dict[str, str]
    source_dataset: str = Field(min_length=1)
    source_version: str = Field(min_length=1)
    timestamp: str = Field(min_length=1)
    index: str = Field(min_length=1)
    sourcetype: str = Field(min_length=1)
    host: str = Field(min_length=1)
    source: str = Field(min_length=1)
    raw: str = Field(min_length=1)
    fields: dict[str, Any]

    @property
    def identity(self) -> str:
        # A documentation/source revision must not let the same native event cross splits.
        return checksum([self.source_dataset, self.native_id])

    def observed_fields(self) -> dict[str, Any]:
        return {**self.fields, "_raw": self.raw}

    @model_validator(mode="after")
    def locator(self):
        if set(self.native_id) != {"index", "_bkt", "_cd"}:
            raise ValueError("event requires native index, _bkt and _cd")
        if self.native_id["index"] != self.index or any(not v for v in self.native_id.values()):
            raise ValueError("invalid native event locator")
        if self.event_id != json.dumps(self.native_id, sort_keys=True, separators=(",", ":")):
            raise ValueError("event_id must be the serialized original locator")
        metadata = {
            "_time": self.timestamp,
            "index": self.index,
            "sourcetype": self.sourcetype,
            "host": self.host,
            "source": self.source,
            "_bkt": self.native_id["_bkt"],
            "_cd": self.native_id["_cd"],
        }
        if any(self.fields.get(key) != value for key, value in metadata.items()):
            raise ValueError("native metadata differs from preserved exported fields")
        if "_raw" in self.fields and self.fields["_raw"] != self.raw:
            raise ValueError("raw evidence differs from preserved exported field")
        timestamp_key(self.timestamp)
        return self


class Review(Contract):
    status: Literal["pending", "approved", "rejected", "synthetic_fixture"]
    reviewer: str | None = None
    reviewed_at: str | None = None
    rationale: str | None = None
    evidence_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    proposed_answer: str | None = None
    answer_hash: str | None = None

    @model_validator(mode="after")
    def approval(self):
        if self.status == "approved":
            if not all(
                value and value.strip()
                for value in (
                    self.reviewer,
                    self.reviewed_at,
                    self.rationale,
                    self.proposed_answer,
                    self.answer_hash,
                )
            ):
                raise ValueError("approval requires reviewer, time, rationale and answer")
            timestamp_key(self.reviewed_at)
            if self.answer_hash != checksum(self.proposed_answer):
                raise ValueError("review answer hash mismatch")
        return self


class MCPReference(Contract):
    server_id: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)
    schema_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    synthetic: bool


def evidence_hash(events: list[EventEvidence]) -> str:
    return checksum([event.model_dump() for event in sorted(events, key=lambda e: e.identity)])


def validate_answer(answer: str, events: list[EventEvidence], reviewed: bool = False) -> None:
    """Validate supported structured facts; semantic analyst judgments still require review."""
    document = json.loads(answer)
    if set(document) != {"claims", "assessment"} or not isinstance(document["claims"], list):
        raise ValueError("SOC answer requires claims and assessment")
    if document["assessment"] not in {
        "observations_only",
        "requires_investigation",
        "confirmed_attack",
    }:
        raise ValueError("unsupported assessment label")
    if document["assessment"] == "confirmed_attack" and not reviewed:
        raise ValueError("attack confirmation requires documented analyst review")
    index = {event.event_id: event for event in events}
    if not document["claims"]:
        raise ValueError("answer requires evidence-supported facts")
    for claim in document["claims"]:
        ids = claim.get("event_ids", [])
        if not ids or len(ids) != len(set(ids)) or any(eid not in index for eid in ids):
            raise ValueError("claim cites missing or repeated event evidence")
        if claim.get("kind") == "event_count":
            if (
                set(claim) != {"kind", "event_ids", "value"}
                or type(claim["value"]) is not int
                or claim["value"] != len(ids)
            ):
                raise ValueError("unsupported event count")
        elif claim.get("kind") == "observed_field":
            if set(claim) != {"kind", "event_ids", "field", "value"}:
                raise ValueError("invalid field claim")
            for eid in ids:
                fields = index[eid].observed_fields()
                if claim["field"] not in fields or checksum(fields[claim["field"]]) != checksum(
                    claim["value"]
                ):
                    raise ValueError("invented field name or unsupported field value")
        elif claim.get("kind") == "timeline":
            ordered = sorted(ids, key=lambda eid: (timestamp_key(index[eid].timestamp), eid))
            expected = [{"event_id": eid, "timestamp": index[eid].timestamp} for eid in ordered]
            if set(claim) != {"kind", "event_ids", "value"} or claim["value"] != expected:
                raise ValueError("unsupported event timeline")
        else:
            raise ValueError(
                "unsupported claim kind; free-text conclusions require a future reviewed rubric"
            )
