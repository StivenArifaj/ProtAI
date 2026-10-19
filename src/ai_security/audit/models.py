"""Structured audit event schema for the Phase 2 gateway (blueprint section 16.1).

The full event taxonomy is Phase 7 work; this module defines the subset the enforced
gateway emits now, with a stable schema version so later taxonomy changes are
explicit. Payloads carry safe references only — identifiers, decisions, policy/risk
provenance, destinations, and result digests/sizes. They never contain raw arguments,
message bodies, file contents, exception messages, or secrets (§16.3).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai_security.data_security.classification import DataClass
from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.firewall.models import InvocationOutcome
from ai_security.tools.base import STABLE_ID_PATTERN, SideEffectClass

AUDIT_SCHEMA_VERSION: Literal[1] = 1
COMPONENT: Literal["firewall.gateway"] = "firewall.gateway"

_HEX64 = re.compile(r"[0-9a-f]{64}")
_STABLE_ID = re.compile(STABLE_ID_PATTERN)


class AuditEventType(StrEnum):
    """Phase 2 event types (the full taxonomy remains Phase 7)."""

    policy_evaluated = "POLICY_EVALUATED"
    tool_execution_completed = "TOOL_EXECUTION_COMPLETED"
    tool_execution_failed = "TOOL_EXECUTION_FAILED"


class AuditEvent(BaseModel):
    """One canonical audit payload (storage fields are added by the repository)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = AUDIT_SCHEMA_VERSION
    event_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    event_type: AuditEventType
    occurred_at: datetime
    component: Literal["firewall.gateway"] = COMPONENT
    component_version: str = Field(min_length=1, max_length=64)

    request_id: str = Field(min_length=1, max_length=128)
    trace_id: str | None = Field(default=None, min_length=1, max_length=128)
    session_id: str | None = Field(default=None, min_length=1, max_length=128)
    principal_subject_id: str = Field(min_length=1, max_length=256)

    tool_id: str = Field(min_length=1, max_length=128)
    action_id: str = Field(min_length=1, max_length=128)
    decision: FirewallDecision
    reason: DecisionReason
    policy_version: str = Field(min_length=1, max_length=128)
    policy_hash: str = Field(min_length=1, max_length=128)
    outcome: InvocationOutcome | None = None

    side_effect_class: SideEffectClass | None = None
    data_class: DataClass | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    risk_version: str | None = Field(default=None, min_length=1, max_length=32)
    risk_factor_codes: tuple[str, ...] | None = None

    destination: str | None = Field(default=None, min_length=1, max_length=2_048)
    resource_ids: tuple[str, ...] = ()

    duration_ms: int | None = Field(default=None, ge=0, le=3_600_000)
    result_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    result_bytes: int | None = Field(default=None, ge=0, le=10_000_000)
    error_type: str | None = Field(default=None, min_length=1, max_length=64)

    @field_validator("occurred_at")
    @classmethod
    def _timestamp_is_utc(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("resource_ids")
    @classmethod
    def _resources_are_stable_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > 32:
            raise ValueError("at most 32 resource ids may be audited")
        for resource_id in value:
            if _STABLE_ID.fullmatch(resource_id) is None:
                raise ValueError(f"audited resource id {resource_id!r} is not a stable id")
        return value

    @field_validator("result_digest")
    @classmethod
    def _digest_is_lowercase_hex(cls, value: str | None) -> str | None:
        if value is not None and _HEX64.fullmatch(value) is None:
            raise ValueError("result_digest must be lowercase 64-character hex")
        return value

    @field_validator("error_type")
    @classmethod
    def _error_type_is_a_class_name(cls, value: str | None) -> str | None:
        if value is not None and any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in value
        ):
            raise ValueError("error_type must not contain control characters")
        return value

    def to_payload(self) -> dict[str, object]:
        """The canonical-payload mapping (no None fields; no storage-only fields)."""
        return self.model_dump(mode="json", exclude_none=True)


__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "COMPONENT",
    "AuditEvent",
    "AuditEventType",
]
