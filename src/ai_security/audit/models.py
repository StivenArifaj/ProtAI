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
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai_security.data_security.classification import DataClass
from ai_security.data_security.dlp import (
    DestinationTrustLabel,
    DlpCategory,
    DlpOutcome,
    DlpPhase,
    DlpReport,
    EgressReason,
)
from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.firewall.models import InvocationOutcome
from ai_security.tools.base import STABLE_ID_PATTERN, SideEffectClass

AUDIT_SCHEMA_VERSION: Literal[1] = 1
COMPONENT: Literal["firewall.gateway", "firewall.approval"] = "firewall.gateway"

_HEX64 = re.compile(r"[0-9a-f]{64}")
_STABLE_ID = re.compile(STABLE_ID_PATTERN)
_PATTERN_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
# Field paths are schema keys/indexes, never free text. Control characters are refused
# so an audit payload can never be used for log injection.
_AUDIT_FIELD_PATH = Annotated[
    str, Field(min_length=1, max_length=256, pattern=r"^[^\x00-\x1f\x7f]+$")
]


class AuditEventType(StrEnum):
    """Phase 2 event types (the full taxonomy remains Phase 7)."""

    policy_evaluated = "POLICY_EVALUATED"
    tool_execution_completed = "TOOL_EXECUTION_COMPLETED"
    tool_execution_failed = "TOOL_EXECUTION_FAILED"
    approval_requested = "APPROVAL_REQUESTED"
    approval_decided = "APPROVAL_DECIDED"
    approval_consumed = "APPROVAL_CONSUMED"
    approval_expired = "APPROVAL_EXPIRED"


class DlpAuditFinding(BaseModel):
    """One redacted DLP finding: stable code, category, count, and field paths."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(min_length=1, max_length=64, pattern=_PATTERN_CODE.pattern)
    category: DlpCategory
    count: int = Field(ge=1, le=1_000_000)
    fields: tuple[_AUDIT_FIELD_PATH, ...] = Field(default=(), max_length=32)


class DlpAuditRecord(BaseModel):
    """Redacted, self-contained DLP evidence attached to an existing audit event.

    This record is audit-safe by construction: it carries content digests and sizes,
    stable finding codes/categories/counts, and schema field paths. It never contains
    matched text, raw arguments, result bodies, or exception messages (section 16.3).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    phase: DlpPhase
    outcome: DlpOutcome
    egress_reason: EgressReason | None = None
    max_data_class: DataClass
    findings: tuple[DlpAuditFinding, ...] = ()
    version: str = Field(min_length=1, max_length=128)
    config_hash: str = Field(pattern=_HEX64.pattern)
    content_digest: str = Field(pattern=_HEX64.pattern)
    content_bytes: int = Field(ge=0, le=10_000_000)
    truncated: bool = False
    inspection_error: bool = False
    destination: str | None = Field(default=None, min_length=1, max_length=2_048)
    destination_trust: DestinationTrustLabel | None = None
    destination_max_data_class: DataClass | None = None
    released_digest: str | None = Field(default=None, pattern=_HEX64.pattern)

    @field_validator("findings")
    @classmethod
    def _findings_are_bounded(
        cls, value: tuple[DlpAuditFinding, ...]
    ) -> tuple[DlpAuditFinding, ...]:
        if len(value) > 64:
            raise ValueError("at most 64 DLP findings may be audited")
        return value

    @classmethod
    def from_report(cls, report: DlpReport) -> DlpAuditRecord:
        """Project a (redacted) report onto the auditable subset."""
        trust = report.destination_trust
        return cls(
            phase=report.phase,
            outcome=report.outcome,
            egress_reason=report.egress_reason,
            max_data_class=report.max_data_class,
            findings=tuple(
                DlpAuditFinding(
                    code=finding.code,
                    category=finding.category,
                    count=finding.count,
                    fields=finding.fields,
                )
                for finding in report.findings
            ),
            version=report.version,
            config_hash=report.config_hash,
            content_digest=report.content_digest,
            content_bytes=report.content_bytes,
            truncated=report.truncated,
            inspection_error=report.inspection_error,
            destination=None if trust is None else trust.destination,
            destination_trust=None if trust is None else trust.trust,
            destination_max_data_class=None if trust is None else trust.max_data_class,
            released_digest=report.released_digest,
        )


class AuditEvent(BaseModel):
    """One canonical audit payload (storage fields are added by the repository)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = AUDIT_SCHEMA_VERSION
    event_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    event_type: AuditEventType
    occurred_at: datetime
    component: Literal["firewall.gateway", "firewall.approval"] = COMPONENT
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

    approval_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    approver_subject_id: str | None = Field(default=None, min_length=1, max_length=256)

    duration_ms: int | None = Field(default=None, ge=0, le=3_600_000)
    result_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    result_bytes: int | None = Field(default=None, ge=0, le=10_000_000)
    error_type: str | None = Field(default=None, min_length=1, max_length=64)
    dlp: DlpAuditRecord | None = None

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

    @field_validator("error_type", "approver_subject_id")
    @classmethod
    def _error_type_is_a_class_name(cls, value: str | None) -> str | None:
        if value is not None and any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in value
        ):
            raise ValueError("field must not contain control characters")
        return value

    def to_payload(self) -> dict[str, object]:
        """The canonical-payload mapping (no None fields; no storage-only fields)."""
        return self.model_dump(mode="json", exclude_none=True)


__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "COMPONENT",
    "AuditEvent",
    "AuditEventType",
    "DlpAuditFinding",
    "DlpAuditRecord",
]
