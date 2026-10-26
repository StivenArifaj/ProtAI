"""Structured audit event schema (blueprint section 16.1; ADR-014).

Phase 7 completes the stable event taxonomy. Every event carries the request envelope
(``schema_version``, ``event_id``, ``event_type``, UTC timestamp, component/version,
``request_id``, optional ``trace_id``/``session_id``, and policy provenance). Fields
that only apply to some events (tool/action, decision/reason, outcome, DLP evidence,
result digests) are omitted from events where they do not apply rather than filled
with invented values.

Payloads carry safe references only — identifiers, decisions, policy/risk provenance,
destinations, and result digests/sizes. They never contain raw arguments, message
bodies, file contents, exception messages, or secrets (§16.3).

Schema evolution is additive within ``schema_version=1`` for the pre-release project:
new event types may be added, and a previously mandatory field may become
event-type-conditional. Existing payloads remain valid and the hash formula over the
stored canonical bytes never changes (ADR-014).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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
COMPONENT: Literal["firewall.gateway", "firewall.approval", "intent.service"] = "firewall.gateway"

_HEX64 = re.compile(r"[0-9a-f]{64}")
_STABLE_ID = re.compile(STABLE_ID_PATTERN)
_PATTERN_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
# Field paths are schema keys/indexes, never free text. Control characters are refused
# so an audit payload can never be used for log injection.
_AUDIT_FIELD_PATH = Annotated[
    str, Field(min_length=1, max_length=256, pattern=r"^[^\x00-\x1f\x7f]+$")
]


class AuditEventType(StrEnum):
    """Stable event names from blueprint section 16.1 (plus approval consumption).

    ``APPROVAL_CONSUMED`` is not listed in section 16.1 but is required by the
    approved-action consumption contract in sections 13.2-13.3.

    ``PRINCIPAL_RESOLVED``/``PRINCIPAL_REJECTED``, ``INPUT_INSPECTED``, and
    ``SECURITY_ALERT_RAISED`` have no producer yet; they belong to the Phase 8 HTTP
    ingress and Phase 10 alerting work and must not be emitted speculatively. The
    intent service emits ``INTENT_CREATED``/``INTENT_FAILED`` when a recorder is
    configured.
    """

    request_received = "REQUEST_RECEIVED"
    principal_resolved = "PRINCIPAL_RESOLVED"
    principal_rejected = "PRINCIPAL_REJECTED"
    input_inspected = "INPUT_INSPECTED"
    intent_created = "INTENT_CREATED"
    intent_failed = "INTENT_FAILED"
    tool_call_proposed = "TOOL_CALL_PROPOSED"
    policy_evaluated = "POLICY_EVALUATED"
    approval_requested = "APPROVAL_REQUESTED"
    approval_decided = "APPROVAL_DECIDED"
    approval_consumed = "APPROVAL_CONSUMED"
    approval_expired = "APPROVAL_EXPIRED"
    tool_execution_started = "TOOL_EXECUTION_STARTED"
    tool_execution_completed = "TOOL_EXECUTION_COMPLETED"
    tool_execution_failed = "TOOL_EXECUTION_FAILED"
    egress_inspected = "EGRESS_INSPECTED"
    output_inspected = "OUTPUT_INSPECTED"
    response_released = "RESPONSE_RELEASED"
    response_suppressed = "RESPONSE_SUPPRESSED"
    security_alert_raised = "SECURITY_ALERT_RAISED"


#: Events that describe one concrete tool action and therefore require tool/action ids.
_TOOL_SCOPED_EVENTS = frozenset(
    {
        AuditEventType.tool_call_proposed,
        AuditEventType.policy_evaluated,
        AuditEventType.approval_requested,
        AuditEventType.approval_decided,
        AuditEventType.approval_consumed,
        AuditEventType.approval_expired,
        AuditEventType.tool_execution_started,
        AuditEventType.tool_execution_completed,
        AuditEventType.tool_execution_failed,
        AuditEventType.egress_inspected,
        AuditEventType.output_inspected,
        AuditEventType.response_released,
        AuditEventType.response_suppressed,
    }
)

#: Events that record an authorization decision and therefore require decision/reason.
_DECISION_EVENTS = frozenset(
    {
        AuditEventType.policy_evaluated,
        AuditEventType.approval_requested,
        AuditEventType.approval_decided,
        AuditEventType.approval_consumed,
        AuditEventType.approval_expired,
        AuditEventType.tool_execution_started,
        AuditEventType.tool_execution_completed,
        AuditEventType.tool_execution_failed,
        AuditEventType.response_released,
        AuditEventType.response_suppressed,
    }
)

#: Events that describe an execution/response status and therefore require an outcome.
_OUTCOME_EVENTS = frozenset(
    {
        AuditEventType.tool_execution_completed,
        AuditEventType.tool_execution_failed,
        AuditEventType.response_released,
        AuditEventType.response_suppressed,
    }
)


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
    component: Literal["firewall.gateway", "firewall.approval", "intent.service"] = COMPONENT
    component_version: str = Field(min_length=1, max_length=64)

    request_id: str = Field(min_length=1, max_length=128)
    trace_id: str | None = Field(default=None, min_length=1, max_length=128)
    session_id: str | None = Field(default=None, min_length=1, max_length=128)
    principal_subject_id: str | None = Field(default=None, min_length=1, max_length=256)

    call_id: str | None = Field(default=None, min_length=1, max_length=128)
    tool_id: str | None = Field(default=None, min_length=1, max_length=128)
    action_id: str | None = Field(default=None, min_length=1, max_length=128)
    decision: FirewallDecision | None = None
    reason: DecisionReason | None = None
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

    @field_validator("error_type", "approver_subject_id", "principal_subject_id")
    @classmethod
    def _error_type_is_a_class_name(cls, value: str | None) -> str | None:
        if value is not None and any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in value
        ):
            raise ValueError("field must not contain control characters")
        return value

    @field_validator("call_id")
    @classmethod
    def _call_id_is_stable(cls, value: str | None) -> str | None:
        if value is not None and _STABLE_ID.fullmatch(value) is None:
            raise ValueError("call_id must be a stable identifier")
        return value

    @model_validator(mode="after")
    def _required_fields_match_the_event_type(self) -> Self:
        if (
            self.event_type is not AuditEventType.principal_rejected
            and self.principal_subject_id is None
        ):
            raise ValueError(
                f"{self.event_type.value} requires principal_subject_id "
                "(only PRINCIPAL_REJECTED may omit it)"
            )
        if self.event_type in _TOOL_SCOPED_EVENTS and (
            self.tool_id is None or self.action_id is None
        ):
            raise ValueError(f"{self.event_type.value} requires tool_id and action_id")
        if (self.decision is None) != (self.reason is None):
            raise ValueError("decision and reason must be provided together")
        if self.event_type in _DECISION_EVENTS and self.decision is None:
            raise ValueError(f"{self.event_type.value} requires a decision and reason")
        if self.event_type in _OUTCOME_EVENTS and self.outcome is None:
            raise ValueError(f"{self.event_type.value} requires an outcome")
        if self.event_type is AuditEventType.tool_execution_started and self.outcome is not None:
            raise ValueError("TOOL_EXECUTION_STARTED must not carry an outcome")
        if self.event_type is AuditEventType.tool_execution_completed and (
            self.outcome is not InvocationOutcome.executed
        ):
            raise ValueError("TOOL_EXECUTION_COMPLETED requires outcome EXECUTED")
        if self.event_type is AuditEventType.tool_execution_failed and self.outcome not in (
            InvocationOutcome.adapter_failed,
            InvocationOutcome.timeout,
            InvocationOutcome.result_rejected,
        ):
            raise ValueError("TOOL_EXECUTION_FAILED requires a failed execution outcome")
        if self.event_type is AuditEventType.egress_inspected:
            if self.dlp is None or self.dlp.phase is not DlpPhase.egress:
                raise ValueError("EGRESS_INSPECTED requires an EGRESS DLP record")
        if self.event_type is AuditEventType.output_inspected:
            if self.dlp is None or self.dlp.phase is not DlpPhase.output:
                raise ValueError("OUTPUT_INSPECTED requires an OUTPUT DLP record")
        if self.event_type is AuditEventType.response_released:
            if self.dlp is None or self.dlp.phase is not DlpPhase.output:
                raise ValueError("RESPONSE_RELEASED requires an OUTPUT DLP record")
            if self.outcome is not InvocationOutcome.executed:
                raise ValueError("RESPONSE_RELEASED requires outcome EXECUTED")
            if self.result_digest is None:
                raise ValueError("RESPONSE_RELEASED requires the result digest")
        if self.event_type is AuditEventType.response_suppressed:
            if self.dlp is None or self.dlp.phase is not DlpPhase.output:
                raise ValueError("RESPONSE_SUPPRESSED requires an OUTPUT DLP record")
            if self.outcome is not InvocationOutcome.response_blocked:
                raise ValueError("RESPONSE_SUPPRESSED requires outcome RESPONSE_BLOCKED")
            if self.result_digest is None:
                raise ValueError("RESPONSE_SUPPRESSED requires the result digest")
        return self

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
