"""Strict, redacted response contracts for the console API.

Every field here is safe by construction: identifiers, codes, counts, digests, sizes,
and timestamps. No raw request text, tool output, exception message, approval token,
password, or secret reference is representable. The frontend can only receive what
these models allow.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ai_security.console.auth import ConsoleRole, Permission, SessionInfo


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HealthState(StrEnum):
    healthy = "healthy"
    degraded = "degraded"
    unavailable = "unavailable"


class HealthItem(_Strict):
    name: str
    state: HealthState
    detail: str = Field(max_length=256)


class Overview(_Strict):
    generated_at: datetime
    chain_id: str
    chain_head_sequence: int
    chain_head_hash: str
    last_checkpoint_seal: str | None
    event_count: int
    alert_count: int
    pending_approval_count: int
    verified_event_count: int
    health: tuple[HealthItem, ...]
    policy_version: str
    policy_hash: str
    live: bool = True


class AuditEventView(_Strict):
    sequence_number: int
    occurred_at: datetime | None
    event_type: str | None
    component: str | None
    request_id: str | None
    trace_id: str | None
    call_id: str | None
    decision: str | None
    reason: str | None
    outcome: str | None
    tool_id: str | None
    action_id: str | None
    principal_subject_id: str | None
    destination: str | None
    risk_score: int | None
    policy_version: str | None
    policy_hash: str | None
    event_hash: str
    previous_hash: str
    has_dlp_evidence: bool
    has_input_evidence: bool
    resource_count: int
    result_bytes: int | None
    duration_ms: int | None


class AuditPage(_Strict):
    items: tuple[AuditEventView, ...]
    total: int
    limit: int
    offset: int
    has_more: bool


class AuditCorrelation(_Strict):
    events: tuple[AuditEventView, ...]
    by_request: dict[str, tuple[int, ...]]


class VerificationView(_Strict):
    verified: bool
    chain_id: str
    event_count: int
    head_sequence: int | None
    head_hash: str | None
    failure_codes: tuple[str, ...]
    failures_truncated: bool


class AlertView(_Strict):
    sequence_number: int
    occurred_at: datetime
    rule_id: str
    severity: str
    count: int
    window_seconds: int
    evidence: tuple[str, ...]
    request_id: str
    triage_status: str
    triage_note: str | None = None
    assignee: str | None = None
    hypothesis: str | None = None


class AlertRuleView(_Strict):
    rule_id: str
    kind: str
    window_seconds: int
    threshold: int
    severity: str
    enabled: bool
    description: str


class AlertRulesView(_Strict):
    version: str
    rules: tuple[AlertRuleView, ...]


class ApprovalView(_Strict):
    approval_id: str
    request_id: str
    tenant_id: str | None
    requester_subject_id: str
    tool_id: str
    action_id: str
    status: str
    required_approver_rule: str
    expires_at: datetime
    created_at: datetime
    resource_count: int
    destination: str | None
    risk_score: int
    policy_version: str
    policy_hash: str
    self_approval_allowed: bool
    decided_by_subject_id: str | None


class ToolView(_Strict):
    tool_id: str
    action_id: str
    side_effect_class: str
    data_class: str
    enabled_in_policy: bool
    external_destinations: tuple[str, ...]
    timeout_seconds: int | None
    max_concurrency: int | None


class ConnectorView(_Strict):
    connector_id: str
    name: str
    status: str
    requires_network: bool
    egress_destination_count: int
    permission_count: int
    secret_ref_digest: str | None
    enabled_at: datetime | None


class PolicyView(_Strict):
    version: str
    combined_hash: str
    tools: tuple[ToolView, ...]
    thresholds: dict[str, Any]
    self_checks: tuple[str, ...]


class ConfigView(_Strict):
    name: str
    version: str
    summary: dict[str, Any]


class LimiterView(_Strict):
    window_seconds: int
    buckets: tuple[str, ...]
    store_kind: str
    shared: bool
    caveat: str


class CheckpointView(_Strict):
    sequence_number: int
    head_hash: str
    previous_seal: str | None
    seal: str
    occurred_at: datetime
    verified: bool


class SettingView(_Strict):
    key: str
    value: str
    sensitive: bool = False
    restart_required: bool = True


class EvaluationReportView(_Strict):
    name: str
    generated_at: str | None
    cases: int | None
    summary: dict[str, Any]


class UserView(_Strict):
    username: str
    role: ConsoleRole
    tenant_id: str | None


class LogEntry(_Strict):
    id: str
    occurred_at: datetime | None
    service: str
    level: str
    message: str = Field(max_length=500)
    source: Literal["audit", "runtime"]
    sequence_number: int | None = None


class LogServiceCount(_Strict):
    service: str
    count: int


class MetricRow(_Strict):
    name: str
    count: int


class MetricsView(_Strict):
    window_events: int
    decisions: tuple[MetricRow, ...]
    event_types: tuple[MetricRow, ...]
    top_tools: tuple[MetricRow, ...]
    avg_risk_score: float
    alerts_per_100_events: float
    chain_verified: bool
    source: Literal["audit_chain"] = "audit_chain"


class WriteResult(_Strict):
    ok: bool
    message: str
    id: str | None = None


class TriageBody(_Strict):
    status: Literal["new", "acknowledged", "resolved"] = "acknowledged"
    note: str = Field(default="", max_length=512)
    assignee: str | None = Field(default=None, max_length=128)


class DecideBody(_Strict):
    approval_token: str = Field(min_length=1, max_length=512)
    approve: bool


class RevokeBody(_Strict):
    reason: str = Field(min_length=1, max_length=256)


class SummarizeBody(_Strict):
    alert_sequence: int = Field(ge=1)


class EnableBody(_Strict):
    threat_review_id: str = Field(min_length=1, max_length=128)


__all__ = [
    "AlertRulesView",
    "AlertRuleView",
    "AlertView",
    "ApprovalView",
    "AuditCorrelation",
    "AuditEventView",
    "AuditPage",
    "CheckpointView",
    "ConfigView",
    "ConnectorView",
    "DecideBody",
    "EnableBody",
    "EvaluationReportView",
    "HealthItem",
    "HealthState",
    "LimiterView",
    "Overview",
    "PolicyView",
    "RevokeBody",
    "SessionInfo",
    "SettingView",
    "SummarizeBody",
    "ToolView",
    "TriageBody",
    "UserView",
    "VerificationView",
    "WriteResult",
    "Permission",
]
