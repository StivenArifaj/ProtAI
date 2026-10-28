"""Gateway domain models (blueprint sections 12.1-12.3).

These are the typed inputs and outputs of the single enforced execution path:

- ``RequestContext`` binds a proposal to a server request (and optional trace/session
  identifiers); it is constructed by the API layer, never from model output.
- ``ProposedToolCall`` is an *untrusted* claim. Every field is validated, but only the
  verified ``Principal`` plus registry/policy facts are authoritative.
- ``InvocationOutcome`` distinguishes a policy denial from an execution that was
  attempted and failed — callers must never treat a failed attempt as a result.
- ``ToolInvocationResult`` is the gateway's typed reply. ``result`` is populated only
  for ``EXECUTED``; audit sequence numbers reference the persisted decision/outcome
  events so callers can correlate without reading raw audit payloads. Phase 6 adds the
  redacted ``dlp_egress``/``dlp_output`` evidence and the ``RESPONSE_BLOCKED`` outcome.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from ai_security.data_security.classification import DataClass
from ai_security.data_security.dlp import DlpReport
from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.firewall.risk_engine import RiskAssessment
from ai_security.identity.models import Principal
from ai_security.intent.models import IntentManifest
from ai_security.policy.models import TOOL_ID_PATTERN
from ai_security.tools.base import STABLE_ID_PATTERN, SideEffectClass, ToolResult

_STABLE_ID = re.compile(STABLE_ID_PATTERN)
_MAX_DECLARED_RESOURCES = 32


class RequestContext(BaseModel):
    """Server-side request correlation context (never model-supplied)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=128, pattern=STABLE_ID_PATTERN)
    trace_id: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=STABLE_ID_PATTERN
    )
    session_id: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=STABLE_ID_PATTERN
    )


class ProposedToolCall(BaseModel):
    """An untrusted proposed action, validated before policy evaluation.

    ``target_resource_ids`` and ``destination`` are the caller's declared targets; the
    gateway derives the authoritative values from the validated arguments and refuses a
    call whose declared and derived targets differ. ``deadline`` is a tz-aware instant
    after which the proposal must not execute.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    call_id: str = Field(min_length=1, max_length=128, pattern=STABLE_ID_PATTERN)
    request_id: str = Field(min_length=1, max_length=128, pattern=STABLE_ID_PATTERN)
    principal_subject_id: str = Field(min_length=1, max_length=256)
    tool_id: str = Field(min_length=1, max_length=128, pattern=TOOL_ID_PATTERN)
    action_id: str = Field(min_length=1, max_length=128, pattern=STABLE_ID_PATTERN)
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    target_resource_ids: tuple[str, ...] = ()
    destination: str | None = Field(default=None, min_length=1, max_length=2_048)
    deadline: datetime | None = None

    @field_validator("target_resource_ids")
    @classmethod
    def _resources_are_canonical_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > _MAX_DECLARED_RESOURCES:
            raise ValueError(f"at most {_MAX_DECLARED_RESOURCES} target resources may be declared")
        if len(set(value)) != len(value):
            raise ValueError("target_resource_ids must be unique")
        for resource_id in value:
            if _STABLE_ID.fullmatch(resource_id) is None:
                raise ValueError(f"target resource id {resource_id!r} is not a stable id")
        return value

    @field_validator("deadline")
    @classmethod
    def _deadline_is_timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.utcoffset() is None:
            raise ValueError("deadline must be timezone-aware (UTC recommended)")
        return value


class InvocationOutcome(StrEnum):
    """What actually happened (never conflate a denial with a failed attempt)."""

    denied = "DENIED"
    executed = "EXECUTED"
    adapter_failed = "ADAPTER_FAILED"
    timeout = "TIMEOUT"
    result_rejected = "RESULT_REJECTED"
    response_blocked = "RESPONSE_BLOCKED"
    audit_failed = "AUDIT_FAILED"


@dataclass(frozen=True)
class ToolEvaluation:
    """The gateway's non-executing evaluation of one proposal (preview-safe).

    It carries the authoritative facts produced by validation, egress inspection, risk
    scoring, and policy evaluation. It is not an execution grant: no authorization was
    issued, no approval was consumed, no manifest use was reserved, and no adapter ran.
    """

    call_id: str
    tool_id: str
    action_id: str
    decision: FirewallDecision
    reason: DecisionReason
    risk: RiskAssessment | None
    policy_version: str
    policy_hash: str
    decision_audit_sequence: int | None
    action_digest: str | None = None
    data_class: DataClass | None = None
    side_effect_class: SideEffectClass | None = None
    resource_ids: tuple[str, ...] = ()
    destination: str | None = None
    dlp_egress: DlpReport | None = None
    approval_id: str | None = None
    approver_subject_id: str | None = None
    approval_required: bool = False
    required_approver_rule: str | None = None


@dataclass(frozen=True)
class ToolInvocationResult:
    """Typed gateway reply for one ``invoke_tool`` call."""

    call_id: str
    tool_id: str
    action_id: str
    decision: FirewallDecision
    reason: DecisionReason
    outcome: InvocationOutcome
    result: ToolResult | None
    risk: RiskAssessment | None
    policy_version: str
    policy_hash: str
    decision_audit_sequence: int | None
    outcome_audit_sequence: int | None
    approval_id: str | None = None
    approver_subject_id: str | None = None
    # Phase 6: redacted DLP evidence. ``dlp_egress`` explains a pre-execution denial;
    # ``dlp_output`` explains a REDACT release or RESPONSE_BLOCKED suppression. The
    # reports contain digests, categories, counts, and field paths — never match text.
    dlp_egress: DlpReport | None = None
    dlp_output: DlpReport | None = None
    # Phase 8: authoritative action facts (gateway-derived, never caller-supplied) so the
    # ingress can create an approval bound to the exact evaluated action without
    # re-parsing untrusted arguments.
    action_digest: str | None = None
    data_class: DataClass | None = None
    side_effect_class: SideEffectClass | None = None
    resource_ids: tuple[str, ...] = ()
    destination: str | None = None
    approval_required: bool = False
    required_approver_rule: str | None = None


class ToolExecutor(Protocol):
    """The only interface the agent runtime may receive (blueprint section 12.1)."""

    async def invoke_tool(
        self,
        *,
        principal: Principal,
        request_context: RequestContext,
        proposal: ProposedToolCall,
        manifest: IntentManifest | None = None,
        approval_id: str | None = None,
    ) -> ToolInvocationResult:
        """Evaluate and (only on ALLOW) execute one proposed action."""
        ...


__all__ = [
    "InvocationOutcome",
    "ProposedToolCall",
    "RequestContext",
    "ToolEvaluation",
    "ToolExecutor",
    "ToolInvocationResult",
]
