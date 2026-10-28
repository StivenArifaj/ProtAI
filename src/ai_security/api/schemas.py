"""Strict request and response models for the Phase 8 HTTP ingress (ADR-015).

Request models forbid unknown fields: a client cannot smuggle a ``decision``,
``risk``, ``approval``, caller-chosen ``request_id``, or permission set into a route.
The server generates request/call identifiers and derives every authoritative fact
from validated arguments, the verified principal, and the loaded policy.

Response models describe safe summaries only. They never carry raw tool arguments,
email bodies, approval tokens except the single creation response, or exception text.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StrictBool, field_validator

from ai_security.data_security.classification import DataClass
from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.identity.assertion import PrincipalAssertion
from ai_security.intent.models import MAX_EXTRACTED_TEXT_BYTES
from ai_security.policy.models import TOOL_ID_PATTERN
from ai_security.tools.base import STABLE_ID_PATTERN, SideEffectClass

_MAX_ARGUMENT_KEYS = 64


class RequestState(StrEnum):
    """Stable application states for ``POST /v1/requests`` (ADR-015)."""

    completed = "COMPLETED"
    no_action = "NO_ACTION"
    requires_clarification = "REQUIRES_CLARIFICATION"
    rejected = "REJECTED"
    approval_required = "APPROVAL_REQUIRED"
    denied = "DENIED"
    failed = "FAILED"


class RequestCreateBody(BaseModel):
    """One bounded user request; only the signed principal and text are accepted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal: PrincipalAssertion
    text: str = Field(min_length=1, max_length=MAX_EXTRACTED_TEXT_BYTES)

    @field_validator("text")
    @classmethod
    def _text_is_bounded_and_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("text must not be blank")
        if len(value.encode("utf-8")) > MAX_EXTRACTED_TEXT_BYTES:
            raise ValueError(f"text must not exceed {MAX_EXTRACTED_TEXT_BYTES} UTF-8 bytes")
        return value


class ToolPreviewBody(BaseModel):
    """A typed tool proposal for the preview-only evaluation route.

    Declared resource ids, destinations, deadlines, call ids, decisions, and approval
    outcomes are intentionally absent: the gateway derives the authoritative values
    from the validated arguments and refuses mismatches.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal: PrincipalAssertion
    tool_id: str = Field(min_length=1, max_length=128, pattern=TOOL_ID_PATTERN)
    action_id: str = Field(min_length=1, max_length=128, pattern=STABLE_ID_PATTERN)
    arguments: dict[str, JsonValue] = Field(default_factory=dict, max_length=_MAX_ARGUMENT_KEYS)


class ApprovalDecisionBody(BaseModel):
    """The only fields accepted by the approval decision route (token in signed body)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal: PrincipalAssertion
    approval_token: str = Field(min_length=1, max_length=512)
    approve: StrictBool

    @field_validator("approval_token")
    @classmethod
    def _token_is_control_free(cls, value: str) -> str:
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise ValueError("approval_token must not contain control characters")
        return value


class RiskSummary(BaseModel):
    """Reproducible risk facts; the score is not a calibrated probability."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    score: int = Field(ge=0, le=100)
    version: str = Field(min_length=1, max_length=32)
    factor_codes: tuple[str, ...] = ()


class ApprovalGrant(BaseModel):
    """The one-time approval token returned only to the signed host."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    approval_token: str = Field(min_length=1, max_length=512)
    expires_at: datetime
    required_approver_rule: str = Field(min_length=1, max_length=256)


class RequestResponse(BaseModel):
    """A successful or clarification-bearing request outcome."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=128)
    state: RequestState
    message: str = Field(min_length=1, max_length=256)
    result: dict[str, JsonValue] | None = None
    clarification: str | None = Field(default=None, min_length=1, max_length=1_024)
    approval: ApprovalGrant | None = None


class ToolEvaluationResponse(BaseModel):
    """Preview-only policy facts; this is not an execution grant."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=128)
    call_id: str = Field(min_length=1, max_length=128)
    tool_id: str = Field(min_length=1, max_length=128)
    action_id: str = Field(min_length=1, max_length=128)
    decision: FirewallDecision
    reason: DecisionReason
    risk: RiskSummary | None = None
    policy_version: str = Field(min_length=1, max_length=128)
    policy_hash: str = Field(min_length=1, max_length=128)
    approval_required: bool = False
    required_approver_rule: str | None = Field(default=None, min_length=1, max_length=256)
    data_class: DataClass | None = None
    side_effect_class: SideEffectClass | None = None


class ApprovalDecisionResponse(BaseModel):
    """The recorded decision outcome (never the consumed token)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=128)
    approval_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    status: str = Field(pattern=r"^(approved|denied)$")


class ErrorDetail(BaseModel):
    """Stable error fields; messages are safe summaries, never internals."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=256)
    request_id: str = Field(min_length=1, max_length=128)


class ErrorResponse(BaseModel):
    """Error envelope shared by the new routes (``state`` appears for outcomes)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    error: ErrorDetail
    state: RequestState | None = None


__all__ = [
    "ApprovalDecisionBody",
    "ApprovalDecisionResponse",
    "ApprovalGrant",
    "ErrorDetail",
    "ErrorResponse",
    "RequestCreateBody",
    "RequestResponse",
    "RequestState",
    "RiskSummary",
    "ToolEvaluationResponse",
    "ToolPreviewBody",
]
