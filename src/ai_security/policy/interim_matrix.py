"""Interim transcription of the v1 policy decision matrix (SCAFFOLDING).

This module is a deliberately minimal, deterministic transcription of
``docs/POLICY_DECISION_MATRIX.md`` (blueprint section 10.3) whose only purpose is to
evaluate the policy self-check fixtures during Phase 0b. It is *not* the policy engine:
the real engine (safe YAML policy loading, strict models, risk thresholds, tool
registry) arrives in Phase 1 and replaces this evaluator while keeping the
``PolicyInput``/``PolicyDecision`` contract.

Transcription rules (from the matrix, including its precedence order):

1. hard constraints dominate every score and approval (hard deny, unknown tool,
   invalid arguments, unauthorized resource);
2. side-effect/data-class rows decide the base outcome;
3. unresolved risk becomes ``BLOCK`` unless the matrix explicitly makes the action
   approval-eligible (``ASK_USER``);
4. unknown or invalid enum values fail closed (enforced by strict models upstream).

Semantics are intentionally conservative: where the matrix says "only if policy
explicitly permits/approves", this evaluator requires the corresponding explicit fixture
flag to be true, otherwise it blocks.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

RISK_LOW_MAX = 39
RISK_HIGH_MIN = 80


class SideEffectClass(StrEnum):
    """Canonical side-effect classes (blueprint section 10.3)."""

    read_only = "READ_ONLY"
    local_mutation = "LOCAL_MUTATION"
    external_mutation = "EXTERNAL_MUTATION"
    destructive = "DESTRUCTIVE"


class DataClass(StrEnum):
    """Canonical data classes (blueprint section 10.3)."""

    public = "PUBLIC"
    internal = "INTERNAL"
    confidential = "CONFIDENTIAL"
    restricted = "RESTRICTED"


class Decision(StrEnum):
    allow = "ALLOW"
    ask_user = "ASK_USER"
    block = "BLOCK"


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    reason: str


class PolicyInput(BaseModel):
    """One deterministic evaluation case.

    Strict (``extra="forbid"``), and enum fields accept only the exact canonical values;
    anything else is a validation error (fail closed upstream, never coerced).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str = Field(min_length=1, max_length=256)
    side_effect_class: SideEffectClass
    data_class: DataClass
    risk: int = Field(ge=0, le=100)

    hard_deny: bool = False
    tool_known: bool = True
    arguments_valid: bool = True
    resource_authorized: bool = True

    approval_eligible: bool = False
    action_explicitly_permitted: bool = False
    destination_allowlisted: bool = False
    external_egress_enabled: bool = False


def evaluate(case: PolicyInput) -> PolicyDecision:
    """Evaluate one case against the v1 matrix transcription (fail closed)."""
    if case.hard_deny:
        return PolicyDecision(Decision.block, "hard_denied")
    if not case.tool_known:
        return PolicyDecision(Decision.block, "unknown_tool")
    if not case.arguments_valid:
        return PolicyDecision(Decision.block, "invalid_arguments")
    if not case.resource_authorized:
        return PolicyDecision(Decision.block, "resource_not_authorized")

    match case.side_effect_class:
        case SideEffectClass.read_only:
            return _read_only(case)
        case SideEffectClass.local_mutation:
            return _local_mutation(case)
        case SideEffectClass.external_mutation:
            return _external_mutation(case)
        case SideEffectClass.destructive:
            return PolicyDecision(Decision.block, "destructive_not_registered")
    raise ValueError(  # pragma: no cover - enum exhaustiveness guard
        f"unhandled side-effect class {case.side_effect_class!r}"
    )


def _risk_branch(case: PolicyInput, allow_reason: str, low_risk_condition: bool) -> PolicyDecision:
    if case.risk <= RISK_LOW_MAX:
        if low_risk_condition:
            return PolicyDecision(Decision.allow, allow_reason)
        return PolicyDecision(Decision.block, "explicit_permission_required")
    if case.risk < RISK_HIGH_MIN:
        if case.approval_eligible:
            return PolicyDecision(Decision.ask_user, "risk_requires_clarification")
        return PolicyDecision(Decision.block, "approval_not_eligible")
    return PolicyDecision(Decision.block, "risk_too_high")


def _read_only(case: PolicyInput) -> PolicyDecision:
    if case.risk <= RISK_LOW_MAX:
        return PolicyDecision(Decision.allow, "authorized_read")
    if case.risk < RISK_HIGH_MIN:
        if case.approval_eligible:
            return PolicyDecision(Decision.ask_user, "risk_requires_clarification")
        return PolicyDecision(Decision.block, "approval_not_eligible")
    return PolicyDecision(Decision.block, "risk_too_high")


def _local_mutation(case: PolicyInput) -> PolicyDecision:
    if case.data_class is DataClass.restricted:
        return PolicyDecision(Decision.block, "restricted_write_not_registered")
    if case.data_class is DataClass.confidential:
        if case.risk < RISK_HIGH_MIN:
            if case.approval_eligible:
                return PolicyDecision(Decision.ask_user, "confidential_write_requires_approval")
            return PolicyDecision(Decision.block, "approval_not_eligible")
        return PolicyDecision(Decision.block, "risk_too_high")
    return _risk_branch(case, "explicitly_permitted_local_write", case.action_explicitly_permitted)


def _external_mutation(case: PolicyInput) -> PolicyDecision:
    if case.data_class is DataClass.confidential:
        return PolicyDecision(Decision.block, "confidential_egress_blocked")
    if case.data_class is DataClass.restricted:
        return PolicyDecision(Decision.block, "restricted_egress_blocked")
    if case.risk >= RISK_HIGH_MIN:
        return PolicyDecision(Decision.block, "risk_too_high")

    approved_destination = case.external_egress_enabled and case.destination_allowlisted
    if case.data_class is DataClass.internal:
        if not approved_destination:
            return PolicyDecision(Decision.block, "internal_egress_requires_approved_destination")
        if case.approval_eligible:
            return PolicyDecision(Decision.ask_user, "internal_egress_requires_approval")
        return PolicyDecision(Decision.block, "approval_not_eligible")

    if not case.external_egress_enabled:
        return PolicyDecision(Decision.block, "external_egress_disabled")
    if not case.destination_allowlisted:
        return PolicyDecision(Decision.block, "destination_not_allowlisted")
    if case.risk <= RISK_LOW_MAX:
        return PolicyDecision(Decision.allow, "allowlisted_external_call")
    if case.approval_eligible:
        return PolicyDecision(Decision.ask_user, "risk_requires_clarification")
    return PolicyDecision(Decision.block, "approval_not_eligible")
