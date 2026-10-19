"""The deterministic v1 policy engine (blueprint sections 10.1-10.3; ADR-008).

The engine is the authoritative permission evaluator for one already-validated action
proposal. It is pure: no network, no LLM, no side effects, no mutation of the loaded
bundle. Its inputs are (a) the ``PolicyEvaluationRequest`` — the action description plus
facts produced by earlier layers (identity resolution, tool registry membership,
argument validation, scope checks, risk scoring) — and (b) the loaded ``PolicyBundle``
(policy-derived facts: tool permissions, approval eligibility, egress enablement and
destination allowlist, thresholds).

Evaluation order (blueprint section 10.2, enforced and tested):

1. principal resolved by the trusted adapter;
2. tool/action exists in the policy/registry catalog (absent -> ``unknown_tool``);
3. the declared side-effect class matches the policy record; arguments are valid;
4. hard-deny facts block regardless of score or approval;
5. resource scope and permission;
6. destination bounds (canonical exact match; no wildcards in v1);
7. the decision matrix rows (blueprint section 10.3) with configured thresholds;
8. a ``DecisionRecord`` carrying decision, stable reason code, and policy version/hash.

Fail-closed rules: any unknown/invalid state, malformed destination, or inconsistent
evidence yields ``BLOCK``; risk thresholds apply only to otherwise eligible actions; a
risk score of 0 cannot make a forbidden action legal.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from ai_security.data_security.classification import DataClass
from ai_security.policy.models import TOOL_ID_PATTERN, PolicyBundle, ToolPolicy
from ai_security.security.urls import (
    DestinationCanonicalizationError,
    canonicalize_destination,
)
from ai_security.tools.base import SideEffectClass

from .decision import DecisionReason, DecisionRecord, FirewallDecision

RISK_SCORE_MIN = 0
RISK_SCORE_MAX = 100


class PolicyEvaluationRequest(BaseModel):
    """The action description plus upstream facts for one policy evaluation.

    ``principal_resolved``/``arguments_valid``/``hard_deny``/``resource_authorized``/
    ``risk_score`` are facts produced by earlier layers (Phase 2+ registry, validator,
    scope checks, risk engine). Policy-derived facts (tool membership, explicit
    permission, approval eligibility, egress enablement, destination allowlist) are
    never accepted from this request — they come from the loaded policy bundle.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str = Field(min_length=1, max_length=128, pattern=TOOL_ID_PATTERN)
    side_effect_class: SideEffectClass
    data_class: DataClass
    risk_score: int = Field(ge=RISK_SCORE_MIN, le=RISK_SCORE_MAX, strict=True)

    principal_resolved: bool = True
    arguments_valid: bool = True
    hard_deny: bool = False
    resource_authorized: bool = True

    destination: str | None = Field(default=None, min_length=1, max_length=2048)


class PolicyEngine:
    """Deterministic evaluation of one request against one loaded policy bundle."""

    def __init__(self, bundle: PolicyBundle) -> None:
        self._bundle = bundle

    @property
    def bundle(self) -> PolicyBundle:
        return self._bundle

    def evaluate(self, request: PolicyEvaluationRequest) -> DecisionRecord:
        decision, reason = self._decide(request)
        return DecisionRecord(
            decision=decision,
            reason=reason,
            policy_version=self._bundle.version,
            policy_hash=self._bundle.combined_hash,
        )

    # -- evaluation order (section 10.2) ----------------------------------------------

    def _decide(self, request: PolicyEvaluationRequest) -> tuple[FirewallDecision, DecisionReason]:
        block = FirewallDecision.block

        # 1. verified principal (missing/invalid principal is a hard constraint).
        if not request.principal_resolved:
            return block, DecisionReason.principal_not_resolved

        # 2. tool/action must exist in the catalog; absent = unknown = deny.
        tool_policy = self._bundle.tool_policy(request.tool_id)
        if tool_policy is None:
            return block, DecisionReason.unknown_tool

        # 3. the proposal's declared class must match the registered class; arguments
        #    must have passed the tool's strict schema.
        if tool_policy.side_effect_class is not request.side_effect_class:
            return block, DecisionReason.side_effect_class_mismatch
        if not request.arguments_valid:
            return block, DecisionReason.invalid_arguments

        # 4. hard-deny facts dominate every score and approval.
        if request.hard_deny:
            return block, DecisionReason.hard_denied

        # 5. resource scope and permission.
        if not request.resource_authorized:
            return block, DecisionReason.resource_not_authorized

        # 6. destination bounds: only EXTERNAL_MUTATION may carry a destination, and it
        #    must canonicalize; anything else is a malformed action (fail closed).
        canonical_destination: str | None = None
        if request.destination is not None:
            if request.side_effect_class is not SideEffectClass.external_mutation:
                return block, DecisionReason.invalid_destination
            try:
                canonical_destination = canonicalize_destination(request.destination)
            except DestinationCanonicalizationError:
                return block, DecisionReason.invalid_destination

        # 7. matrix rows for otherwise fully eligible actions.
        return self._apply_matrix(tool_policy, request, canonical_destination)

    # -- matrix rows (section 10.3) ---------------------------------------------------

    def _apply_matrix(
        self,
        tool_policy: ToolPolicy,
        request: PolicyEvaluationRequest,
        canonical_destination: str | None,
    ) -> tuple[FirewallDecision, DecisionReason]:
        match request.side_effect_class:
            case SideEffectClass.read_only:
                return self._read_only(tool_policy, request.risk_score)
            case SideEffectClass.local_mutation:
                return self._local_mutation(tool_policy, request)
            case SideEffectClass.external_mutation:
                return self._external_mutation(tool_policy, request, canonical_destination)
            case SideEffectClass.destructive:
                return FirewallDecision.block, DecisionReason.destructive_not_registered
        raise ValueError(  # pragma: no cover - enum exhaustiveness guard
            f"unhandled side-effect class {request.side_effect_class!r}"
        )

    def _band(self, risk_score: int) -> str:
        if risk_score < self._bundle.ask_user_at_or_above:
            return "low"
        if risk_score < self._bundle.block_at_or_above:
            return "mid"
        return "high"

    def _read_only(
        self, tool_policy: ToolPolicy, risk_score: int
    ) -> tuple[FirewallDecision, DecisionReason]:
        band = self._band(risk_score)
        if band == "low":
            return FirewallDecision.allow, DecisionReason.authorized_read
        if band == "mid":
            if tool_policy.approval_eligible:
                return FirewallDecision.ask_user, DecisionReason.risk_requires_clarification
            return FirewallDecision.block, DecisionReason.approval_not_eligible
        return FirewallDecision.block, DecisionReason.risk_too_high

    def _local_mutation(
        self, tool_policy: ToolPolicy, request: PolicyEvaluationRequest
    ) -> tuple[FirewallDecision, DecisionReason]:
        if request.data_class is DataClass.restricted:
            return FirewallDecision.block, DecisionReason.restricted_write_not_registered
        if request.data_class is DataClass.confidential:
            if self._band(request.risk_score) == "high":
                return FirewallDecision.block, DecisionReason.risk_too_high
            if tool_policy.approval_eligible:
                return (
                    FirewallDecision.ask_user,
                    DecisionReason.confidential_write_requires_approval,
                )
            return FirewallDecision.block, DecisionReason.approval_not_eligible

        band = self._band(request.risk_score)
        if band == "low":
            if tool_policy.explicitly_permitted:
                return FirewallDecision.allow, DecisionReason.explicitly_permitted_local_write
            return FirewallDecision.block, DecisionReason.explicit_permission_required
        if band == "mid":
            if tool_policy.approval_eligible:
                return FirewallDecision.ask_user, DecisionReason.risk_requires_clarification
            return FirewallDecision.block, DecisionReason.approval_not_eligible
        return FirewallDecision.block, DecisionReason.risk_too_high

    def _external_mutation(
        self,
        tool_policy: ToolPolicy,
        request: PolicyEvaluationRequest,
        canonical_destination: str | None,
    ) -> tuple[FirewallDecision, DecisionReason]:
        if request.data_class is DataClass.confidential:
            return FirewallDecision.block, DecisionReason.confidential_egress_blocked
        if request.data_class is DataClass.restricted:
            return FirewallDecision.block, DecisionReason.restricted_egress_blocked
        if self._band(request.risk_score) == "high":
            return FirewallDecision.block, DecisionReason.risk_too_high

        destination_allowlisted = (
            canonical_destination is not None
            and canonical_destination in tool_policy.allowed_destinations
        )
        approved_destination = tool_policy.external_egress_enabled and destination_allowlisted

        if request.data_class is DataClass.internal:
            if not approved_destination:
                return (
                    FirewallDecision.block,
                    DecisionReason.internal_egress_requires_approved_destination,
                )
            if tool_policy.approval_eligible:
                return FirewallDecision.ask_user, DecisionReason.internal_egress_requires_approval
            return FirewallDecision.block, DecisionReason.approval_not_eligible

        # PUBLIC (or unclassified values never get here: the enum is closed).
        if not tool_policy.external_egress_enabled:
            return FirewallDecision.block, DecisionReason.external_egress_disabled
        if not destination_allowlisted:
            return FirewallDecision.block, DecisionReason.destination_not_allowlisted
        if self._band(request.risk_score) == "low":
            return FirewallDecision.allow, DecisionReason.allowlisted_external_call
        if tool_policy.approval_eligible:
            return FirewallDecision.ask_user, DecisionReason.risk_requires_clarification
        return FirewallDecision.block, DecisionReason.approval_not_eligible


__all__ = [
    "PolicyEngine",
    "PolicyEvaluationRequest",
]
