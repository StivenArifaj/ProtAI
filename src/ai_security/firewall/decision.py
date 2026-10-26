"""Firewall decision contract: decisions, stable reason codes, decision records.

``FirewallDecision`` is the v1 decision enum (blueprint section 6.1: ``ALLOW``,
``BLOCK``, ``ASK_USER``). ``DecisionReason`` is the stable machine-readable reason-code
vocabulary — decisions are data, and every reason code maps to exactly one documented
policy matrix outcome. ``DecisionRecord`` is the Phase 1 minimal record: decision,
reason, and the loaded policy version/hash (§10.6, ADR-007). Constraint, approval, and
correlation fields arrive with the features that produce them.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class FirewallDecision(StrEnum):
    """v1 decision enum (blueprint section 6.1)."""

    allow = "ALLOW"
    block = "BLOCK"
    ask_user = "ASK_USER"


class DecisionReason(StrEnum):
    """Stable reason codes; each maps to one v1 decision-matrix outcome (section 10.3).

    Reason codes are part of the observable contract (fixtures, tests, later audit
    events). Renaming or removing one is a breaking change.
    """

    # Hard constraints (evaluation-order steps 1-6, section 10.2)
    principal_not_resolved = "principal_not_resolved"
    binding_mismatch = "binding_mismatch"
    unknown_tool = "unknown_tool"
    invalid_arguments = "invalid_arguments"
    hard_denied = "hard_denied"
    deadline_exceeded = "deadline_exceeded"
    resource_not_authorized = "resource_not_authorized"
    side_effect_class_mismatch = "side_effect_class_mismatch"
    invalid_destination = "invalid_destination"

    # READ_ONLY outcomes
    authorized_read = "authorized_read"

    # LOCAL_MUTATION outcomes
    explicitly_permitted_local_write = "explicitly_permitted_local_write"
    confidential_write_requires_approval = "confidential_write_requires_approval"
    restricted_write_not_registered = "restricted_write_not_registered"

    # EXTERNAL_MUTATION outcomes
    external_egress_disabled = "external_egress_disabled"
    destination_not_allowlisted = "destination_not_allowlisted"
    allowlisted_external_call = "allowlisted_external_call"
    internal_egress_requires_approved_destination = "internal_egress_requires_approved_destination"
    internal_egress_requires_approval = "internal_egress_requires_approval"
    confidential_egress_blocked = "confidential_egress_blocked"
    restricted_egress_blocked = "restricted_egress_blocked"

    # DESTRUCTIVE and risk-threshold outcomes
    destructive_not_registered = "destructive_not_registered"
    risk_requires_clarification = "risk_requires_clarification"
    approval_not_eligible = "approval_not_eligible"
    explicit_permission_required = "explicit_permission_required"
    risk_too_high = "risk_too_high"

    # Intent-manifest failures (Phase 4, blueprints sections 8 and 12.3). The manifest
    # can only narrow what policy allows; these never grant execution.
    intent_manifest_invalid = "intent_manifest_invalid"
    intent_requires_clarification = "intent_requires_clarification"
    intent_action_not_allowed = "intent_action_not_allowed"
    intent_constraint_violation = "intent_constraint_violation"
    intent_limit_exceeded = "intent_limit_exceeded"

    # Approval workflow reasons (Phase 5, section 13). ``approval_granted`` is used by
    # approval audit events; the gateway itself keeps the engine's ASK_USER reason when
    # it executes an approved action. Approval failures are failures of a required
    # control and block execution.
    approval_granted = "approval_granted"
    approval_denied = "approval_denied"
    approval_expired = "approval_expired"
    approval_invalid = "approval_invalid"

    # Operational overrides produced by the gateway (fail closed, section 16.4).
    # These may only ever downgrade a decision to BLOCK; they never grant execution.
    policy_evaluation_error = "policy_evaluation_error"
    audit_unavailable = "audit_unavailable"


class DecisionRecord(BaseModel):
    """One deterministic policy outcome with provenance (Phase 1 minimal shape)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: FirewallDecision
    reason: DecisionReason
    policy_version: str = Field(min_length=1, max_length=128)
    policy_hash: str = Field(min_length=1, max_length=128)
