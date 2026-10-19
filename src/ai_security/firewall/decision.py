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

    # Hard constraints (evaluation-order steps 1-5, section 10.2)
    principal_not_resolved = "principal_not_resolved"
    unknown_tool = "unknown_tool"
    invalid_arguments = "invalid_arguments"
    hard_denied = "hard_denied"
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


class DecisionRecord(BaseModel):
    """One deterministic policy outcome with provenance (Phase 1 minimal shape)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: FirewallDecision
    reason: DecisionReason
    policy_version: str = Field(min_length=1, max_length=128)
    policy_hash: str = Field(min_length=1, max_length=128)
