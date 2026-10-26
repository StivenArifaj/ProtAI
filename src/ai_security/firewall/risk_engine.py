"""Deterministic, versioned risk scoring (blueprint sections 11.3-11.4, 12.3).

Risk is computed by the firewall from server-verified facts — never supplied by the
model, the request body, or the caller. ``risk-v2`` keeps the exact v1 weights and adds
one bounded request-breadth factor (multiple target resources). Every factor carries a
stable code, its additive weight, and a human-readable rationale so a decision can be
reproduced and audited without reconstructing the inputs:

- base weight by canonical side-effect class;
- +10 when an external mutation carries a destination (post-canonicalization);
- data-class weight declared by the tool registration (Phase 6 adds per-content DLP,
  which may only raise sensitivity, never lower it);
- +5/+10/+15 for 2-4/5-8/9+ distinct target resources;
- total capped at 100.

The weights are initial defaults, not calibrated values. ``risk-v2`` names this exact
algorithm; changing any weight or factor is a version change and must be recorded in an
ADR so historical audit events remain interpretable. Threshold configuration lives in
``config/risk_thresholds.yaml`` and is part of the hashed policy bundle; calibration is
Phase 9 work.
"""

from __future__ import annotations

from dataclasses import dataclass

from ai_security.data_security.classification import DataClass
from ai_security.tools.base import SideEffectClass

RISK_ENGINE_VERSION = "risk-v2"
RISK_SCORE_MAX = 100
MAX_TARGET_RESOURCES = 32

_SIDE_EFFECT_WEIGHTS: dict[SideEffectClass, int] = {
    SideEffectClass.read_only: 0,
    SideEffectClass.local_mutation: 10,
    SideEffectClass.external_mutation: 15,
    SideEffectClass.destructive: 100,
}
_DATA_CLASS_WEIGHTS: dict[DataClass, int] = {
    DataClass.public: 0,
    DataClass.internal: 5,
    DataClass.confidential: 15,
    DataClass.restricted: 25,
}
_DESTINATION_WEIGHT = 10

_FACTOR_SIDE_EFFECT = {value: f"side_effect_{value.name}" for value in SideEffectClass}
_FACTOR_DATA_CLASS = {value: f"data_class_{value.name}" for value in DataClass}
_FACTOR_DESTINATION = "external_destination"


class RiskScoringError(ValueError):
    """The facts cannot be scored consistently (fail closed before execution)."""


@dataclass(frozen=True)
class RiskFactor:
    """One stable, auditable contribution to the score."""

    code: str
    weight: int
    rationale: str


@dataclass(frozen=True)
class RiskAssessment:
    """A versioned score plus the factors that produced it."""

    score: int
    version: str
    factors: tuple[RiskFactor, ...]

    @property
    def factor_codes(self) -> tuple[str, ...]:
        return tuple(factor.code for factor in self.factors)


def _breadth_factor(resource_count: int) -> RiskFactor | None:
    if resource_count <= 1:
        return None
    if resource_count <= 4:
        return RiskFactor(
            code="breadth_2_to_4_resources",
            weight=5,
            rationale="request targets more than one resource",
        )
    if resource_count <= 8:
        return RiskFactor(
            code="breadth_5_to_8_resources",
            weight=10,
            rationale="request targets five or more resources",
        )
    return RiskFactor(
        code="breadth_9_or_more_resources",
        weight=15,
        rationale="request targets nine or more resources",
    )


def assess_risk(
    *,
    side_effect_class: SideEffectClass,
    data_class: DataClass,
    destination: str | None,
    resource_count: int = 0,
) -> RiskAssessment:
    """Score one action from server-side facts (pure and deterministic).

    ``destination`` must already be canonical and is only meaningful for
    ``EXTERNAL_MUTATION``. ``resource_count`` is the number of distinct target
    resources derived from validated arguments; 0/1 adds no breadth factor. An
    inconsistent combination raises instead of producing a score a caller could mistake
    for evidence of safety.
    """
    if not isinstance(side_effect_class, SideEffectClass):
        raise RiskScoringError("side_effect_class must be a canonical SideEffectClass")
    if not isinstance(data_class, DataClass):
        raise RiskScoringError("data_class must be a canonical DataClass")
    if (
        not isinstance(resource_count, int)
        or isinstance(resource_count, bool)
        or not 0 <= resource_count <= MAX_TARGET_RESOURCES
    ):
        raise RiskScoringError(f"resource_count must be an integer in [0, {MAX_TARGET_RESOURCES}]")
    if destination is not None and side_effect_class is not SideEffectClass.external_mutation:
        raise RiskScoringError(
            "only EXTERNAL_MUTATION may carry a destination; refusing to score an "
            "inconsistent action"
        )

    factors: list[RiskFactor] = [
        RiskFactor(
            code=_FACTOR_SIDE_EFFECT[side_effect_class],
            weight=_SIDE_EFFECT_WEIGHTS[side_effect_class],
            rationale=f"canonical side-effect class {side_effect_class.value}",
        )
    ]
    if destination is not None:
        factors.append(
            RiskFactor(
                code=_FACTOR_DESTINATION,
                weight=_DESTINATION_WEIGHT,
                rationale="action sends data to an external destination",
            )
        )
    data_weight = _DATA_CLASS_WEIGHTS[data_class]
    if data_weight:
        factors.append(
            RiskFactor(
                code=_FACTOR_DATA_CLASS[data_class],
                weight=data_weight,
                rationale=f"registered data class {data_class.value}",
            )
        )
    breadth = _breadth_factor(resource_count)
    if breadth is not None:
        factors.append(breadth)

    total = sum(factor.weight for factor in factors)
    return RiskAssessment(
        score=min(total, RISK_SCORE_MAX),
        version=RISK_ENGINE_VERSION,
        factors=tuple(factors),
    )


__all__ = [
    "MAX_TARGET_RESOURCES",
    "RISK_ENGINE_VERSION",
    "RiskAssessment",
    "RiskFactor",
    "RiskScoringError",
    "assess_risk",
]
