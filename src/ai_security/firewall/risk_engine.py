"""Deterministic, versioned risk scoring (blueprint sections 12.3 step 7, 10.4, 11.4).

Risk is computed by the firewall from server-verified facts — never supplied by the
model, the request body, or the caller. The v1 algorithm is intentionally small and
explicit so decisions are reproducible and auditable:

- base weight by canonical side-effect class;
- +10 when an external mutation carries a destination (post-canonicalization);
- data-class weight declared by the tool registration (Phase 6 adds per-content DLP,
  which may only raise sensitivity, never lower it);
- total capped at 100.

The weights are initial defaults, not calibrated values. ``risk-v1`` names this exact
algorithm; changing any weight is a version change and must be recorded in an ADR so
historical audit events remain interpretable. Configuration-driven weights and
calibration are Phase 5 work (blueprint section 13).
"""

from __future__ import annotations

from dataclasses import dataclass

from ai_security.data_security.classification import DataClass
from ai_security.tools.base import SideEffectClass

RISK_ENGINE_VERSION = "risk-v1"
RISK_SCORE_MAX = 100

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


@dataclass(frozen=True)
class RiskAssessment:
    """A versioned score plus the factors that produced it."""

    score: int
    version: str
    factors: tuple[RiskFactor, ...]

    @property
    def factor_codes(self) -> tuple[str, ...]:
        return tuple(factor.code for factor in self.factors)


def assess_risk(
    *,
    side_effect_class: SideEffectClass,
    data_class: DataClass,
    destination: str | None,
) -> RiskAssessment:
    """Score one action from server-side facts (pure and deterministic).

    ``destination`` must already be canonical and is only meaningful for
    ``EXTERNAL_MUTATION``. An inconsistent combination raises instead of producing a
    score a caller could mistake for evidence of safety.
    """
    if not isinstance(side_effect_class, SideEffectClass):
        raise RiskScoringError("side_effect_class must be a canonical SideEffectClass")
    if not isinstance(data_class, DataClass):
        raise RiskScoringError("data_class must be a canonical DataClass")
    if destination is not None and side_effect_class is not SideEffectClass.external_mutation:
        raise RiskScoringError(
            "only EXTERNAL_MUTATION may carry a destination; refusing to score an "
            "inconsistent action"
        )

    factors: list[RiskFactor] = [
        RiskFactor(
            code=_FACTOR_SIDE_EFFECT[side_effect_class],
            weight=_SIDE_EFFECT_WEIGHTS[side_effect_class],
        )
    ]
    if destination is not None:
        factors.append(RiskFactor(code=_FACTOR_DESTINATION, weight=_DESTINATION_WEIGHT))
    data_weight = _DATA_CLASS_WEIGHTS[data_class]
    if data_weight:
        factors.append(RiskFactor(code=_FACTOR_DATA_CLASS[data_class], weight=data_weight))

    total = sum(factor.weight for factor in factors)
    return RiskAssessment(
        score=min(total, RISK_SCORE_MAX),
        version=RISK_ENGINE_VERSION,
        factors=tuple(factors),
    )


__all__ = [
    "RISK_ENGINE_VERSION",
    "RiskAssessment",
    "RiskFactor",
    "RiskScoringError",
    "assess_risk",
]
