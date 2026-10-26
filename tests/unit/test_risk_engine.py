"""Deterministic risk engine tests (blueprint sections 12.3, 10.4)."""

from __future__ import annotations

import pytest

from ai_security.data_security.classification import DataClass
from ai_security.firewall.risk_engine import (
    RISK_ENGINE_VERSION,
    RiskScoringError,
    assess_risk,
)
from ai_security.tools.base import SideEffectClass

DEST = "https://mock-sink.invalid/collect"


def score(
    side_effect_class: SideEffectClass,
    data_class: DataClass = DataClass.public,
    destination: str | None = None,
    resource_count: int = 0,
) -> int:
    return assess_risk(
        side_effect_class=side_effect_class,
        data_class=data_class,
        destination=destination,
        resource_count=resource_count,
    ).score


@pytest.mark.parametrize(
    "side_effect_class,expected",
    [
        (SideEffectClass.read_only, 0),
        (SideEffectClass.local_mutation, 10),
        (SideEffectClass.external_mutation, 15),
        (SideEffectClass.destructive, 100),
    ],
)
def test_side_effect_base_weights(side_effect_class: SideEffectClass, expected: int) -> None:
    assert score(side_effect_class) == expected


@pytest.mark.parametrize(
    "data_class,expected",
    [
        (DataClass.public, 0),
        (DataClass.internal, 5),
        (DataClass.confidential, 15),
        (DataClass.restricted, 25),
    ],
)
def test_data_class_weights(data_class: DataClass, expected: int) -> None:
    assert score(SideEffectClass.read_only, data_class) == expected


def test_destination_adds_weight_for_external_mutation() -> None:
    assert score(SideEffectClass.external_mutation) == 15
    assert score(SideEffectClass.external_mutation, destination=DEST) == 25


def test_read_only_with_a_destination_is_rejected() -> None:
    with pytest.raises(RiskScoringError):
        assess_risk(
            side_effect_class=SideEffectClass.read_only,
            data_class=DataClass.public,
            destination=DEST,
        )


def test_score_is_capped_at_one_hundred() -> None:
    assessment = assess_risk(
        side_effect_class=SideEffectClass.destructive,
        data_class=DataClass.restricted,
        destination=None,
    )
    assert assessment.score == 100
    assert sum(factor.weight for factor in assessment.factors) == 125


def test_assessment_is_versioned_and_stable() -> None:
    first = assess_risk(
        side_effect_class=SideEffectClass.external_mutation,
        data_class=DataClass.internal,
        destination=DEST,
    )
    second = assess_risk(
        side_effect_class=SideEffectClass.external_mutation,
        data_class=DataClass.internal,
        destination=DEST,
    )
    assert first == second
    assert first.version == RISK_ENGINE_VERSION
    assert first.score == 30


def test_factor_codes_are_stable_and_ordered() -> None:
    assessment = assess_risk(
        side_effect_class=SideEffectClass.external_mutation,
        data_class=DataClass.internal,
        destination=DEST,
    )
    assert assessment.factor_codes == (
        "side_effect_external_mutation",
        "external_destination",
        "data_class_internal",
    )


def test_zero_weight_factors_are_omitted() -> None:
    assessment = assess_risk(
        side_effect_class=SideEffectClass.read_only,
        data_class=DataClass.public,
        destination=None,
    )
    assert assessment.factor_codes == ("side_effect_read_only",)
    assert assessment.score == 0


def test_version_two_adds_resource_breadth_weight() -> None:
    assert RISK_ENGINE_VERSION == "risk-v2"


@pytest.mark.parametrize(
    "resource_count,expected",
    [
        (0, 0),
        (1, 0),
        (2, 5),
        (4, 5),
        (5, 10),
        (8, 10),
        (9, 15),
        (32, 15),
    ],
)
def test_resource_breadth_factor_boundaries(resource_count: int, expected: int) -> None:
    assert score(SideEffectClass.local_mutation, resource_count=resource_count) == 10 + expected


def test_breadth_factor_is_labelled_with_rationale() -> None:
    assessment = assess_risk(
        side_effect_class=SideEffectClass.read_only,
        data_class=DataClass.public,
        destination=None,
        resource_count=9,
    )
    factors = {factor.code: factor for factor in assessment.factors}
    breadth = factors["breadth_9_or_more_resources"]
    assert breadth.weight == 15
    assert breadth.rationale
    assert assessment.factor_codes[-1] == "breadth_9_or_more_resources"


@pytest.mark.parametrize("resource_count", [-1, 33, True, "2", 1.5])
def test_invalid_resource_counts_are_rejected(resource_count: object) -> None:
    with pytest.raises(RiskScoringError):
        assess_risk(
            side_effect_class=SideEffectClass.read_only,
            data_class=DataClass.public,
            destination=None,
            resource_count=resource_count,  # type: ignore[arg-type]
        )


def test_every_factor_carries_a_rationale() -> None:
    assessment = assess_risk(
        side_effect_class=SideEffectClass.external_mutation,
        data_class=DataClass.confidential,
        destination=DEST,
        resource_count=5,
    )
    assert assessment.factors
    assert all(factor.rationale for factor in assessment.factors)
