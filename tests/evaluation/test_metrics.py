"""Hand-calculated metric tests (blueprint section 19.3)."""

from __future__ import annotations

import pytest

from ai_security.evaluation.metrics import (
    ConfusionMatrix,
    binary_metrics_from_labels,
    confusion_from_labels,
    latency_summary,
    multiclass_counts,
    rate,
)
from ai_security.evaluation.runners import missed_execution_rate, unauthorized_side_effect_rate


def test_confusion_matrix_and_metrics_match_hand_calculation() -> None:
    expected = [True, True, True, False, False, False, False]
    observed = [True, False, True, False, True, False, False]
    matrix = confusion_from_labels(expected, observed)
    assert (matrix.tp, matrix.tn, matrix.fp, matrix.fn) == (2, 3, 1, 1)
    assert matrix.total == 7
    assert matrix.positives == 3
    assert matrix.negatives == 4

    metrics = matrix.metrics()
    assert metrics.precision == pytest.approx(2 / 3)
    assert metrics.recall == pytest.approx(2 / 3)
    assert metrics.f1 == pytest.approx(2 / 3)
    assert metrics.accuracy == pytest.approx(5 / 7)
    assert metrics.false_positive_rate == pytest.approx(1 / 4)
    assert metrics.false_negative_rate == pytest.approx(1 / 3)
    assert metrics.false_negative_rate == pytest.approx(1 - metrics.recall)


def test_undefined_denominators_are_none_not_zero() -> None:
    matrix = ConfusionMatrix()
    metrics = matrix.metrics()
    assert metrics.precision is None
    assert metrics.recall is None
    assert metrics.f1 is None
    assert metrics.accuracy is None
    assert metrics.false_positive_rate is None
    assert metrics.false_negative_rate is None


def test_zero_precision_with_observed_positives_keeps_f1_zero() -> None:
    # TP=0, FP=2 gives precision 0; FN=1 gives recall 0; both are defined.
    metrics = ConfusionMatrix(tp=0, fp=2, fn=1, tn=1).metrics()
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1 == 0.0
    assert metrics.accuracy == pytest.approx(1 / 4)


def test_undefined_precision_makes_f1_undefined_even_with_recall() -> None:
    # No predicted positives: precision is undefined (0/0) while recall is defined (0.0).
    metrics = ConfusionMatrix(tp=0, fn=2, fp=0, tn=0).metrics()
    assert metrics.precision is None
    assert metrics.recall == 0.0
    assert metrics.f1 is None
    assert metrics.accuracy == 0.0
    assert metrics.false_positive_rate is None
    assert metrics.false_negative_rate == 1.0


def test_confusion_rejects_mismatched_lengths_and_non_booleans() -> None:
    with pytest.raises(ValueError):
        confusion_from_labels([True], [True, False])
    with pytest.raises(TypeError):
        confusion_from_labels([1], [True])  # type: ignore[list-item]


def test_confusion_counts_must_be_non_negative_integers() -> None:
    with pytest.raises(ValueError):
        ConfusionMatrix(tp=-1)
    with pytest.raises(ValueError):
        ConfusionMatrix(tp=True)  # type: ignore[arg-type]


def test_binary_metrics_wrapper_matches_matrix_metrics() -> None:
    wrapped = binary_metrics_from_labels([True, False], [False, False])
    matrix = ConfusionMatrix(tp=0, fn=1, tn=1, fp=0).metrics()
    assert wrapped == matrix


def test_nearest_rank_latency_percentiles() -> None:
    summary = latency_summary([10, 1, 9, 2, 8, 3, 7, 4, 6, 5])
    assert summary.count == 10
    assert summary.p50 == 5
    assert summary.p95 == 10
    assert summary.p99 == 10
    assert summary.mean == pytest.approx(5.5)
    assert summary.minimum == 1
    assert summary.maximum == 10


def test_nearest_rank_uses_ceiling_rank() -> None:
    summary = latency_summary([float(value) for value in range(1, 21)])
    assert summary.p50 == 10
    assert summary.p95 == 19
    assert summary.p99 == 20


def test_empty_latency_summary_is_all_none() -> None:
    summary = latency_summary([])
    assert summary.count == 0
    assert summary.p50 is None
    assert summary.p95 is None
    assert summary.p99 is None
    assert summary.mean is None
    assert summary.minimum is None
    assert summary.maximum is None


def test_multiclass_counts_include_zero_filled_union_labels() -> None:
    matrix = multiclass_counts(
        ["ACTIVE", "ACTIVE", "REJECTED"], ["ACTIVE", "INVALID_EXTRACTION", "REJECTED"]
    )
    assert matrix == {
        "ACTIVE": {"ACTIVE": 1, "INVALID_EXTRACTION": 1, "REJECTED": 0},
        "INVALID_EXTRACTION": {"ACTIVE": 0, "INVALID_EXTRACTION": 0, "REJECTED": 0},
        "REJECTED": {"ACTIVE": 0, "INVALID_EXTRACTION": 0, "REJECTED": 1},
    }


def test_multiclass_counts_reject_mismatched_lengths() -> None:
    with pytest.raises(ValueError):
        multiclass_counts(["A"], ["A", "B"])


def test_rate_has_none_for_zero_denominator() -> None:
    assert rate(1, 4) == 0.25
    assert rate(0, 4) == 0.0
    assert rate(0, 0) is None


def test_authorization_rates_match_hand_calculation() -> None:
    counts = {
        "unauthorized_executions": 1,
        "blocked_expected": 5,
        "missed_executions": 2,
        "executed_expected": 3,
    }
    assert unauthorized_side_effect_rate(counts) == pytest.approx(1 / 5)
    assert missed_execution_rate(counts) == pytest.approx(2 / 3)
    assert unauthorized_side_effect_rate({"unauthorized_executions": 1}) is None
    assert missed_execution_rate({"blocked_expected": 3}) is None
