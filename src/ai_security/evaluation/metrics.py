"""Metric primitives with explicit undefined-value semantics (blueprint section 19.3).

Every binary task declares its positive class at the call site. A confusion matrix is
counts only; metric properties return ``None`` when the denominator is zero. ``None``
serializes to ``null`` in JSON and ``N/A`` in Markdown — never a misleading zero.

Latency percentiles use the nearest-rank method over the observed samples. They describe
the local in-process evaluation environment only; they are not production latency.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class BinaryMetrics:
    """Binary metrics; ``None`` means the denominator was zero (report as ``N/A``)."""

    precision: float | None
    recall: float | None
    f1: float | None
    accuracy: float | None
    false_positive_rate: float | None
    false_negative_rate: float | None


@dataclass(frozen=True)
class ConfusionMatrix:
    """Counts for one declared positive class.

    ``tp``/``fn`` are positive cases observed positive/negative; ``fp``/``tn`` are
    negative cases observed positive/negative.
    """

    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0

    def __post_init__(self) -> None:
        for name in ("tp", "tn", "fp", "fn"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")

    @property
    def total(self) -> int:
        return self.tp + self.tn + self.fp + self.fn

    @property
    def positives(self) -> int:
        return self.tp + self.fn

    @property
    def negatives(self) -> int:
        return self.fp + self.tn

    def metrics(self) -> BinaryMetrics:
        tp, tn, fp, fn = self.tp, self.tn, self.fp, self.fn
        precision = _ratio(tp, tp + fp)
        recall = _ratio(tp, tp + fn)
        f1: float | None
        if precision is None or recall is None:
            f1 = None
        elif precision + recall == 0:
            # Both metrics are defined and zero; the conventional F1 value is zero.
            f1 = 0.0
        else:
            f1 = 2 * precision * recall / (precision + recall)
        return BinaryMetrics(
            precision=precision,
            recall=recall,
            f1=f1,
            accuracy=_ratio(tp + tn, self.total),
            false_positive_rate=_ratio(fp, fp + tn),
            false_negative_rate=_ratio(fn, tp + fn),
        )


@dataclass(frozen=True)
class LatencySummary:
    """Nearest-rank latency summary in milliseconds (in-process only)."""

    count: int
    p50: float | None
    p95: float | None
    p99: float | None
    mean: float | None
    minimum: float | None
    maximum: float | None


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def confusion_from_labels(
    expected_positive: Iterable[bool], observed_positive: Iterable[bool]
) -> ConfusionMatrix:
    """Build a confusion matrix from aligned label sequences."""
    expected = tuple(expected_positive)
    observed = tuple(observed_positive)
    if len(expected) != len(observed):
        raise ValueError("expected and observed label sequences must have equal length")
    tp = tn = fp = fn = 0
    for expected_value, observed_value in zip(expected, observed, strict=True):
        if not isinstance(expected_value, bool) or not isinstance(observed_value, bool):
            raise TypeError("confusion labels must be booleans")
        if expected_value and observed_value:
            tp += 1
        elif expected_value and not observed_value:
            fn += 1
        elif not expected_value and observed_value:
            fp += 1
        else:
            tn += 1
    return ConfusionMatrix(tp=tp, tn=tn, fp=fp, fn=fn)


def binary_metrics_from_labels(
    expected_positive: Iterable[bool], observed_positive: Iterable[bool]
) -> BinaryMetrics:
    """Convenience wrapper: confusion matrix followed by metric derivation."""
    return confusion_from_labels(expected_positive, observed_positive).metrics()


def latency_summary(samples_ms: Sequence[float]) -> LatencySummary:
    """Summarize observed latencies using nearest-rank percentiles."""
    samples = tuple(float(sample) for sample in samples_ms)
    if not samples:
        return LatencySummary(
            count=0, p50=None, p95=None, p99=None, mean=None, minimum=None, maximum=None
        )
    ordered = sorted(samples)
    count = len(ordered)
    return LatencySummary(
        count=count,
        p50=_nearest_rank(ordered, 50),
        p95=_nearest_rank(ordered, 95),
        p99=_nearest_rank(ordered, 99),
        mean=sum(ordered) / count,
        minimum=ordered[0],
        maximum=ordered[-1],
    )


def _nearest_rank(ordered: Sequence[float], percentile: int) -> float:
    if not ordered:  # pragma: no cover - guarded by latency_summary
        raise ValueError("at least one sample is required")
    if not 0 < percentile <= 100:
        raise ValueError("percentile must be in (0, 100]")
    rank = max(1, math.ceil(percentile / 100 * len(ordered)))
    return ordered[rank - 1]


def multiclass_counts(
    expected: Sequence[str], observed: Sequence[str]
) -> dict[str, dict[str, int]]:
    """Sparse multiclass confusion counts keyed by expected then observed label."""
    if len(expected) != len(observed):
        raise ValueError("expected and observed label sequences must have equal length")
    labels = sorted(set(expected) | set(observed))
    matrix = {label: dict.fromkeys(labels, 0) for label in labels}
    for expected_value, observed_value in zip(expected, observed, strict=True):
        matrix[expected_value][observed_value] += 1
    return matrix


def rate(numerator: int, denominator: int) -> float | None:
    """A count ratio with the same ``N/A`` semantics as binary metrics."""
    if denominator == 0:
        return None
    return numerator / denominator


__all__ = [
    "BinaryMetrics",
    "ConfusionMatrix",
    "LatencySummary",
    "binary_metrics_from_labels",
    "confusion_from_labels",
    "latency_summary",
    "multiclass_counts",
    "rate",
]
