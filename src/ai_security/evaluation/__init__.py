"""Reproducible evaluation harness (blueprint section 19; Phase 9).

The package measures existing behavior only. It never adds an execution path, never
changes policy, and never grants authority: every task runner constructs the same
services and mocks used by the shipped code, observes typed outcomes, and reports
confusion matrices, latencies, and security-critical failures.

Public entry point: ``python -m ai_security.evaluation`` (see ``cli.py``).
"""

from __future__ import annotations

from .metrics import (
    BinaryMetrics,
    ConfusionMatrix,
    LatencySummary,
    binary_metrics_from_labels,
    confusion_from_labels,
    latency_summary,
)
from .models import (
    DatasetManifest,
    EvaluationCase,
    Split,
    Task,
)

__all__ = [
    "BinaryMetrics",
    "ConfusionMatrix",
    "DatasetManifest",
    "EvaluationCase",
    "LatencySummary",
    "Split",
    "Task",
    "binary_metrics_from_labels",
    "confusion_from_labels",
    "latency_summary",
]
