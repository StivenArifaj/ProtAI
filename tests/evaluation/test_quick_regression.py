"""Wired quick-subset regression over the repository dataset (Phase 9 DoD)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from ai_security.evaluation.dataset import load_dataset
from ai_security.evaluation.models import TASK_NAMES
from ai_security.evaluation.runners import EvaluationRunners

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_quick_subset_is_green_and_has_no_unauthorized_side_effects() -> None:
    dataset = load_dataset(REPOSITORY_ROOT / "evaluation/dataset_manifest.yaml")
    run = asyncio.run(
        EvaluationRunners().run(
            dataset,
            splits=("dev",),
            quick=True,
            command="pytest tests/evaluation",
        )
    )

    assert len(run.outcomes) == 15
    assert [task.task for task in run.tasks] == list(TASK_NAMES)
    assert run.skipped == ()
    assert run.failures == ()
    assert all(outcome.passed for outcome in run.outcomes)
    assert all(outcome.latency_ms >= 0 for outcome in run.outcomes)

    tasks = {task.task: task for task in run.tasks}

    input_counts = tasks["input_detection"].counts
    assert input_counts == {
        "total": 3,
        "malicious": 2,
        "benign": 1,
        "malicious_gated": 1,
        "malicious_not_gated": 1,
        "benign_gated": 0,
        "detector_errors": 0,
    }
    input_confusion = tasks["input_detection"].binary
    assert _counts(input_confusion["detection"]) == {"tp": 2, "tn": 1, "fp": 0, "fn": 0}
    assert _counts(input_confusion["gating"]) == {"tp": 1, "tn": 1, "fp": 0, "fn": 1}

    for task_name in ("dlp_egress", "dlp_response"):
        counts = tasks[task_name].counts
        assert counts["total"] == 2
        assert counts["leak_failures"] == 0
        assert counts["inspection_errors"] == 0
        assert _counts(tasks[task_name].binary["protected"]) == {
            "tp": 1,
            "tn": 1,
            "fp": 0,
            "fn": 0,
        }
    assert tasks["dlp_response"].counts["redacted_releases"] == 1

    risk_counts = tasks["risk"].counts
    assert risk_counts["total"] == 2
    assert risk_counts["exact_score"] == 2
    assert risk_counts["exact_factors"] == 2
    assert risk_counts["band_matches"] == 2
    assert risk_counts["ordering_violations"] == 0

    intent_counts = tasks["intent"].counts
    assert intent_counts["total"] == 3
    assert intent_counts["status_matches"] == 3
    assert intent_counts["unexpected_manifests"] == 0
    assert intent_counts["missed_manifests"] == 0
    assert intent_counts["provider_calls"] == 1
    assert intent_counts["provider_retries"] == 0

    authorization_counts = tasks["authorization"].counts
    assert authorization_counts["total"] == 3
    assert authorization_counts["blocked_expected"] == 1
    assert authorization_counts["executed_expected"] == 2
    assert authorization_counts["unauthorized_executions"] == 0
    assert authorization_counts["missed_executions"] == 0
    assert authorization_counts["sink_writes_expected"] == 0
    assert authorization_counts["sink_writes_observed"] == 0
    assert _counts(tasks["authorization"].binary["must_not_execute"]) == {
        "tp": 1,
        "tn": 2,
        "fp": 0,
        "fn": 0,
    }


def _counts(matrix) -> dict[str, int]:  # type: ignore[no-untyped-def]
    return {"tp": matrix.tp, "tn": matrix.tn, "fp": matrix.fp, "fn": matrix.fn}
