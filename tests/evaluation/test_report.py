"""Report construction and rendering tests (blueprint section 19.6)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from ai_security.evaluation.dataset import load_dataset
from ai_security.evaluation.report import build_report, render_markdown, write_reports
from ai_security.evaluation.runners import EvaluationRunners


def _quick_dev_run(dataset_builder):  # type: ignore[no-untyped-def]
    dataset = load_dataset(dataset_builder().write())
    return asyncio.run(
        EvaluationRunners().run(dataset, splits=("dev",), quick=True, command="pytest report")
    )


def test_report_contains_required_metadata_and_task_blocks(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    report = build_report(_quick_dev_run(dataset_builder))

    assert report["schema_version"] == 1
    assert report["report_type"] == "protai-evaluation"
    metadata = report["metadata"]
    for key in (
        "generated_at",
        "command",
        "seed",
        "git",
        "environment",
        "configuration",
        "uv_lock_sha256",
    ):
        assert key in metadata
    assert metadata["command"] == "pytest report"
    assert metadata["configuration"]["policy_version"]
    assert metadata["configuration"]["risk_engine_version"]

    assert report["dataset"]["selected_cases"] == 6
    assert report["dataset"]["total_cases"] == 8
    assert report["dataset"]["splits"] == ["dev"]
    assert report["dataset"]["quick"] is True

    summary = report["summary"]
    assert summary["tasks_run"] == [
        "input_detection",
        "dlp_egress",
        "dlp_response",
        "risk",
        "intent",
        "authorization",
    ]
    assert summary["tasks_skipped"] == []
    assert summary["case_count"] == 6
    assert summary["failed_cases"] == 0
    assert summary["unauthorized_side_effects"] == 0
    # The minimal dataset has no must-not-execute case, so the rate denominator is zero.
    assert summary["unauthorized_side_effect_rate"] is None
    assert summary["dlp_leak_failures"] == 0
    assert summary["intent_unexpected_manifests"] == 0
    assert summary["input_detector_errors"] == 0
    assert report["failures"] == []
    assert report["skipped_tests"] == []
    assert report["limitations"]
    assert "precision" in report["metric_definitions"]

    tasks = {task["task"]: task for task in report["tasks"]}
    assert set(tasks) == {
        "input_detection",
        "dlp_egress",
        "dlp_response",
        "risk",
        "intent",
        "authorization",
    }
    assert set(tasks["input_detection"]["confusion"]) == {"detection", "gating"}
    assert tasks["input_detection"]["confusion"]["gating"]["counts"] == {
        "tp": 0,
        "tn": 1,
        "fp": 0,
        "fn": 0,
    }
    # No predicted positives in this slice: precision/recall are undefined, not zero.
    assert tasks["input_detection"]["confusion"]["gating"]["metrics"]["precision"] is None
    assert tasks["input_detection"]["confusion"]["gating"]["metrics"]["recall"] is None
    assert tasks["authorization"]["confusion"]["must_not_execute"]["counts"] == {
        "tp": 0,
        "tn": 1,
        "fp": 0,
        "fn": 0,
    }
    assert tasks["risk"]["derived"]["exact_score_rate"] == 1.0


def test_markdown_is_derived_from_report_values(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    report = build_report(_quick_dev_run(dataset_builder))

    markdown = render_markdown(report)

    assert markdown.startswith("# ProtAI evaluation report")
    assert "## Headline" in markdown
    assert "## Confusion matrices" in markdown
    assert "## Metric definitions" in markdown
    assert "| `overall` | 0 | 1 | 0 | 0 | N/A | N/A | N/A |" in markdown
    assert "No failed cases." in markdown
    assert "None." in markdown
    assert f"`{report['dataset']['version']}`" in markdown


def test_write_reports_persists_matching_json_and_markdown(
    dataset_builder,
    tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    run = _quick_dev_run(dataset_builder)
    report = build_report(run)
    output = tmp_path / "reports"

    json_path, markdown_path = write_reports(run, output, report_name="custom")

    assert json_path == output / "custom.json"
    assert markdown_path == output / "custom.md"
    assert json.loads(json_path.read_text(encoding="utf-8")) == report
    assert markdown_path.read_text(encoding="utf-8") == render_markdown(report)


@pytest.mark.parametrize("name", ["", "../escape", "nested/report", "nested\\report", ".hidden"])
def test_write_reports_rejects_unsafe_names(dataset_builder, tmp_path: Path, name: str) -> None:  # type: ignore[no-untyped-def]
    run = _quick_dev_run(dataset_builder)
    with pytest.raises(ValueError, match="plain file stem"):
        write_reports(run, tmp_path, report_name=name)


def test_failed_case_is_reported_in_summary_task_and_markdown(
    dataset_builder,
    tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    builder = dataset_builder()
    builder.cases["input_detection"][0]["expected_malicious"] = True
    run = asyncio.run(
        EvaluationRunners().run(
            load_dataset(builder.write()), splits=("dev",), quick=True, command="pytest"
        )
    )

    report = build_report(run)
    markdown = render_markdown(report)

    assert report["summary"]["failed_cases"] == 1
    assert report["failures"][0]["case_id"] == "in-dev-benign-01"
    assert report["failures"][0]["expected"] == "MALICIOUS"
    tasks = {task["task"]: task for task in report["tasks"]}
    assert len(tasks["input_detection"]["failures"]) == 1
    assert "`in-dev-benign-01`" in markdown
    assert "MALICIOUS" in markdown
    assert "| `overall` | 0 | 0 | 0 | 1 | N/A | 0.000 | N/A | 0.000 | N/A | 1.000 |" in markdown
