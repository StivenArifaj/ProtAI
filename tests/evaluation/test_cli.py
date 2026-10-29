"""CLI reproduction tests: one command, verified dataset, exit codes (section 19.2)."""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

import pytest

from ai_security.evaluation.cli import main

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPOSITORY_ROOT / "evaluation/dataset_manifest.yaml"


def test_quick_cli_run_writes_reports_and_exits_zero(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    output = tmp_path / "reports"

    exit_code = main(
        [
            "--dataset",
            str(MANIFEST),
            "--output-dir",
            str(output),
            "--split",
            "dev",
            "--quick",
            "--report-name",
            "quick_report",
            "--fail-on-failures",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "ran 15 case(s) across 6 task(s); 0 failed expectation(s)" in captured.out
    assert "0 unauthorized side effect(s), rate=0.000" in captured.out

    report = json.loads((output / "quick_report.json").read_text(encoding="utf-8"))
    assert report["dataset"]["quick"] is True
    assert report["dataset"]["splits"] == ["dev"]
    assert report["dataset"]["selected_cases"] == 15
    assert report["dataset"]["total_cases"] == 106
    assert report["summary"]["failed_cases"] == 0
    assert report["summary"]["unauthorized_side_effects"] == 0
    assert report["summary"]["tasks_skipped"] == []
    assert report["metadata"]["command"].endswith(
        "--split dev --quick --report-name quick_report --fail-on-failures"
    )
    assert (output / "quick_report.md").is_file()


def test_module_style_invocation_records_the_actual_arguments(
    dataset_builder,
    tmp_path: Path,
    monkeypatch,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    builder = dataset_builder()
    manifest = builder.write()
    output = tmp_path / "reports"
    arguments = [
        "--dataset",
        str(manifest),
        "--output-dir",
        str(output),
        "--split",
        "dev",
        "--quick",
        "--report-name",
        "module_style",
    ]
    monkeypatch.setattr(sys, "argv", ["ai-security-evaluation", *arguments])

    exit_code = main(None)

    assert exit_code == 0
    capsys.readouterr()
    report = json.loads((output / "module_style.json").read_text(encoding="utf-8"))
    assert report["metadata"]["command"] == (
        "python -m ai_security.evaluation " + shlex.join(arguments)
    )


def test_missing_dataset_exits_one_without_writing(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(
        [
            "--dataset",
            str(tmp_path / "missing.yaml"),
            "--output-dir",
            str(tmp_path / "reports"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "dataset error:" in captured.out
    assert not (tmp_path / "reports").exists()


def test_quick_without_dev_split_is_usage_error() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--dataset", str(MANIFEST), "--quick"])
    assert excinfo.value.code == 2


def test_fail_on_failures_returns_two_for_a_failed_expectation(
    dataset_builder,
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    builder = dataset_builder()
    builder.cases["input_detection"][0]["expected_malicious"] = True
    manifest = builder.write()
    output = tmp_path / "reports"

    exit_code = main(
        [
            "--dataset",
            str(manifest),
            "--output-dir",
            str(output),
            "--split",
            "dev",
            "--quick",
            "--report-name",
            "failing",
            "--fail-on-failures",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "1 failed expectation(s)" in captured.out
    report = json.loads((output / "failing.json").read_text(encoding="utf-8"))
    assert report["summary"]["failed_cases"] == 1
    assert report["failures"][0]["case_id"] == "in-dev-benign-01"
