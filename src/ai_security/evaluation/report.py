"""Machine-readable and human-readable evaluation reports (blueprint section 19.6).

The JSON report is the authoritative artifact; the Markdown summary is derived from the
same in-memory values. Metric values are computed here from confusion counts, never
typed in by hand. An undefined denominator is serialized as ``null`` in JSON and ``N/A``
in Markdown, never as a misleading zero.

Every JSON report carries the run metadata (git commit, lock hash, Python/platform,
dataset identity, policy/detector/engine versions, thresholds, seed, timestamp), the
per-task and per-category confusion matrices, latency percentiles with the sample count,
failures/retries, unauthorized side effects, skipped tasks, and known limitations.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .metrics import ConfusionMatrix
from .runners import (
    EvaluationRun,
    TaskResult,
    missed_execution_rate,
    unauthorized_side_effect_rate,
)

REPORT_SCHEMA_VERSION = 1
REPORT_JSON_NAME = "evaluation_report.json"
REPORT_MARKDOWN_NAME = "evaluation_report.md"

METRIC_DEFINITIONS: Mapping[str, str] = {
    "positive_class": (
        "Declared per task/block. TP is an expected-positive case observed positive; FN "
        "is expected positive observed negative; FP is expected negative observed "
        "positive; TN is expected negative observed negative."
    ),
    "precision": "TP / (TP + FP); undefined (N/A) when TP + FP = 0.",
    "recall": "TP / (TP + FN); undefined (N/A) when TP + FN = 0.",
    "f1": (
        "2 * precision * recall / (precision + recall); undefined when either component "
        "is undefined, and 0.0 when both are defined and zero."
    ),
    "accuracy": "(TP + TN) / total; undefined (N/A) when the sample count is zero.",
    "false_positive_rate": "FP / (FP + TN); undefined (N/A) when FP + TN = 0.",
    "false_negative_rate": (
        "FN / (TP + FN); undefined (N/A) when TP + FN = 0. For the authorization "
        "must-not-execute block this is the unauthorized side-effect rate."
    ),
    "latency": (
        "Nearest-rank p50/p95/p99 over in-process wall-clock samples. It is not "
        "production latency and no throughput claim is made."
    ),
}

_POSITIVE_CLASSES: Mapping[tuple[str, str], str] = {
    ("input_detection", "detection"): "malicious or unauthorized input",
    ("input_detection", "gating"): ("malicious input that must be gated (REJECT or QUARANTINE)"),
    ("dlp_egress", "protected"): (
        "protected content that must not egress to the declared destination"
    ),
    ("dlp_response", "protected"): ("protected content that must not be released unmodified"),
    ("authorization", "must_not_execute"): (
        "an action that must not execute; an executed positive case is an unauthorized side effect"
    ),
}


def build_report(run: EvaluationRun) -> dict[str, Any]:
    """Build the authoritative JSON-compatible report structure."""
    task_reports = [_task_report(task) for task in run.tasks]
    summary = _summary(run)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": "protai-evaluation",
        "metadata": _json_safe(asdict(run.metadata)),
        "dataset": {
            "version": run.metadata.dataset_version,
            "manifest_sha256": run.metadata.dataset_manifest_sha256,
            "split_file_sha256": run.metadata.split_file_sha256,
            "splits": list(run.metadata.splits),
            "quick": run.metadata.quick,
            "selected_cases": run.metadata.selected_cases,
            "total_cases": run.metadata.total_cases,
        },
        "metric_definitions": dict(METRIC_DEFINITIONS),
        "summary": summary,
        "tasks": task_reports,
        "failures": [_json_safe(asdict(outcome)) for outcome in run.failures],
        "skipped_tests": list(run.skipped),
        "limitations": list(run.limitations),
        "reproduce": {
            "command": run.metadata.command,
            "quick_subset_is_partial": run.metadata.quick,
        },
    }


def _task_report(task: TaskResult) -> dict[str, Any]:
    blocks: dict[str, dict[str, Any]] = {}
    for name, matrix in task.binary.items():
        base, category = _split_matrix_name(name)
        block = blocks.setdefault(
            base,
            {
                "positive_class": _positive_class(task.task, base),
                "counts": None,
                "metrics": None,
                "categories": {},
            },
        )
        entry = {
            "counts": _matrix_counts(matrix),
            "metrics": _matrix_metrics(matrix),
        }
        if category is None:
            block["counts"] = entry["counts"]
            block["metrics"] = entry["metrics"]
        else:
            cast_categories: dict[str, Any] = block["categories"]
            cast_categories[category] = entry
    missing_overall = sorted(name for name, block in blocks.items() if block["counts"] is None)
    if missing_overall:
        raise ValueError("confusion block(s) without overall counts: " + ", ".join(missing_overall))

    return {
        "task": task.task,
        "case_count": task.case_count,
        "latency_ms": _json_safe(asdict(task.latency)),
        "confusion": blocks,
        "counts": dict(task.counts),
        "derived": _derived(task),
        "details": _json_safe(task.details),
        "failures": [
            _json_safe(asdict(outcome)) for outcome in task.outcomes if not outcome.passed
        ],
    }


def _summary(run: EvaluationRun) -> dict[str, Any]:
    authorization = next((task for task in run.tasks if task.task == "authorization"), None)
    intent = next((task for task in run.tasks if task.task == "intent"), None)
    dlp = [task for task in run.tasks if task.task in {"dlp_egress", "dlp_response"}]
    input_task = next((task for task in run.tasks if task.task == "input_detection"), None)
    return {
        "tasks_run": [task.task for task in run.tasks],
        "tasks_skipped": list(run.skipped),
        "case_count": len(run.outcomes),
        "failed_cases": len(run.failures),
        "failed_case_rate": _ratio(len(run.failures), len(run.outcomes)),
        "unauthorized_side_effects": (
            authorization.counts.get("unauthorized_executions", 0)
            if authorization is not None
            else None
        ),
        "unauthorized_side_effect_rate": (
            unauthorized_side_effect_rate(authorization.counts)
            if authorization is not None
            else None
        ),
        "dlp_leak_failures": sum(task.counts.get("leak_failures", 0) for task in dlp),
        "intent_unexpected_manifests": (
            intent.counts.get("unexpected_manifests", 0) if intent is not None else None
        ),
        "intent_provider_calls": (
            intent.counts.get("provider_calls", 0) if intent is not None else None
        ),
        "intent_provider_retries": (
            intent.counts.get("provider_retries", 0) if intent is not None else None
        ),
        "input_detector_errors": (
            input_task.counts.get("detector_errors", 0) if input_task is not None else None
        ),
    }


def _derived(task: TaskResult) -> dict[str, Any]:
    counts = task.counts
    if task.task == "input_detection":
        return {
            "malicious_gate_rate": _ratio(
                counts.get("malicious_gated", 0), counts.get("malicious", 0)
            ),
            "benign_gate_rate": _ratio(counts.get("benign_gated", 0), counts.get("benign", 0)),
        }
    if task.task in {"dlp_egress", "dlp_response"}:
        return {
            "leak_failure_rate": _ratio(counts.get("leak_failures", 0), counts.get("total", 0)),
            "inspection_error_rate": _ratio(
                counts.get("inspection_errors", 0), counts.get("total", 0)
            ),
        }
    if task.task == "risk":
        return {
            "exact_score_rate": _ratio(counts.get("exact_score", 0), counts.get("total", 0)),
            "exact_factor_rate": _ratio(counts.get("exact_factors", 0), counts.get("total", 0)),
            "band_match_rate": _ratio(counts.get("band_matches", 0), counts.get("total", 0)),
            "ordering_violation_count": counts.get("ordering_violations", 0),
        }
    if task.task == "intent":
        return {
            "status_match_rate": _ratio(counts.get("status_matches", 0), counts.get("total", 0)),
            "unexpected_manifest_rate": _ratio(
                counts.get("unexpected_manifests", 0),
                counts.get("expected_non_active", 0),
            ),
            "missed_manifest_rate": _ratio(
                counts.get("missed_manifests", 0), counts.get("expected_active", 0)
            ),
            "constraint_mismatch_rate": _ratio(
                counts.get("constraint_mismatches", 0), counts.get("expected_active", 0)
            ),
            "provider_retry_rate": _ratio(
                counts.get("provider_retries", 0), counts.get("provider_calls", 0)
            ),
        }
    if task.task == "authorization":
        return {
            "unauthorized_side_effect_count": counts.get("unauthorized_executions", 0),
            "unauthorized_side_effect_rate": unauthorized_side_effect_rate(counts),
            "missed_execution_rate": missed_execution_rate(counts),
            "sink_write_mismatch": (
                counts.get("sink_writes_observed", 0) - counts.get("sink_writes_expected", 0)
            ),
        }
    return {}


def _positive_class(task: str, block: str) -> str:
    return _POSITIVE_CLASSES.get((task, block), f"declared positive class for {task}/{block}")


def _split_matrix_name(name: str) -> tuple[str, str | None]:
    marker = "/category/"
    if marker in name:
        base, category = name.split(marker, 1)
        return base, category
    return name, None


def _matrix_counts(matrix: ConfusionMatrix) -> dict[str, int]:
    return {"tp": matrix.tp, "tn": matrix.tn, "fp": matrix.fp, "fn": matrix.fn}


def _matrix_metrics(matrix: ConfusionMatrix) -> dict[str, float | None]:
    metrics = matrix.metrics()
    return {
        "precision": metrics.precision,
        "recall": metrics.recall,
        "f1": metrics.f1,
        "accuracy": metrics.accuracy,
        "false_positive_rate": metrics.false_positive_rate,
        "false_negative_rate": metrics.false_negative_rate,
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def _json_safe(value: object) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return _json_safe(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def render_markdown(report: Mapping[str, Any]) -> str:
    """Render a deterministic human-readable summary from the JSON report values."""
    metadata = _expect_mapping(report["metadata"], "metadata")
    dataset = _expect_mapping(report["dataset"], "dataset")
    summary = _expect_mapping(report["summary"], "summary")
    tasks = _expect_list(report["tasks"], "tasks")
    failures = _expect_list(report["failures"], "failures")
    skipped = _expect_list(report["skipped_tests"], "skipped_tests")
    limitations = _expect_list(report["limitations"], "limitations")

    git = _expect_mapping(metadata.get("git"), "metadata.git")
    configuration = _expect_mapping(metadata.get("configuration"), "metadata.configuration")
    environment = _expect_mapping(metadata.get("environment"), "metadata.environment")

    lines: list[str] = []
    lines.append("# ProtAI evaluation report")
    lines.append("")
    lines.append(f"- Generated: `{metadata.get('generated_at')}`")
    lines.append(f"- Dataset: `{dataset.get('version')}` (seed `{metadata.get('seed')}`)")
    lines.append(
        f"- Cases: {dataset.get('selected_cases')} selected / "
        f"{dataset.get('total_cases')} total; splits: "
        + ", ".join(f"`{split}`" for split in _expect_list(dataset.get("splits"), "splits"))
    )
    lines.append(f"- Quick subset: {'yes (partial)' if dataset.get('quick') else 'no'}")
    lines.append(f"- Git commit: `{git.get('commit')}` on branch `{git.get('branch')}`")
    lines.append(
        f"- Policy: `{configuration.get('policy_version')}` "
        f"(`{_short(configuration.get('policy_hash'))}`); thresholds: "
        f"ASK_USER >= {configuration.get('ask_user_at_or_above')}, "
        f"BLOCK >= {configuration.get('block_at_or_above')}"
    )
    lines.append(
        f"- Python: {environment.get('python_version')} on "
        f"{environment.get('platform')} ({environment.get('machine')})"
    )
    lines.append(f"- Dependency lock sha256: `{metadata.get('uv_lock_sha256')}`")
    lines.append(f"- Command: `{_expect_mapping(report['reproduce'], 'reproduce').get('command')}`")
    lines.append("")

    lines.append("## Headline")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    for key in (
        "case_count",
        "failed_cases",
        "failed_case_rate",
        "unauthorized_side_effects",
        "unauthorized_side_effect_rate",
        "dlp_leak_failures",
        "intent_unexpected_manifests",
        "intent_provider_calls",
        "intent_provider_retries",
        "input_detector_errors",
    ):
        lines.append(f"| `{key}` | {_format_value(summary.get(key))} |")
    lines.append("")

    lines.append("## Tasks")
    lines.append("")
    lines.append("| Task | Cases | p50 ms | p95 ms | p99 ms | Failed |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for task_value in tasks:
        task = _expect_mapping(task_value, "task")
        latency = _expect_mapping(task.get("latency_ms"), "task.latency_ms")
        failed = len(_expect_list(task.get("failures"), "task.failures"))
        lines.append(
            f"| `{task.get('task')}` | {task.get('case_count')} | "
            f"{_format_value(latency.get('p50'))} | {_format_value(latency.get('p95'))} | "
            f"{_format_value(latency.get('p99'))} | {failed} |"
        )
    lines.append("")

    lines.append("## Confusion matrices")
    lines.append("")
    lines.append(
        "Positive classes are declared per block. `N/A` means the denominator is zero; "
        "it is never reported as zero."
    )
    lines.append("")
    for task_value in tasks:
        task = _expect_mapping(task_value, "task")
        lines.append(f"### {task.get('task')}")
        lines.append("")
        for block_name, block_value in _expect_mapping(
            task.get("confusion"), "task.confusion"
        ).items():
            block = _expect_mapping(block_value, f"confusion.{block_name}")
            lines.append(f"**{block_name}** — positive: {block.get('positive_class')}")
            lines.append("")
            lines.append(
                "| Slice | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR | FNR |"
            )
            lines.append(
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
            )
            lines.append(_matrix_row("overall", block))
            for category, entry_value in _expect_mapping(
                block.get("categories"), f"confusion.{block_name}.categories"
            ).items():
                entry = _expect_mapping(entry_value, "category")
                lines.append(_matrix_row(f"category/{category}", entry))
            lines.append("")

    lines.append("## Security-critical counts")
    lines.append("")
    for task_value in tasks:
        task = _expect_mapping(task_value, "task")
        if task.get("task") not in {"authorization", "intent", "input_detection", "risk"}:
            continue
        lines.append(f"### {task.get('task')}")
        lines.append("")
        lines.append("| Count | Value |")
        lines.append("| --- | ---: |")
        for name, value in _expect_mapping(task.get("counts"), "task.counts").items():
            lines.append(f"| `{name}` | {_format_value(value)} |")
        lines.append("")
        lines.append("| Derived | Value |")
        lines.append("| --- | ---: |")
        for name, value in _expect_mapping(task.get("derived"), "task.derived").items():
            lines.append(f"| `{name}` | {_format_value(value)} |")
        lines.append("")

    lines.append("## Failures")
    lines.append("")
    if failures:
        lines.append("| Case | Task | Category | Expected | Observed | Detail |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for failure_value in failures:
            failure = _expect_mapping(failure_value, "failure")
            lines.append(
                f"| `{failure.get('case_id')}` | `{failure.get('task')}` | "
                f"`{failure.get('category')}` | {_escape(failure.get('expected'))} | "
                f"{_escape(failure.get('observed'))} | {_escape(failure.get('detail'))} |"
            )
    else:
        lines.append("No failed cases.")
    lines.append("")

    lines.append("## Skipped tests")
    lines.append("")
    if skipped:
        for task in skipped:
            lines.append(f"- `{task}` had no selected cases and was not run.")
    else:
        lines.append("None.")
    lines.append("")

    lines.append("## Limitations")
    lines.append("")
    for limitation in limitations:
        lines.append(f"- {limitation}")
    lines.append("")

    lines.append("## Metric definitions")
    lines.append("")
    for name, definition in _expect_mapping(
        report.get("metric_definitions"), "metric_definitions"
    ).items():
        lines.append(f"- **{name}**: {definition}")
    lines.append("")
    return "\n".join(lines)


def _matrix_row(label: str, entry: Mapping[str, Any]) -> str:
    counts = _expect_mapping(entry.get("counts"), "matrix counts")
    metrics = _expect_mapping(entry.get("metrics"), "matrix metrics")
    return (
        f"| `{label}` | {counts.get('tp')} | {counts.get('tn')} | "
        f"{counts.get('fp')} | {counts.get('fn')} | "
        f"{_format_value(metrics.get('precision'))} | "
        f"{_format_value(metrics.get('recall'))} | "
        f"{_format_value(metrics.get('f1'))} | "
        f"{_format_value(metrics.get('accuracy'))} | "
        f"{_format_value(metrics.get('false_positive_rate'))} | "
        f"{_format_value(metrics.get('false_negative_rate'))} |"
    )


def _format_value(value: object) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def _escape(value: object) -> str:
    if value is None:
        return "N/A"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _short(value: object) -> str:
    text = str(value) if value is not None else "N/A"
    return text[:12] + "…" if len(text) > 12 else text


def _expect_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be a mapping")
    return value


def _expect_list(value: object, label: str) -> Sequence[Any]:
    if isinstance(value, (list, tuple)):
        return value
    raise ValueError(f"{label} must be a list")


def write_reports(
    run: EvaluationRun,
    output_dir: str | Path,
    *,
    report_name: str = "evaluation_report",
) -> tuple[Path, Path]:
    """Write ``<report_name>.json`` and ``<report_name>.md``; return both paths."""
    if not report_name or "/" in report_name or "\\" in report_name or report_name.startswith("."):
        raise ValueError("report_name must be a plain file stem")
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    report = build_report(run)
    json_path = directory / f"{report_name}.json"
    markdown_path = directory / f"{report_name}.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, markdown_path


__all__ = [
    "METRIC_DEFINITIONS",
    "REPORT_JSON_NAME",
    "REPORT_MARKDOWN_NAME",
    "REPORT_SCHEMA_VERSION",
    "build_report",
    "render_markdown",
    "write_reports",
]
