"""Evaluation CLI: one command reproduces a report from a versioned dataset.

Usage::

    uv run python -m ai_security.evaluation \
        --dataset evaluation/dataset_manifest.yaml \
        --output-dir evaluation/reports

``--quick`` restricts the run to the manifest's dev-only quick regression subset;
``--split`` may be repeated to select explicit splits. The command loads and verifies
the exact fixture bytes/hashes/counts before running anything, then writes JSON and
Markdown reports derived from the observed outcomes.
"""

from __future__ import annotations

import argparse
import asyncio
import shlex
import sys
from collections.abc import Sequence

from .dataset import DatasetError, load_dataset
from .models import SPLIT_NAMES
from .report import write_reports
from .runners import EvaluationRunners, unauthorized_side_effect_rate

DEFAULT_DATASET = "evaluation/dataset_manifest.yaml"
DEFAULT_OUTPUT_DIR = "evaluation/reports"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-security-evaluation",
        description=(
            "Run the ProtAI evaluation harness against repository-owned synthetic "
            "fixtures and write JSON + Markdown reports."
        ),
    )
    parser.add_argument(
        "--dataset",
        default=DEFAULT_DATASET,
        help=f"dataset manifest path (default: {DEFAULT_DATASET})",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"report directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--split",
        action="append",
        choices=SPLIT_NAMES,
        default=None,
        help="run one split (repeatable); default: all splits",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="run only the dev quick-regression subset",
    )
    parser.add_argument(
        "--report-name",
        default="evaluation_report",
        help="file stem for the JSON/Markdown reports",
    )
    parser.add_argument(
        "--fail-on-failures",
        action="store_true",
        help="exit 2 when any case fails its expectation (CI regression mode)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    # Record the actual invocation, including module-style calls where argparse reads
    # sys.argv. A report must name the command that produced it (blueprint §19.6).
    arguments = list(argv) if argv is not None else list(sys.argv[1:])
    parser = build_parser()
    parsed = parser.parse_args(arguments)
    splits: tuple[str, ...] = tuple(parsed.split) if parsed.split else SPLIT_NAMES
    if parsed.quick and set(splits) != {"dev"}:
        parser.error("--quick is defined only for the dev split; use --split dev")

    try:
        dataset = load_dataset(parsed.dataset)
    except DatasetError as exc:
        print(f"dataset error: {exc}")
        return 1

    command = "python -m ai_security.evaluation " + shlex.join(arguments)
    runners = EvaluationRunners()
    run = asyncio.run(
        runners.run(dataset, splits=splits, quick=parsed.quick, command=command.strip())
    )
    json_path, markdown_path = write_reports(run, parsed.output_dir, report_name=parsed.report_name)

    print(
        f"ran {len(run.outcomes)} case(s) across {len(run.tasks)} task(s); "
        f"{len(run.failures)} failed expectation(s)"
    )
    authorization = next((task for task in run.tasks if task.task == "authorization"), None)
    if authorization is not None:
        rate = unauthorized_side_effect_rate(authorization.counts)
        print(
            "authorization: "
            f"{authorization.counts.get('unauthorized_executions', 0)} unauthorized "
            f"side effect(s), rate={_format_rate(rate)}"
        )
    print(f"json report: {json_path}")
    print(f"markdown report: {markdown_path}")

    if parsed.fail_on_failures and run.failures:
        return 2
    return 0


def _format_rate(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.3f}"


__all__ = ["DEFAULT_DATASET", "DEFAULT_OUTPUT_DIR", "build_parser", "main"]
