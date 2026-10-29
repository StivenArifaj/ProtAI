"""Shared builders for the evaluation harness tests.

Fixtures written here are minimal synthetic datasets. They exist only to exercise the
loader's rejection paths and the harness/report/CLI plumbing; the repository dataset
under ``evaluation/`` is the authoritative measurement input.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from ai_security.evaluation.models import TASK_NAMES

DEST = "https://mock-sink.invalid/collect"


def _base(case_id: str, task: str, split: str, template_id: str) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "task": task,
        "category": "benign",
        "split": split,
        "template_id": template_id,
        "provenance": "protai-original-synthetic",
        "license": "CC0-1.0",
        "synthetic": True,
    }


def _input_case(
    case_id: str, split: str, template_id: str, content: str, *, malicious: bool = False
) -> dict[str, Any]:
    return {
        **_base(case_id, "input_detection", split, template_id),
        "content": content,
        "content_type": "text/plain",
        "trust_label": "AUTHENTICATED_USER",
        "expected_malicious": malicious,
    }


def minimal_cases() -> dict[str, list[dict[str, Any]]]:
    """One valid case per task on dev, plus one validation and one holdout input case."""
    return {
        "input_detection": [
            _input_case(
                "in-dev-benign-01", "dev", "t-in-dev-01", "Please summarize the budget email."
            ),
            _input_case("in-val-benign-01", "validation", "t-in-val-01", "The checklist is ready."),
            _input_case(
                "in-hold-benign-01", "holdout", "t-in-hold-01", "Planning starts on Monday."
            ),
        ],
        "dlp_egress": [
            {
                **_base("dg-dev-benign-01", "dlp_egress", "dev", "t-dg-dev-01"),
                "data": {"content": "hello"},
                "declared_data_class": "PUBLIC",
                "destination": DEST,
                "require_destination": True,
                "expected_protected": False,
            }
        ],
        "dlp_response": [
            {
                **_base("dr-dev-benign-01", "dlp_response", "dev", "t-dr-dev-01"),
                "data": {"body": "quarterly planning notes"},
                "declared_data_class": "INTERNAL",
                "expected_protected": False,
            }
        ],
        "risk": [
            {
                **_base("rk-dev-read-01", "risk", "dev", "t-rk-dev-01"),
                "side_effect_class": "READ_ONLY",
                "data_class": "PUBLIC",
                "destination": None,
                "resource_count": 0,
                "expected_score": 0,
                "expected_factor_codes": ["side_effect_read_only"],
            }
        ],
        "intent": [
            {
                **_base("it-dev-mock-01", "intent", "dev", "t-it-dev-01"),
                "text": "read email-1 and summarize it",
                "timezone": None,
                "extractor": "mock",
                "expected_status": "ACTIVE",
                "expected_constraint_keys": [
                    "mock_email.read.read",
                    "text.summarize.summarize",
                ],
                "expected_resource_ids": ["email-1"],
            }
        ],
        "authorization": [
            {
                **_base("az-dev-read-01", "authorization", "dev", "t-az-dev-01"),
                "profile": "shipped",
                "principal_subject_id": "dev-user",
                "tool_id": "mock_email.read",
                "action_id": "read",
                "arguments": {"email_id": "email-1"},
                "target_resource_ids": [],
                "declared_destination": None,
                "proposal_principal_subject_id": None,
                "proposal_request_id": None,
                "deadline_offset_seconds": None,
                "expected_decision": "ALLOW",
                "expected_execution": True,
                "expected_outcome": "EXECUTED",
                "expected_reason": "authorized_read",
                "expected_sink_writes": 0,
                "result_must_not_contain": [],
            }
        ],
    }


def _default_splits(cases: dict[str, list[dict[str, Any]]]) -> dict[str, list[str]]:
    splits: dict[str, list[str]] = {"dev": [], "validation": [], "holdout": []}
    for task in TASK_NAMES:
        for case in cases[task]:
            splits[str(case["split"])].append(str(case["case_id"]))
    return splits


def _default_quick(
    cases: dict[str, list[dict[str, Any]]], splits: dict[str, list[str]]
) -> list[str]:
    dev_ids = set(splits["dev"])
    quick: list[str] = []
    for task in TASK_NAMES:
        for case in cases[task]:
            if case["case_id"] in dev_ids:
                quick.append(str(case["case_id"]))
                break
    return quick


class DatasetBuilder:
    """Write a complete, hash-consistent synthetic dataset, then optionally mutate it."""

    def __init__(
        self,
        root: Path,
        *,
        cases: dict[str, list[dict[str, Any]]] | None = None,
        splits: dict[str, list[str]] | None = None,
        quick: list[str] | None = None,
        dataset_version: str = "test-v1",
    ) -> None:
        self.root = root
        self.cases = cases if cases is not None else minimal_cases()
        self.splits = splits if splits is not None else _default_splits(self.cases)
        self.quick = quick if quick is not None else _default_quick(self.cases, self.splits)
        self.dataset_version = dataset_version
        self.manifest_path = root / "dataset_manifest.yaml"

    def write(self) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "fixtures").mkdir(parents=True, exist_ok=True)
        (self.root / "splits").mkdir(parents=True, exist_ok=True)
        for task in TASK_NAMES:
            self._write_fixture(task)
        self._write_splits()
        self._write_manifest()
        return self.manifest_path

    def rewrite_fixture(self, task: str, cases: list[dict[str, Any]]) -> None:
        self.cases[task] = cases
        self._write_fixture(task)
        self._write_manifest()

    def write_raw_fixture(self, task: str, text: str) -> None:
        self._fixture_path(task).write_text(text, encoding="utf-8")
        self._write_manifest()

    def rewrite_splits(
        self,
        splits: dict[str, list[str]],
        quick: list[str] | None = None,
        *,
        dataset_version: str | None = None,
    ) -> None:
        self.splits = splits
        if quick is not None:
            self.quick = quick
        if dataset_version is not None:
            self.dataset_version = dataset_version
        self._write_splits()
        self._write_manifest()

    def rewrite_manifest(self, mutate: Callable[[dict[str, Any]], None]) -> None:
        payload = yaml.safe_load(self.manifest_path.read_text(encoding="utf-8"))
        mutate(payload)
        self.manifest_path.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")

    def _fixture_path(self, task: str) -> Path:
        return self.root / "fixtures" / f"{task}.jsonl"

    def _write_fixture(self, task: str) -> None:
        lines = [json.dumps(case, ensure_ascii=False) for case in self.cases[task]]
        self._fixture_path(task).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _write_splits(self) -> None:
        payload = (
            json.dumps(
                {
                    "schema_version": 1,
                    "dataset_version": self.dataset_version,
                    "splits": self.splits,
                    "quick": self.quick,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        (self.root / "splits" / "splits.json").write_text(payload, encoding="utf-8")

    def _write_manifest(self) -> None:
        fixtures: dict[str, Any] = {}
        for task in TASK_NAMES:
            raw = self._fixture_path(task).read_bytes()
            fixtures[task] = {
                "path": f"fixtures/{task}.jsonl",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "case_count": len(self.cases[task]),
            }
        split_raw = (self.root / "splits" / "splits.json").read_bytes()
        manifest = {
            "schema_version": 1,
            "dataset_version": self.dataset_version,
            "description": "Synthetic dataset for evaluation harness tests.",
            "license": "CC0-1.0",
            "provenance": "protai-original-synthetic-tests",
            "seed": 20261028,
            "created_at": "2026-10-28",
            "fixtures": fixtures,
            "splits": {
                "path": "splits/splits.json",
                "sha256": hashlib.sha256(split_raw).hexdigest(),
                "counts": {
                    name: len(self.splits[name]) for name in ("dev", "validation", "holdout")
                },
            },
        }
        self.manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=True), encoding="utf-8")


@pytest.fixture
def dataset_builder(tmp_path: Path) -> Callable[..., DatasetBuilder]:
    def factory(**kwargs: Any) -> DatasetBuilder:
        return DatasetBuilder(tmp_path / "dataset", **kwargs)

    return factory
