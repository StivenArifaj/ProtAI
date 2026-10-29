"""Strict dataset loading, split validation, and leakage checks.

A run is reproducible only if the exact fixture bytes, case counts, split partition, and
quick subset are verified before any code executes. This loader refuses:

- a path that escapes the dataset directory;
- a missing, unhashed, miscounted, or non-UTF-8 fixture;
- duplicate JSON keys, duplicate case IDs, or a case whose task does not match its file;
- a split file that does not exactly partition the cases or disagrees with a case's
  declared split;
- the same template appearing in more than one split;
- exact duplicate content anywhere (duplicates would double-count a metric);
- a quick subset that is empty, larger than the documented bound, references a
  non-dev case, or does not cover every task.

Public benchmark data is never loaded here; fixtures are repository-owned and synthetic.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, cast

from pydantic import TypeAdapter, ValidationError

from ai_security.security.safe_yaml import SafeYamlError, parse_unique_yaml

from .models import (
    SPLIT_NAMES,
    TASK_NAMES,
    AuthorizationCase,
    DatasetManifest,
    DlpEgressCase,
    DlpResponseCase,
    EvaluationCase,
    InputDetectionCase,
    IntentCase,
    RiskCase,
    SplitDocument,
)

MAX_QUICK_CASES = 30

# The discriminator makes the adapter exhaustive over the six task models. mypy's
# pydantic plugin rejects an Annotated discriminated union as the argument type, so the
# adapter is untyped here and every validated payload is immediately cast back.
_CASE_ADAPTER: TypeAdapter[Any] = TypeAdapter(EvaluationCase)  # type: ignore[arg-type]


class DatasetError(ValueError):
    """The dataset is missing, malformed, inconsistent, or leaks across splits."""


@dataclass(frozen=True)
class LoadedDataset:
    """A verified dataset: manifest, cases, exact split partition, and quick subset."""

    root: Path
    manifest_path: Path
    manifest_sha256: str
    manifest: DatasetManifest
    cases: tuple[EvaluationCase, ...]
    splits: Mapping[str, tuple[str, ...]]
    quick: tuple[str, ...]
    fixture_sha256: Mapping[str, str]
    split_sha256: str

    @property
    def case_count(self) -> int:
        return len(self.cases)

    def case_by_id(self) -> dict[str, EvaluationCase]:
        return {case.case_id: case for case in self.cases}

    def cases_for(
        self, *, splits: Iterable[str], quick: bool = False
    ) -> tuple[EvaluationCase, ...]:
        selected = set(splits)
        unknown = selected - set(SPLIT_NAMES)
        if unknown:
            raise DatasetError("unknown split(s): " + ", ".join(sorted(unknown)))
        allowed_ids: set[str] = set()
        for split_name in selected:
            allowed_ids.update(self.splits[split_name])
        if quick:
            allowed_ids &= set(self.quick)
        return tuple(case for case in self.cases if case.case_id in allowed_ids)

    def task_counts(self, cases: Iterable[EvaluationCase] | None = None) -> dict[str, int]:
        selected = self.cases if cases is None else tuple(cases)
        counts: Counter[str] = Counter(case.task for case in selected)
        return {task: counts.get(task, 0) for task in TASK_NAMES}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise DatasetError(f"{path} cannot be read: {exc}") from exc
    return digest.hexdigest()


def _safe_member(root: Path, relative: str) -> Path:
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        raise DatasetError(f"dataset path {relative!r} must be a relative member path")
    resolved_root = root.resolve()
    resolved = (resolved_root / Path(*candidate.parts)).resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise DatasetError(f"dataset path {relative!r} escapes the dataset directory")
    return resolved


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _read_text(path: Path, *, label: str) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DatasetError(f"{label} {path} cannot be read: {exc}") from exc
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DatasetError(f"{label} {path} is not valid UTF-8") from exc


def _validation_summary(exc: ValidationError, *, label: str) -> str:
    details = []
    for error in exc.errors(include_input=False, include_url=False)[:3]:
        location = ".".join(str(part) for part in error.get("loc", ())) or "<root>"
        details.append(f"{location}: {error.get('msg', 'invalid value')}")
    return f"{label} failed strict validation ({exc.error_count()} error(s)): " + "; ".join(details)


def _load_manifest(path: Path) -> tuple[DatasetManifest, str]:
    raw = _read_text(path, label="dataset manifest")
    try:
        payload = parse_unique_yaml(raw)
    except SafeYamlError as exc:
        raise DatasetError(f"dataset manifest {path}: {exc}") from exc
    try:
        manifest = DatasetManifest.model_validate(payload)
    except ValidationError as exc:
        raise DatasetError(_validation_summary(exc, label=f"dataset manifest {path}")) from exc
    return manifest, hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load_fixture(
    path: Path, *, task: str, expected_sha256: str, expected_count: int
) -> tuple[tuple[EvaluationCase, ...], str]:
    actual_sha256 = sha256_file(path)
    if actual_sha256 != expected_sha256:
        raise DatasetError(
            f"fixture {path.name} sha256 mismatch: manifest {expected_sha256}, "
            f"actual {actual_sha256}"
        )
    text = _read_text(path, label="fixture")
    cases: list[EvaluationCase] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise DatasetError(f"fixture {path.name} line {line_number} is blank")
        try:
            payload = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, ValueError) as exc:
            raise DatasetError(f"fixture {path.name} line {line_number}: {exc}") from exc
        if not isinstance(payload, dict):
            raise DatasetError(f"fixture {path.name} line {line_number} is not a JSON object")
        try:
            case = cast(EvaluationCase, _CASE_ADAPTER.validate_python(payload))
        except ValidationError as exc:
            raise DatasetError(
                _validation_summary(exc, label=f"fixture {path.name} line {line_number}")
            ) from exc
        if case.task != task:
            raise DatasetError(
                f"fixture {path.name} line {line_number} declares task {case.task!r}, "
                f"expected {task!r}"
            )
        cases.append(case)
    if len(cases) != expected_count:
        raise DatasetError(
            f"fixture {path.name} case count mismatch: manifest {expected_count}, "
            f"actual {len(cases)}"
        )
    return tuple(cases), actual_sha256


def _load_splits(path: Path, *, expected_sha256: str) -> tuple[SplitDocument, str]:
    actual_sha256 = sha256_file(path)
    if actual_sha256 != expected_sha256:
        raise DatasetError(
            f"split file sha256 mismatch: manifest {expected_sha256}, actual {actual_sha256}"
        )
    text = _read_text(path, label="split file")
    try:
        payload = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError) as exc:
        raise DatasetError(f"split file {path.name}: {exc}") from exc
    try:
        document = SplitDocument.model_validate(payload)
    except ValidationError as exc:
        raise DatasetError(_validation_summary(exc, label=f"split file {path.name}")) from exc
    return document, actual_sha256


def _normalized_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def _input_key(case: InputDetectionCase) -> str:
    if case.content is not None:
        content = _normalized_text(case.content)
    else:
        content = "b64:" + (case.content_b64 or "")
    return f"{case.task}|{case.content_type}|{case.trust_label.value}|{content}"


def _json_key(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _dedupe_key(case: EvaluationCase) -> str:
    """Stable content/input identity; expectation labels are intentionally excluded."""
    if isinstance(case, InputDetectionCase):
        return _input_key(case)
    if isinstance(case, DlpEgressCase):
        return (
            f"{case.task}|{case.declared_data_class.value}|{case.destination}|"
            f"{case.require_destination}|{_json_key(case.data)}"
        )
    if isinstance(case, DlpResponseCase):
        return f"{case.task}|{case.declared_data_class.value}|{_json_key(case.data)}"
    if isinstance(case, RiskCase):
        return (
            f"{case.task}|{case.side_effect_class.value}|{case.data_class.value}|"
            f"{case.destination}|{case.resource_count}"
        )
    if isinstance(case, IntentCase):
        return (
            f"{case.task}|{_normalized_text(case.text)}|{case.timezone}|{case.extractor}|"
            f"{case.provider_output}|{case.provider_failure}"
        )
    if isinstance(case, AuthorizationCase):
        return f"{case.task}|" + _json_key(
            {
                "profile": case.profile,
                "principal": case.principal_subject_id,
                "tool_id": case.tool_id,
                "action_id": case.action_id,
                "arguments": case.arguments,
                "targets": case.target_resource_ids,
                "destination": case.declared_destination,
                "proposal_principal": case.proposal_principal_subject_id,
                "proposal_request": case.proposal_request_id,
                "deadline": case.deadline_offset_seconds,
            }
        )
    raise DatasetError(f"case {case.case_id!r} has an unsupported task model")


def _validate_cases(
    cases: tuple[EvaluationCase, ...], *, splits: SplitDocument
) -> dict[str, tuple[str, ...]]:
    by_id: dict[str, EvaluationCase] = {}
    for case in cases:
        if case.case_id in by_id:
            raise DatasetError(f"duplicate case_id {case.case_id!r}")
        by_id[case.case_id] = case

    split_ids: dict[str, tuple[str, ...]] = {}
    assigned: dict[str, str] = {}
    for split_name in SPLIT_NAMES:
        ids = splits.splits[split_name]
        for case_id in ids:
            if case_id not in by_id:
                raise DatasetError(f"split {split_name!r} references unknown case {case_id!r}")
            if case_id in assigned:
                raise DatasetError(f"case {case_id!r} appears in multiple splits")
            assigned[case_id] = split_name
            if by_id[case_id].split != split_name:
                raise DatasetError(
                    f"case {case_id!r} declares split {by_id[case_id].split!r} but the "
                    f"split file places it in {split_name!r}"
                )
        split_ids[split_name] = ids
    missing = sorted(set(by_id) - set(assigned))
    if missing:
        raise DatasetError("case(s) missing from the split file: " + ", ".join(missing))

    template_splits: dict[tuple[str, str], set[str]] = {}
    for case in cases:
        template_splits.setdefault((case.task, case.template_id), set()).add(case.split)
    leaked = sorted(
        f"{task}/{template}" for (task, template), seen in template_splits.items() if len(seen) > 1
    )
    if leaked:
        raise DatasetError("template(s) leak across splits: " + ", ".join(leaked))

    seen_keys: dict[str, str] = {}
    for case in cases:
        key = _dedupe_key(case)
        previous = seen_keys.get(key)
        if previous is not None:
            raise DatasetError(
                f"duplicate content: cases {previous!r} and {case.case_id!r} have the same input"
            )
        seen_keys[key] = case.case_id

    _validate_quick(splits.quick, by_id=by_id, split_ids=split_ids)
    return split_ids


def _validate_quick(
    quick: tuple[str, ...],
    *,
    by_id: Mapping[str, EvaluationCase],
    split_ids: Mapping[str, tuple[str, ...]],
) -> None:
    if len(quick) > MAX_QUICK_CASES:
        raise DatasetError(f"quick subset has {len(quick)} cases; the bound is {MAX_QUICK_CASES}")
    dev_ids = set(split_ids["dev"])
    outside_dev = sorted(set(quick) - dev_ids)
    if outside_dev:
        raise DatasetError(
            "quick subset must use dev cases only; outside dev: " + ", ".join(outside_dev)
        )
    quick_tasks = {by_id[case_id].task for case_id in quick}
    missing = sorted(set(TASK_NAMES) - quick_tasks)
    if missing:
        raise DatasetError("quick subset does not cover task(s): " + ", ".join(missing))


def load_dataset(manifest_path: str | Path) -> LoadedDataset:
    """Load and fully verify a dataset; any inconsistency raises ``DatasetError``."""
    path = Path(manifest_path).resolve()
    if not path.is_file():
        raise DatasetError(f"dataset manifest {path} does not exist")
    root = path.parent
    manifest, manifest_sha256 = _load_manifest(path)

    cases: list[EvaluationCase] = []
    fixture_hashes: dict[str, str] = {}
    for task in TASK_NAMES:
        entry = manifest.fixtures[task]
        fixture_path = _safe_member(root, entry.path)
        fixture_cases, fixture_sha256 = _load_fixture(
            fixture_path,
            task=task,
            expected_sha256=entry.sha256,
            expected_count=entry.case_count,
        )
        cases.extend(fixture_cases)
        fixture_hashes[task] = fixture_sha256

    split_path = _safe_member(root, manifest.splits.path)
    split_document, split_sha256 = _load_splits(split_path, expected_sha256=manifest.splits.sha256)
    if split_document.dataset_version != manifest.dataset_version:
        raise DatasetError("split file dataset_version does not match the manifest")

    all_cases = tuple(cases)
    split_ids = _validate_cases(all_cases, splits=split_document)
    for split_name in SPLIT_NAMES:
        actual = len(split_ids[split_name])
        declared = manifest.splits.counts[split_name]
        if actual != declared:
            raise DatasetError(
                f"split {split_name!r} count mismatch: manifest {declared}, actual {actual}"
            )

    return LoadedDataset(
        root=root,
        manifest_path=path,
        manifest_sha256=manifest_sha256,
        manifest=manifest,
        cases=all_cases,
        splits=split_ids,
        quick=split_document.quick,
        fixture_sha256=fixture_hashes,
        split_sha256=split_sha256,
    )


__all__ = [
    "DatasetError",
    "LoadedDataset",
    "MAX_QUICK_CASES",
    "load_dataset",
    "sha256_file",
]
