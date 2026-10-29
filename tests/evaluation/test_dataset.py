"""Dataset loading, rejection, and leakage tests (blueprint sections 19.1, 19.4, 19.5)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ai_security.evaluation.dataset import DatasetError, load_dataset
from ai_security.evaluation.models import TASK_NAMES

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _ids_in_task(builder, task: str) -> list[str]:  # type: ignore[no-untyped-def]
    return [str(case["case_id"]) for case in builder.cases[task]]


def test_loads_a_valid_minimal_dataset(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    manifest_path = builder.write()

    dataset = load_dataset(manifest_path)

    assert dataset.case_count == 8
    assert dataset.manifest.dataset_version == "test-v1"
    assert dataset.task_counts() == {
        "input_detection": 3,
        "dlp_egress": 1,
        "dlp_response": 1,
        "risk": 1,
        "intent": 1,
        "authorization": 1,
    }
    assert {name: len(ids) for name, ids in dataset.splits.items()} == {
        "dev": 6,
        "validation": 1,
        "holdout": 1,
    }
    assert len(dataset.quick) == 6
    assert dataset.cases_for(splits=("dev",), quick=True) == tuple(
        dataset.case_by_id()[case_id] for case_id in dataset.quick
    )
    assert set(dataset.fixture_sha256) == set(TASK_NAMES)
    assert len(dataset.manifest_sha256) == 64
    assert len(dataset.split_sha256) == 64


def test_repository_dataset_loads_with_expected_shape() -> None:
    dataset = load_dataset(REPOSITORY_ROOT / "evaluation/dataset_manifest.yaml")

    assert dataset.case_count == 106
    assert dataset.task_counts() == {
        "input_detection": 20,
        "dlp_egress": 16,
        "dlp_response": 14,
        "risk": 18,
        "intent": 18,
        "authorization": 20,
    }
    assert {name: len(ids) for name, ids in dataset.splits.items()} == {
        "dev": 42,
        "validation": 34,
        "holdout": 30,
    }
    assert len(dataset.quick) == 15
    quick = dataset.cases_for(splits=("dev",), quick=True)
    assert len(quick) == 15
    assert {case.task for case in quick} == set(TASK_NAMES)


def test_missing_manifest_is_refused(tmp_path: Path) -> None:
    with pytest.raises(DatasetError, match="does not exist"):
        load_dataset(tmp_path / "missing.yaml")


def test_duplicate_case_id_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    first = dict(builder.cases["input_detection"][0])
    duplicate = {**first, "content": "A different benign sentence."}
    builder.cases["input_detection"].append(duplicate)
    manifest_path = builder.write()

    with pytest.raises(DatasetError, match="duplicate case_id"):
        load_dataset(manifest_path)


def test_duplicate_content_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    validation = builder.cases["input_detection"][1]
    validation["content"] = builder.cases["input_detection"][0]["content"]
    manifest_path = builder.write()

    with pytest.raises(DatasetError, match="duplicate content"):
        load_dataset(manifest_path)


def test_template_leakage_across_splits_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    builder.cases["input_detection"][1]["template_id"] = builder.cases["input_detection"][0][
        "template_id"
    ]
    manifest_path = builder.write()

    with pytest.raises(DatasetError, match="leak across splits"):
        load_dataset(manifest_path)


def test_case_split_disagreement_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    moved = builder.splits["dev"].pop()
    builder.splits["validation"].append(moved)
    manifest_path = builder.write()

    with pytest.raises(DatasetError, match="declares split"):
        load_dataset(manifest_path)


def test_unassigned_case_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    removed = builder.splits["dev"].pop()
    builder.quick = [case_id for case_id in builder.quick if case_id != removed]
    manifest_path = builder.write()

    with pytest.raises(DatasetError, match="missing from the split file"):
        load_dataset(manifest_path)


def test_unknown_split_case_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    builder.splits["validation"].append("ghost-case-01")
    manifest_path = builder.write()

    with pytest.raises(DatasetError, match="unknown case"):
        load_dataset(manifest_path)


def test_missing_provenance_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    builder.cases["input_detection"][0].pop("provenance")
    manifest_path = builder.write()

    with pytest.raises(DatasetError, match="failed strict validation"):
        load_dataset(manifest_path)


def test_non_synthetic_case_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    builder.cases["dlp_egress"][0]["synthetic"] = False
    manifest_path = builder.write()

    with pytest.raises(DatasetError, match="failed strict validation"):
        load_dataset(manifest_path)


def test_wrong_fixture_hash_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    builder.write()
    builder.rewrite_manifest(
        lambda manifest: manifest["fixtures"]["input_detection"].__setitem__("sha256", "0" * 64)
    )

    with pytest.raises(DatasetError, match="sha256 mismatch"):
        load_dataset(builder.manifest_path)


def test_wrong_case_count_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    builder.write()
    builder.rewrite_manifest(
        lambda manifest: manifest["fixtures"]["risk"].__setitem__("case_count", 99)
    )

    with pytest.raises(DatasetError, match="case count mismatch"):
        load_dataset(builder.manifest_path)


def test_fixture_path_escape_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    builder.write()
    builder.rewrite_manifest(
        lambda manifest: manifest["fixtures"]["risk"].__setitem__("path", "../outside.jsonl")
    )

    with pytest.raises(DatasetError, match="relative member path"):
        load_dataset(builder.manifest_path)


def test_split_count_mismatch_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    builder.write()
    builder.rewrite_manifest(lambda manifest: manifest["splits"]["counts"].__setitem__("dev", 7))

    with pytest.raises(DatasetError, match="count mismatch"):
        load_dataset(builder.manifest_path)


def test_split_dataset_version_mismatch_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    builder.write()
    builder.rewrite_splits(builder.splits, builder.quick, dataset_version="other-v1")
    # Keep the manifest version unchanged so only the split document disagrees.
    builder.rewrite_manifest(lambda manifest: manifest.__setitem__("dataset_version", "test-v1"))

    with pytest.raises(DatasetError, match="dataset_version"):
        load_dataset(builder.manifest_path)


def test_quick_subset_must_stay_on_dev(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    builder.quick = [*builder.quick, "in-val-benign-01"]
    manifest_path = builder.write()

    with pytest.raises(DatasetError, match="dev cases only"):
        load_dataset(manifest_path)


def test_quick_subset_must_cover_every_task(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    builder.quick = [case_id for case_id in builder.quick if not case_id.startswith("az-")]
    manifest_path = builder.write()

    with pytest.raises(DatasetError, match="does not cover task"):
        load_dataset(manifest_path)


def test_quick_subset_has_a_hard_size_bound(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    extra = []
    for index in range(25):
        case = {
            **builder.cases["input_detection"][0],
            "case_id": f"in-dev-extra-{index:02d}",
            "template_id": f"t-in-dev-extra-{index:02d}",
            "content": f"Additional benign synthetic sentence {index}.",
        }
        extra.append(case)
    builder.cases["input_detection"].extend(extra)
    for case in extra:
        builder.splits["dev"].append(str(case["case_id"]))
    builder.quick = list(builder.splits["dev"])
    assert len(builder.quick) == 31
    manifest_path = builder.write()

    with pytest.raises(DatasetError, match="bound is 30"):
        load_dataset(manifest_path)


def test_duplicate_json_key_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    builder.write()
    lines = (builder.root / "fixtures/input_detection.jsonl").read_text().splitlines()
    first = lines[0]
    lines[0] = '{"case_id":"in-dev-benign-01",' + first[1:]
    builder.write_raw_fixture("input_detection", "\n".join(lines) + "\n")

    with pytest.raises(DatasetError, match="duplicate JSON key"):
        load_dataset(builder.manifest_path)


def test_blank_fixture_line_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    builder.write()
    path = builder.root / "fixtures/risk.jsonl"
    builder.write_raw_fixture("risk", path.read_text() + "\n")

    with pytest.raises(DatasetError, match="is blank"):
        load_dataset(builder.manifest_path)


def test_duplicate_manifest_key_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    builder.write()
    text = builder.manifest_path.read_text()
    builder.manifest_path.write_text("schema_version: 1\n" + text, encoding="utf-8")

    with pytest.raises(DatasetError, match="duplicate key"):
        load_dataset(builder.manifest_path)


def test_unknown_split_name_is_refused(dataset_builder) -> None:  # type: ignore[no-untyped-def]
    builder = dataset_builder()
    builder.splits["staging"] = []
    manifest_path = builder.write()

    with pytest.raises(DatasetError):
        load_dataset(manifest_path)

    assert _ids_in_task(builder, "risk") == ["rk-dev-read-01"]
