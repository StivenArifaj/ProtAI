"""Provenance metadata tests: observed values, never fabricated (section 19.5)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from ai_security.data_security.dlp import load_output_dlp_config
from ai_security.evaluation.dataset import load_dataset
from ai_security.evaluation.metadata import (
    MetadataError,
    collect_configuration_metadata,
    collect_environment_metadata,
    collect_run_metadata,
    read_git_metadata,
    sha256_text,
)
from ai_security.firewall.risk_engine import RISK_ENGINE_VERSION
from ai_security.input_defense.config import load_input_defense_config
from ai_security.policy.loader import load_policy_bundle

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def test_missing_git_directory_yields_nulls(tmp_path: Path) -> None:
    metadata = read_git_metadata(tmp_path)
    assert metadata.commit is None
    assert metadata.branch is None


def test_loose_ref_is_read_directly(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git"
    (git_dir / "refs/heads").mkdir(parents=True)
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git_dir / "refs/heads/main").write_text(COMMIT + "\n", encoding="utf-8")

    metadata = read_git_metadata(tmp_path)

    assert metadata.commit == COMMIT
    assert metadata.branch == "main"


def test_packed_ref_is_used_when_the_loose_ref_is_absent(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git_dir / "packed-refs").write_text(
        f"# pack-refs with: peeled fully-peeled sorted\n{COMMIT} refs/heads/main\n",
        encoding="utf-8",
    )

    metadata = read_git_metadata(tmp_path)

    assert metadata.commit == COMMIT
    assert metadata.branch == "main"


def test_detached_head_is_recorded_without_a_branch(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text(COMMIT + "\n", encoding="utf-8")

    metadata = read_git_metadata(tmp_path)

    assert metadata.commit == COMMIT
    assert metadata.branch is None


def test_malformed_head_is_not_guessed(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("this is not a commit\n", encoding="utf-8")

    metadata = read_git_metadata(tmp_path)

    assert metadata.commit is None
    assert metadata.branch is None


def test_worktree_git_file_is_resolved(tmp_path: Path) -> None:
    real_git = tmp_path / "real-git"
    (real_git / "refs/heads").mkdir(parents=True)
    (real_git / "HEAD").write_text("ref: refs/heads/feature\n", encoding="utf-8")
    (real_git / "refs/heads/feature").write_text(COMMIT + "\n", encoding="utf-8")
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / ".git").write_text(f"gitdir: {real_git}\n", encoding="utf-8")

    metadata = read_git_metadata(worktree)

    assert metadata.commit == COMMIT
    assert metadata.branch == "feature"


def test_sha256_text_matches_known_digest() -> None:
    assert sha256_text("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_environment_metadata_is_observed() -> None:
    metadata = collect_environment_metadata()
    assert metadata.python_version.startswith("3.")
    assert metadata.python_implementation
    assert metadata.platform
    assert metadata.machine


def test_configuration_metadata_requires_an_extractor_version() -> None:
    bundle = load_policy_bundle(
        REPOSITORY_ROOT / "config/policies.yaml",
        REPOSITORY_ROOT / "config/risk_thresholds.yaml",
    )
    input_config = load_input_defense_config(REPOSITORY_ROOT / "config/input_defense.yaml")
    output_config = load_output_dlp_config(REPOSITORY_ROOT / "config/output_dlp.yaml")

    with pytest.raises(MetadataError, match="at least one"):
        collect_configuration_metadata(
            policy_bundle=bundle,
            input_config=input_config,
            output_config=output_config,
            risk_engine_version=RISK_ENGINE_VERSION,
            extractor_versions={},
        )


def test_configuration_metadata_freezes_versions_and_hashes() -> None:
    bundle = load_policy_bundle(
        REPOSITORY_ROOT / "config/policies.yaml",
        REPOSITORY_ROOT / "config/risk_thresholds.yaml",
    )
    input_config = load_input_defense_config(REPOSITORY_ROOT / "config/input_defense.yaml")
    output_config = load_output_dlp_config(REPOSITORY_ROOT / "config/output_dlp.yaml")

    metadata = collect_configuration_metadata(
        policy_bundle=bundle,
        input_config=input_config,
        output_config=output_config,
        risk_engine_version=RISK_ENGINE_VERSION,
        extractor_versions={"mock": "mock-v1", "local": "local-v1"},
    )

    assert metadata.policy_version == bundle.version
    assert metadata.policy_hash == bundle.combined_hash
    assert metadata.policies_sha256 == bundle.policies_sha256
    assert metadata.risk_thresholds_sha256 == bundle.thresholds_sha256
    assert metadata.ask_user_at_or_above == bundle.ask_user_at_or_above
    assert metadata.block_at_or_above == bundle.block_at_or_above
    assert metadata.input_defense_sha256 == input_config.sha256
    assert metadata.output_dlp_sha256 == output_config.sha256
    assert metadata.risk_engine_version == RISK_ENGINE_VERSION
    assert metadata.intent_extractor_versions == (("local", "local-v1"), ("mock", "mock-v1"))


def test_run_metadata_records_null_when_git_and_lock_are_absent(
    dataset_builder,
    tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    builder = dataset_builder()
    dataset = load_dataset(builder.write())
    bundle = load_policy_bundle(
        REPOSITORY_ROOT / "config/policies.yaml",
        REPOSITORY_ROOT / "config/risk_thresholds.yaml",
    )
    input_config = load_input_defense_config(REPOSITORY_ROOT / "config/input_defense.yaml")
    output_config = load_output_dlp_config(REPOSITORY_ROOT / "config/output_dlp.yaml")
    empty_root = tmp_path / "empty-root"
    empty_root.mkdir()

    metadata = collect_run_metadata(
        dataset=dataset,
        splits=("dev",),
        quick=True,
        selected_cases=6,
        policy_bundle=bundle,
        input_config=input_config,
        output_config=output_config,
        risk_engine_version=RISK_ENGINE_VERSION,
        extractor_versions={"mock": "mock-v1"},
        command="pytest evaluation",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        repository_root=empty_root,
    )

    assert metadata.generated_at == "2026-01-01T00:00:00Z"
    assert metadata.seed == dataset.manifest.seed
    assert metadata.dataset_version == "test-v1"
    assert metadata.dataset_manifest_sha256 == dataset.manifest_sha256
    assert metadata.split_file_sha256 == dataset.split_sha256
    assert metadata.splits == ("dev",)
    assert metadata.quick is True
    assert metadata.selected_cases == 6
    assert metadata.total_cases == 8
    assert metadata.command == "pytest evaluation"
    assert metadata.git.commit is None
    assert metadata.git.branch is None
    assert metadata.uv_lock_sha256 is None
    assert metadata.environment.python_version


def test_run_metadata_hashes_an_existing_lockfile(
    dataset_builder,
    tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    builder = dataset_builder()
    dataset = load_dataset(builder.write())
    bundle = load_policy_bundle(
        REPOSITORY_ROOT / "config/policies.yaml",
        REPOSITORY_ROOT / "config/risk_thresholds.yaml",
    )
    repository_root = tmp_path / "repo"
    repository_root.mkdir()
    lock_text = "version = 1\n"
    (repository_root / "uv.lock").write_text(lock_text, encoding="utf-8")

    metadata = collect_run_metadata(
        dataset=dataset,
        splits=("dev",),
        quick=False,
        selected_cases=8,
        policy_bundle=bundle,
        input_config=load_input_defense_config(REPOSITORY_ROOT / "config/input_defense.yaml"),
        output_config=load_output_dlp_config(REPOSITORY_ROOT / "config/output_dlp.yaml"),
        risk_engine_version=RISK_ENGINE_VERSION,
        extractor_versions={"mock": "mock-v1"},
        command="pytest evaluation",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        repository_root=repository_root,
    )

    assert metadata.uv_lock_sha256 == sha256_text(lock_text)
