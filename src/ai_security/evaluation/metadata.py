"""Provenance metadata for a reproducible evaluation run (blueprint section 19.5).

Every run records the git commit, dependency-lock hash, Python/platform/hardware,
dataset identity, configuration versions/hashes, thresholds, extractor versions, seed,
and a UTC timestamp. Git state is read directly from ``.git/HEAD`` and refs; the harness
never starts a child process (``scripts/check.sh`` forbids that in ``src/``).

A missing value is recorded as ``null`` rather than invented. In particular, a source
archive without ``.git`` or ``uv.lock`` yields ``null`` commit/lock hashes instead of a
fabricated one.
"""

from __future__ import annotations

import hashlib
import os
import platform
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ai_security import __version__
from ai_security.data_security.dlp import LoadedOutputDlpConfig
from ai_security.input_defense.config import LoadedInputDefenseConfig
from ai_security.policy.models import PolicyBundle

from .dataset import LoadedDataset, sha256_file

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_HEX_DIGITS = frozenset("0123456789abcdef")


class MetadataError(RuntimeError):
    """Run metadata cannot be collected without inventing a value."""


@dataclass(frozen=True)
class GitMetadata:
    """Exact commit identity read from the local repository."""

    commit: str | None
    branch: str | None


@dataclass(frozen=True)
class EnvironmentMetadata:
    """Python and machine facts that affect in-process latency measurements."""

    python_version: str
    python_implementation: str
    platform: str
    machine: str
    processor: str | None
    cpu_count: int | None
    total_memory_bytes: int | None


@dataclass(frozen=True)
class ConfigurationMetadata:
    """Every configuration and detector/engine identity a run depends on."""

    policy_version: str
    policy_hash: str
    policies_sha256: str
    risk_thresholds_version: str
    risk_thresholds_sha256: str
    ask_user_at_or_above: int
    block_at_or_above: int
    input_defense_version: str
    input_defense_sha256: str
    output_dlp_version: str
    output_dlp_sha256: str
    risk_engine_version: str
    intent_extractor_versions: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class RunMetadata:
    """The complete provenance block embedded in every JSON report."""

    schema_version: int
    harness_version: str
    generated_at: str
    command: str
    seed: int
    dataset_version: str
    dataset_manifest_sha256: str
    split_file_sha256: str
    splits: tuple[str, ...]
    quick: bool
    selected_cases: int
    total_cases: int
    git: GitMetadata
    environment: EnvironmentMetadata
    configuration: ConfigurationMetadata
    uv_lock_sha256: str | None


def _is_hex_object_id(value: str) -> bool:
    return len(value) in (40, 64) and all(character in _HEX_DIGITS for character in value)


def _git_directory(root: Path) -> Path | None:
    """Resolve the real git directory, including linked worktrees (``.git`` file)."""
    dot_git = root / ".git"
    if dot_git.is_dir():
        return dot_git
    if not dot_git.is_file():
        return None
    try:
        line = dot_git.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not line.startswith("gitdir:"):
        return None
    candidate = Path(line.removeprefix("gitdir:").strip())
    if not candidate.is_absolute():
        candidate = (root / candidate).resolve()
    return candidate if candidate.is_dir() else None


def _packed_ref(git_dir: Path, ref: str) -> str | None:
    packed = git_dir / "packed-refs"
    try:
        lines = packed.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("^"):
            continue
        parts = stripped.split(maxsplit=1)
        if len(parts) == 2 and parts[1] == ref and _is_hex_object_id(parts[0]):
            return parts[0]
    return None


def read_git_metadata(root: Path = REPOSITORY_ROOT) -> GitMetadata:
    """Read HEAD/refs directly; never run git and never guess a commit."""
    git_dir = _git_directory(root)
    if git_dir is None:
        return GitMetadata(commit=None, branch=None)
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return GitMetadata(commit=None, branch=None)

    if head.startswith("ref:"):
        ref = head.removeprefix("ref:").strip()
        branch = ref.removeprefix("refs/heads/") if ref.startswith("refs/heads/") else None
        commit: str | None = None
        ref_path = git_dir / ref
        try:
            candidate = ref_path.read_text(encoding="utf-8").strip()
        except OSError:
            candidate = ""
        if _is_hex_object_id(candidate):
            commit = candidate
        else:
            commit = _packed_ref(git_dir, ref)
        return GitMetadata(commit=commit, branch=branch)

    if _is_hex_object_id(head):
        return GitMetadata(commit=head, branch=None)
    return GitMetadata(commit=None, branch=None)


def _total_memory_bytes() -> int | None:
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        page_count = os.sysconf("SC_PHYS_PAGES")
    except (AttributeError, OSError, ValueError):
        return None
    if not isinstance(page_size, int) or not isinstance(page_count, int):
        return None
    if page_size <= 0 or page_count <= 0:
        return None
    return page_size * page_count


def collect_environment_metadata() -> EnvironmentMetadata:
    processor = platform.processor().strip() or None
    return EnvironmentMetadata(
        python_version=platform.python_version(),
        python_implementation=platform.python_implementation(),
        platform=platform.platform(),
        machine=platform.machine(),
        processor=processor,
        cpu_count=os.cpu_count(),
        total_memory_bytes=_total_memory_bytes(),
    )


def collect_configuration_metadata(
    *,
    policy_bundle: PolicyBundle,
    input_config: LoadedInputDefenseConfig,
    output_config: LoadedOutputDlpConfig,
    risk_engine_version: str,
    extractor_versions: Mapping[str, str],
) -> ConfigurationMetadata:
    """Freeze every configuration identity consumed by the run."""
    if not extractor_versions:
        raise MetadataError("at least one intent-extractor version is required")
    ordered_extractors = tuple(sorted(extractor_versions.items()))
    for name, version in ordered_extractors:
        if not name or not version:
            raise MetadataError("extractor names and versions must be non-empty")
    return ConfigurationMetadata(
        policy_version=policy_bundle.version,
        policy_hash=policy_bundle.combined_hash,
        policies_sha256=policy_bundle.policies_sha256,
        risk_thresholds_version=policy_bundle.risk_thresholds.version,
        risk_thresholds_sha256=policy_bundle.thresholds_sha256,
        ask_user_at_or_above=policy_bundle.ask_user_at_or_above,
        block_at_or_above=policy_bundle.block_at_or_above,
        input_defense_version=input_config.config.version,
        input_defense_sha256=input_config.sha256,
        output_dlp_version=output_config.config.version,
        output_dlp_sha256=output_config.sha256,
        risk_engine_version=risk_engine_version,
        intent_extractor_versions=ordered_extractors,
    )


def collect_run_metadata(
    *,
    dataset: LoadedDataset,
    splits: Sequence[str],
    quick: bool,
    selected_cases: int,
    policy_bundle: PolicyBundle,
    input_config: LoadedInputDefenseConfig,
    output_config: LoadedOutputDlpConfig,
    risk_engine_version: str,
    extractor_versions: Mapping[str, str],
    command: str,
    generated_at: datetime | None = None,
    repository_root: Path = REPOSITORY_ROOT,
) -> RunMetadata:
    """Build the provenance block; all values are observed, never fabricated."""
    timestamp = generated_at if generated_at is not None else datetime.now(UTC)
    if timestamp.utcoffset() is None:
        raise MetadataError("generated_at must be timezone-aware")
    lock_path = repository_root / "uv.lock"
    lock_sha256 = sha256_file(lock_path) if lock_path.is_file() else None
    return RunMetadata(
        schema_version=1,
        harness_version=__version__,
        generated_at=timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        command=command,
        seed=dataset.manifest.seed,
        dataset_version=dataset.manifest.dataset_version,
        dataset_manifest_sha256=dataset.manifest_sha256,
        split_file_sha256=dataset.split_sha256,
        splits=tuple(splits),
        quick=quick,
        selected_cases=selected_cases,
        total_cases=dataset.case_count,
        git=read_git_metadata(repository_root),
        environment=collect_environment_metadata(),
        configuration=collect_configuration_metadata(
            policy_bundle=policy_bundle,
            input_config=input_config,
            output_config=output_config,
            risk_engine_version=risk_engine_version,
            extractor_versions=extractor_versions,
        ),
        uv_lock_sha256=lock_sha256,
    )


def sha256_text(value: str) -> str:
    """Small helper for report-level identity fields."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = [
    "ConfigurationMetadata",
    "EnvironmentMetadata",
    "GitMetadata",
    "MetadataError",
    "REPOSITORY_ROOT",
    "RunMetadata",
    "collect_configuration_metadata",
    "collect_environment_metadata",
    "collect_run_metadata",
    "read_git_metadata",
    "sha256_text",
]
