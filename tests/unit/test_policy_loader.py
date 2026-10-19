"""Safe policy YAML loader tests (blueprint sections 10.4, 10.6; ADR-007, ADR-008).

The loader is the only sanctioned YAML entry point: safe construction, duplicate-key
rejection, strict validation, and content hashes for the loaded version/hash metadata.
Every malformed input raises ``PolicyConfigError`` — never a silent pass.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ai_security.policy.loader import (
    PolicyConfigError,
    load_policies,
    load_policy_bundle,
    load_risk_thresholds,
)

VALID_POLICIES = """
schema_version: 1
version: "test-1"
tools:
  mock_email.read:
    side_effect_class: READ_ONLY
"""

VALID_THRESHOLDS = """
schema_version: 1
version: "th-1"
thresholds:
  ask_user_at_or_above: 40
  block_at_or_above: 80
"""


def write(path: Path, text: str | bytes) -> Path:
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


def test_loads_valid_policies_with_content_hash(tmp_path: Path) -> None:
    path = write(tmp_path / "policies.yaml", VALID_POLICIES)
    document, digest = load_policies(path)
    assert document.version == "test-1"
    assert set(document.tools) == {"mock_email.read"}
    assert digest == hashlib.sha256(VALID_POLICIES.encode("utf-8")).hexdigest()


def test_loads_valid_thresholds(tmp_path: Path) -> None:
    path = write(tmp_path / "thresholds.yaml", VALID_THRESHOLDS)
    document, digest = load_risk_thresholds(path)
    assert document.thresholds.block_at_or_above == 80
    assert len(digest) == 64


def test_bundle_hashes_are_stable_and_content_sensitive(tmp_path: Path) -> None:
    policies = write(tmp_path / "policies.yaml", VALID_POLICIES)
    thresholds = write(tmp_path / "thresholds.yaml", VALID_THRESHOLDS)
    first = load_policy_bundle(policies, thresholds)
    second = load_policy_bundle(policies, thresholds)
    assert first.combined_hash == second.combined_hash

    changed = write(tmp_path / "thresholds.yaml", VALID_THRESHOLDS.replace("40", "30"))
    third = load_policy_bundle(policies, changed)
    assert third.combined_hash != first.combined_hash


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("", id="empty-file"),
        pytest.param("fixtures: [", id="malformed-yaml"),
        pytest.param("- name: x", id="root-not-mapping"),
        pytest.param("schema_version: 2\nversion: v1\ntools: {}\n", id="wrong-schema-version"),
        pytest.param("schema_version: 1\ntools: {}\n", id="missing-version"),
        pytest.param(
            "schema_version: 1\nversion: v1\ntools:\n  mock.read:\n    side_effect_class: SHELL\n",
            id="invalid-side-effect-enum",
        ),
        pytest.param(
            "schema_version: 1\nversion: v1\ntools:\n"
            "  'bad id':\n    side_effect_class: READ_ONLY\n",
            id="malformed-tool-id",
        ),
        pytest.param("schema_version: 1\nversion: v1\nextra: true\n", id="unknown-root-key"),
        pytest.param(
            "schema_version: 1\nversion: v1\ntools: {}\nversion: v2\n",
            id="duplicate-key",
        ),
    ],
)
def test_policies_loader_rejects_invalid_documents(tmp_path: Path, text: str) -> None:
    path = write(tmp_path / "policies.yaml", text)
    with pytest.raises(PolicyConfigError):
        load_policies(path)


def test_duplicate_key_error_is_explicit(tmp_path: Path) -> None:
    path = write(tmp_path / "policies.yaml", VALID_POLICIES + "\nversion: v2\n")
    with pytest.raises(PolicyConfigError, match="duplicate key"):
        load_policies(path)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("", id="empty-file"),
        pytest.param("schema_version: 1\nversion: th\n", id="missing-thresholds"),
        pytest.param(
            "schema_version: 1\nversion: th\nthresholds:\n  ask_user_at_or_above: 80\n"
            "  block_at_or_above: 80\n",
            id="equal-bands",
        ),
        pytest.param(
            "schema_version: 1\nversion: th\nthresholds:\n  ask_user_at_or_above: 40\n"
            "  block_at_or_above: 101\n",
            id="block-out-of-range",
        ),
    ],
)
def test_thresholds_loader_rejects_invalid_documents(tmp_path: Path, text: str) -> None:
    path = write(tmp_path / "thresholds.yaml", text)
    with pytest.raises(PolicyConfigError):
        load_risk_thresholds(path)


def test_missing_file_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(PolicyConfigError):
        load_policies(tmp_path / "absent.yaml")


def test_non_utf8_file_is_a_configuration_error(tmp_path: Path) -> None:
    path = write(tmp_path / "policies.yaml", b"\xff\xfe\x00\x00")
    with pytest.raises(PolicyConfigError):
        load_policies(path)


def test_bundle_load_reports_the_missing_side(tmp_path: Path) -> None:
    policies = write(tmp_path / "policies.yaml", VALID_POLICIES)
    with pytest.raises(PolicyConfigError, match="thresholds.yaml"):
        load_policy_bundle(policies, tmp_path / "absent-thresholds.yaml")
