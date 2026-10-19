"""Strict input-defense configuration loading (blueprint section 7.2).

Invalid, incomplete, duplicate-key, or contradictory configuration must refuse startup:
a detector failure or unsafe mapping can never be silently accepted.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ai_security.input_defense.config import (
    InputDefenseConfigError,
    load_input_defense_config,
)
from ai_security.input_defense.models import Disposition, FindingCode

REPO_CONFIG = Path("config/input_defense.yaml")


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "input_defense.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def repo_config_text() -> str:
    return REPO_CONFIG.read_text(encoding="utf-8")


def test_repo_config_loads_with_complete_dispositions() -> None:
    loaded = load_input_defense_config(REPO_CONFIG)
    assert loaded.config.version == "dev-1"
    assert set(loaded.config.dispositions) == set(FindingCode)
    assert loaded.config.dispositions[FindingCode.detector_unavailable] is Disposition.reject
    assert len(loaded.sha256) == 64


def test_missing_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(InputDefenseConfigError):
        load_input_defense_config(tmp_path / "absent.yaml")


def test_non_utf8_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "input_defense.yaml"
    path.write_bytes(b"\xff\xfe\x00garbage")
    with pytest.raises(InputDefenseConfigError):
        load_input_defense_config(path)


def test_duplicate_keys_are_refused(tmp_path: Path) -> None:
    text = repo_config_text().replace("version: dev-1", "version: dev-1\nversion: dev-2")
    with pytest.raises(InputDefenseConfigError):
        load_input_defense_config(write(tmp_path, text))


def test_missing_disposition_is_refused(tmp_path: Path) -> None:
    text = repo_config_text().replace("  DETECTOR_UNAVAILABLE: REJECT\n", "")
    with pytest.raises(InputDefenseConfigError):
        load_input_defense_config(write(tmp_path, text))


def test_pass_mapping_is_refused(tmp_path: Path) -> None:
    text = repo_config_text().replace(
        "  DETECTOR_UNAVAILABLE: REJECT", "  DETECTOR_UNAVAILABLE: PASS"
    )
    with pytest.raises(InputDefenseConfigError):
        load_input_defense_config(write(tmp_path, text))


def test_unknown_finding_code_is_refused(tmp_path: Path) -> None:
    text = repo_config_text().replace("  DETECTOR_UNAVAILABLE: REJECT", "  NOT_A_REAL_CODE: REJECT")
    with pytest.raises(InputDefenseConfigError):
        load_input_defense_config(write(tmp_path, text))


def test_invalid_content_type_is_refused(tmp_path: Path) -> None:
    text = repo_config_text().replace("  - text/plain", "  - not a content type")
    with pytest.raises(InputDefenseConfigError):
        load_input_defense_config(write(tmp_path, text))


def test_content_type_matching_strips_parameters_and_normalizes_case() -> None:
    config = load_input_defense_config(REPO_CONFIG).config
    assert config.base_content_type("Text/Plain; charset=utf-8") == "text/plain"
    assert config.base_content_type("application/json") == "application/json"
    assert config.base_content_type("application/octet-stream") is None
