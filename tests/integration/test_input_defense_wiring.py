"""Phase 3 startup wiring (blueprint section 7.2; ADR-007/008/009 stay intact).

The input-defense configuration must be validated at startup (invalid/incomplete
configuration refuses to boot), and the detection service plus the session signal store
must be available on ``app.state`` for the later routes. Detection never authorizes.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from ai_security.api.app import create_app
from ai_security.input_defense.config import (
    InputDefenseConfigError,
    LoadedInputDefenseConfig,
)
from ai_security.input_defense.models import TrustLabel
from ai_security.input_defense.service import InputDefenseService
from ai_security.persistence.session_repository import SessionSecurityRepository
from ai_security.settings import Settings

SettingsFactory = Callable[..., Settings]
REPO_CONFIG = Path("config/input_defense.yaml")


def test_create_app_builds_input_defense_and_session_store(
    settings_factory: SettingsFactory, migrated_database: str
) -> None:
    app = create_app(settings_factory())
    loaded = app.state.input_defense_config
    service = app.state.input_defense_service
    sessions = app.state.session_security

    assert isinstance(loaded, LoadedInputDefenseConfig)
    assert isinstance(service, InputDefenseService)
    assert isinstance(sessions, SessionSecurityRepository)

    report = service.inspect(
        b"Please summarize the report.",
        content_type="text/plain",
        trust_label=TrustLabel.authenticated_user,
        source_id="request",
    )
    assert report.config_sha256 == loaded.sha256
    assert report.findings == ()


def test_startup_refuses_missing_input_defense_config(
    settings_factory: SettingsFactory, tmp_path: Path
) -> None:
    with pytest.raises(InputDefenseConfigError):
        create_app(settings_factory(input_defense_path=str(tmp_path / "absent.yaml")))


def test_startup_refuses_incomplete_dispositions(
    settings_factory: SettingsFactory, tmp_path: Path
) -> None:
    incomplete = tmp_path / "input_defense.yaml"
    incomplete.write_text(
        REPO_CONFIG.read_text(encoding="utf-8").replace("  DETECTOR_UNAVAILABLE: REJECT\n", ""),
        encoding="utf-8",
    )
    with pytest.raises(InputDefenseConfigError):
        create_app(settings_factory(input_defense_path=str(incomplete)))


def test_startup_refuses_duplicate_config_keys(
    settings_factory: SettingsFactory, tmp_path: Path
) -> None:
    duplicate = tmp_path / "input_defense.yaml"
    duplicate.write_text(
        REPO_CONFIG.read_text(encoding="utf-8").replace(
            "version: dev-1", "version: dev-1\nversion: dev-2"
        ),
        encoding="utf-8",
    )
    with pytest.raises(InputDefenseConfigError):
        create_app(settings_factory(input_defense_path=str(duplicate)))
