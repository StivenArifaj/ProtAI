"""Policy self-check startup/readiness wiring (ADR-007).

Startup must refuse on a missing/malformed fixture file or any matrix mismatch, and
readiness must re-evaluate the file live so post-startup drift flips the probe to 503.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_security.api.app import create_app
from ai_security.api.dependencies import database_ready
from ai_security.policy.self_checks import PolicySelfCheckConfigError, PolicySelfCheckError
from ai_security.settings import Settings

SettingsFactory = Callable[..., Settings]

GOOD_FIXTURES = """
fixtures:
  - name: read-allowed
    case: {tool_id: mock.read, side_effect_class: READ_ONLY, data_class: PUBLIC, risk: 0}
    expected_decision: ALLOW
"""

MISMATCHED_FIXTURES = GOOD_FIXTURES.replace("expected_decision: ALLOW", "expected_decision: BLOCK")


def override_database_ready(app: FastAPI, *, ready: bool) -> None:
    async def _ready() -> bool:
        return ready

    app.dependency_overrides[database_ready] = _ready


def write_fixtures(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_startup_fails_when_fixture_file_is_missing(
    settings_factory: SettingsFactory, tmp_path: Path
) -> None:
    missing = tmp_path / "absent.yaml"
    with pytest.raises(PolicySelfCheckConfigError):
        create_app(settings_factory(policy_self_checks_path=str(missing)))


def test_startup_fails_on_fixture_mismatch(
    settings_factory: SettingsFactory, tmp_path: Path
) -> None:
    path = write_fixtures(tmp_path / "fixtures.yaml", MISMATCHED_FIXTURES)
    with pytest.raises(PolicySelfCheckError) as excinfo:
        create_app(settings_factory(policy_self_checks_path=path))
    assert not isinstance(excinfo.value, PolicySelfCheckConfigError)
    assert "read-allowed" in str(excinfo.value)


def test_startup_and_readiness_pass_with_valid_fixture_file(
    settings_factory: SettingsFactory, tmp_path: Path
) -> None:
    path = write_fixtures(tmp_path / "fixtures.yaml", GOOD_FIXTURES)
    app = create_app(settings_factory(policy_self_checks_path=path))
    override_database_ready(app, ready=True)
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json()["checks"]["policy_self_checks"] is True


def test_readiness_flips_to_503_when_fixture_file_drifts_after_startup(
    settings_factory: SettingsFactory, tmp_path: Path
) -> None:
    path = write_fixtures(tmp_path / "fixtures.yaml", GOOD_FIXTURES)
    app = create_app(settings_factory(policy_self_checks_path=path))
    override_database_ready(app, ready=True)
    with TestClient(app) as client:
        assert client.get("/health/ready").status_code == 200
        write_fixtures(tmp_path / "fixtures.yaml", MISMATCHED_FIXTURES)
        response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["checks"]["policy_self_checks"] is False
