"""Policy startup/readiness wiring (ADR-007, ADR-008).

Startup must refuse on missing/malformed policy documents, a missing/malformed fixture
file, or any matrix mismatch; readiness must re-evaluate the on-disk configuration live
so post-startup drift flips the probe to 503 while the running process keeps its
startup-loaded bundle (no hot reload in v1).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_security.api.app import create_app
from ai_security.api.dependencies import database_ready
from ai_security.policy.loader import PolicyConfigError
from ai_security.policy.self_checks import PolicySelfCheckConfigError, PolicySelfCheckError
from ai_security.settings import Settings

SettingsFactory = Callable[..., Settings]

REPO_POLICIES = Path("config/policies.yaml")

GOOD_FIXTURES = """
fixtures:
  - name: read-allowed
    case:
      tool_id: mock_email.read
      side_effect_class: READ_ONLY
      data_class: PUBLIC
      risk_score: 0
    expected_decision: ALLOW
    expected_reason: authorized_read
"""

MISMATCHED_FIXTURES = GOOD_FIXTURES.replace("expected_decision: ALLOW", "expected_decision: BLOCK")


def override_database_ready(app: FastAPI, *, ready: bool) -> None:
    async def _ready() -> bool:
        return ready

    app.dependency_overrides[database_ready] = _ready


def write_text(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    return str(path)


def copy_repo_policies(tmp_path: Path) -> Path:
    copied = tmp_path / "policies.yaml"
    copied.write_text(REPO_POLICIES.read_text(encoding="utf-8"), encoding="utf-8")
    return copied


# -- startup refusal ------------------------------------------------------------------


def test_startup_fails_when_fixture_file_is_missing(
    settings_factory: SettingsFactory, tmp_path: Path
) -> None:
    missing = tmp_path / "absent.yaml"
    with pytest.raises(PolicySelfCheckConfigError):
        create_app(settings_factory(policy_self_checks_path=str(missing)))


def test_startup_fails_when_policy_file_is_missing(
    settings_factory: SettingsFactory, tmp_path: Path
) -> None:
    missing = tmp_path / "absent-policies.yaml"
    with pytest.raises(PolicyConfigError):
        create_app(settings_factory(policy_path=str(missing)))


def test_startup_fails_on_invalid_policy_documents(
    settings_factory: SettingsFactory, tmp_path: Path
) -> None:
    bad = write_text(tmp_path / "policies.yaml", "schema_version: 2\nversion: v1\ntools: {}\n")
    with pytest.raises(PolicyConfigError):
        create_app(settings_factory(policy_path=bad))


def test_startup_fails_on_fixture_mismatch(
    settings_factory: SettingsFactory, tmp_path: Path
) -> None:
    path = write_text(tmp_path / "fixtures.yaml", MISMATCHED_FIXTURES)
    with pytest.raises(PolicySelfCheckError) as excinfo:
        create_app(settings_factory(policy_self_checks_path=path))
    assert not isinstance(excinfo.value, PolicySelfCheckConfigError)
    assert "read-allowed" in str(excinfo.value)


# -- readiness ------------------------------------------------------------------------


def test_startup_and_readiness_pass_with_valid_fixture_file(
    settings_factory: SettingsFactory, tmp_path: Path
) -> None:
    path = write_text(tmp_path / "fixtures.yaml", GOOD_FIXTURES)
    app = create_app(settings_factory(policy_self_checks_path=path))
    override_database_ready(app, ready=True)
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 200
    payload = response.json()
    assert payload["checks"]["policy_self_checks"] is True
    assert payload["policy_version"] == "dev-1"
    assert len(payload["policy_hash"]) == 64


def test_startup_binds_the_validated_bundle_to_app_state(settings_factory: SettingsFactory) -> None:
    app = create_app(settings_factory())
    assert app.state.policy_bundle.version == "dev-1"
    assert len(app.state.policy_bundle.combined_hash) == 64


def test_readiness_flips_to_503_when_fixture_file_drifts_after_startup(
    settings_factory: SettingsFactory, tmp_path: Path
) -> None:
    path = write_text(tmp_path / "fixtures.yaml", GOOD_FIXTURES)
    app = create_app(settings_factory(policy_self_checks_path=path))
    override_database_ready(app, ready=True)
    with TestClient(app) as client:
        assert client.get("/health/ready").status_code == 200
        write_text(tmp_path / "fixtures.yaml", MISMATCHED_FIXTURES)
        response = client.get("/health/ready")
    assert response.status_code == 503
    payload = response.json()
    assert payload["checks"]["policy_self_checks"] is False
    assert payload["policy_version"] == "dev-1"


def test_readiness_detects_policy_drift_after_startup(
    settings_factory: SettingsFactory, tmp_path: Path
) -> None:
    copied = copy_repo_policies(tmp_path)
    app = create_app(settings_factory(policy_path=str(copied)))
    override_database_ready(app, ready=True)
    with TestClient(app) as client:
        assert client.get("/health/ready").status_code == 200
        write_text(copied, "schema_version: 1\nversion: dev-2\ntools: {}\n")
        response = client.get("/health/ready")
    assert response.status_code == 503
    payload = response.json()
    assert payload["checks"]["policy_self_checks"] is False
    assert payload["policy_version"] == "dev-2"
    # The running process keeps its startup-loaded bundle; hot reload is future work.
    assert app.state.policy_bundle.version == "dev-1"
