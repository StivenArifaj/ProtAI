"""Health endpoints, environment gating, and non-leakage tests (blueprint section 18)."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_security.api.app import create_app
from ai_security.api.dependencies import database_ready, policy_self_checks_ok
from ai_security.settings import Settings

SettingsFactory = Callable[..., Settings]


def override_database_ready(app: FastAPI, *, ready: bool) -> None:
    async def _ready() -> bool:
        return ready

    app.dependency_overrides[database_ready] = _ready


def override_policy_self_checks(app: FastAPI, *, ok: bool) -> None:
    async def _ok() -> bool:
        return ok

    app.dependency_overrides[policy_self_checks_ok] = _ok


@pytest.fixture
def client(settings_factory: SettingsFactory) -> Iterator[TestClient]:
    app = create_app(settings_factory())
    override_database_ready(app, ready=True)
    with TestClient(app) as test_client:
        yield test_client


def test_liveness_returns_alive(client: TestClient) -> None:
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


def test_readiness_returns_ready_when_all_checks_pass(client: TestClient) -> None:
    response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "checks": {"config": True, "database": True, "policy_self_checks": True},
    }


def test_readiness_returns_503_and_leaks_nothing(settings_factory: SettingsFactory) -> None:
    app = create_app(settings_factory())
    override_database_ready(app, ready=False)
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "checks": {"config": True, "database": False, "policy_self_checks": True},
    }
    for forbidden in ("firewall_dev_only", "postgresql", "asyncpg", "Traceback"):
        assert forbidden not in response.text


def test_readiness_returns_503_when_policy_self_checks_fail(
    settings_factory: SettingsFactory,
) -> None:
    app = create_app(settings_factory())
    override_database_ready(app, ready=True)
    override_policy_self_checks(app, ok=False)
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "checks": {"config": True, "database": True, "policy_self_checks": False},
    }


@pytest.mark.parametrize("env", ["development", "test"])
def test_docs_present_only_in_dev_test(settings_factory: SettingsFactory, env: str) -> None:
    app = create_app(settings_factory(app_env=env))
    with TestClient(app) as client:
        assert client.get("/docs").status_code == 200
        assert client.get("/redoc").status_code == 200
        openapi = client.get("/openapi.json")
        assert openapi.status_code == 200
        paths = set(openapi.json()["paths"])
    assert paths == {"/health/live", "/health/ready"}


@pytest.mark.parametrize("env", ["staging", "production"])
def test_docs_absent_outside_dev_test(settings_factory: SettingsFactory, env: str) -> None:
    app = create_app(
        settings_factory(
            app_env=env,
            database_url="postgresql+asyncpg://firewall:zq8-real-credential@db:5432/firewall",
        )
    )
    with TestClient(app) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/redoc").status_code == 404
        assert client.get("/openapi.json").status_code == 404
        assert client.get("/health/live").status_code == 200


def test_app_factory_uses_provided_settings(settings_factory: SettingsFactory) -> None:
    settings = settings_factory(app_env="development")
    app = create_app(settings)
    assert app.state.settings is settings
