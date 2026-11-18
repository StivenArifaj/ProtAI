"""Console API tests with a stubbed session layer (no live PostgreSQL required).

Covers auth, RBAC, CSRF, redacted schemas, and every read route returning 200 with
no secrets or raw content. The stub returns empty audit/approval data; integration
tests for real persistence remain in the main suite.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from ai_security.api.app import create_app
from ai_security.console.auth import (
    ROLE_PERMISSIONS,
    ConsoleRole,
    Permission,
    SessionStore,
    hash_password,
    verify_password,
)
from ai_security.settings import Settings

TEST_SETTINGS = {
    "app_env": "test",
    "log_level": "WARNING",
    "database_url": "postgresql+asyncpg://firewall:firewall_dev_only@127.0.0.1:5432/firewall_test",
    "principal_resolver": "dev",
    "host_auth_keys_json": (
        '{"k":{"secret_b64":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",'
        '"host_id":"h","audience":"a","allowed_tenants":["t"]}}'
    ),
    "console_enabled": True,
}


class _Scalars:
    def all(self) -> list[Any]:
        return []


class _Result:
    def first(self) -> tuple[Any, ...] | None:
        return (1, "0" * 64)

    def scalar(self) -> int:
        return 0

    def scalars(self) -> _Scalars:
        return _Scalars()


class _Session:
    async def execute(self, _statement: Any) -> _Result:
        return _Result()

    async def scalar(self, _statement: Any) -> int:
        return 0

    async def __aenter__(self) -> _Session:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None


def _factory() -> _Session:
    return _Session()


@pytest.fixture
def client() -> TestClient:
    settings = Settings(_env_file=None, **TEST_SETTINGS)  # type: ignore[arg-type]
    app = create_app(settings)
    app.state.database.session_factory = _factory
    app.state.console_service._sessions = _factory  # type: ignore[attr-defined]
    with TestClient(app) as test_client:
        yield test_client


def _login(
    client: TestClient,
    username: str = "admin",
    password: str = "CONSOLE_DEV_ONLY_PASSWORD",  # noqa: S107 - documented local sample
) -> None:
    response = client.post("/admin/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text


def test_password_hashing_and_verification() -> None:
    stored = hash_password("a-strong-password")
    assert stored != "a-strong-password"
    assert verify_password("a-strong-password", stored) is True
    assert verify_password("wrong", stored) is False
    assert verify_password("anything", "malformed") is False


def test_role_permissions() -> None:
    assert Permission.audit_read in ROLE_PERMISSIONS[ConsoleRole.analyst]
    assert Permission.settings_write not in ROLE_PERMISSIONS[ConsoleRole.analyst]
    assert Permission.checkpoint_write in ROLE_PERMISSIONS[ConsoleRole.operator]
    assert Permission.approval_decide in ROLE_PERMISSIONS[ConsoleRole.approver]
    assert len(ROLE_PERMISSIONS[ConsoleRole.admin]) > len(ROLE_PERMISSIONS[ConsoleRole.viewer])


def test_session_store_expiry_and_revocation() -> None:
    from datetime import UTC, datetime, timedelta

    now = [datetime.now(UTC)]
    store = SessionStore(clock=lambda: now[0])
    user = __import__("ai_security.console.auth", fromlist=["ConsoleUser"]).ConsoleUser(
        username="u", role=ConsoleRole.viewer
    )
    session = store.create(user)
    assert store.get(session.token) is not None
    now[0] = now[0] + timedelta(hours=9)
    assert store.get(session.token) is None

    session2 = store.create(user)
    store.revoke(session2.token)
    assert store.get(session2.token) is None


def test_login_required_for_console(client: TestClient) -> None:
    response = client.get("/admin/overview")
    assert response.status_code == 401


def test_login_and_session(client: TestClient) -> None:
    _login(client)
    response = client.get("/admin/meta/session")
    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "admin"
    assert "audit:read" in body["permissions"]
    assert "password" not in body


def test_bad_credentials(client: TestClient) -> None:
    response = client.post("/admin/auth/login", json={"username": "admin", "password": "wrong"})
    assert response.status_code == 401


def test_all_read_routes_are_redacted(client: TestClient) -> None:
    _login(client)
    for path in (
        "/admin/overview",
        "/admin/audit/events?limit=5",
        "/admin/audit/verify",
        "/admin/audit/checkpoints",
        "/admin/alerts",
        "/admin/alerts/rules",
        "/admin/approvals",
        "/admin/tools",
        "/admin/connectors",
        "/admin/policies",
        "/admin/configs",
        "/admin/limiter",
        "/admin/settings",
        "/admin/evaluation/reports",
        "/admin/auth/users",
    ):
        response = client.get(path)
        assert response.status_code == 200, f"{path}: {response.text}"
        text = response.text.lower()
        for forbidden in ("secret_b64", "password", "approval_token", "host_auth_keys"):
            assert forbidden not in text, f"{path} leaked {forbidden}"


def test_csrf_required_for_writes(client: TestClient) -> None:
    _login(client)
    response = client.post("/admin/alerts/summarize", json={"alert_sequence": 1})
    assert response.status_code == 403


def test_analyst_cannot_write_settings(client: TestClient) -> None:
    _login(client, "analyst")
    response = client.post(
        "/admin/auth/users",
        json={"username": "x", "password": "a-very-long-password", "role": "viewer"},
        headers={"X-Console-CSRF": client.cookies.get("protai_console_session") or ""},
    )
    assert response.status_code == 403


def test_v1_routes_unaffected(client: TestClient) -> None:
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


def test_built_spa_is_served(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "ProtAI Console" in response.text
    assert "/assets/" in response.text
