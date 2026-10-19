"""End-to-end host-authentication tests (blueprint section 9.2, §21 Phase 0b).

The real application (with the real middleware, real SQLAlchemy replay store, and the
migrated test database) is exercised with test-only ``/v1`` routes: valid signed
requests reach the route with the verified host context; unsigned, forged, mutated,
stale, unknown-key, replayed, and oversized requests each get their documented denial
and never reach protected processing.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Iterator

import pytest
from fastapi import APIRouter, FastAPI, Request
from fastapi.testclient import TestClient

from ai_security.api.app import create_app
from ai_security.identity.signing import sign_request
from ai_security.persistence.nonce_repository import NonceRegistrationError
from ai_security.settings import HostAuthKey, Settings

SettingsFactory = Callable[..., Settings]

KEY_ID = "test-key"


def build_app(settings: Settings) -> FastAPI:
    """The real application plus test-only /v1 routes that echo authenticated state."""
    app = create_app(settings)
    router = APIRouter()

    @router.post("/v1/echo")
    async def echo(request: Request) -> dict[str, str]:
        host_context = request.scope["state"]["host_auth"]
        body = await request.body()
        return {"host_id": host_context.host_id, "body": body.decode("utf-8")}

    @router.get("/v1/context")
    async def context(request: Request) -> dict[str, list[str]]:
        host_context = request.scope["state"]["host_auth"]
        return {"allowed_tenants": list(host_context.allowed_tenants)}

    app.include_router(router)
    return app


@pytest.fixture
def settings(settings_factory: SettingsFactory, migrated_database: str) -> Settings:
    return settings_factory(database_url=migrated_database)


@pytest.fixture
def key(settings: Settings) -> HostAuthKey:
    return settings.host_auth_keys[KEY_ID]


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(build_app(settings)) as test_client:
        yield test_client


def auth_headers(
    key: HostAuthKey,
    *,
    method: str,
    path: str,
    body: bytes = b"",
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    signature = sign_request(
        key.secret_bytes,
        key_id=KEY_ID,
        method=method,
        path=path,
        body=body,
        timestamp=timestamp,
        nonce=nonce,
    )
    return signature.as_headers()


def test_valid_signed_request_reaches_route(client: TestClient, key: HostAuthKey) -> None:
    body = b"hello gateway"
    headers = auth_headers(key, method="POST", path="/v1/echo", body=body)
    response = client.post("/v1/echo", content=body, headers=headers)
    assert response.status_code == 200
    assert response.json() == {"host_id": "test-host", "body": "hello gateway"}


def test_verified_context_exposes_audience_tenants(client: TestClient, key: HostAuthKey) -> None:
    headers = auth_headers(key, method="GET", path="/v1/context")
    response = client.get("/v1/context", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"allowed_tenants": ["test-tenant"]}


def test_unsigned_request_is_denied(client: TestClient) -> None:
    response = client.post("/v1/echo", content=b"hello")
    assert response.status_code == 400
    assert response.json() == {"detail": "missing_headers"}


def test_forged_signature_is_denied(client: TestClient, key: HostAuthKey) -> None:
    headers = auth_headers(key, method="POST", path="/v1/echo", body=b"hello")
    original = headers["X-Gateway-Signature"]
    headers["X-Gateway-Signature"] = ("0" if original[0] != "0" else "1") + original[1:]
    response = client.post("/v1/echo", content=b"hello", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "bad_signature"}


def test_signed_body_mutation_is_denied(client: TestClient, key: HostAuthKey) -> None:
    headers = auth_headers(key, method="POST", path="/v1/echo", body=b"hello")
    response = client.post("/v1/echo", content=b"hello!", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "bad_signature"}


def test_stale_timestamp_is_denied(client: TestClient, key: HostAuthKey) -> None:
    headers = auth_headers(
        key, method="POST", path="/v1/echo", body=b"hello", timestamp=int(time.time()) - 120
    )
    response = client.post("/v1/echo", content=b"hello", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "stale_timestamp"}


def test_unknown_key_id_is_denied(client: TestClient, key: HostAuthKey) -> None:
    signature = sign_request(
        key.secret_bytes,
        key_id="ghost-key",
        method="POST",
        path="/v1/echo",
        body=b"hello",
        timestamp=int(time.time()),
    )
    response = client.post("/v1/echo", content=b"hello", headers=signature.as_headers())
    assert response.status_code == 401
    assert response.json() == {"detail": "unknown_key_id"}


def test_replayed_nonce_is_denied(client: TestClient, key: HostAuthKey) -> None:
    nonce = uuid.uuid4().hex
    headers = auth_headers(key, method="POST", path="/v1/echo", body=b"hello", nonce=nonce)
    first = client.post("/v1/echo", content=b"hello", headers=headers)
    assert first.status_code == 200
    replay = client.post("/v1/echo", content=b"hello", headers=headers)
    assert replay.status_code == 401
    assert replay.json() == {"detail": "replayed_nonce"}


def test_nonce_store_failure_is_denied_503(settings: Settings, key: HostAuthKey) -> None:
    app = build_app(settings)

    class FailingRegistrar:
        async def register(self, *, key_id: str, nonce: str, ttl_seconds: int) -> bool:
            raise NonceRegistrationError("simulated outage")

    app.state.nonce_registrar = FailingRegistrar()
    with TestClient(app) as client:
        response = client.post(
            "/v1/echo",
            content=b"hello",
            headers=auth_headers(key, method="POST", path="/v1/echo", body=b"hello"),
        )
    assert response.status_code == 503
    assert response.json() == {"detail": "nonce_store_unavailable"}


def test_oversized_content_length_is_denied_413(
    settings_factory: SettingsFactory, migrated_database: str
) -> None:
    settings = settings_factory(database_url=migrated_database, request_max_bytes=64)
    key = settings.host_auth_keys[KEY_ID]
    body = b"x" * 100
    with TestClient(build_app(settings)) as client:
        response = client.post(
            "/v1/echo",
            content=body,
            headers=auth_headers(key, method="POST", path="/v1/echo", body=body),
        )
    assert response.status_code == 413
    assert response.json() == {"detail": "request_too_large"}


def test_oversized_chunked_body_is_denied_413(
    settings_factory: SettingsFactory, migrated_database: str
) -> None:
    settings = settings_factory(database_url=migrated_database, request_max_bytes=64)
    key = settings.host_auth_keys[KEY_ID]

    def chunks() -> Iterator[bytes]:
        for _ in range(10):
            yield b"x" * 20

    with TestClient(build_app(settings)) as client:
        response = client.post(
            "/v1/echo", content=chunks(), headers=auth_headers(key, method="POST", path="/v1/echo")
        )
    assert response.status_code == 413
    assert response.json() == {"detail": "request_too_large"}


def test_query_string_is_denied(client: TestClient, key: HostAuthKey) -> None:
    response = client.get(
        "/v1/context?extra=1", headers=auth_headers(key, method="GET", path="/v1/context")
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "invalid_request_target"}


def test_non_v1_paths_are_not_authenticated(client: TestClient) -> None:
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code in (200, 503)
