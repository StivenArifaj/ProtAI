"""Cloud intent provider tests (ADR-018).

Verifies strict parsing, bounded output, key handling, fail-closed errors, settings
validation, and that model output remains advisory (no authority). Uses httpx2's
MockTransport — no real network or key required.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import httpx2
import pytest

from ai_security.intent.cloud_provider import (
    CloudModelProviderError,
    OpenAIChatIntentModelClient,
    response_text,
)
from ai_security.intent.extractors import LocalModelIntentExtractor
from ai_security.intent.models import IntentExtractionRequest, IntentExtractionStatus
from ai_security.settings import ModelProviderKind, Settings

API_KEY = "test-cloud-key-not-a-real-secret"
MODEL = "gpt-4o-mini"


def _run(coro) -> object:
    return asyncio.run(coro)


def _envelope(content: str) -> bytes:
    return json.dumps(
        {"choices": [{"message": {"role": "assistant", "content": content}}]}
    ).encode()


def test_response_text_valid() -> None:
    assert response_text(_envelope('{"status":"ACTIVE"}')) == '{"status":"ACTIVE"}'


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"{}",
        b"[]",
        b'{"choices": []}',
        b'{"choices": [{"message": {}}]}',
        b'{"choices": [{"message": {"content": 42}}]}',
        b'{"choices": [{"message": {"content": ""}}]}',
        b'{"choices": [{"message": {"content": "a"}}], "choices": []}',  # duplicate key
    ],
)
def test_response_text_rejects_malformed(raw: bytes) -> None:
    with pytest.raises(CloudModelProviderError):
        response_text(raw)


def test_response_text_bounds_output() -> None:
    with pytest.raises(CloudModelProviderError):
        response_text(_envelope("x" * 5000), max_bytes=1024)


def test_client_sends_key_in_authorization_header_and_fixed_path() -> None:
    seen: dict[str, object] = {}

    async def handler(request: httpx2.Request) -> httpx2.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx2.Response(200, json=json.loads(_envelope('{"status":"ACTIVE"}')))

    client = OpenAIChatIntentModelClient(
        origin="https://api.example.com",
        model=MODEL,
        api_key=API_KEY,
        timeout_seconds=5,
        transport=httpx2.MockTransport(handler),
    )
    result = _run(client.complete(prompt="read email-1 and summarize it"))
    assert result == '{"status":"ACTIVE"}'
    assert seen["url"] == "https://api.example.com/chat/completions"
    assert seen["auth"] == f"Bearer {API_KEY}"
    body = seen["body"]
    assert isinstance(body, dict)
    assert body["temperature"] == 0
    assert body["stream"] is False
    assert body["response_format"] == {"type": "json_object"}
    messages = body["messages"]
    assert messages[0]["role"] == "system"
    assert "authorization" not in messages[0]["content"].lower()
    assert "read email-1" in messages[1]["content"]


def test_client_fails_closed_on_non_200_without_echoing_key() -> None:
    def handler(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(401, text=f"invalid key {API_KEY}")

    client = OpenAIChatIntentModelClient(
        origin="https://api.example.com",
        model=MODEL,
        api_key=API_KEY,
        timeout_seconds=5,
        transport=httpx2.MockTransport(handler),
    )
    with pytest.raises(CloudModelProviderError) as exc:
        _run(client.complete(prompt="hello"))
    assert API_KEY not in str(exc.value)
    assert "non-200" in str(exc.value)


def test_client_rejects_non_json_content_type() -> None:
    def handler(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, text="<html>ok</html>", headers={"content-type": "text/html"})

    client = OpenAIChatIntentModelClient(
        origin="https://api.example.com",
        model=MODEL,
        api_key=API_KEY,
        timeout_seconds=5,
        transport=httpx2.MockTransport(handler),
    )
    with pytest.raises(CloudModelProviderError):
        _run(client.complete(prompt="hello"))


def test_extractor_with_cloud_client_produces_advisory_constraints() -> None:
    output = json.dumps(
        {
            "status": "ACTIVE",
            "constraints": [
                {
                    "tool_id": "mock_email.read",
                    "action_id": "read",
                    "allowed_resource_ids": ["email-1"],
                },
                {"tool_id": "text.summarize", "action_id": "summarize"},
            ],
            "confidence_score": 90,
        }
    )

    def handler(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json=json.loads(_envelope(output)))

    client = OpenAIChatIntentModelClient(
        origin="https://api.example.com",
        model=MODEL,
        api_key=API_KEY,
        timeout_seconds=5,
        transport=httpx2.MockTransport(handler),
    )
    extractor = LocalModelIntentExtractor(client)
    request = IntentExtractionRequest(
        request_id="req-1",
        principal_subject_id="user-1",
        text="read email-1 and summarize it",
        received_at=datetime.now(UTC),
    )
    result = _run(extractor.extract(request))
    assert result.status is IntentExtractionStatus.active
    assert len(result.constraints) == 2
    assert result.constraints[0].tool_id == "mock_email.read"
    # Model output never sets authority or bindings.
    assert not hasattr(result, "decision")


def test_settings_cloud_requires_key_and_exact_model() -> None:
    base = {
        "app_env": "test",
        "log_level": "WARNING",
        "database_url": "postgresql+asyncpg://f:f@127.0.0.1:5432/firewall_test",
        "principal_resolver": "dev",
        "host_auth_keys_json": (
            '{"k":{"secret_b64":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",'
            '"host_id":"h","audience":"a","allowed_tenants":["t"]}}'
        ),
        "model_provider": "cloud",
    }
    with pytest.raises(ValueError):
        Settings(_env_file=None, **base)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        Settings(_env_file=None, **base, cloud_model_api_key=API_KEY)  # type: ignore[arg-type]
    settings = Settings(
        _env_file=None,
        **base,
        cloud_model_api_key=API_KEY,
        cloud_model_name=MODEL,
        cloud_model_base_url="https://api.example.com/v1",
    )  # type: ignore[arg-type]
    assert settings.model_provider is ModelProviderKind.cloud
    assert settings.cloud_model_origin == "https://api.example.com/v1"
    assert settings.cloud_model_api_key.get_secret_value() == API_KEY


def test_settings_cloud_rejects_http_outside_dev() -> None:
    base = {
        "app_env": "production",
        "log_level": "WARNING",
        "database_url": "postgresql+asyncpg://f:realpass@127.0.0.1:5432/firewall",
        "principal_resolver": "host",
        "host_auth_keys_json": (
            '{"k":{"secret_b64":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",'
            '"host_id":"h","audience":"a","allowed_tenants":["t"]}}'
        ),
        "model_provider": "cloud",
        "cloud_model_api_key": API_KEY,
        "cloud_model_name": MODEL,
        "cloud_model_base_url": "http://api.example.com",
    }
    with pytest.raises(ValueError):
        Settings(_env_file=None, **base)  # type: ignore[arg-type]
