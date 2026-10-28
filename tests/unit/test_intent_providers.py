"""Unit tests for the Ollama-compatible local model client (ADR-015)."""

from __future__ import annotations

import asyncio
import json

import httpx2
import pytest

from ai_security.intent.extractors import MAX_MODEL_OUTPUT_BYTES, IntentExtractorUnavailable
from ai_security.intent.providers import (
    LocalModelProviderError,
    OllamaIntentModelClient,
)

ORIGIN = "http://localhost:11434"
MODEL = "test-model:latest"
GENERATE_URL = f"{ORIGIN}/api/generate"


def make_client(
    handler: httpx2.MockTransport,
    *,
    max_response_bytes: int = 1_048_576,
) -> OllamaIntentModelClient:
    return OllamaIntentModelClient(
        origin=ORIGIN,
        model=MODEL,
        timeout_seconds=5,
        transport=handler,
        max_response_bytes=max_response_bytes,
    )


def complete(client: OllamaIntentModelClient) -> str:
    return asyncio.run(client.complete(prompt="summarize my email"))


def envelope(response: str = '{"status": "REQUIRES_CLARIFICATION"}') -> httpx2.Response:
    return httpx2.Response(
        200,
        headers={"content-type": "application/json"},
        content=json.dumps({"response": response, "done": True}).encode("utf-8"),
    )


def test_complete_posts_one_strict_generate_request() -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return envelope()

    result = complete(make_client(httpx2.MockTransport(handler)))

    assert result == '{"status": "REQUIRES_CLARIFICATION"}'
    assert len(seen) == 1
    request = seen[0]
    assert request.method == "POST"
    assert str(request.url) == GENERATE_URL
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.content) == {
        "model": MODEL,
        "prompt": "summarize my email",
        "format": "json",
        "stream": False,
        "options": {"temperature": 0},
    }


def test_json_content_type_with_charset_is_accepted() -> None:
    response = httpx2.Response(
        200,
        headers={"content-type": "Application/JSON; charset=utf-8"},
        content=b'{"response": "{}", "done": true}',
    )
    result = complete(make_client(httpx2.MockTransport(lambda _request: response)))
    assert result == "{}"


@pytest.mark.parametrize(
    "body",
    (
        b'{"response": "{}", "response": "{}"}',
        b'{"response": "{}", "options": {"temperature": 0, "temperature": 1}}',
        b"not json",
        b"\xff\xfe",
        b"[]",
        b'{"done": true}',
        b'{"response": 7}',
        b'{"response": null}',
    ),
)
def test_malformed_envelopes_are_typed_failures(body: bytes) -> None:
    response = httpx2.Response(200, headers={"content-type": "application/json"}, content=body)
    with pytest.raises(LocalModelProviderError):
        complete(make_client(httpx2.MockTransport(lambda _request: response)))


def test_non_json_content_type_is_rejected() -> None:
    response = httpx2.Response(
        200, headers={"content-type": "text/plain"}, content=b'{"response": "{}"}'
    )
    with pytest.raises(LocalModelProviderError):
        complete(make_client(httpx2.MockTransport(lambda _request: response)))


def test_oversized_envelope_is_rejected_while_streaming() -> None:
    response = httpx2.Response(
        200,
        headers={"content-type": "application/json"},
        content=json.dumps({"response": "x" * 1_000}).encode("utf-8"),
    )
    with pytest.raises(LocalModelProviderError, match="bounded size"):
        complete(
            make_client(httpx2.MockTransport(lambda _request: response), max_response_bytes=64)
        )


def test_oversized_model_output_is_rejected() -> None:
    response = envelope("x" * (MAX_MODEL_OUTPUT_BYTES + 1))
    with pytest.raises(LocalModelProviderError, match="bounded size"):
        complete(make_client(httpx2.MockTransport(lambda _request: response)))


@pytest.mark.parametrize("status", (201, 204, 400, 404, 500, 503))
def test_non_200_status_is_rejected(status: int) -> None:
    response = httpx2.Response(
        status,
        headers={"content-type": "application/json"},
        content=b'{"response": "{}"}',
    )
    with pytest.raises(LocalModelProviderError, match="non-200"):
        complete(make_client(httpx2.MockTransport(lambda _request: response)))


def test_redirects_are_not_followed() -> None:
    calls: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(str(request.url))
        if request.url.path == "/api/generate":
            return httpx2.Response(
                302,
                headers={"location": "http://evil.example/steal"},
                content=b"",
            )
        return envelope()

    with pytest.raises(LocalModelProviderError):
        complete(make_client(httpx2.MockTransport(handler)))
    assert calls == [GENERATE_URL]


@pytest.mark.parametrize(
    "error",
    (
        httpx2.ConnectError("refused"),
        httpx2.ReadTimeout("slow"),
        httpx2.WriteTimeout("slow"),
        httpx2.PoolTimeout("busy"),
    ),
)
def test_transport_failures_are_typed_failures(error: Exception) -> None:
    def handler(_request: httpx2.Request) -> httpx2.Response:
        raise error

    with pytest.raises(LocalModelProviderError):
        complete(make_client(httpx2.MockTransport(handler)))


def test_provider_error_is_an_extractor_unavailable() -> None:
    error = LocalModelProviderError("local model request failed")
    assert isinstance(error, IntentExtractorUnavailable)


@pytest.mark.parametrize(
    "kwargs",
    (
        {"origin": "ftp://localhost:11434"},
        {"origin": "http://user:pass@localhost:11434"},
        {"origin": "http://localhost:11434?x=1"},
        {"origin": "http://localhost:11434#fragment"},
        {"model": ""},
        {"timeout_seconds": 0},
        {"timeout_seconds": 61},
        {"timeout_seconds": True},
        {"max_response_bytes": 0},
        {"max_response_bytes": True},
    ),
)
def test_invalid_constructor_arguments_are_rejected(kwargs: dict[str, object]) -> None:
    arguments: dict[str, object] = {
        "origin": ORIGIN,
        "model": MODEL,
        "timeout_seconds": 5,
        "transport": httpx2.MockTransport(lambda _request: envelope()),
    }
    arguments.update(kwargs)
    with pytest.raises(ValueError):
        OllamaIntentModelClient(**arguments)  # type: ignore[arg-type]


def test_trailing_slash_origin_is_normalized() -> None:
    client = OllamaIntentModelClient(
        origin=f"{ORIGIN}/",
        model=MODEL,
        timeout_seconds=5,
        transport=httpx2.MockTransport(lambda _request: envelope()),
    )
    assert client.url == GENERATE_URL
    assert complete(client) == '{"status": "REQUIRES_CLARIFICATION"}'
