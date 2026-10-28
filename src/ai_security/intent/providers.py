"""Ollama-compatible local model client for intent extraction (Phase 8; ADR-015).

This module is the only place in v1 that speaks to a model server. It is optional:
``MODEL_PROVIDER=mock`` is the default and performs no network I/O. When the operator
selects ``local``, the client sends one non-streaming ``/api/generate`` request with
``format=json`` and ``temperature=0``, refuses redirects and environment proxies, bounds
the whole exchange with a timeout, and bounds the response body before parsing it with
duplicate-key rejection.

Nothing here can authorize an action. A successful call returns model text that
``LocalModelIntentExtractor`` validates into advisory constraints; a failed call raises
``LocalModelProviderError`` (an ``IntentExtractorUnavailable``), which the intent service
turns into ``EXTRACTOR_UNAVAILABLE`` with no manifest. Provider failures never reach
policy, DLP, approval, or execution as an allow signal.
"""

from __future__ import annotations

import json
from typing import Any

import httpx2

from ai_security.intent.extractors import (
    MAX_MODEL_OUTPUT_BYTES,
    IntentExtractorUnavailable,
    IntentModelClient,
)
from ai_security.settings import LOCAL_MODEL_GENERATE_PATH

DEFAULT_MAX_RESPONSE_BYTES = 1_048_576
_JSON_CONTENT_TYPE = "application/json"
_MAX_MODEL_NAME_LENGTH = 256


class LocalModelProviderError(IntentExtractorUnavailable):
    """A typed local-provider failure; always yields no manifest and no execution."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _response_text(raw: bytes) -> str:
    """Extract the bounded ``response`` string from one Ollama envelope.

    The envelope is untrusted local-process output: duplicate keys, invalid UTF-8,
    non-object documents, a missing/non-string ``response``, and an oversized response
    are all typed provider failures. Unknown envelope fields are ignored because the
    Ollama protocol includes metadata this client does not need.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LocalModelProviderError("local model returned invalid UTF-8") from exc
    try:
        payload: Any = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise LocalModelProviderError("local model returned a malformed envelope") from exc
    if not isinstance(payload, dict):
        raise LocalModelProviderError("local model envelope must be a JSON object")
    response = payload.get("response")
    if not isinstance(response, str):
        raise LocalModelProviderError("local model envelope has no response string")
    if len(response.encode("utf-8")) > MAX_MODEL_OUTPUT_BYTES:
        raise LocalModelProviderError("local model output exceeds the bounded size")
    return response


class OllamaIntentModelClient(IntentModelClient):
    """Strict non-streaming client for an Ollama-compatible ``/api/generate`` endpoint.

    A client is constructed from operator-validated settings and performs no I/O until
    ``complete`` is awaited. The fixed generate path, no redirects, no environment proxy
    trust, and per-request timeout bound the provider as an optional dependency.
    """

    def __init__(
        self,
        *,
        origin: str,
        model: str,
        timeout_seconds: float,
        transport: httpx2.AsyncBaseTransport | None = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        if not isinstance(origin, str) or not origin.startswith(("http://", "https://")):
            raise ValueError("origin must be an absolute http(s) origin")
        if any(character in origin for character in "?#@") or any(
            character in origin for character in "\r\n\t "
        ):
            raise ValueError("origin must not contain credentials, a query, or a fragment")
        if not isinstance(model, str) or not model:
            raise ValueError("model must not be empty")
        if len(model) > _MAX_MODEL_NAME_LENGTH or any(character in model for character in "\r\n\t"):
            raise ValueError("model must be a bounded single-line name")
        if isinstance(timeout_seconds, bool) or not 0.1 <= timeout_seconds <= 60:
            raise ValueError("timeout_seconds must be in [0.1, 60]")
        if isinstance(max_response_bytes, bool) or not 1 <= max_response_bytes <= 8_388_608:
            raise ValueError("max_response_bytes must be in [1, 8388608]")
        self._url = f"{origin.rstrip('/')}{LOCAL_MODEL_GENERATE_PATH}"
        self._model = model
        self._timeout = float(timeout_seconds)
        self._transport = transport
        self._max_response_bytes = max_response_bytes

    @property
    def url(self) -> str:
        """The fixed endpoint URL (for operator diagnostics and tests)."""
        return self._url

    async def complete(self, *, prompt: str) -> str:
        request_body = {
            "model": self._model,
            "prompt": prompt,
            "format": "json",
            "stream": False,
            "options": {"temperature": 0},
        }
        try:
            async with httpx2.AsyncClient(
                timeout=httpx2.Timeout(self._timeout),
                follow_redirects=False,
                trust_env=False,
                transport=self._transport,
            ) as client:
                async with client.stream("POST", self._url, json=request_body) as response:
                    if response.status_code != 200:
                        raise LocalModelProviderError("local model returned a non-200 response")
                    content_type = response.headers.get("content-type", "")
                    media_type = content_type.split(";", 1)[0].strip().lower()
                    if media_type != _JSON_CONTENT_TYPE:
                        raise LocalModelProviderError(
                            "local model returned a non-JSON content type"
                        )
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > self._max_response_bytes:
                            raise LocalModelProviderError(
                                "local model response exceeds the bounded size"
                            )
        except LocalModelProviderError:
            raise
        except (httpx2.HTTPError, OSError) as exc:
            raise LocalModelProviderError("local model request failed") from exc
        return _response_text(bytes(raw))


__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "LocalModelProviderError",
    "OllamaIntentModelClient",
]
