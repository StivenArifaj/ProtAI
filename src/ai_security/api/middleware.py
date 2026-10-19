"""Host-authentication middleware (blueprint section 9.2; ADR-001).

A pure ASGI middleware applied by request path, not by route registration: every
request whose raw path starts with ``/v1/`` is authenticated fail-closed even if no
``/v1`` route exists. Order of enforcement:

1. request-size bound — ``Content-Length`` is checked first; the body stream is also
   capped while being buffered, so an oversized body is rejected before signature
   verification and never buffered beyond the configured bound (413);
2. signature verification (``host_auth.verify_host_request``) — malformed targets or
   headers → 400, unknown key/stale timestamp/bad signature → 401;
3. nonce replay rejection — atomically registered through
   ``scope["app"].state.nonce_registrar`` (a per-application test-overridable hook);
   an already-used nonce → 401, a nonce-store failure → 503 (fail closed).

Only after all checks pass is the buffered body replayed to the downstream application,
with the verified host context placed in ``scope["state"]["host_auth"]``. Signatures,
bodies, and secrets are never logged. Denial bodies carry a stable machine-readable
``detail`` code only — no stack traces, no internals.
"""

from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ai_security.identity.host_auth import (
    HostAuthError,
    verified_nonce,
    verify_host_request,
)
from ai_security.persistence.nonce_repository import NonceRegistrar, NonceRegistrationError
from ai_security.settings import Settings

PROTECTED_PATH_PREFIX = b"/v1/"

DETAIL_REQUEST_TOO_LARGE = "request_too_large"
DETAIL_MALFORMED_CONTENT_LENGTH = "malformed_content_length"
DETAIL_REPLAYED_NONCE = "replayed_nonce"
DETAIL_NONCE_STORE_UNAVAILABLE = "nonce_store_unavailable"


class _BodyTooLarge(Exception):
    pass


class _ClientDisconnected(Exception):
    pass


def _raw_path(scope: Scope) -> bytes:
    raw: bytes | None = scope.get("raw_path")
    if raw is not None:
        return raw
    return str(scope["path"]).encode("ascii")


def _content_length(scope: Scope) -> int | None:
    """Parsed unique Content-Length, or None. Raises ValueError when malformed."""
    values = [value for name, value in scope["headers"] if name.lower() == b"content-length"]
    if not values:
        return None
    if len(values) > 1:
        raise ValueError("duplicated content-length")
    try:
        text = values[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("non-ascii content-length") from exc
    if not text.isdigit():
        raise ValueError("non-digit content-length")
    return int(text)


async def _read_capped_body(receive: Receive, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    more_body = True
    while more_body:
        message = await receive()
        if message["type"] == "http.disconnect":
            raise _ClientDisconnected
        if message["type"] != "http.request":
            continue
        chunk = message.get("body", b"")
        total += len(chunk)
        if total > limit:
            raise _BodyTooLarge
        chunks.append(chunk)
        more_body = message.get("more_body", False)
    return b"".join(chunks)


def _replaying_receive(body: bytes, original_receive: Receive) -> Receive:
    replayed = False

    async def receive() -> Message:
        nonlocal replayed
        if not replayed:
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await original_receive()

    return receive


async def _deny(scope: Scope, receive: Receive, send: Send, status: int, detail: str) -> None:
    await JSONResponse({"detail": detail}, status_code=status)(scope, receive, send)


class HostAuthMiddleware:
    """Fail-closed host authentication for all ``/v1/*`` requests."""

    def __init__(self, app: ASGIApp, *, settings: Settings) -> None:
        self._app = app
        self._settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not _raw_path(scope).startswith(PROTECTED_PATH_PREFIX):
            await self._app(scope, receive, send)
            return

        try:
            content_length = _content_length(scope)
        except ValueError:
            await _deny(scope, receive, send, 400, DETAIL_MALFORMED_CONTENT_LENGTH)
            return
        if content_length is not None and content_length > self._settings.request_max_bytes:
            await _deny(scope, receive, send, 413, DETAIL_REQUEST_TOO_LARGE)
            return

        try:
            body = await _read_capped_body(receive, self._settings.request_max_bytes)
        except _BodyTooLarge:
            await _deny(scope, receive, send, 413, DETAIL_REQUEST_TOO_LARGE)
            return
        except _ClientDisconnected:
            return

        try:
            context = verify_host_request(
                method=str(scope["method"]),
                raw_path=_raw_path(scope),
                query_string=scope.get("query_string", b""),
                headers=scope["headers"],
                body=body,
                keys=self._settings.host_auth_keys,
                tolerance_seconds=self._settings.host_auth_timestamp_tolerance_seconds,
            )
            nonce = verified_nonce(scope["headers"])
        except HostAuthError as exc:
            await _deny(scope, receive, send, exc.http_status, exc.code.value)
            return

        registrar: NonceRegistrar | None = getattr(scope["app"].state, "nonce_registrar", None)
        if registrar is None:
            await _deny(scope, receive, send, 503, DETAIL_NONCE_STORE_UNAVAILABLE)
            return
        try:
            fresh = await registrar.register(
                key_id=context.key_id,
                nonce=nonce,
                ttl_seconds=self._settings.host_auth_nonce_ttl_seconds,
            )
        except NonceRegistrationError:
            await _deny(scope, receive, send, 503, DETAIL_NONCE_STORE_UNAVAILABLE)
            return
        if not fresh:
            await _deny(scope, receive, send, 401, DETAIL_REPLAYED_NONCE)
            return

        scope.setdefault("state", {})["host_auth"] = context
        await self._app(scope, _replaying_receive(body, receive), send)
