"""Safe HTTP error envelopes and strict JSON body parsing for the ``/v1`` ingress.

Every new business route returns the documented error shape::

    {"error": {"code": "<stable_code>", "message": "<safe text>", "request_id": "<id>"}}

Transport-level middleware denials keep their older ``{"detail": "<code>"}`` contract;
this module applies only to the application routes introduced in Phase 8.

Body parsing is deliberately manual instead of relying on FastAPI's default JSON
decoder so duplicate object keys, non-finite numbers, non-object documents, and
unsupported media types are rejected before any typed model exists. Error messages
never echo the submitted body, a stack trace, or an exception string.
"""

from __future__ import annotations

import json
import re
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_MAX_MESSAGE_LENGTH = 256
_JSON_CONTENT_TYPE = "application/json"


class ApiError(Exception):
    """A route failure that maps to a stable, non-leaking HTTP error envelope."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        request_id: str,
        state: str | None = None,
    ) -> None:
        if not 400 <= status_code <= 599:
            raise ValueError("ApiError status_code must be a client/server error status")
        if _ERROR_CODE.fullmatch(code) is None:
            raise ValueError(f"invalid API error code {code!r}")
        if (
            not message
            or len(message) > _MAX_MESSAGE_LENGTH
            or _CONTROL_CHARACTERS.search(message) is not None
        ):
            raise ValueError("API error messages must be short and control-free")
        if not request_id or _CONTROL_CHARACTERS.search(request_id) is not None:
            raise ValueError("API error request_id must be non-empty and control-free")
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.request_id = request_id
        self.state = state

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "error": {
                "code": self.code,
                "message": self.message,
                "request_id": self.request_id,
            }
        }
        if self.state is not None:
            payload["state"] = self.state
        return payload


async def api_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    """Render ``ApiError`` without exposing internals (registered per application)."""
    if not isinstance(exc, ApiError):
        raise exc
    return JSONResponse(status_code=exc.status_code, content=exc.to_payload())


class RequestBodyError(ValueError):
    """The raw request body is not an acceptable JSON object."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RequestBodyError("duplicate_json_key")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> Any:
    raise RequestBodyError("non_finite_number")


async def read_json_object(request: Request, *, request_id: str) -> dict[str, Any]:
    """Read one bounded, strict JSON object with duplicate-key rejection."""
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != _JSON_CONTENT_TYPE:
        raise ApiError(
            415,
            "unsupported_media_type",
            "The request body must use application/json.",
            request_id=request_id,
        )
    body = await request.body()
    if not body:
        raise ApiError(
            400,
            "invalid_request",
            "The request body must be a JSON object.",
            request_id=request_id,
        )
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApiError(
            400,
            "invalid_request",
            "The request body must be UTF-8 JSON.",
            request_id=request_id,
        ) from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except (json.JSONDecodeError, RequestBodyError) as exc:
        raise ApiError(
            400,
            "invalid_request",
            "The request body must be a well-formed JSON object without duplicate keys.",
            request_id=request_id,
        ) from exc
    if not isinstance(parsed, dict):
        raise ApiError(
            400,
            "invalid_request",
            "The request body must be a JSON object.",
            request_id=request_id,
        )
    return parsed


def validate_body[ModelT: BaseModel](
    model: type[ModelT], payload: object, *, request_id: str
) -> ModelT:
    """Validate a parsed body; validation details are never reflected to the caller."""
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        raise ApiError(
            400,
            "invalid_request",
            "The request body does not match the required schema.",
            request_id=request_id,
        ) from exc


__all__ = [
    "ApiError",
    "RequestBodyError",
    "api_error_handler",
    "read_json_object",
    "validate_body",
]
