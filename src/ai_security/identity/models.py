"""Typed principal contract (blueprint section 6.1; ADR-001).

A ``Principal`` is the server-resolved identity/context every decision consumes. It is
constructed only by a principal resolver after the configured authentication check has
succeeded; request dialogs, LLM output, and memory-derived text can never populate
these fields. The model is frozen and rejects unknown fields so downstream code can
rely on its shape.
"""

from __future__ import annotations

import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator

CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")

_FREE_TEXT_FIELDS = (
    "subject_id",
    "tenant_id",
    "auth_method",
    "issuer",
    "permissions_context_ref",
)


class Principal(BaseModel):
    """Server-resolved principal context.

    ``tenant_id`` is present when the host integration supports tenancy; ``timezone``
    is an optional IANA timezone carried by the signed host assertion or trusted
    user-profile adapter. ``auth_method``/``issuer`` record how the principal was
    authenticated, and ``permissions_context_ref`` is the stable reference later used
    to bind authorization context into the audit trail (blueprint section 6.1).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_id: str = Field(min_length=1, max_length=256)
    roles: tuple[str, ...] = ()
    tenant_id: str | None = Field(default=None, min_length=1, max_length=256)
    timezone: str | None = Field(default=None, min_length=1, max_length=64)
    auth_method: str = Field(min_length=1, max_length=256)
    issuer: str = Field(min_length=1, max_length=256)
    permissions_context_ref: str = Field(min_length=1, max_length=256)

    @field_validator(*_FREE_TEXT_FIELDS)
    @classmethod
    def _no_control_characters(cls, value: str | None) -> str | None:
        if value is not None and CONTROL_CHARACTERS.search(value):
            raise ValueError("must not contain control characters")
        return value

    @field_validator("roles")
    @classmethod
    def _roles_are_clean(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for role in value:
            if not role or CONTROL_CHARACTERS.search(role):
                raise ValueError("role entries must be non-empty and control-free")
        return value

    @field_validator("timezone")
    @classmethod
    def _timezone_is_iana(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"{value!r} is not a known IANA timezone") from exc
        return value


class PrincipalResolutionError(RuntimeError):
    """The active resolver could not produce a verified principal.

    Resolution fails closed: callers must treat any ``PrincipalResolutionError`` as a
    denial, never fall back to an unauthenticated or caller-supplied principal.
    """
