"""Host-signed principal assertions (blueprint sections 9.1-9.4; ADR-001, ADR-015).

The host authenticates the user in its own system and places this assertion inside the
request body. The body is covered by the host HMAC signature and one-time nonce; this
module is the typed, fail-closed verification step that turns the signed assertion into
a ``Principal``. It never reads authorization from the assertion: roles are inputs to
local policy mapping, and the assertion cannot carry permissions, decisions, risk, or
approval outcomes (unknown fields are rejected).

The configured key record constrains the assertion: ``iss`` must equal the key's
``host_id``, ``aud`` must equal its ``audience``, and ``tenant_id`` must be allowed by
the key's tenant scope. Rejections are typed and stable; callers must treat every
rejection as a denial and must not fall back to an unverified principal.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .host_auth import VerifiedHostContext
from .models import CONTROL_CHARACTERS, Principal, PrincipalResolutionError

MAX_ROLES = 32
MAX_ROLE_LENGTH = 128
_HOST_REF_PREFIX = "host:"

_FREE_TEXT_FIELDS = ("iss", "aud", "sub", "tenant_id", "permissions_context_ref")


class PrincipalAssertionErrorCode(StrEnum):
    """Stable principal-assertion rejection codes (never contain secrets)."""

    missing_verified_host = "missing_verified_host"
    missing_assertion = "missing_assertion"
    malformed_assertion = "malformed_assertion"
    issuer_mismatch = "issuer_mismatch"
    audience_mismatch = "audience_mismatch"
    tenant_required = "tenant_required"
    tenant_not_allowed = "tenant_not_allowed"
    tenant_not_supported = "tenant_not_supported"
    authentication_time_in_future = "authentication_time_in_future"
    invalid_principal = "invalid_principal"


class PrincipalAssertionError(PrincipalResolutionError, ValueError):
    """The signed assertion is not acceptable for this host key (fail closed)."""

    def __init__(self, code: PrincipalAssertionErrorCode) -> None:
        super().__init__(code.value)
        self.code = code
        self.http_status = 403


class PrincipalAssertion(BaseModel):
    """Strict host-asserted principal context carried inside the signed body."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    iss: str = Field(min_length=1, max_length=256)
    aud: str = Field(min_length=1, max_length=256)
    sub: str = Field(min_length=1, max_length=256)
    tenant_id: str | None = Field(default=None, min_length=1, max_length=256)
    roles: tuple[str, ...] = ()
    authenticated_at: datetime
    timezone: str | None = Field(default=None, min_length=1, max_length=64)
    permissions_context_ref: str | None = Field(default=None, min_length=1, max_length=256)

    @field_validator(*_FREE_TEXT_FIELDS)
    @classmethod
    def _no_control_characters(cls, value: str | None) -> str | None:
        if value is not None and CONTROL_CHARACTERS.search(value):
            raise ValueError("must not contain control characters")
        return value

    @field_validator("roles")
    @classmethod
    def _roles_are_bounded_and_clean(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_ROLES:
            raise ValueError(f"at most {MAX_ROLES} roles may be asserted")
        for role in value:
            if (
                not role
                or len(role) > MAX_ROLE_LENGTH
                or CONTROL_CHARACTERS.search(role) is not None
            ):
                raise ValueError(
                    f"roles must be non-empty, control-free, and at most "
                    f"{MAX_ROLE_LENGTH} characters"
                )
        return value

    @field_validator("authenticated_at")
    @classmethod
    def _authentication_time_is_aware(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("authenticated_at must be timezone-aware")
        return value.astimezone(UTC)


def _default_permissions_context_ref(host: VerifiedHostContext, subject: str) -> str:
    return f"{_HOST_REF_PREFIX}{host.host_id}:{subject}"


def verify_principal_assertion(
    assertion: PrincipalAssertion,
    *,
    verified_host: VerifiedHostContext,
    now: datetime | None = None,
    max_future_skew_seconds: int = 60,
) -> Principal:
    """Verify the assertion against the key scope and return a ``Principal``.

    The outer HMAC timestamp and nonce prove request freshness. ``authenticated_at`` is
    evidence of when the host authenticated the user; it may legitimately be older than
    the request, so only a future value beyond the configured skew is rejected.
    """
    if not isinstance(verified_host, VerifiedHostContext):
        raise PrincipalAssertionError(PrincipalAssertionErrorCode.missing_verified_host)
    if not isinstance(assertion, PrincipalAssertion):
        raise PrincipalAssertionError(PrincipalAssertionErrorCode.missing_assertion)

    if assertion.iss != verified_host.host_id:
        raise PrincipalAssertionError(PrincipalAssertionErrorCode.issuer_mismatch)
    if assertion.aud != verified_host.audience:
        raise PrincipalAssertionError(PrincipalAssertionErrorCode.audience_mismatch)

    if verified_host.allowed_tenants:
        if assertion.tenant_id is None:
            raise PrincipalAssertionError(PrincipalAssertionErrorCode.tenant_required)
        if assertion.tenant_id not in verified_host.allowed_tenants:
            raise PrincipalAssertionError(PrincipalAssertionErrorCode.tenant_not_allowed)
    elif assertion.tenant_id is not None:
        raise PrincipalAssertionError(PrincipalAssertionErrorCode.tenant_not_supported)

    moment = datetime.now(UTC) if now is None else now
    if moment.utcoffset() is None:
        raise ValueError("verification time must be timezone-aware")
    if max_future_skew_seconds < 0:
        raise ValueError("max_future_skew_seconds must be non-negative")
    if assertion.authenticated_at > moment + timedelta(seconds=max_future_skew_seconds):
        raise PrincipalAssertionError(PrincipalAssertionErrorCode.authentication_time_in_future)

    try:
        return Principal(
            subject_id=assertion.sub,
            roles=assertion.roles,
            tenant_id=assertion.tenant_id,
            timezone=assertion.timezone,
            auth_method="host-hmac-v1",
            issuer=assertion.iss,
            permissions_context_ref=(
                assertion.permissions_context_ref
                if assertion.permissions_context_ref is not None
                else _default_permissions_context_ref(verified_host, assertion.sub)
            ),
        )
    except ValueError as exc:
        raise PrincipalAssertionError(PrincipalAssertionErrorCode.invalid_principal) from exc


__all__ = [
    "MAX_ROLES",
    "PrincipalAssertion",
    "PrincipalAssertionError",
    "PrincipalAssertionErrorCode",
    "verify_principal_assertion",
]
