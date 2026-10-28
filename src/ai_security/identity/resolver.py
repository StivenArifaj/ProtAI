"""Principal resolvers (blueprint sections 9.1-9.4; ADR-001, ADR-015).

The resolver maps an already-authenticated request to a ``Principal``. Two resolvers
exist in v1:

- ``DevPrincipalResolver`` — the conspicuously development-only adapter. It returns one
  fixed development principal and ignores every caller-supplied field. It refuses to
  exist outside development/test, so a misconfigured deployment fails at construction
  even if settings validation were bypassed. It is not an HTTP authentication mode: the
  HMAC middleware and nonce replay check still run first.
- ``HostPrincipalResolver`` — the production path. It accepts only a typed assertion
  from the already-HMAC-verified host context and verifies issuer, audience, tenant
  scope, and authentication-time sanity before constructing the principal. Any missing,
  malformed, or out-of-scope assertion fails closed with a typed rejection.

``build_principal_resolver`` is the single construction point used by the application
factory; it is defense in depth on top of settings validation.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from ai_security.settings import AppEnv, PrincipalResolverKind, Settings

from .assertion import (
    PrincipalAssertion,
    PrincipalAssertionError,
    PrincipalAssertionErrorCode,
    verify_principal_assertion,
)
from .host_auth import VerifiedHostContext
from .models import Principal, PrincipalResolutionError

DEV_SUBJECT_ID = "dev-user"

DEV_PRINCIPAL = Principal(
    subject_id=DEV_SUBJECT_ID,
    roles=("developer",),
    tenant_id="dev-tenant",
    timezone="UTC",
    auth_method="dev-test-adapter",
    issuer="dev-principal-resolver",
    permissions_context_ref="dev-fixed-principal",
)


class PrincipalResolver(Protocol):
    """Maps an authenticated request context to a server-resolved principal."""

    def resolve(
        self,
        verified_host: VerifiedHostContext | None = None,
        *,
        assertion: PrincipalAssertion | None = None,
    ) -> Principal: ...


class DevResolverRefusedError(PrincipalResolutionError):
    """Raised when the development resolver is constructed outside development/test."""


class DevPrincipalResolver:
    """Development-only fixed-principal adapter (ADR-001).

    Returns the same server-defined principal for every request; request headers,
    bodies, and assertions can never influence the result.
    """

    def __init__(self, app_env: AppEnv) -> None:
        if not app_env.development_like:
            raise DevResolverRefusedError(
                f"the development principal resolver is refused in {app_env.value!r} "
                "(blueprint section 9.3, ADR-001)"
            )
        self._app_env = app_env

    def resolve(
        self,
        verified_host: VerifiedHostContext | None = None,
        *,
        assertion: PrincipalAssertion | None = None,
    ) -> Principal:
        del verified_host, assertion  # the dev adapter ignores all caller inputs
        return DEV_PRINCIPAL


class HostPrincipalResolver:
    """Verify a host-signed principal assertion and resolve a ``Principal``."""

    def __init__(
        self,
        *,
        tolerance_seconds: int = 60,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if tolerance_seconds < 0:
            raise ValueError("tolerance_seconds must be non-negative")
        self._tolerance_seconds = tolerance_seconds
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))

    def resolve(
        self,
        verified_host: VerifiedHostContext | None = None,
        *,
        assertion: PrincipalAssertion | None = None,
    ) -> Principal:
        if verified_host is None:
            raise PrincipalAssertionError(PrincipalAssertionErrorCode.missing_verified_host)
        if assertion is None:
            raise PrincipalAssertionError(PrincipalAssertionErrorCode.missing_assertion)
        now = self._clock()
        if now.utcoffset() is None:
            raise RuntimeError("principal clock must return a timezone-aware datetime")
        return verify_principal_assertion(
            assertion,
            verified_host=verified_host,
            now=now,
            max_future_skew_seconds=self._tolerance_seconds,
        )


def build_principal_resolver(settings: Settings) -> PrincipalResolver:
    """Construct the configured resolver; refuses development adapters outside dev/test."""
    match settings.principal_resolver:
        case PrincipalResolverKind.dev:
            return DevPrincipalResolver(settings.app_env)
        case PrincipalResolverKind.host:
            return HostPrincipalResolver(
                tolerance_seconds=settings.host_auth_timestamp_tolerance_seconds
            )
    raise PrincipalResolutionError(  # pragma: no cover - enum exhaustiveness guard
        f"unknown principal resolver kind {settings.principal_resolver!r}"
    )


__all__ = [
    "DEV_PRINCIPAL",
    "DEV_SUBJECT_ID",
    "DevPrincipalResolver",
    "DevResolverRefusedError",
    "HostPrincipalResolver",
    "PrincipalResolver",
    "build_principal_resolver",
]
