"""Principal resolvers (blueprint sections 9.1-9.3; ADR-001).

The resolver maps an already-authenticated request (or, for the development adapter, an
entirely development environment) to a ``Principal``. Two resolvers exist in v1:

- ``DevPrincipalResolver`` — the conspicuously development-only adapter. It returns one
  fixed development principal and ignores every caller-supplied field. It refuses to
  exist outside development/test, so a misconfigured deployment fails at construction
  even if settings validation were bypassed.
- ``HostPrincipalResolver`` — the declared production integration point: the principal
  comes from the HMAC-verified host assertion. Its typed-assertion handling arrives
  with the Phase 1 typed contracts (ADR-001 section 9.3). Until then it constructs (the
  app factory catches misconfiguration at startup) but ``resolve`` fails closed rather
  than resolving an unverified principal; Phase 0b defines no ``/v1`` business routes,
  so it is never invoked in a real deployment.

``build_principal_resolver`` is the single construction point used by the application
factory; it is defense in depth on top of settings validation.
"""

from __future__ import annotations

from typing import Protocol

from ai_security.settings import AppEnv, PrincipalResolverKind, Settings

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

    def resolve(self, verified_host: VerifiedHostContext | None = None) -> Principal: ...


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

    def resolve(self, verified_host: VerifiedHostContext | None = None) -> Principal:
        del verified_host  # the dev adapter intentionally ignores all caller inputs
        return DEV_PRINCIPAL


class HostPrincipalResolver:
    """Production principal integration point; fails closed until Phase 1.

    The Phase 1 typed contracts define the assertion payload (subject, roles, tenant,
    timezone, permissions context) that the verified host is allowed to establish.
    Until those contracts exist, resolving a principal from an untyped assertion would
    be an unverified trust decision, so this resolver refuses.
    """

    def resolve(self, verified_host: VerifiedHostContext | None = None) -> Principal:
        del verified_host
        raise PrincipalResolutionError(
            "host principal resolution requires the Phase 1 typed-assertion contracts; "
            "refusing to resolve an unverified principal"
        )


def build_principal_resolver(settings: Settings) -> PrincipalResolver:
    """Construct the configured resolver; refuses development adapters outside dev/test."""
    match settings.principal_resolver:
        case PrincipalResolverKind.dev:
            return DevPrincipalResolver(settings.app_env)
        case PrincipalResolverKind.host:
            return HostPrincipalResolver()
    raise PrincipalResolutionError(  # pragma: no cover - enum exhaustiveness guard
        f"unknown principal resolver kind {settings.principal_resolver!r}"
    )
