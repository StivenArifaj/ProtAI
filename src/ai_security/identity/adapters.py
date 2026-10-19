"""Principal test adapter (blueprint sections 6.1, 9.3; ADR-001).

The test adapter exists so tests can construct explicit principals (for example, to
exercise cross-scope or approver semantics later) without weakening either guard:

- it is constructible only when ``APP_ENV=test`` (stricter than the development
  resolver, which also permits ``development``);
- it is not selectable through settings or ``build_principal_resolver`` — the factory
  supports only ``dev``/``host``, so no configuration can ever activate it;
- it never bypasses host HMAC authentication: the middleware chain is identical, and a
  test client still needs a validly signed request to reach any route.

Like the development resolver, it returns one server-defined principal and ignores all
caller-supplied input.
"""

from __future__ import annotations

from ai_security.settings import AppEnv

from .host_auth import VerifiedHostContext
from .models import Principal, PrincipalResolutionError


class TestAdapterRefusedError(PrincipalResolutionError):
    """Raised when the test principal adapter is constructed outside APP_ENV=test."""


class TestPrincipalResolver:
    """Fixed-principal adapter for tests only; ignores every caller input."""

    def __init__(self, app_env: AppEnv, principal: Principal) -> None:
        if app_env is not AppEnv.test:
            raise TestAdapterRefusedError(
                f"the test principal adapter is refused in {app_env.value!r}; it exists "
                "only for APP_ENV=test (blueprint section 6.1, ADR-001)"
            )
        self._principal = principal

    def resolve(self, verified_host: VerifiedHostContext | None = None) -> Principal:
        del verified_host  # the test adapter intentionally ignores all caller inputs
        return self._principal
