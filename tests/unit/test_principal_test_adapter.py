"""Principal test adapter tests (blueprint sections 6.1, 9.3; ADR-001).

The adapter exists for tests only: it must be constructible solely under ``APP_ENV=test``,
must ignore all caller input, and must be unreachable through configuration. These tests
pin those guardrails.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from ai_security.identity.adapters import (
    TestAdapterRefusedError as AdapterRefusedError,
)
from ai_security.identity.adapters import (
    TestPrincipalResolver as PrincipalTestAdapter,
)
from ai_security.identity.host_auth import VerifiedHostContext
from ai_security.identity.models import Principal, PrincipalResolutionError
from ai_security.identity.resolver import (
    DevPrincipalResolver,
    HostPrincipalResolver,
    build_principal_resolver,
)
from ai_security.settings import AppEnv, PrincipalResolverKind, Settings

HOST_CONTEXT = VerifiedHostContext(
    key_id="k1",
    host_id="host-a",
    audience="gateway",
    allowed_tenants=("tenant-1",),
)

ADAPTER_PRINCIPAL = Principal(
    subject_id="test-user",
    roles=("tester",),
    tenant_id="tenant-1",
    timezone="UTC",
    auth_method="test-adapter",
    issuer="test-suite",
    permissions_context_ref="ctx-test",
)


def test_refused_error_is_a_resolution_error() -> None:
    assert issubclass(AdapterRefusedError, PrincipalResolutionError)


def test_test_adapter_constructs_in_test_env() -> None:
    resolver = PrincipalTestAdapter(AppEnv.test, ADAPTER_PRINCIPAL)
    assert resolver.resolve() is ADAPTER_PRINCIPAL


def test_test_adapter_ignores_all_caller_input() -> None:
    resolver = PrincipalTestAdapter(AppEnv.test, ADAPTER_PRINCIPAL)
    assert resolver.resolve(None) is ADAPTER_PRINCIPAL
    assert resolver.resolve(HOST_CONTEXT) is ADAPTER_PRINCIPAL


@pytest.mark.parametrize("env", [AppEnv.development, AppEnv.staging, AppEnv.production])
def test_test_adapter_is_refused_outside_test(env: AppEnv) -> None:
    with pytest.raises(AdapterRefusedError, match="APP_ENV=test"):
        PrincipalTestAdapter(env, ADAPTER_PRINCIPAL)


def test_test_adapter_is_not_selectable_through_settings() -> None:
    assert {kind.value for kind in PrincipalResolverKind} == {"dev", "host"}
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            app_env="test",
            log_level="WARNING",
            database_url=(
                "postgresql+asyncpg://firewall:firewall_dev_only@127.0.0.1:5432/firewall_test"
            ),
            principal_resolver="test",
            host_auth_keys_json="{}",
        )


def test_factory_never_returns_the_test_adapter(
    settings_factory: Callable[..., Settings],
) -> None:
    dev_resolver = build_principal_resolver(settings_factory(principal_resolver="dev"))
    host_resolver = build_principal_resolver(settings_factory(principal_resolver="host"))
    assert isinstance(dev_resolver, DevPrincipalResolver)
    assert isinstance(host_resolver, HostPrincipalResolver)
    for resolver in (dev_resolver, host_resolver):
        assert not isinstance(resolver, PrincipalTestAdapter)
