"""Principal model and resolver tests (blueprint sections 6.1, 9.3; ADR-001)."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from ai_security.identity.host_auth import VerifiedHostContext
from ai_security.identity.models import Principal, PrincipalResolutionError
from ai_security.identity.resolver import (
    DEV_PRINCIPAL,
    DevPrincipalResolver,
    DevResolverRefusedError,
    HostPrincipalResolver,
    build_principal_resolver,
)
from ai_security.settings import AppEnv, PrincipalResolverKind, Settings

HOST_CONTEXT = VerifiedHostContext(
    key_id="k1",
    host_id="host-a",
    audience="gateway",
    allowed_tenants=("other-tenant",),
)


# --- Principal model ---


def make_principal(**overrides: object) -> Principal:
    values: dict[str, object] = {
        "subject_id": "user-1",
        "roles": ("owner",),
        "tenant_id": "tenant-1",
        "timezone": "Europe/Berlin",
        "auth_method": "host-assertion",
        "issuer": "host-integration",
        "permissions_context_ref": "ctx-1",
    }
    values.update(overrides)
    return Principal.model_validate(values)


def test_principal_accepts_full_context() -> None:
    principal = make_principal()
    assert principal.subject_id == "user-1"
    assert principal.roles == ("owner",)


def test_principal_is_frozen() -> None:
    principal = make_principal()
    with pytest.raises(ValidationError):
        principal.subject_id = "someone-else"  # type: ignore[misc]


def test_principal_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        make_principal(is_admin=True)


def test_principal_rejects_invalid_timezone() -> None:
    with pytest.raises(ValidationError, match="IANA"):
        make_principal(timezone="Mars/Phobos")


def test_principal_rejects_control_characters() -> None:
    with pytest.raises(ValidationError, match="control characters"):
        make_principal(subject_id="user\n1")


def test_principal_optional_fields_may_be_absent() -> None:
    principal = make_principal(tenant_id=None, timezone=None, roles=())
    assert principal.tenant_id is None
    assert principal.timezone is None


# --- Development resolver ---


@pytest.mark.parametrize("env", [AppEnv.development, AppEnv.test])
def test_dev_resolver_returns_fixed_principal(env: AppEnv) -> None:
    resolver = DevPrincipalResolver(env)
    assert resolver.resolve() == DEV_PRINCIPAL
    # Caller-supplied host context can never influence the resolved principal.
    assert resolver.resolve(HOST_CONTEXT) == DEV_PRINCIPAL


@pytest.mark.parametrize("env", [AppEnv.staging, AppEnv.production])
def test_dev_resolver_refuses_non_dev_environments(env: AppEnv) -> None:
    with pytest.raises(DevResolverRefusedError):
        DevPrincipalResolver(env)


# --- Host resolver (typed signed assertion) ---


def test_host_resolver_refuses_without_verified_host_or_assertion() -> None:
    resolver = HostPrincipalResolver()
    with pytest.raises(PrincipalResolutionError):
        resolver.resolve()
    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(HOST_CONTEXT)


# --- Application-factory construction point ---


def test_build_principal_resolver_dev(settings_factory: Callable[..., Settings]) -> None:
    resolver = build_principal_resolver(settings_factory())
    assert isinstance(resolver, DevPrincipalResolver)


def test_build_principal_resolver_host(settings_factory: Callable[..., Settings]) -> None:
    resolver = build_principal_resolver(settings_factory(principal_resolver="host"))
    assert isinstance(resolver, HostPrincipalResolver)


def test_build_refuses_dev_resolver_outside_dev_even_if_settings_bypassed() -> None:
    # model_construct skips validation on purpose: defense in depth must hold even when
    # a forged/unvalidated Settings instance reaches the factory.
    forged = Settings.model_construct(
        app_env=AppEnv.production,
        principal_resolver=PrincipalResolverKind.dev,
    )
    with pytest.raises(DevResolverRefusedError):
        build_principal_resolver(forged)
