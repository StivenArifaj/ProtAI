"""Host-signed principal assertion verification (blueprint §§9.1-9.4; ADR-015)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from ai_security.identity.assertion import (
    PrincipalAssertion,
    PrincipalAssertionError,
    PrincipalAssertionErrorCode,
    verify_principal_assertion,
)
from ai_security.identity.host_auth import VerifiedHostContext
from ai_security.identity.resolver import HostPrincipalResolver

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
HOST = VerifiedHostContext(
    key_id="key-1",
    host_id="host-a",
    audience="gateway",
    allowed_tenants=("tenant-1",),
)


def assertion(**overrides: object) -> PrincipalAssertion:
    values: dict[str, object] = {
        "iss": "host-a",
        "aud": "gateway",
        "sub": "user-1",
        "tenant_id": "tenant-1",
        "roles": ("analyst", "owner"),
        "authenticated_at": NOW - timedelta(minutes=5),
        "timezone": "Europe/Berlin",
        "permissions_context_ref": "ctx-1",
    }
    values.update(overrides)
    return PrincipalAssertion.model_validate(values)


def verify(value: PrincipalAssertion, *, host: VerifiedHostContext = HOST) -> object:
    return verify_principal_assertion(value, verified_host=host, now=NOW)


def test_valid_assertion_resolves_a_principal() -> None:
    principal = verify(assertion())
    assert principal.subject_id == "user-1"  # type: ignore[attr-defined]
    assert principal.roles == ("analyst", "owner")  # type: ignore[attr-defined]
    assert principal.tenant_id == "tenant-1"  # type: ignore[attr-defined]
    assert principal.timezone == "Europe/Berlin"  # type: ignore[attr-defined]
    assert principal.auth_method == "host-hmac-v1"  # type: ignore[attr-defined]
    assert principal.issuer == "host-a"  # type: ignore[attr-defined]
    assert principal.permissions_context_ref == "ctx-1"  # type: ignore[attr-defined]


def test_permissions_context_ref_has_a_stable_default() -> None:
    principal = verify(assertion(permissions_context_ref=None))
    assert principal.permissions_context_ref == "host:host-a:user-1"  # type: ignore[attr-defined]


def test_assertion_rejects_unknown_authority_fields() -> None:
    with pytest.raises(ValidationError):
        PrincipalAssertion.model_validate(
            {
                **assertion().model_dump(),
                "permissions": ["admin"],
            }
        )
    with pytest.raises(ValidationError):
        PrincipalAssertion.model_validate(
            {
                **assertion().model_dump(),
                "decision": "ALLOW",
            }
        )


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"iss": "other-host"}, PrincipalAssertionErrorCode.issuer_mismatch),
        ({"aud": "other-audience"}, PrincipalAssertionErrorCode.audience_mismatch),
        ({"tenant_id": None}, PrincipalAssertionErrorCode.tenant_required),
        ({"tenant_id": "tenant-2"}, PrincipalAssertionErrorCode.tenant_not_allowed),
    ],
)
def test_assertion_scope_mismatches_are_typed(
    overrides: dict[str, object], code: PrincipalAssertionErrorCode
) -> None:
    with pytest.raises(PrincipalAssertionError) as caught:
        verify(assertion(**overrides))
    assert caught.value.code is code
    assert caught.value.http_status == 403


def test_single_tenant_key_refuses_an_asserted_tenant() -> None:
    host = VerifiedHostContext(
        key_id="key-1", host_id="host-a", audience="gateway", allowed_tenants=()
    )
    with pytest.raises(PrincipalAssertionError) as caught:
        verify(assertion(), host=host)
    assert caught.value.code is PrincipalAssertionErrorCode.tenant_not_supported


def test_single_tenant_key_accepts_an_absent_tenant() -> None:
    host = VerifiedHostContext(
        key_id="key-1", host_id="host-a", audience="gateway", allowed_tenants=()
    )
    principal = verify(assertion(tenant_id=None), host=host)
    assert principal.tenant_id is None  # type: ignore[attr-defined]


def test_future_authentication_time_is_rejected() -> None:
    with pytest.raises(PrincipalAssertionError) as caught:
        verify(assertion(authenticated_at=NOW + timedelta(minutes=5)))
    assert caught.value.code is PrincipalAssertionErrorCode.authentication_time_in_future


def test_old_authentication_time_is_allowed_because_request_freshness_is_hmac_bound() -> None:
    principal = verify(assertion(authenticated_at=NOW - timedelta(days=30)))
    assert principal.subject_id == "user-1"  # type: ignore[attr-defined]


def test_naive_authentication_time_is_rejected() -> None:
    with pytest.raises(ValidationError):
        assertion(authenticated_at=datetime(2026, 10, 28, 12, 0))


def test_control_characters_and_invalid_timezone_fail_closed() -> None:
    with pytest.raises(ValidationError):
        assertion(sub="user\n1")
    with pytest.raises(ValidationError):
        assertion(roles=("a\nb",))
    with pytest.raises(PrincipalAssertionError) as caught:
        verify(assertion(timezone="Mars/Phobos"))
    assert caught.value.code is PrincipalAssertionErrorCode.invalid_principal


def test_roles_are_bounded() -> None:
    with pytest.raises(ValidationError):
        assertion(roles=tuple(f"role-{index}" for index in range(33)))


def test_missing_inputs_are_typed_rejections() -> None:
    with pytest.raises(PrincipalAssertionError) as caught:
        verify_principal_assertion(assertion(), verified_host=None)  # type: ignore[arg-type]
    assert caught.value.code is PrincipalAssertionErrorCode.missing_verified_host

    with pytest.raises(PrincipalAssertionError) as caught:
        verify_principal_assertion(None, verified_host=HOST)  # type: ignore[arg-type]
    assert caught.value.code is PrincipalAssertionErrorCode.missing_assertion


def test_resolver_uses_its_clock_and_tolerance() -> None:
    resolver = HostPrincipalResolver(tolerance_seconds=30, clock=lambda: NOW)
    principal = resolver.resolve(HOST, assertion=assertion())
    assert principal.subject_id == "user-1"

    with pytest.raises(PrincipalAssertionError):
        resolver.resolve(HOST, assertion=assertion(authenticated_at=NOW + timedelta(seconds=31)))
