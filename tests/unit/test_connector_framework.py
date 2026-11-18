"""Tests for the connector framework (post-v1 additive foundation).

Verifies registration, disabled-by-default, explicit enable/disable, validation, and
content-free secret digests. No real connector is implemented; no authorization surface
exists.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ai_security.soc.connector_framework import (
    ConnectorPermission,
    ConnectorRegistration,
    ConnectorRegistry,
    ConnectorSideEffect,
    ConnectorStatus,
)

FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _registration(
    connector_id: str = "directory-connector",
    *,
    status: ConnectorStatus = ConnectorStatus.registered,
    permissions: tuple[ConnectorPermission, ...] = (),
    egress_destinations: tuple[str, ...] = (),
    secret_ref: str | None = None,
) -> ConnectorRegistration:
    return ConnectorRegistration(
        connector_id=connector_id,
        name="Directory Connector",
        description="Reads employee directory records",
        status=status,
        permissions=permissions,
        egress_destinations=egress_destinations,
        secret_ref=secret_ref,
        created_at=FIXED_NOW,
    )


def test_registration_is_disabled_by_default() -> None:
    reg = _registration()
    assert reg.status is ConnectorStatus.registered
    assert reg.is_enabled is False


def test_registry_registers_and_lists() -> None:
    registry = ConnectorRegistry()
    reg = _registration()
    registry.register(reg)

    assert registry.get("directory-connector") == reg
    assert registry.list_enabled() == ()
    assert len(registry.list_all()) == 1


def test_explicit_enable_and_disable() -> None:
    registry = ConnectorRegistry()
    registry.register(_registration())

    registry.enable("directory-connector", enabled_by="admin-1", now=FIXED_NOW)
    assert registry.get("directory-connector").is_enabled is True
    assert registry.get("directory-connector").enabled_by == "admin-1"

    registry.disable("directory-connector")
    assert registry.get("directory-connector").is_enabled is False


def test_duplicate_registration_rejected() -> None:
    registry = ConnectorRegistry()
    registry.register(_registration())
    try:
        registry.register(_registration())
        raise AssertionError("expected ValueError for duplicate registration")
    except ValueError:
        pass


def test_enable_unregistered_rejected() -> None:
    registry = ConnectorRegistry()
    try:
        registry.enable("nonexistent", enabled_by="admin-1", now=FIXED_NOW)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_validate_duplicate_action_among_enabled() -> None:
    registry = ConnectorRegistry()
    perm = ConnectorPermission(
        tool_id="directory.read",
        action_id="read",
        side_effect_class=ConnectorSideEffect.read_only,
    )
    reg1 = _registration("connector-1", status=ConnectorStatus.enabled, permissions=(perm,))
    reg2 = _registration("connector-2", status=ConnectorStatus.enabled, permissions=(perm,))
    registry.register(reg1)
    registry.register(reg2)

    ok, error = registry.validate_registration(reg2)
    assert ok is False
    assert "directory.read" in error


def test_validate_external_mutation_without_destinations() -> None:
    registry = ConnectorRegistry()
    perm = ConnectorPermission(
        tool_id="sink.write",
        action_id="write",
        side_effect_class=ConnectorSideEffect.external_mutation,
    )
    reg = _registration("sink-connector", permissions=(perm,))

    ok, error = registry.validate_registration(reg)
    assert ok is False
    assert "egress" in error.lower()


def test_validate_read_only_connector_passes() -> None:
    registry = ConnectorRegistry()
    perm = ConnectorPermission(
        tool_id="directory.read",
        action_id="read",
        side_effect_class=ConnectorSideEffect.read_only,
    )
    reg = _registration("directory-connector", permissions=(perm,))

    ok, error = registry.validate_registration(reg)
    assert ok is True
    assert error == ""


def test_secret_digest_is_content_free() -> None:
    registry = ConnectorRegistry()
    reg = _registration(secret_ref="vault://ref/directory-credential")  # noqa: S106 - test fixture ref
    registry.register(reg)

    digest = registry.connector_secret_digest("directory-connector")
    assert digest is not None
    assert len(digest) == 32
    assert "vault" not in digest
    assert "secret" not in digest
    assert "credential" not in digest


def test_no_secret_ref_returns_none_digest() -> None:
    registry = ConnectorRegistry()
    registry.register(_registration())
    assert registry.connector_secret_digest("directory-connector") is None


def test_permission_map() -> None:
    perm = ConnectorPermission(
        tool_id="directory.read",
        action_id="read",
        side_effect_class=ConnectorSideEffect.read_only,
    )
    reg = _registration(permissions=(perm,))
    assert reg.permission_map[("directory.read", "read")] == perm


def test_invalid_tool_id_rejected() -> None:
    try:
        ConnectorPermission(
            tool_id="bad id",
            action_id="read",
            side_effect_class=ConnectorSideEffect.read_only,
        )
        raise AssertionError("expected ValueError for invalid tool id")
    except ValueError:
        pass


def test_connector_has_no_authority_surface() -> None:
    """The connector framework has no authorize/allow methods — the gateway decides."""
    from ai_security.soc.connector_framework import ConnectorRegistry

    for forbidden in ("authorize", "allow", "decide", "grant", "approve"):
        assert not hasattr(ConnectorRegistry, forbidden)
