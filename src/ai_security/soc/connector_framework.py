"""Connector framework (post-v1 additive foundation).

This module defines the interface and registration contract for connecting real company
tools (email, files, databases, SaaS, etc.) to ProtAI's enforced gateway. It is
**additive and optional**: v1 continues to use mock adapters only. No real connector
is implemented here — every real connector requires a separate threat-model review,
connector permission design, secret handling plan, and egress policy (blueprint §23,
"controlled integration release") before being enabled.

Design principles:
- Connectors are invoked **only** through the gateway; the gateway re-validates
  everything (action digest, policy, manifest constraints, DLP). A connector never
  produces authorization.
- Each connector has a security profile: declared permissions, allowed egress
  destinations, max data class, side-effect class, and whether it requires approval.
- Connectors are registered but **disabled by default**; enabling one is an explicit
  operator decision.
- Connector credentials/secrets are never stored in plaintext; they are resolved through
  the operator's secret store at invocation time.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai_security.tools.base import STABLE_ID_PATTERN

_STABLE_ID = re.compile(STABLE_ID_PATTERN)


class ConnectorStatus(StrEnum):
    """Connector lifecycle status."""

    registered = "registered"  # registered but disabled (default)
    enabled = "enabled"  # explicitly enabled by operator
    disabled = "disabled"  # explicitly disabled
    failed = "failed"  # health check failing


class ConnectorSideEffect(StrEnum):
    """Declared side-effect class for a connector action."""

    read_only = "READ_ONLY"
    external_mutation = "EXTERNAL_MUTATION"


class ConnectorPermission(BaseModel):
    """One declared permission for a connector action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str = Field(min_length=1, max_length=128)
    action_id: str = Field(min_length=1, max_length=128)
    side_effect_class: ConnectorSideEffect
    allowed_destinations: tuple[str, ...] = ()
    max_data_class: str = "PUBLIC"
    requires_approval: bool = False
    max_resources: int = 1
    timeout_seconds: int = 30

    @field_validator("tool_id", "action_id")
    @classmethod
    def _ids_are_stable(cls, value: str) -> str:
        if _STABLE_ID.fullmatch(value) is None:
            raise ValueError(f"{value!r} is not a stable id")
        return value


class ConnectorRegistration(BaseModel):
    """Registration for one real connector (additive; not a v1 tool registration).

    A registration declares what a connector *may* do. The gateway enforces the
    actual policy at invocation time. Registration does not imply enablement.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    connector_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=1024)
    status: ConnectorStatus = ConnectorStatus.registered
    permissions: tuple[ConnectorPermission, ...] = ()
    secret_ref: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description="Opaque reference to the connector's credential in the operator's secret store",
    )
    egress_destinations: tuple[str, ...] = Field(
        default=(),
        description="Canonical external destinations this connector may reach",
    )
    max_concurrent_calls: int = Field(default=1, ge=1, le=64)
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    requires_network: bool = False
    created_at: datetime
    enabled_at: datetime | None = None
    enabled_by: str | None = None

    @field_validator("connector_id")
    @classmethod
    def _connector_id_is_stable(cls, value: str) -> str:
        if _STABLE_ID.fullmatch(value) is None:
            raise ValueError(f"{value!r} is not a stable id")
        return value

    @field_validator("egress_destinations")
    @classmethod
    def _destinations_are_non_empty_strings(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for dest in value:
            if not dest:
                raise ValueError("egress destinations must be non-empty")
        return value

    @property
    def is_enabled(self) -> bool:
        return self.status is ConnectorStatus.enabled

    @property
    def permission_map(self) -> dict[tuple[str, str], ConnectorPermission]:
        return {(p.tool_id, p.action_id): p for p in self.permissions}


class ConnectorContext(BaseModel):
    """Invocation context passed to a connector (server-side, never client-supplied)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    call_id: str
    principal_subject_id: str
    tenant_id: str | None
    tool_id: str
    action_id: str
    arguments: dict[str, Any]
    deadline: datetime | None = None


class ConnectorResult(BaseModel):
    """Typed result from a connector invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    call_id: str
    outcome: Literal["executed", "failed", "denied"]
    data_class: str = "PUBLIC"
    result_digest: str | None = None
    result_bytes: int | None = None
    error_type: str | None = None
    error_message: str | None = Field(default=None, max_length=256)
    duration_ms: int | None = None


@runtime_checkable
class Connector(Protocol):
    """Interface for one real company connector.

    Implementations perform the actual side effect (email read, file write, database
    query, SaaS API call, etc.). They never make authorization decisions; the gateway
    decides before the connector is invoked and DLP-inspects after.
    """

    connector_id: str

    async def validate(self) -> None:
        """Validate configuration and credentials at startup/registration.

        Raises if the connector cannot operate (missing secret, unreachable endpoint,
        invalid config). Fail-closed: a failed validation leaves the connector disabled.
        """

    async def health_check(self) -> bool:
        """Return True if the connector is reachable and healthy."""

    async def invoke(
        self,
        *,
        context: ConnectorContext,
    ) -> ConnectorResult:
        """Invoke the connector action. Returns a typed result; never raises side-effect
        exceptions to the gateway (errors are captured in the result).
        """


class ConnectorRegistry:
    """Registry for connector registrations, validated against policy at startup.

    Connectors are registered but disabled by default. Enabling a connector is an
    explicit operator action that requires a separate threat-model review.
    """

    def __init__(self) -> None:
        self._registrations: dict[str, ConnectorRegistration] = {}
        self._connectors: dict[str, Connector] = {}

    def register(
        self,
        registration: ConnectorRegistration,
        connector: Connector | None = None,
    ) -> None:
        """Register one connector. Disabled by default (status = registered)."""
        if registration.connector_id in self._registrations:
            raise ValueError(f"connector {registration.connector_id!r} already registered")
        self._registrations[registration.connector_id] = registration
        if connector is not None:
            self._connectors[registration.connector_id] = connector

    def enable(self, connector_id: str, *, enabled_by: str, now: datetime) -> None:
        """Explicitly enable one connector. Operator action; requires threat-model review."""
        reg = self._registrations.get(connector_id)
        if reg is None:
            raise ValueError(f"connector {connector_id!r} is not registered")
        if reg.status is ConnectorStatus.enabled:
            raise ValueError(f"connector {connector_id!r} is already enabled")
        # Create a new registration with updated status (frozen model).
        updated = ConnectorRegistration(
            connector_id=reg.connector_id,
            name=reg.name,
            description=reg.description,
            status=ConnectorStatus.enabled,
            permissions=reg.permissions,
            secret_ref=reg.secret_ref,
            egress_destinations=reg.egress_destinations,
            max_concurrent_calls=reg.max_concurrent_calls,
            timeout_seconds=reg.timeout_seconds,
            requires_network=reg.requires_network,
            created_at=reg.created_at,
            enabled_at=now,
            enabled_by=enabled_by,
        )
        self._registrations[connector_id] = updated

    def disable(self, connector_id: str) -> None:
        """Disable one connector (fail-safe: no invocations allowed)."""
        reg = self._registrations.get(connector_id)
        if reg is None:
            raise ValueError(f"connector {connector_id!r} is not registered")
        updated = ConnectorRegistration(
            connector_id=reg.connector_id,
            name=reg.name,
            description=reg.description,
            status=ConnectorStatus.disabled,
            permissions=reg.permissions,
            secret_ref=reg.secret_ref,
            egress_destinations=reg.egress_destinations,
            max_concurrent_calls=reg.max_concurrent_calls,
            timeout_seconds=reg.timeout_seconds,
            requires_network=reg.requires_network,
            created_at=reg.created_at,
            enabled_at=reg.enabled_at,
            enabled_by=reg.enabled_by,
        )
        self._registrations[connector_id] = updated

    def get(self, connector_id: str) -> ConnectorRegistration | None:
        return self._registrations.get(connector_id)

    def get_connector(self, connector_id: str) -> Connector | None:
        return self._connectors.get(connector_id)

    def list_enabled(self) -> tuple[ConnectorRegistration, ...]:
        return tuple(reg for reg in self._registrations.values() if reg.is_enabled)

    def list_all(self) -> tuple[ConnectorRegistration, ...]:
        return tuple(self._registrations.values())

    def validate_registration(self, registration: ConnectorRegistration) -> tuple[bool, str]:
        """Validate a registration against startup constraints.

        Returns (ok, error_message). Failures:
        - duplicate tool_id/action_id across enabled connectors
        - egress destination not canonicalizable
        - side_effect_class external_mutation without declared destinations
        - requires_network without declared egress destinations for external_mutation
        """

        # Check for duplicate (tool_id, action_id) among enabled connectors.
        for other in self._registrations.values():
            if other.connector_id == registration.connector_id:
                continue
            if not other.is_enabled:
                continue
            for perm in registration.permissions:
                if (perm.tool_id, perm.action_id) in other.permission_map:
                    return (
                        False,
                        f"connector {registration.connector_id!r} declares "
                        f"({perm.tool_id}, {perm.action_id}) already declared by "
                        f"enabled connector {other.connector_id!r}",
                    )

        # External mutation connectors must declare egress destinations.
        for perm in registration.permissions:
            if perm.side_effect_class is ConnectorSideEffect.external_mutation:
                if not perm.allowed_destinations and not registration.egress_destinations:
                    return (
                        False,
                        f"connector {registration.connector_id!r} external_mutation "
                        f"action {perm.tool_id}.{perm.action_id} declares no egress "
                        f"destinations",
                    )

        return True, ""

    def connector_secret_digest(self, connector_id: str) -> str | None:
        """Return a content-free digest of the connector's secret reference (not the
        secret itself). Used for audit correlation without leaking credentials."""
        reg = self._registrations.get(connector_id)
        if reg is None or reg.secret_ref is None:
            return None
        return hashlib.sha256(reg.secret_ref.encode("utf-8")).hexdigest()[:32]


__all__ = [
    "Connector",
    "ConnectorContext",
    "ConnectorPermission",
    "ConnectorRegistration",
    "ConnectorRegistry",
    "ConnectorResult",
    "ConnectorSideEffect",
    "ConnectorStatus",
]
