"""Canonical tool-registry domain types and execution-authorization guard.

``SideEffectClass`` is the single canonical definition (blueprint section 6.1); every
other module imports it from here. Unknown, missing, or invalid values fail closed
everywhere they are consumed: registration fails at startup and policy evaluation
returns ``BLOCK``. There are no string aliases and no coercions.

Phase 2 adds the tool-adapter protocol and the execution-authorization guard
(blueprint section 12; ADR-009). Every adapter invocation must carry an
``ExecutionAuthorization`` issued by the gateway *after* a policy ``ALLOW``. The
authorization binds the canonical action digest (principal, request, tool/action,
validated arguments, resource IDs, destination, policy hash) so a mutated tool name or
argument set can never execute; Phase 5 approval consumption binds the same digest.

This guard is an in-process safety/anti-bypass control, not a sandbox: code running in
the same Python process could import the private issuer. Process isolation and a real
trust boundary between the agent runtime and adapters are later-phase hardening
(blueprint sections 14.2, 20.2, 21 Phase 10).
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from ai_security.security.canonical_json import canonical_json_bytes
from ai_security.security.constant_time import constant_time_hex32_equal

if TYPE_CHECKING:  # pragma: no cover - typing only (avoids registry/base import cycle)
    from ai_security.identity.models import Principal

    from .registry import ToolRegistration

#: Stable identifier pattern shared by tool ids, action ids, and resource ids:
#: 1-128 chars, alphanumeric start/end, ``. _ -`` inside (anchored full match).
STABLE_ID_PATTERN = r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$"


class SideEffectClass(StrEnum):
    """Canonical side-effect classes (blueprint section 6.1)."""

    read_only = "READ_ONLY"
    local_mutation = "LOCAL_MUTATION"
    external_mutation = "EXTERNAL_MUTATION"
    destructive = "DESTRUCTIVE"


class ToolExecutionError(RuntimeError):
    """Base class for tool execution/authorization failures (fail closed)."""


class UngatedExecutionError(ToolExecutionError):
    """An adapter was invoked without a gateway-issued execution authorization."""


class ExecutionAuthorizationError(ToolExecutionError):
    """An execution authorization does not match the action it is being used for."""


_EXECUTION_SENTINEL = object()


@dataclass(frozen=True)
class ExecutionAuthorization:
    """Gateway-issued right to execute one exact, canonicalized action.

    Constructing this directly (without the private issuer) fails closed. The gateway
    issues it only after: the policy engine returned ``ALLOW``, the decision audit
    event was persisted, and a canonical action digest was computed over the validated
    arguments and canonical resource/destination fields.
    """

    call_id: str
    request_id: str
    principal_subject_id: str
    tool_id: str
    action_id: str
    resource_ids: tuple[str, ...]
    destination: str | None
    policy_hash: str
    action_digest: str
    _sentinel: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._sentinel is not _EXECUTION_SENTINEL:
            raise UngatedExecutionError(
                "execution authorizations may only be issued by the firewall gateway "
                "(blueprint section 12.1, ADR-009)"
            )


def _issue_execution_authorization(
    *,
    call_id: str,
    request_id: str,
    principal_subject_id: str,
    tool_id: str,
    action_id: str,
    resource_ids: tuple[str, ...],
    destination: str | None,
    policy_hash: str,
    action_digest: str,
) -> ExecutionAuthorization:
    """Private issuer used by ``firewall.gateway`` only (not exported)."""
    return ExecutionAuthorization(
        call_id=call_id,
        request_id=request_id,
        principal_subject_id=principal_subject_id,
        tool_id=tool_id,
        action_id=action_id,
        resource_ids=resource_ids,
        destination=destination,
        policy_hash=policy_hash,
        action_digest=action_digest,
        _sentinel=_EXECUTION_SENTINEL,
    )


def compute_action_digest(
    *,
    request_id: str,
    principal_subject_id: str,
    tool_id: str,
    action_id: str,
    arguments: dict[str, Any],
    resource_ids: Sequence[str],
    destination: str | None,
    policy_hash: str,
) -> str:
    """SHA-256 hex digest over the canonical action payload (blueprint §13.2 binding).

    The payload uses the shared canonical JSON rules (sorted keys, UTF-8, NFC, no
    floats); any payload that cannot be canonicalized raises ``CanonicalJSONError`` and
    must fail closed before execution.
    """
    payload: dict[str, Any] = {
        "action_id": action_id,
        "arguments": arguments,
        "destination": destination,
        "policy_hash": policy_hash,
        "principal_subject_id": principal_subject_id,
        "request_id": request_id,
        "resource_ids": list(resource_ids),
        "tool_id": tool_id,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


class ToolArguments(BaseModel):
    """Base class for strict per-tool argument schemas (extra fields rejected).

    ``strict=True`` disables pydantic coercions, so a JSON string can never satisfy an
    integer field (or vice versa): validated arguments must match the declared schema
    exactly.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ToolResult(BaseModel):
    """Base class for strict per-tool result schemas (extra fields rejected)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


@runtime_checkable
class ToolAdapter(Protocol):
    """A mock-only tool adapter (blueprint section 14.1).

    ``execute`` requires a gateway-issued ``ExecutionAuthorization``; adapters must
    never be called directly by the agent runtime. ``check_resource_access`` is a pure,
    side-effect-free pre-decision check (ownership/scope) whose result becomes the
    ``resource_authorized`` policy fact; ``execute`` re-checks access defensively.
    """

    adapter_version: str

    def registrations(self) -> tuple[ToolRegistration, ...]:
        """The registrations this adapter serves (used only at registry build time)."""
        ...

    def check_resource_access(
        self,
        *,
        principal: Principal,
        tool_id: str,
        action_id: str,
        resource_ids: tuple[str, ...],
    ) -> bool:
        """Return whether the principal may access every requested resource."""
        ...

    async def execute(
        self,
        *,
        tool_id: str,
        action_id: str,
        arguments: ToolArguments,
        authorization: ExecutionAuthorization,
    ) -> ToolResult:
        """Execute one already-authorized action; must verify the authorization."""
        ...


def verify_execution_authorization(
    authorization: ExecutionAuthorization,
    *,
    tool_id: str,
    action_id: str,
    arguments: ToolArguments,
    resource_ids: Sequence[str],
    destination: str | None,
) -> None:
    """Adapter-side verification of a gateway authorization (fail closed).

    Binds the tool/action identity and recomputes the canonical action digest from the
    arguments the adapter is about to use. A changed tool name, action, argument,
    resource, or destination therefore fails before any side effect.
    """
    if not isinstance(authorization, ExecutionAuthorization):
        raise ExecutionAuthorizationError(
            "execution requires an authorization issued by the firewall gateway"
        )
    if authorization.tool_id != tool_id or authorization.action_id != action_id:
        raise ExecutionAuthorizationError(
            "execution authorization does not match the tool/action being invoked"
        )
    if (
        tuple(resource_ids) != authorization.resource_ids
        or destination != authorization.destination
    ):
        raise ExecutionAuthorizationError(
            "execution authorization does not match the resource/destination being used"
        )
    try:
        expected = compute_action_digest(
            request_id=authorization.request_id,
            principal_subject_id=authorization.principal_subject_id,
            tool_id=tool_id,
            action_id=action_id,
            arguments=arguments.model_dump(mode="json"),
            resource_ids=authorization.resource_ids,
            destination=authorization.destination,
            policy_hash=authorization.policy_hash,
        )
    except ValueError as exc:  # CanonicalJSONError is a ValueError
        raise ExecutionAuthorizationError(
            "action arguments cannot be canonicalized for digest verification"
        ) from exc
    if not constant_time_hex32_equal(authorization.action_digest, expected):
        raise ExecutionAuthorizationError(
            "action digest mismatch: the tool/action or arguments changed after "
            "authorization (blueprint section 12.4)"
        )


__all__ = [
    "ExecutionAuthorization",
    "ExecutionAuthorizationError",
    "STABLE_ID_PATTERN",
    "SideEffectClass",
    "ToolAdapter",
    "ToolArguments",
    "ToolExecutionError",
    "ToolResult",
    "UngatedExecutionError",
    "compute_action_digest",
    "verify_execution_authorization",
]
