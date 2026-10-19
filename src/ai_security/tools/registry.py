"""Tool registry: capability registration and startup consistency checks (§12.2).

The registry separates *capability* (what an adapter can do: schemas, bounds, resources,
destinations, timeout/concurrency) from *authorization* (what policy permits:
``config/policies.yaml``). Both are required; drift between them fails startup instead
of leaving an executable-but-unpredictable path.

Rules enforced at construction (fail closed):

- stable tool/action ids; one registration per tool id; no ``DESTRUCTIVE`` registration
  in v1 (§6.1, §14.1);
- strict pydantic argument/result schemas (``extra="forbid"`` required);
- declared resource-id arguments exist in the argument schema; declared destinations are
  canonical and unique;
- every policy tool has a registration (policy can never authorize an unknown
  capability), side-effect classes match, an approval-required registration must be
  policy approval-eligible, and every policy destination is within the adapter's
  declared destination capability.

A registration absent from the policy document is *registered but disabled*: the policy
engine has no entry for it and therefore denies it (``unknown_tool``). This is how the
v1 starter policy enables the demo actions from blueprint section 10.5 while the
registry still declares every MVP adapter from section 14.1 (for example
``mock_files.search``).

Unknown tool ids are never resolved (no dynamic imports, no name-derived module loading).
Adapters are reachable only through the registry and can only execute with a
gateway-issued ``ExecutionAuthorization`` (``tools/base.py``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from pydantic import BaseModel

from ai_security.data_security.classification import DataClass
from ai_security.policy.models import PolicyBundle
from ai_security.security.urls import (
    DestinationCanonicalizationError,
    canonicalize_destination,
)

from .base import STABLE_ID_PATTERN, SideEffectClass, ToolAdapter, ToolArguments, ToolResult

_RESOURCE_PREFIX = re.compile(r"[A-Za-z0-9._-]{1,64}")
_RULE_MAX_LENGTH = 256
_ADAPTER_VERSION_MAX_LENGTH = 64
_MAX_TIMEOUT_MS = 60_000
_MAX_RESULT_BYTES = 1_048_576
_MAX_CONCURRENCY = 64


class ToolRegistryConfigError(RuntimeError):
    """The registry or its relationship to the policy document is invalid (fail startup)."""


@dataclass(frozen=True)
class ToolRegistration:
    """One registered tool/action capability (blueprint section 12.2).

    ``data_class`` is the registry-declared sensitivity of the data this action handles;
    Phase 6 adds per-content DLP classification. ``destinations`` is the adapter's
    capability allowlist (exact canonical destinations); policy additionally authorizes
    a subset of it. ``required_approver_rule`` syntax is evaluated by Phase 5 approvals.
    """

    tool_id: str
    action_id: str
    side_effect_class: SideEffectClass
    data_class: DataClass
    argument_schema: type[ToolArguments]
    result_schema: type[ToolResult]
    resource_id_arguments: tuple[str, ...]
    resource_prefixes: tuple[str, ...]
    destination_argument: str | None
    destinations: tuple[str, ...]
    timeout_ms: int
    max_concurrent_invocations: int
    max_result_bytes: int
    approval_required: bool
    required_approver_rule: str | None
    adapter_version: str

    def __post_init__(self) -> None:
        _validate_registration(self)


@dataclass(frozen=True)
class RegisteredTool:
    """A resolved registration plus its adapter.

    Only the firewall gateway may invoke ``adapter.execute``; the adapter itself rejects
    invocations without a gateway-issued authorization.
    """

    registration: ToolRegistration
    adapter: ToolAdapter


def _require_stable_id(value: object, *, field: str) -> None:
    if not isinstance(value, str) or re.fullmatch(STABLE_ID_PATTERN, value) is None:
        raise ToolRegistryConfigError(
            f"{field} must be a stable id: 1-128 chars, alphanumeric start/end, "
            "'.', '_', '-' inside"
        )


def _require_strict_schema(schema: object, *, field: str, base: type[BaseModel]) -> None:
    if not isinstance(schema, type) or not issubclass(schema, base):
        raise ToolRegistryConfigError(
            f"{field} must be a pydantic model subclass of {base.__name__}"
        )
    if schema.model_config.get("extra") != "forbid":
        raise ToolRegistryConfigError(
            f"{field} {schema.__name__} must set extra='forbid' (unexpected fields are "
            "rejected, never ignored; blueprint section 6.2)"
        )


def _require_int(value: object, *, field: str, minimum: int, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ToolRegistryConfigError(f"{field} must be an integer in [{minimum}, {maximum}]")


def _validate_registration(registration: ToolRegistration) -> None:
    _require_stable_id(registration.tool_id, field="tool_id")
    _require_stable_id(registration.action_id, field="action_id")

    if not isinstance(registration.side_effect_class, SideEffectClass):
        raise ToolRegistryConfigError("side_effect_class must be a canonical SideEffectClass")
    if registration.side_effect_class is SideEffectClass.destructive:
        raise ToolRegistryConfigError(
            f"tool {registration.tool_id!r} declares DESTRUCTIVE; destructive tools are "
            "not registered in v1 (blueprint sections 6.1, 14.1)"
        )
    if not isinstance(registration.data_class, DataClass):
        raise ToolRegistryConfigError("data_class must be a canonical DataClass")

    _require_strict_schema(
        registration.argument_schema, field="argument_schema", base=ToolArguments
    )
    _require_strict_schema(registration.result_schema, field="result_schema", base=ToolResult)
    argument_fields = registration.argument_schema.model_fields

    if len(set(registration.resource_id_arguments)) != len(registration.resource_id_arguments):
        raise ToolRegistryConfigError("resource_id_arguments must be unique")
    for argument_name in registration.resource_id_arguments:
        field = argument_fields.get(argument_name)
        if field is None:
            raise ToolRegistryConfigError(
                f"resource_id_arguments entry {argument_name!r} is not a field of "
                f"{registration.argument_schema.__name__}"
            )
        if field.annotation is not str:
            raise ToolRegistryConfigError(
                f"resource-id argument {argument_name!r} must be annotated as str"
            )

    if len(set(registration.resource_prefixes)) != len(registration.resource_prefixes):
        raise ToolRegistryConfigError("resource_prefixes must be unique")
    for prefix in registration.resource_prefixes:
        if not isinstance(prefix, str) or _RESOURCE_PREFIX.fullmatch(prefix) is None:
            raise ToolRegistryConfigError(
                "resource_prefixes entries must be 1-64 chars of [A-Za-z0-9._-]"
            )

    if len(set(registration.destinations)) != len(registration.destinations):
        raise ToolRegistryConfigError("destinations must be unique after canonicalization")
    canonical_destinations: list[str] = []
    for destination in registration.destinations:
        try:
            canonical = canonicalize_destination(destination)
        except DestinationCanonicalizationError as exc:
            raise ToolRegistryConfigError(
                f"destination {destination!r} is not canonicalizable: {exc}"
            ) from exc
        canonical_destinations.append(canonical)
    if tuple(canonical_destinations) != registration.destinations:
        raise ToolRegistryConfigError(
            "destinations must already be in canonical form (no non-canonical aliases)"
        )

    if registration.destination_argument is None:
        if registration.destinations:
            raise ToolRegistryConfigError(
                "destinations require a destination_argument; a tool without egress "
                "must not declare destination capability"
            )
    else:
        destination_field = argument_fields.get(registration.destination_argument)
        if destination_field is None:
            raise ToolRegistryConfigError(
                f"destination_argument {registration.destination_argument!r} is not a "
                f"field of {registration.argument_schema.__name__}"
            )
        if destination_field.annotation is not str:
            raise ToolRegistryConfigError(
                f"destination argument {registration.destination_argument!r} must be "
                "annotated as str"
            )
        if registration.side_effect_class is not SideEffectClass.external_mutation:
            raise ToolRegistryConfigError(
                "only EXTERNAL_MUTATION tools may accept a destination argument"
            )
        if not registration.destinations:
            raise ToolRegistryConfigError(
                "an egress tool must declare at least one destination capability"
            )

    _require_int(registration.timeout_ms, field="timeout_ms", minimum=1, maximum=_MAX_TIMEOUT_MS)
    _require_int(
        registration.max_concurrent_invocations,
        field="max_concurrent_invocations",
        minimum=1,
        maximum=_MAX_CONCURRENCY,
    )
    _require_int(
        registration.max_result_bytes,
        field="max_result_bytes",
        minimum=1,
        maximum=_MAX_RESULT_BYTES,
    )

    if not isinstance(registration.approval_required, bool):
        raise ToolRegistryConfigError("approval_required must be a boolean")
    if registration.approval_required:
        rule = registration.required_approver_rule
        if (
            not isinstance(rule, str)
            or not rule.strip()
            or len(rule) > _RULE_MAX_LENGTH
            or _has_control_characters(rule)
        ):
            raise ToolRegistryConfigError(
                "approval-required registrations must declare a control-free, non-empty "
                f"required_approver_rule (max {_RULE_MAX_LENGTH} chars)"
            )
    elif registration.required_approver_rule is not None:
        raise ToolRegistryConfigError(
            "required_approver_rule is only meaningful when approval_required is true"
        )

    if (
        not isinstance(registration.adapter_version, str)
        or not registration.adapter_version
        or len(registration.adapter_version) > _ADAPTER_VERSION_MAX_LENGTH
        or _has_control_characters(registration.adapter_version)
    ):
        raise ToolRegistryConfigError(
            "adapter_version must be a non-empty control-free string of at most "
            f"{_ADAPTER_VERSION_MAX_LENGTH} chars"
        )


def _has_control_characters(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


class ToolRegistry:
    """Immutable registry built from adapters; one registration per tool id."""

    def __init__(self, adapters: Iterable[ToolAdapter]) -> None:
        by_key: dict[tuple[str, str], RegisteredTool] = {}
        by_tool_id: dict[str, str] = {}
        for adapter in adapters:
            for registration in adapter.registrations():
                if registration.adapter_version != adapter.adapter_version:
                    raise ToolRegistryConfigError(
                        f"registration {registration.tool_id!r} declares adapter_version "
                        f"{registration.adapter_version!r} but its adapter is "
                        f"{adapter.adapter_version!r}"
                    )
                if registration.tool_id in by_tool_id:
                    raise ToolRegistryConfigError(
                        f"duplicate registration for tool id {registration.tool_id!r}"
                    )
                by_tool_id[registration.tool_id] = registration.action_id
                by_key[(registration.tool_id, registration.action_id)] = RegisteredTool(
                    registration=registration, adapter=adapter
                )
        self._by_key = by_key

    def resolve(self, tool_id: str, action_id: str) -> RegisteredTool | None:
        """Exact registration lookup; ``None`` means unknown (deny, never import)."""
        return self._by_key.get((tool_id, action_id))

    def registrations(self) -> tuple[ToolRegistration, ...]:
        """All registrations in deterministic (tool id) order."""
        return tuple(
            entry.registration
            for _, entry in sorted(self._by_key.items(), key=lambda item: item[0][0])
        )


def build_registry(bundle: PolicyBundle, adapters: Iterable[ToolAdapter]) -> ToolRegistry:
    """Build the registry and prove it matches the loaded policy document exactly.

    A policy entry without an adapter, an adapter without a policy entry, a
    side-effect-class mismatch, an approval misconfiguration, or a policy destination
    outside the adapter's capability refuses startup (blueprint sections 12.2, 12.4).
    """
    registry = ToolRegistry(adapters)
    registrations = registry.registrations()
    registered_ids = {registration.tool_id for registration in registrations}
    policy_tools = bundle.policies.tools

    missing_adapters = sorted(set(policy_tools) - registered_ids)
    if missing_adapters:
        raise ToolRegistryConfigError(
            "policy declares tool(s) with no registered adapter: " + ", ".join(missing_adapters)
        )
    for registration in registrations:
        tool_policy = policy_tools.get(registration.tool_id)
        if tool_policy is None:
            continue
        if tool_policy.side_effect_class is not registration.side_effect_class:
            raise ToolRegistryConfigError(
                f"side-effect class mismatch for {registration.tool_id!r}: policy says "
                f"{tool_policy.side_effect_class.value}, adapter says "
                f"{registration.side_effect_class.value}"
            )
        if registration.approval_required and not tool_policy.approval_eligible:
            raise ToolRegistryConfigError(
                f"{registration.tool_id!r} requires approval but the policy does not mark "
                "it approval-eligible; the action could never be approvable"
            )
        if tool_policy.external_egress_enabled and not registration.destinations:
            raise ToolRegistryConfigError(
                f"policy enables external egress for {registration.tool_id!r} but the "
                "adapter declares no destination capability"
            )
        for destination in tool_policy.allowed_destinations:
            if destination not in registration.destinations:
                raise ToolRegistryConfigError(
                    f"policy allowlists destination {destination!r} for "
                    f"{registration.tool_id!r}, but the adapter does not declare it"
                )
    return registry


__all__ = [
    "RegisteredTool",
    "ToolRegistration",
    "ToolRegistry",
    "ToolRegistryConfigError",
    "build_registry",
]
