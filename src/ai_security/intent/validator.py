"""Concrete action-versus-intent validation and bounded use tracking (blueprint §11.1).

The validator compares the gateway-validated action against the manifest's exact
tool/action, resource ids, canonical destination, and allowed parameter values. It
never consults the policy engine and can only narrow execution: the policy engine
remains the sole ``ALLOW`` producer.

``IntentUsageTracker`` enforces per-constraint ``max_uses`` for the lifetime of a
manifest. It is an in-memory, per-process guardrail; the manifest still carries an
expiry and every call is bound to the server-issued manifest id.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from ai_security.intent.models import IntentManifest
from ai_security.tools.base import ToolArguments

DEFAULT_MAX_TRACKED_MANIFESTS = 10_000
_UsageKey = tuple[str, str]


class IntentConstraintViolation(StrEnum):
    """Why an action does not satisfy the manifest (mapped to gateway reasons)."""

    no_matching_action = "NO_MATCHING_ACTION"
    resource_scope = "RESOURCE_SCOPE"
    destination_scope = "DESTINATION_SCOPE"
    parameter_value = "PARAMETER_VALUE"


def validate_intent_constraints(
    manifest: IntentManifest,
    *,
    tool_id: str,
    action_id: str,
    arguments: ToolArguments,
    resource_ids: tuple[str, ...],
    destination: str | None,
) -> IntentConstraintViolation | None:
    """Return the first concrete violation, or ``None`` when all limits are met."""
    constraint = manifest.constraint_for(tool_id, action_id)
    if constraint is None:
        return IntentConstraintViolation.no_matching_action

    allowed_resources = set(constraint.allowed_resource_ids)
    if any(resource_id not in allowed_resources for resource_id in resource_ids):
        return IntentConstraintViolation.resource_scope

    if destination is not None and destination not in constraint.allowed_destinations:
        return IntentConstraintViolation.destination_scope

    for parameter_name, allowed_values in constraint.allowed_parameter_values.items():
        actual = getattr(arguments, parameter_name)
        if not any(type(actual) is type(value) and actual == value for value in allowed_values):
            return IntentConstraintViolation.parameter_value

    return None


class IntentUsageTracker:
    """Bound manifest uses without turning intent into an authorization source."""

    def __init__(self, *, max_tracked_manifests: int = DEFAULT_MAX_TRACKED_MANIFESTS) -> None:
        if max_tracked_manifests < 1:
            raise ValueError("max_tracked_manifests must be positive")
        self._max_tracked_manifests = max_tracked_manifests
        self._expiry: dict[str, datetime] = {}
        self._usage: dict[str, dict[_UsageKey, int]] = {}

    def reserve(
        self,
        *,
        manifest: IntentManifest,
        tool_id: str,
        action_id: str,
        now: datetime,
    ) -> bool:
        """Atomically reserve one use; return ``False`` when the manifest is exhausted.

        Called only after policy would allow the action and before the decision audit
        write. A later execution/audit failure conservatively keeps the reservation.
        """
        if now.utcoffset() is None:
            raise ValueError("reservation time must be timezone-aware")
        self._purge_expired(now)
        if manifest.expires_at <= now:
            return False

        constraint = manifest.constraint_for(tool_id, action_id)
        if constraint is None:
            return False

        usage = self._usage.get(manifest.manifest_id)
        if usage is None:
            if len(self._usage) >= self._max_tracked_manifests:
                return False
            usage = {}
            self._usage[manifest.manifest_id] = usage
            self._expiry[manifest.manifest_id] = manifest.expires_at

        key: _UsageKey = (tool_id, action_id)
        used = usage.get(key, 0)
        if used >= constraint.max_uses:
            return False
        usage[key] = used + 1
        return True

    def _purge_expired(self, now: datetime) -> None:
        expired = [manifest_id for manifest_id, expiry in self._expiry.items() if expiry <= now]
        for manifest_id in expired:
            self._expiry.pop(manifest_id, None)
            self._usage.pop(manifest_id, None)


__all__ = [
    "DEFAULT_MAX_TRACKED_MANIFESTS",
    "IntentConstraintViolation",
    "IntentUsageTracker",
    "validate_intent_constraints",
]
