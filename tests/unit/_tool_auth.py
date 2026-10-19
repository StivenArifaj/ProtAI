"""Test-only helper that issues gateway-style execution authorizations.

Tests are the only place allowed to import the private issuer; production adapters can
only obtain an authorization from ``firewall.gateway``. Keeping the helper here makes
that asymmetry explicit.
"""

from __future__ import annotations

from ai_security.tools.base import (
    ExecutionAuthorization,
    ToolArguments,
    _issue_execution_authorization,
    compute_action_digest,
)

DEFAULT_POLICY_HASH = "a" * 64


def issue_authorization(
    *,
    tool_id: str,
    action_id: str,
    arguments: ToolArguments,
    resource_ids: tuple[str, ...] = (),
    destination: str | None = None,
    principal_subject_id: str = "dev-user",
    request_id: str = "req-1",
    call_id: str = "call-1",
    policy_hash: str = DEFAULT_POLICY_HASH,
) -> ExecutionAuthorization:
    digest = compute_action_digest(
        request_id=request_id,
        principal_subject_id=principal_subject_id,
        tool_id=tool_id,
        action_id=action_id,
        arguments=arguments.model_dump(mode="json"),
        resource_ids=resource_ids,
        destination=destination,
        policy_hash=policy_hash,
    )
    return _issue_execution_authorization(
        call_id=call_id,
        request_id=request_id,
        principal_subject_id=principal_subject_id,
        tool_id=tool_id,
        action_id=action_id,
        resource_ids=resource_ids,
        destination=destination,
        policy_hash=policy_hash,
        action_digest=digest,
    )
