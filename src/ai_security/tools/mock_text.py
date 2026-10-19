"""Deterministic mock text-summary adapter (blueprint sections 14.1, 14.3).

No model is invoked: the "summary" is a deterministic whitespace normalization and
prefix, so tests can assert exact outputs. The starter policy sets
``external_egress: false`` for this tool.
"""

from __future__ import annotations

from pydantic import Field

from ai_security.data_security.classification import DataClass
from ai_security.identity.models import Principal

from .base import (
    ExecutionAuthorization,
    SideEffectClass,
    ToolArguments,
    ToolExecutionError,
    ToolResult,
    verify_execution_authorization,
)
from .registry import ToolRegistration

TOOL_ID = "text.summarize"
ACTION_ID = "summarize"
ADAPTER_VERSION = "mock-text-v1"
MAX_RESULT_BYTES = 8_192


class SummarizeArguments(ToolArguments):
    text: str = Field(min_length=1, max_length=4_096)
    max_chars: int = Field(default=200, ge=20, le=1_000, strict=True)


class SummarizeResult(ToolResult):
    summary: str
    original_chars: int
    truncated: bool


class MockTextAdapter:
    """Deterministic, network-free text summarizer."""

    adapter_version = ADAPTER_VERSION

    def registrations(self) -> tuple[ToolRegistration, ...]:
        return (
            ToolRegistration(
                tool_id=TOOL_ID,
                action_id=ACTION_ID,
                side_effect_class=SideEffectClass.read_only,
                data_class=DataClass.internal,
                argument_schema=SummarizeArguments,
                result_schema=SummarizeResult,
                resource_id_arguments=(),
                resource_prefixes=(),
                destination_argument=None,
                destinations=(),
                timeout_ms=1_000,
                max_concurrent_invocations=8,
                max_result_bytes=MAX_RESULT_BYTES,
                approval_required=False,
                required_approver_rule=None,
                adapter_version=ADAPTER_VERSION,
            ),
        )

    def check_resource_access(
        self,
        *,
        principal: Principal,
        tool_id: str,
        action_id: str,
        resource_ids: tuple[str, ...],
    ) -> bool:
        return tool_id == TOOL_ID and action_id == ACTION_ID and not resource_ids

    async def execute(
        self,
        *,
        tool_id: str,
        action_id: str,
        arguments: ToolArguments,
        authorization: ExecutionAuthorization,
    ) -> ToolResult:
        if tool_id != TOOL_ID or action_id != ACTION_ID:
            raise ToolExecutionError(f"unregistered mock text action {action_id!r}")
        if not isinstance(arguments, SummarizeArguments):
            raise ToolExecutionError("summarize arguments were not validated by the gateway")
        verify_execution_authorization(
            authorization,
            tool_id=tool_id,
            action_id=action_id,
            arguments=arguments,
            resource_ids=(),
            destination=None,
        )
        normalized = " ".join(arguments.text.split())
        summary = normalized[: arguments.max_chars]
        return SummarizeResult(
            summary=summary,
            original_chars=len(arguments.text),
            truncated=len(summary) < len(normalized),
        )
