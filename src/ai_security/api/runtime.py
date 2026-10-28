"""Bounded deterministic demo runtime for ``POST /v1/requests`` (ADR-015).

The runtime is deliberately narrow: it accepts exactly the manifest shape produced by
the mock extractor's supported demo intent (one ``mock_email.read`` followed by one
``text.summarize``) and refuses everything else with ``NO_ACTION``. It receives only a
``ToolExecutor`` — never an adapter, registry, policy engine, or approval service — so
the gateway remains the sole execution path.

A relative time window is never executed unfiltered: the mock email adapter has no
window filter, so a manifest carrying one yields ``NO_ACTION`` rather than silently
reading the whole mailbox. The runtime reserves every planned tool-call rate-limit slot
before the first call, so a partially available bucket cannot execute an unbounded
prefix of the plan.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import JsonValue

from ai_security.api.schemas import RequestState
from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.firewall.gateway import ToolGateway
from ai_security.firewall.models import (
    InvocationOutcome,
    ProposedToolCall,
    RequestContext,
    ToolExecutor,
    ToolInvocationResult,
)
from ai_security.identity.models import Principal
from ai_security.intent.models import IntentConstraint, IntentManifest
from ai_security.tools.mock_email import EmailReadResult
from ai_security.tools.mock_text import SummarizeResult

logger = logging.getLogger(__name__)

READ_TOOL_ID = "mock_email.read"
READ_ACTION_ID = "read"
SUMMARIZE_TOOL_ID = "text.summarize"
SUMMARIZE_ACTION_ID = "summarize"
SUPPORTED_PLAN_SIZE = 2
MIN_SUMMARY_CHARS = 20
MAX_SUMMARY_CHARS = 1_000


@dataclass(frozen=True)
class PlannedToolCall:
    """One runtime-prepared call; arguments never contain client-supplied authority."""

    tool_id: str
    action_id: str
    arguments: dict[str, JsonValue]
    resource_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuntimeOutcome:
    """A safe, transport-ready runtime result (no raw tool output beyond the summary)."""

    state: RequestState
    message: str
    http_status: int = 200
    error_code: str | None = None
    result: dict[str, JsonValue] | None = None
    approval_facts: ToolInvocationResult | None = None


class ReceiptedToolExecutor:
    """``ToolExecutor`` that tells a concrete gateway the receipt already exists.

    The HTTP ingress persists ``REQUEST_RECEIVED`` before intent extraction. Wrapping the
    gateway keeps the demo runtime limited to the ``ToolExecutor`` protocol while still
    preventing one HTTP request from producing multiple receipts.
    """

    def __init__(self, gateway: ToolGateway) -> None:
        self._gateway = gateway

    async def invoke_tool(
        self,
        *,
        principal: Principal,
        request_context: RequestContext,
        proposal: ProposedToolCall,
        manifest: IntentManifest | None = None,
        approval_id: str | None = None,
    ) -> ToolInvocationResult:
        return await self._gateway.invoke_tool(
            principal=principal,
            request_context=request_context,
            proposal=proposal,
            manifest=manifest,
            approval_id=approval_id,
            receipt_already_audited=True,
        )


class DemoRuntime:
    """Plan and execute only the supported read-then-summarize demo intent."""

    def __init__(
        self,
        executor: ToolExecutor,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._executor = executor
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))

    def plan(self, manifest: IntentManifest) -> tuple[PlannedToolCall, ...] | None:
        """Return the exact supported plan, or ``None`` when the runtime must not act."""
        if manifest.time_window is not None:
            return None
        if len(manifest.constraints) != SUPPORTED_PLAN_SIZE:
            return None

        read = _find_constraint(manifest, READ_TOOL_ID, READ_ACTION_ID)
        summarize = _find_constraint(manifest, SUMMARIZE_TOOL_ID, SUMMARIZE_ACTION_ID)
        if read is None or summarize is None:
            return None
        if not _is_plain_read_constraint(read):
            return None
        max_chars = _summary_max_chars(summarize)
        if max_chars is None:
            return None

        email_id = read.allowed_resource_ids[0]
        return (
            PlannedToolCall(
                tool_id=READ_TOOL_ID,
                action_id=READ_ACTION_ID,
                arguments={"email_id": email_id},
                resource_ids=(email_id,),
            ),
            PlannedToolCall(
                tool_id=SUMMARIZE_TOOL_ID,
                action_id=SUMMARIZE_ACTION_ID,
                arguments={"max_chars": max_chars},
            ),
        )

    async def execute(
        self,
        *,
        principal: Principal,
        request_context: RequestContext,
        manifest: IntentManifest,
        deadline: datetime,
        reserve_tool_calls: Callable[[int], bool],
    ) -> RuntimeOutcome:
        """Execute the supported plan only after reserving every planned call slot."""
        plan = self.plan(manifest)
        if plan is None:
            return RuntimeOutcome(
                state=RequestState.no_action,
                message="No supported executable action plan was found; nothing was executed.",
            )
        if self._now() >= deadline:
            return RuntimeOutcome(
                state=RequestState.failed,
                http_status=504,
                error_code="request_timeout",
                message="The request deadline was exceeded before execution.",
            )
        try:
            reserved = reserve_tool_calls(len(plan))
        except Exception:  # noqa: BLE001 - limiter failure must not execute anything
            logger.error("tool-call rate limiter failed for request %s", request_context.request_id)
            return RuntimeOutcome(
                state=RequestState.failed,
                http_status=503,
                error_code="dependency_unavailable",
                message="The request could not be admitted safely; nothing was executed.",
            )
        if not reserved:
            return RuntimeOutcome(
                state=RequestState.failed,
                http_status=429,
                error_code="rate_limited",
                message="Too many tool calls; nothing was executed.",
            )

        read_call, summarize_call = plan
        read_result = await self._invoke(
            principal=principal,
            request_context=request_context,
            manifest=manifest,
            call=read_call,
            deadline=deadline,
        )
        read_outcome = _outcome_for(read_result)
        if read_outcome is not None:
            return read_outcome
        if not isinstance(read_result.result, EmailReadResult):
            return _invalid_result(read_result)

        max_chars = summarize_call.arguments["max_chars"]
        if isinstance(max_chars, bool) or not isinstance(max_chars, int):
            return _invalid_result(read_result)
        summarize_call = PlannedToolCall(
            tool_id=summarize_call.tool_id,
            action_id=summarize_call.action_id,
            arguments={"text": read_result.result.body, "max_chars": max_chars},
        )
        summary_result = await self._invoke(
            principal=principal,
            request_context=request_context,
            manifest=manifest,
            call=summarize_call,
            deadline=deadline,
        )
        summary_outcome = _outcome_for(summary_result)
        if summary_outcome is not None:
            return summary_outcome
        if not isinstance(summary_result.result, SummarizeResult):
            return _invalid_result(summary_result)

        return RuntimeOutcome(
            state=RequestState.completed,
            message="Request completed.",
            result={
                "email_id": read_result.result.email_id,
                "summary": summary_result.result.summary,
                "original_chars": summary_result.result.original_chars,
                "truncated": summary_result.result.truncated,
            },
        )

    async def _invoke(
        self,
        *,
        principal: Principal,
        request_context: RequestContext,
        manifest: IntentManifest,
        call: PlannedToolCall,
        deadline: datetime,
    ) -> ToolInvocationResult:
        proposal = ProposedToolCall(
            call_id=_new_call_id(),
            request_id=request_context.request_id,
            principal_subject_id=principal.subject_id,
            tool_id=call.tool_id,
            action_id=call.action_id,
            arguments=call.arguments,
            target_resource_ids=call.resource_ids,
            deadline=deadline,
        )
        return await self._executor.invoke_tool(
            principal=principal,
            request_context=request_context,
            proposal=proposal,
            manifest=manifest,
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.utcoffset() is None:
            raise RuntimeError("runtime clock must return a timezone-aware datetime")
        return value


def _find_constraint(
    manifest: IntentManifest, tool_id: str, action_id: str
) -> IntentConstraint | None:
    return manifest.constraint_for(tool_id, action_id)


def _is_plain_read_constraint(constraint: IntentConstraint) -> bool:
    return (
        len(constraint.allowed_resource_ids) == 1
        and not constraint.allowed_destinations
        and not constraint.allowed_parameter_values
        and constraint.max_uses == 1
    )


def _summary_max_chars(constraint: IntentConstraint) -> int | None:
    if constraint.allowed_resource_ids or constraint.allowed_destinations:
        return None
    if constraint.max_uses != 1:
        return None
    allowed = constraint.allowed_parameter_values
    if set(allowed) != {"max_chars"}:
        return None
    values = allowed["max_chars"]
    if len(values) != 1:
        return None
    value = values[0]
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if not MIN_SUMMARY_CHARS <= value <= MAX_SUMMARY_CHARS:
        return None
    return value


def _outcome_for(result: ToolInvocationResult) -> RuntimeOutcome | None:
    """Map a non-success gateway result; ``None`` means the call executed successfully."""
    if result.reason is DecisionReason.deadline_exceeded:
        return RuntimeOutcome(
            state=RequestState.failed,
            http_status=504,
            error_code="request_timeout",
            message="The request deadline was exceeded before execution.",
        )
    if result.decision is FirewallDecision.ask_user:
        if result.approval_required:
            return RuntimeOutcome(
                state=RequestState.approval_required,
                http_status=202,
                message="Approval is required before this action can execute.",
                approval_facts=result,
            )
        return RuntimeOutcome(
            state=RequestState.denied,
            http_status=403,
            error_code="approval_not_allowed",
            message="The action is not eligible for approval and was not executed.",
        )
    if result.decision is FirewallDecision.block:
        if result.reason is DecisionReason.audit_unavailable:
            return RuntimeOutcome(
                state=RequestState.failed,
                http_status=503,
                error_code="audit_unavailable",
                message="Audit persistence failed; nothing was executed.",
            )
        return RuntimeOutcome(
            state=RequestState.denied,
            http_status=403,
            error_code="policy_denied",
            message="The action was denied by policy and was not executed.",
        )
    if result.decision is FirewallDecision.allow and result.outcome is InvocationOutcome.executed:
        return None
    if result.outcome is InvocationOutcome.audit_failed:
        return RuntimeOutcome(
            state=RequestState.failed,
            http_status=503,
            error_code="audit_unavailable",
            message="Audit persistence failed and the result was withheld.",
        )
    if result.outcome is InvocationOutcome.response_blocked:
        return RuntimeOutcome(
            state=RequestState.failed,
            http_status=502,
            error_code="response_blocked",
            message="The tool result was withheld by output inspection.",
        )
    if result.outcome in (
        InvocationOutcome.adapter_failed,
        InvocationOutcome.timeout,
        InvocationOutcome.result_rejected,
    ):
        return RuntimeOutcome(
            state=RequestState.failed,
            http_status=502,
            error_code="tool_execution_failed",
            message="Tool execution failed; no result was released.",
        )
    return RuntimeOutcome(
        state=RequestState.failed,
        http_status=502,
        error_code="tool_execution_failed",
        message="The tool did not return a releasable result.",
    )


def _invalid_result(result: ToolInvocationResult) -> RuntimeOutcome:
    logger.error("unexpected tool result type for %s/%s", result.tool_id, result.action_id)
    return RuntimeOutcome(
        state=RequestState.failed,
        http_status=502,
        error_code="invalid_tool_result",
        message="The tool returned an unexpected result; nothing was released.",
    )


def _new_call_id() -> str:
    return f"call-{secrets.token_hex(16)}"


__all__ = [
    "DemoRuntime",
    "PlannedToolCall",
    "ReceiptedToolExecutor",
    "RuntimeOutcome",
]
