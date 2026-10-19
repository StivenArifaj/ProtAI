"""The single enforced tool gateway (blueprint sections 12.1-12.4; ADR-009).

Every adapter invocation — read-only, local mutation, or external side effect — goes
through ``ToolGateway.invoke_tool``. The agent runtime receives only the ``ToolExecutor``
protocol; adapters reject execution without a gateway-issued ``ExecutionAuthorization``
whose digest binds the verified principal, request, exact tool/action, validated
arguments, canonical resource ids, canonical destination, and policy hash.

Order of operations (section 12.3):

1. verify proposal/request/principal bindings;
2. resolve the exact registration (unknown -> BLOCK, never import);
3. validate arguments with the registration schema and canonicalize them;
4. derive and cross-check resource ids and the canonical destination;
5. run the adapter's least-privilege resource check;
6. compute deterministic risk factors (server-side facts only);
7. evaluate the deterministic policy engine;
8. persist the decision audit event — for ``ALLOW`` this is mandatory and happens
   *before* any side effect (section 16.4);
9. issue the execution authorization and run the adapter under a timeout and
   per-tool concurrency limit;
10. bound/validate the result, then persist the outcome event;
11. return a typed result.

A denial or failure never returns a result. If the outcome event cannot be persisted
after an execution attempt, the outcome is ``AUDIT_FAILED`` and the result is withheld
(the side effect may already have happened, so success must not be claimed).

Concurrency limiters are per event loop and per process; a multi-worker deployment
gets one limiter per worker. Distributed limits remain future work.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from weakref import WeakKeyDictionary

from pydantic import ValidationError

from ai_security import __version__
from ai_security.audit.models import AuditEvent, AuditEventType
from ai_security.audit.writer import AuditRecorder, AuditWriteError
from ai_security.firewall.decision import DecisionReason, DecisionRecord, FirewallDecision
from ai_security.firewall.models import (
    InvocationOutcome,
    ProposedToolCall,
    RequestContext,
    ToolInvocationResult,
)
from ai_security.firewall.policy_engine import PolicyEngine, PolicyEvaluationRequest
from ai_security.firewall.risk_engine import (
    RiskAssessment,
    RiskScoringError,
    assess_risk,
)
from ai_security.identity.models import Principal
from ai_security.persistence.audit_repository import AppendedAuditEvent
from ai_security.security.canonical_json import (
    CanonicalJSONError,
    canonical_json_bytes,
)
from ai_security.security.urls import (
    DestinationCanonicalizationError,
    canonicalize_destination,
)
from ai_security.tools.base import (
    STABLE_ID_PATTERN,
    ExecutionAuthorization,
    ToolArguments,
    ToolResult,
    _issue_execution_authorization,
    compute_action_digest,
)
from ai_security.tools.registry import RegisteredTool, ToolRegistration, ToolRegistry

logger = logging.getLogger(__name__)


class ToolGateway:
    """Evaluate and (only on ``ALLOW``) execute one proposed tool call."""

    def __init__(
        self,
        *,
        registry: ToolRegistry,
        engine: PolicyEngine,
        recorder: AuditRecorder,
        clock: Callable[[], datetime] | None = None,
        component_version: str = __version__,
    ) -> None:
        self._registry = registry
        self._engine = engine
        self._bundle = engine.bundle
        self._recorder = recorder
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._component_version = component_version
        self._limiters: WeakKeyDictionary[
            asyncio.AbstractEventLoop, dict[str, asyncio.Semaphore]
        ] = WeakKeyDictionary()

    async def invoke_tool(
        self,
        *,
        principal: Principal,
        request_context: RequestContext,
        proposal: ProposedToolCall,
    ) -> ToolInvocationResult:
        """Evaluate and, only on ``ALLOW``, execute the proposed action."""
        now = self._now()

        if not self._binding_is_valid(
            principal=principal, request_context=request_context, proposal=proposal
        ):
            decision = self._decision(FirewallDecision.block, DecisionReason.binding_mismatch)
            sequence = await self._record_decision_event(
                request_context=request_context,
                principal=principal,
                proposal=proposal,
                decision=decision,
            )
            return self._result(
                proposal, decision, InvocationOutcome.denied, None, None, sequence, None
            )

        registered = self._registry.resolve(proposal.tool_id, proposal.action_id)
        if registered is None:
            decision = self._decision(FirewallDecision.block, DecisionReason.unknown_tool)
            sequence = await self._record_decision_event(
                request_context=request_context,
                principal=principal,
                proposal=proposal,
                decision=decision,
            )
            return self._result(
                proposal, decision, InvocationOutcome.denied, None, None, sequence, None
            )

        registration = registered.registration
        validated = self._validate_arguments(registered, proposal)
        if validated is None:
            decision = self._decision(FirewallDecision.block, DecisionReason.invalid_arguments)
            sequence = await self._record_decision_event(
                request_context=request_context,
                principal=principal,
                proposal=proposal,
                decision=decision,
                registration=registration,
            )
            return self._result(
                proposal, decision, InvocationOutcome.denied, None, None, sequence, None
            )

        arguments, resource_ids, canonical_destination, targets_consistent = validated
        if not targets_consistent:
            decision = self._decision(FirewallDecision.block, DecisionReason.invalid_arguments)
            sequence = await self._record_decision_event(
                request_context=request_context,
                principal=principal,
                proposal=proposal,
                decision=decision,
                registration=registration,
                destination=canonical_destination,
                resource_ids=resource_ids,
            )
            return self._result(
                proposal, decision, InvocationOutcome.denied, None, None, sequence, None
            )

        resource_authorized = self._resource_authorized(
            registered=registered,
            principal=principal,
            resource_ids=resource_ids,
        )

        try:
            risk = assess_risk(
                side_effect_class=registration.side_effect_class,
                data_class=registration.data_class,
                destination=canonical_destination,
            )
        except RiskScoringError:
            logger.error(
                "risk scoring rejected an inconsistent action for tool %s",
                proposal.tool_id,
            )
            decision = self._decision(
                FirewallDecision.block, DecisionReason.policy_evaluation_error
            )
            sequence = await self._record_decision_event(
                request_context=request_context,
                principal=principal,
                proposal=proposal,
                decision=decision,
                registration=registration,
                destination=canonical_destination,
                resource_ids=resource_ids,
            )
            return self._result(
                proposal, decision, InvocationOutcome.denied, None, None, sequence, None
            )

        deadline_exceeded = proposal.deadline is not None and proposal.deadline <= now
        decision = self._evaluate(
            registration=registration,
            proposal=proposal,
            risk=risk,
            canonical_destination=canonical_destination,
            resource_authorized=resource_authorized,
            deadline_exceeded=deadline_exceeded,
        )

        action_digest: str | None = None
        if decision.decision is FirewallDecision.allow:
            try:
                action_digest = self._digest(
                    principal=principal,
                    proposal=proposal,
                    arguments=arguments.model_dump(mode="json"),
                    resource_ids=resource_ids,
                    destination=canonical_destination,
                )
            except CanonicalJSONError:
                decision = self._decision(FirewallDecision.block, DecisionReason.invalid_arguments)

        decision_sequence = await self._record_decision_event(
            request_context=request_context,
            principal=principal,
            proposal=proposal,
            decision=decision,
            registration=registration,
            risk=risk,
            destination=canonical_destination,
            resource_ids=resource_ids,
        )
        if decision.decision is not FirewallDecision.allow:
            return self._result(
                proposal,
                decision,
                InvocationOutcome.denied,
                None,
                risk,
                decision_sequence,
                None,
            )
        if decision_sequence is None:
            # The decision event could not be persisted: never execute a side effect.
            blocked = self._decision(FirewallDecision.block, DecisionReason.audit_unavailable)
            return self._result(proposal, blocked, InvocationOutcome.denied, None, risk, None, None)

        if action_digest is None:  # pragma: no cover - ALLOW always computes a digest
            raise RuntimeError("ALLOW decision without an action digest")
        authorization = _issue_execution_authorization(
            call_id=proposal.call_id,
            request_id=proposal.request_id,
            principal_subject_id=principal.subject_id,
            tool_id=proposal.tool_id,
            action_id=proposal.action_id,
            resource_ids=resource_ids,
            destination=canonical_destination,
            policy_hash=decision.policy_hash,
            action_digest=action_digest,
        )
        return await self._execute(
            request_context=request_context,
            principal=principal,
            proposal=proposal,
            registration=registration,
            registered=registered,
            decision=decision,
            risk=risk,
            destination=canonical_destination,
            resource_ids=resource_ids,
            arguments=arguments,
            authorization=authorization,
            decision_sequence=decision_sequence,
        )

    # -- validation steps -------------------------------------------------------------

    @staticmethod
    def _binding_is_valid(
        *,
        principal: Principal,
        request_context: RequestContext,
        proposal: ProposedToolCall,
    ) -> bool:
        return (
            proposal.request_id == request_context.request_id
            and proposal.principal_subject_id == principal.subject_id
        )

    def _validate_arguments(
        self, registered: RegisteredTool, proposal: ProposedToolCall
    ) -> tuple[ToolArguments, tuple[str, ...], str | None, bool] | None:
        """Validate/canonicalize arguments; returns None for a malformed call.

        The tuple is (validated arguments, canonical resource ids, canonical
        destination, declared-targets-consistent).
        """
        registration = registered.registration
        try:
            arguments = registration.argument_schema.model_validate(proposal.arguments)
            canonical_json_bytes(arguments.model_dump(mode="json"))
        except (ValidationError, CanonicalJSONError):
            return None

        resource_ids: list[str] = []
        for argument_name in registration.resource_id_arguments:
            value = getattr(arguments, argument_name)
            if not isinstance(value, str) or _is_stable_id(value) is False:
                return None
            resource_ids.append(value)
        derived_resources = tuple(resource_ids)

        canonical_destination: str | None = None
        if registration.destination_argument is not None:
            raw_destination = getattr(arguments, registration.destination_argument)
            if not isinstance(raw_destination, str):
                return None
            try:
                canonical_destination = canonicalize_destination(raw_destination)
            except DestinationCanonicalizationError:
                return None
            if proposal.destination is not None:
                try:
                    declared_destination = canonicalize_destination(proposal.destination)
                except DestinationCanonicalizationError:
                    return None
                if declared_destination != canonical_destination:
                    return None
        elif proposal.destination is not None:
            return None

        targets_consistent = not proposal.target_resource_ids or (
            proposal.target_resource_ids == derived_resources
        )
        return arguments, derived_resources, canonical_destination, targets_consistent

    def _resource_authorized(
        self,
        *,
        registered: RegisteredTool,
        principal: Principal,
        resource_ids: tuple[str, ...],
    ) -> bool:
        if not resource_ids:
            return True
        try:
            authorized = registered.adapter.check_resource_access(
                principal=principal,
                tool_id=registered.registration.tool_id,
                action_id=registered.registration.action_id,
                resource_ids=resource_ids,
            )
        except Exception:
            logger.error(
                "resource-access check raised for tool %s; treating as not authorized",
                registered.registration.tool_id,
            )
            return False
        return authorized is True

    def _evaluate(
        self,
        *,
        registration: ToolRegistration,
        proposal: ProposedToolCall,
        risk: RiskAssessment,
        canonical_destination: str | None,
        resource_authorized: bool,
        deadline_exceeded: bool,
    ) -> DecisionRecord:
        request = PolicyEvaluationRequest(
            tool_id=proposal.tool_id,
            side_effect_class=registration.side_effect_class,
            data_class=registration.data_class,
            risk_score=risk.score,
            principal_resolved=True,
            binding_valid=True,
            arguments_valid=True,
            hard_deny=False,
            deadline_exceeded=deadline_exceeded,
            resource_authorized=resource_authorized,
            destination_consistent=True,
            destination_registered=(
                canonical_destination is None or canonical_destination in registration.destinations
            ),
            destination=canonical_destination,
        )
        try:
            return self._engine.evaluate(request)
        except Exception:
            logger.error("policy engine raised for tool %s; failing closed", proposal.tool_id)
            return self._decision(FirewallDecision.block, DecisionReason.policy_evaluation_error)

    def _digest(
        self,
        *,
        principal: Principal,
        proposal: ProposedToolCall,
        arguments: dict[str, object],
        resource_ids: tuple[str, ...],
        destination: str | None,
    ) -> str:
        return compute_action_digest(
            request_id=proposal.request_id,
            principal_subject_id=principal.subject_id,
            tool_id=proposal.tool_id,
            action_id=proposal.action_id,
            arguments=arguments,
            resource_ids=resource_ids,
            destination=destination,
            policy_hash=self._bundle.combined_hash,
        )

    # -- execution --------------------------------------------------------------------

    async def _execute(
        self,
        *,
        request_context: RequestContext,
        principal: Principal,
        proposal: ProposedToolCall,
        registration: ToolRegistration,
        registered: RegisteredTool,
        decision: DecisionRecord,
        risk: RiskAssessment,
        destination: str | None,
        resource_ids: tuple[str, ...],
        arguments: ToolArguments,
        authorization: ExecutionAuthorization,
        decision_sequence: int,
    ) -> ToolInvocationResult:
        semaphore = self._semaphore(proposal.tool_id, registration.max_concurrent_invocations)
        started = time.perf_counter()
        try:
            async with asyncio.timeout(registration.timeout_ms / 1_000):
                async with semaphore:
                    adapter_result = await registered.adapter.execute(
                        tool_id=proposal.tool_id,
                        action_id=proposal.action_id,
                        arguments=arguments,
                        authorization=authorization,
                    )
        except TimeoutError:
            return await self._failed_execution(
                request_context=request_context,
                principal=principal,
                proposal=proposal,
                registration=registration,
                decision=decision,
                risk=risk,
                destination=destination,
                resource_ids=resource_ids,
                decision_sequence=decision_sequence,
                outcome=InvocationOutcome.timeout,
                error_type="TimeoutError",
                duration_ms=_elapsed_ms(started),
            )
        except Exception as exc:
            logger.warning(
                "tool adapter raised for tool %s (%s)", proposal.tool_id, type(exc).__name__
            )
            return await self._failed_execution(
                request_context=request_context,
                principal=principal,
                proposal=proposal,
                registration=registration,
                decision=decision,
                risk=risk,
                destination=destination,
                resource_ids=resource_ids,
                decision_sequence=decision_sequence,
                outcome=InvocationOutcome.adapter_failed,
                error_type=type(exc).__name__,
                duration_ms=_elapsed_ms(started),
            )

        result_error = self._result_error(registration, adapter_result)
        if result_error is not None:
            return await self._failed_execution(
                request_context=request_context,
                principal=principal,
                proposal=proposal,
                registration=registration,
                decision=decision,
                risk=risk,
                destination=destination,
                resource_ids=resource_ids,
                decision_sequence=decision_sequence,
                outcome=InvocationOutcome.result_rejected,
                error_type=result_error,
                duration_ms=_elapsed_ms(started),
            )

        if not isinstance(adapter_result, ToolResult):  # pragma: no cover - checked above
            raise RuntimeError("adapter result lost its schema during validation")
        canonical_result = canonical_json_bytes(adapter_result.model_dump(mode="json"))
        result_digest = hashlib.sha256(canonical_result).hexdigest()
        duration_ms = _elapsed_ms(started)
        event = self._execution_event(
            request_context=request_context,
            principal=principal,
            proposal=proposal,
            registration=registration,
            decision=decision,
            risk=risk,
            destination=destination,
            resource_ids=resource_ids,
            outcome=InvocationOutcome.executed,
            duration_ms=duration_ms,
            result_digest=result_digest,
            result_bytes=len(canonical_result),
            error_type=None,
        )
        outcome_sequence = await self._record_event(event)
        if outcome_sequence is None:
            return self._result(
                proposal,
                decision,
                InvocationOutcome.audit_failed,
                None,
                risk,
                decision_sequence,
                None,
            )
        return self._result(
            proposal,
            decision,
            InvocationOutcome.executed,
            adapter_result,
            risk,
            decision_sequence,
            outcome_sequence.sequence_number,
        )

    def _result_error(self, registration: ToolRegistration, adapter_result: object) -> str | None:
        if not isinstance(adapter_result, registration.result_schema):
            return "ResultSchemaMismatch"
        try:
            canonical_result = canonical_json_bytes(adapter_result.model_dump(mode="json"))
        except CanonicalJSONError:
            return "ResultNotCanonicalizable"
        if len(canonical_result) > registration.max_result_bytes:
            return "ResultTooLarge"
        return None

    async def _failed_execution(
        self,
        *,
        request_context: RequestContext,
        principal: Principal,
        proposal: ProposedToolCall,
        registration: ToolRegistration,
        decision: DecisionRecord,
        risk: RiskAssessment,
        destination: str | None,
        resource_ids: tuple[str, ...],
        decision_sequence: int,
        outcome: InvocationOutcome,
        error_type: str,
        duration_ms: int,
    ) -> ToolInvocationResult:
        event = self._execution_event(
            request_context=request_context,
            principal=principal,
            proposal=proposal,
            registration=registration,
            decision=decision,
            risk=risk,
            destination=destination,
            resource_ids=resource_ids,
            outcome=outcome,
            duration_ms=duration_ms,
            result_digest=None,
            result_bytes=None,
            error_type=error_type,
        )
        outcome_sequence = await self._record_event(event)
        if outcome_sequence is None:
            return self._result(
                proposal,
                decision,
                InvocationOutcome.audit_failed,
                None,
                risk,
                decision_sequence,
                None,
            )
        return self._result(
            proposal,
            decision,
            outcome,
            None,
            risk,
            decision_sequence,
            outcome_sequence.sequence_number,
        )

    def _semaphore(self, tool_id: str, limit: int) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        per_loop = self._limiters.get(loop)
        if per_loop is None:
            per_loop = {}
            self._limiters[loop] = per_loop
        semaphore = per_loop.get(tool_id)
        if semaphore is None:
            semaphore = asyncio.Semaphore(limit)
            per_loop[tool_id] = semaphore
        return semaphore

    # -- audit ------------------------------------------------------------------------

    async def _record_decision_event(
        self,
        *,
        request_context: RequestContext,
        principal: Principal,
        proposal: ProposedToolCall,
        decision: DecisionRecord,
        registration: ToolRegistration | None = None,
        risk: RiskAssessment | None = None,
        destination: str | None = None,
        resource_ids: tuple[str, ...] = (),
    ) -> int | None:
        event = self._event(
            event_type=AuditEventType.policy_evaluated,
            request_context=request_context,
            principal=principal,
            proposal=proposal,
            decision=decision,
            registration=registration,
            risk=risk,
            destination=destination,
            resource_ids=resource_ids,
            outcome=None,
            duration_ms=None,
            result_digest=None,
            result_bytes=None,
            error_type=None,
        )
        appended = await self._record_event(event)
        return None if appended is None else appended.sequence_number

    def _execution_event(
        self,
        *,
        request_context: RequestContext,
        principal: Principal,
        proposal: ProposedToolCall,
        registration: ToolRegistration,
        decision: DecisionRecord,
        risk: RiskAssessment,
        destination: str | None,
        resource_ids: tuple[str, ...],
        outcome: InvocationOutcome,
        duration_ms: int,
        result_digest: str | None,
        result_bytes: int | None,
        error_type: str | None,
    ) -> AuditEvent:
        event_type = (
            AuditEventType.tool_execution_completed
            if outcome is InvocationOutcome.executed
            else AuditEventType.tool_execution_failed
        )
        return self._event(
            event_type=event_type,
            request_context=request_context,
            principal=principal,
            proposal=proposal,
            decision=decision,
            registration=registration,
            risk=risk,
            destination=destination,
            resource_ids=resource_ids,
            outcome=outcome,
            duration_ms=duration_ms,
            result_digest=result_digest,
            result_bytes=result_bytes,
            error_type=error_type,
        )

    def _event(
        self,
        *,
        event_type: AuditEventType,
        request_context: RequestContext,
        principal: Principal,
        proposal: ProposedToolCall,
        decision: DecisionRecord,
        registration: ToolRegistration | None,
        risk: RiskAssessment | None,
        destination: str | None,
        resource_ids: tuple[str, ...],
        outcome: InvocationOutcome | None,
        duration_ms: int | None,
        result_digest: str | None,
        result_bytes: int | None,
        error_type: str | None,
    ) -> AuditEvent:
        return AuditEvent(
            event_id=uuid.uuid4().hex,
            event_type=event_type,
            occurred_at=self._now(),
            component_version=self._component_version,
            request_id=request_context.request_id,
            trace_id=request_context.trace_id,
            session_id=request_context.session_id,
            principal_subject_id=principal.subject_id,
            tool_id=proposal.tool_id,
            action_id=proposal.action_id,
            decision=decision.decision,
            reason=decision.reason,
            policy_version=decision.policy_version,
            policy_hash=decision.policy_hash,
            outcome=outcome,
            side_effect_class=None if registration is None else registration.side_effect_class,
            data_class=None if registration is None else registration.data_class,
            risk_score=None if risk is None else risk.score,
            risk_version=None if risk is None else risk.version,
            risk_factor_codes=None if risk is None else risk.factor_codes,
            destination=destination,
            resource_ids=resource_ids,
            duration_ms=duration_ms,
            result_digest=result_digest,
            result_bytes=result_bytes,
            error_type=error_type,
        )

    async def _record_event(self, event: AuditEvent) -> AppendedAuditEvent | None:
        """Persist one event; returns None when audit is unavailable (caller decides)."""
        try:
            return await self._recorder.record(event)
        except AuditWriteError:
            logger.error(
                "audit persistence failed for %s (tool %s)",
                event.event_type.value,
                event.tool_id,
            )
            return None

    # -- result helpers ---------------------------------------------------------------

    def _decision(self, decision: FirewallDecision, reason: DecisionReason) -> DecisionRecord:
        return DecisionRecord(
            decision=decision,
            reason=reason,
            policy_version=self._bundle.version,
            policy_hash=self._bundle.combined_hash,
        )

    def _result(
        self,
        proposal: ProposedToolCall,
        decision: DecisionRecord,
        outcome: InvocationOutcome,
        result: ToolResult | None,
        risk: RiskAssessment | None,
        decision_sequence: int | None,
        outcome_sequence: int | None,
    ) -> ToolInvocationResult:
        # ``result`` is always a ``ToolResult`` or None by construction; the cast keeps
        # the frozen dataclass free of pydantic revalidation.
        return ToolInvocationResult(
            call_id=proposal.call_id,
            tool_id=proposal.tool_id,
            action_id=proposal.action_id,
            decision=decision.decision,
            reason=decision.reason,
            outcome=outcome,
            result=result,
            risk=risk,
            policy_version=decision.policy_version,
            policy_hash=decision.policy_hash,
            decision_audit_sequence=decision_sequence,
            outcome_audit_sequence=outcome_sequence,
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.utcoffset() is None:
            raise RuntimeError("gateway clock must return a timezone-aware datetime")
        return value


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.perf_counter() - started) * 1_000))


def _is_stable_id(value: str) -> bool:
    return re.fullmatch(STABLE_ID_PATTERN, value) is not None


__all__ = ["ToolGateway"]
