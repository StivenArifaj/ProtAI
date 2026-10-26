"""Enforced-gateway tests (blueprint sections 12.1-12.4, 16.4).

The gateway is the only execution path: denied calls never touch an adapter, an ALLOW
decision is audited before the side effect, and every failure mode is a typed outcome
rather than a result.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from ai_security.audit.models import AuditEvent, AuditEventType
from ai_security.audit.writer import AuditWriteError
from ai_security.data_security.classification import DataClass
from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.firewall.gateway import ToolGateway
from ai_security.firewall.models import (
    InvocationOutcome,
    ProposedToolCall,
    RequestContext,
)
from ai_security.firewall.policy_engine import PolicyEngine
from ai_security.identity.models import Principal
from ai_security.persistence.audit_repository import AppendedAuditEvent
from ai_security.policy.loader import load_policy_bundle
from ai_security.policy.models import PolicyBundle, ToolPolicy
from ai_security.security.canonical_json import canonical_json_bytes
from ai_security.tools.base import (
    ExecutionAuthorization,
    SideEffectClass,
    ToolArguments,
    ToolExecutionError,
    ToolResult,
    verify_execution_authorization,
)
from ai_security.tools.mock_email import MockEmailAdapter
from ai_security.tools.mock_external_sink import (
    DESTINATION,
    MockExternalSinkAdapter,
    SinkStore,
)
from ai_security.tools.mock_files import MockFilesAdapter
from ai_security.tools.mock_text import MockTextAdapter
from ai_security.tools.registry import ToolRegistration, build_registry

POLICIES = "config/policies.yaml"
THRESHOLDS = "config/risk_thresholds.yaml"
FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
REQUEST_ID = "req-1"


class RecordingAuditRecorder:
    """Deterministic in-memory recorder with selectable failure points."""

    def __init__(self, *, fail_on_call: int | None = None) -> None:
        self.events: list[AuditEvent] = []
        self.calls = 0
        self._fail_on_call = fail_on_call

    async def record(self, event: AuditEvent) -> AppendedAuditEvent:
        self.calls += 1
        if self._fail_on_call is not None and self.calls >= self._fail_on_call:
            raise AuditWriteError("audit unavailable (test)")
        self.events.append(event)
        return AppendedAuditEvent(
            chain_id="test-chain",
            sequence_number=self.calls,
            previous_hash="0" * 64,
            event_hash=f"{self.calls:064x}",
        )


def starter_bundle() -> PolicyBundle:
    return load_policy_bundle(POLICIES, THRESHOLDS)


def sink_enabled_bundle() -> PolicyBundle:
    return starter_bundle().with_tool_policy(
        "mock_external_sink.write",
        ToolPolicy(
            side_effect_class="EXTERNAL_MUTATION",
            external_egress_enabled=True,
            allowed_destinations=(DESTINATION,),
        ),
    )


def principal(subject_id: str = "dev-user") -> Principal:
    return Principal(
        subject_id=subject_id,
        auth_method="test",
        issuer="test",
        permissions_context_ref="test-ref",
    )


def context(request_id: str = REQUEST_ID) -> RequestContext:
    return RequestContext(request_id=request_id)


def proposal(
    tool_id: str,
    action_id: str,
    *,
    arguments: dict[str, object] | None = None,
    target_resources: tuple[str, ...] = (),
    destination: str | None = None,
    deadline: datetime | None = None,
    request_id: str = REQUEST_ID,
    principal_subject_id: str = "dev-user",
    call_id: str = "call-1",
) -> ProposedToolCall:
    return ProposedToolCall(
        call_id=call_id,
        request_id=request_id,
        principal_subject_id=principal_subject_id,
        tool_id=tool_id,
        action_id=action_id,
        arguments=arguments or {},
        target_resource_ids=target_resources,
        destination=destination,
        deadline=deadline,
    )


def mock_adapters(store: SinkStore) -> tuple[object, ...]:
    return (
        MockEmailAdapter(),
        MockFilesAdapter(),
        MockExternalSinkAdapter(store),
        MockTextAdapter(),
    )


def make_gateway(
    *,
    bundle: PolicyBundle,
    recorder: RecordingAuditRecorder,
    extra_adapters: tuple[object, ...] = (),
    clock: Callable[[], datetime] = lambda: FIXED_NOW,
) -> tuple[ToolGateway, SinkStore]:
    store = SinkStore()
    registry = build_registry(bundle, (*mock_adapters(store), *extra_adapters))
    gateway = ToolGateway(
        registry=registry,
        engine=PolicyEngine(bundle),
        recorder=recorder,
        clock=clock,
    )
    return gateway, store


# -- custom adapters for failure-mode tests -------------------------------------------


class NoArguments(ToolArguments):
    pass


class ValueResult(ToolResult):
    value: str


class OtherResult(ToolResult):
    other: str


class HookAdapter:
    """Custom read-only adapter whose behavior is supplied by the test."""

    adapter_version = "custom-v1"

    def __init__(
        self,
        registration: ToolRegistration,
        hook: Callable[[], Awaitable[ToolResult]],
    ) -> None:
        self._registration = registration
        self._hook = hook

    def registrations(self) -> tuple[ToolRegistration, ...]:
        return (self._registration,)

    def check_resource_access(self, **kwargs: object) -> bool:
        return True

    async def execute(
        self,
        *,
        tool_id: str,
        action_id: str,
        arguments: ToolArguments,
        authorization: ExecutionAuthorization,
    ) -> ToolResult:
        if not isinstance(arguments, NoArguments):
            raise ToolExecutionError("unexpected arguments")
        verify_execution_authorization(
            authorization,
            tool_id=tool_id,
            action_id=action_id,
            arguments=arguments,
            resource_ids=(),
            destination=None,
        )
        return await self._hook()


def custom_registration(
    *,
    result_schema: type[ToolResult] = ValueResult,
    max_result_bytes: int = 1_024,
    timeout_ms: int = 1_000,
    max_concurrent_invocations: int = 4,
) -> ToolRegistration:
    return ToolRegistration(
        tool_id="mock_custom.run",
        action_id="run",
        side_effect_class=SideEffectClass.read_only,
        data_class=DataClass.public,
        argument_schema=NoArguments,
        result_schema=result_schema,
        resource_id_arguments=(),
        resource_prefixes=(),
        destination_argument=None,
        destinations=(),
        timeout_ms=timeout_ms,
        max_concurrent_invocations=max_concurrent_invocations,
        max_result_bytes=max_result_bytes,
        approval_required=False,
        required_approver_rule=None,
        adapter_version="custom-v1",
    )


class TwoResourceArguments(ToolArguments):
    first_id: str
    second_id: str


class TwoResourceAdapter:
    """Read-only adapter with two resource-id arguments (dedup regression)."""

    adapter_version = "custom-v1"

    def __init__(self, registration: ToolRegistration) -> None:
        self._registration = registration
        self.seen_resource_ids: tuple[str, ...] | None = None

    def registrations(self) -> tuple[ToolRegistration, ...]:
        return (self._registration,)

    def check_resource_access(self, **kwargs: object) -> bool:
        resource_ids = kwargs.get("resource_ids")
        assert isinstance(resource_ids, tuple)
        self.seen_resource_ids = resource_ids
        return True

    async def execute(
        self,
        *,
        tool_id: str,
        action_id: str,
        arguments: ToolArguments,
        authorization: ExecutionAuthorization,
    ) -> ToolResult:
        if not isinstance(arguments, TwoResourceArguments):
            raise ToolExecutionError("unexpected arguments")
        verify_execution_authorization(
            authorization,
            tool_id=tool_id,
            action_id=action_id,
            arguments=arguments,
            resource_ids=("res-1",),
            destination=None,
        )
        return ValueResult(value="ok")


def custom_bundle() -> PolicyBundle:
    return starter_bundle().with_tool_policy(
        "mock_custom.run", ToolPolicy(side_effect_class="READ_ONLY")
    )


def custom_proposal(call_id: str = "call-1") -> ProposedToolCall:
    return proposal("mock_custom.run", "run", call_id=call_id)


# -- allowed execution ----------------------------------------------------------------


def test_allowed_read_executes_and_audits_decision_then_outcome() -> None:
    recorder = RecordingAuditRecorder()
    gateway, _ = make_gateway(bundle=starter_bundle(), recorder=recorder)
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal(
                "mock_email.read",
                "read",
                arguments={"email_id": "email-1"},
                target_resources=("email-1",),
            ),
        )
    )
    assert result.decision is FirewallDecision.allow
    assert result.reason is DecisionReason.authorized_read
    assert result.outcome is InvocationOutcome.executed
    assert result.result is not None
    assert result.result.email_id == "email-1"  # type: ignore[attr-defined]
    assert result.risk is not None and result.risk.score == 5
    assert result.decision_audit_sequence == 1
    assert result.outcome_audit_sequence == 2

    assert [event.event_type for event in recorder.events] == [
        AuditEventType.policy_evaluated,
        AuditEventType.tool_execution_completed,
    ]
    decision_event, outcome_event = recorder.events
    assert decision_event.decision is FirewallDecision.allow
    assert decision_event.risk_factor_codes == (
        "side_effect_read_only",
        "data_class_internal",
    )
    assert outcome_event.outcome is InvocationOutcome.executed
    assert outcome_event.result_digest is not None
    assert outcome_event.result_bytes is not None and outcome_event.result_bytes > 0
    # Audit payloads never include raw content (section 16.3).
    payload = canonical_json_bytes(outcome_event.to_payload()).decode("utf-8")
    assert "budget" not in payload
    assert "Please review" not in payload


def test_enabled_egress_executes_the_sink_and_records_the_digest() -> None:
    recorder = RecordingAuditRecorder()
    gateway, store = make_gateway(bundle=sink_enabled_bundle(), recorder=recorder)
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal(
                "mock_external_sink.write",
                "write",
                arguments={"destination": DESTINATION, "content": "canary"},
                destination=DESTINATION,
            ),
        )
    )
    assert result.decision is FirewallDecision.allow
    assert result.reason is DecisionReason.allowlisted_external_call
    assert result.outcome is InvocationOutcome.executed
    assert result.risk is not None and result.risk.score == 25
    assert len(store.records()) == 1
    assert store.records()[0].content_digest != "canary"


# -- denials with no side effect ------------------------------------------------------


def test_unknown_tool_is_denied_and_never_resolves_an_adapter() -> None:
    recorder = RecordingAuditRecorder()
    gateway, store = make_gateway(bundle=starter_bundle(), recorder=recorder)
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal("mock_email.delete", "delete", arguments={}),
        )
    )
    assert result.decision is FirewallDecision.block
    assert result.reason is DecisionReason.unknown_tool
    assert result.outcome is InvocationOutcome.denied
    assert result.result is None
    assert len(store.records()) == 0
    assert len(recorder.events) == 1
    assert recorder.events[0].side_effect_class is None


def test_registered_but_policy_disabled_tool_is_denied() -> None:
    recorder = RecordingAuditRecorder()
    gateway, _ = make_gateway(bundle=starter_bundle(), recorder=recorder)
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal("mock_files.search", "search", arguments={"query": "notes"}),
        )
    )
    assert result.reason is DecisionReason.unknown_tool
    assert result.outcome is InvocationOutcome.denied


def test_binding_mismatch_on_principal_is_denied_before_evaluation() -> None:
    recorder = RecordingAuditRecorder()
    gateway, _ = make_gateway(bundle=starter_bundle(), recorder=recorder)
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal(
                "mock_email.read",
                "read",
                arguments={"email_id": "email-1"},
                principal_subject_id="other-user",
            ),
        )
    )
    assert result.reason is DecisionReason.binding_mismatch
    assert result.outcome is InvocationOutcome.denied
    assert recorder.events[0].reason is DecisionReason.binding_mismatch


def test_binding_mismatch_on_request_is_denied() -> None:
    recorder = RecordingAuditRecorder()
    gateway, _ = make_gateway(bundle=starter_bundle(), recorder=recorder)
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal(
                "mock_email.read",
                "read",
                arguments={"email_id": "email-1"},
                request_id="req-2",
            ),
        )
    )
    assert result.reason is DecisionReason.binding_mismatch


def test_invalid_arguments_are_denied() -> None:
    recorder = RecordingAuditRecorder()
    gateway, _ = make_gateway(bundle=starter_bundle(), recorder=recorder)
    for arguments in ({}, {"email_id": "email-1", "extra": True}, {"email_id": 17}):
        result = asyncio.run(
            gateway.invoke_tool(
                principal=principal(),
                request_context=context(),
                proposal=proposal("mock_email.read", "read", arguments=arguments),
            )
        )
        assert result.reason is DecisionReason.invalid_arguments
        assert result.outcome is InvocationOutcome.denied


def test_declared_targets_must_match_the_validated_arguments() -> None:
    recorder = RecordingAuditRecorder()
    gateway, _ = make_gateway(bundle=starter_bundle(), recorder=recorder)
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal(
                "mock_email.read",
                "read",
                arguments={"email_id": "email-1"},
                target_resources=("email-2",),
            ),
        )
    )
    assert result.reason is DecisionReason.invalid_arguments


def test_duplicate_derived_resource_ids_are_collapsed_before_risk_and_audit() -> None:
    recorder = RecordingAuditRecorder()
    registration = replace(
        custom_registration(),
        argument_schema=TwoResourceArguments,
        resource_id_arguments=("first_id", "second_id"),
        resource_prefixes=("res",),
    )
    adapter = TwoResourceAdapter(registration)
    gateway, _ = make_gateway(bundle=custom_bundle(), recorder=recorder, extra_adapters=(adapter,))
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal(
                "mock_custom.run",
                "run",
                arguments={"first_id": "res-1", "second_id": "res-1"},
                target_resources=("res-1",),
            ),
        )
    )
    assert result.outcome is InvocationOutcome.executed
    assert result.risk is not None
    assert "breadth_2_to_4_resources" not in result.risk.factor_codes
    assert adapter.seen_resource_ids == ("res-1",)
    assert recorder.events[0].resource_ids == ("res-1",)


def test_cross_user_read_is_denied_by_the_resource_check() -> None:
    recorder = RecordingAuditRecorder()
    gateway, _ = make_gateway(bundle=starter_bundle(), recorder=recorder)
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal("other-user"),
            request_context=context(),
            proposal=proposal(
                "mock_email.read",
                "read",
                arguments={"email_id": "email-1"},
                target_resources=("email-1",),
                principal_subject_id="other-user",
            ),
        )
    )
    assert result.reason is DecisionReason.resource_not_authorized
    assert result.outcome is InvocationOutcome.denied


def test_expired_deadline_is_denied() -> None:
    recorder = RecordingAuditRecorder()
    gateway, _ = make_gateway(bundle=starter_bundle(), recorder=recorder)
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal(
                "mock_email.read",
                "read",
                arguments={"email_id": "email-1"},
                deadline=FIXED_NOW - timedelta(seconds=1),
            ),
        )
    )
    assert result.reason is DecisionReason.deadline_exceeded


def test_disabled_egress_blocks_the_sink_and_leaves_it_unchanged() -> None:
    recorder = RecordingAuditRecorder()
    gateway, store = make_gateway(bundle=starter_bundle(), recorder=recorder)
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal(
                "mock_external_sink.write",
                "write",
                arguments={"destination": DESTINATION, "content": "canary"},
                destination=DESTINATION,
            ),
        )
    )
    assert result.decision is FirewallDecision.block
    assert result.reason is DecisionReason.external_egress_disabled
    assert result.outcome is InvocationOutcome.denied
    assert store.records() == ()
    assert len(recorder.events) == 1
    assert recorder.events[0].outcome is None


# -- operational failures -------------------------------------------------------------


def test_audit_failure_before_execution_blocks_an_allowed_action() -> None:
    recorder = RecordingAuditRecorder(fail_on_call=1)
    gateway, store = make_gateway(bundle=sink_enabled_bundle(), recorder=recorder)
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal(
                "mock_external_sink.write",
                "write",
                arguments={"destination": DESTINATION, "content": "canary"},
                destination=DESTINATION,
            ),
        )
    )
    assert result.decision is FirewallDecision.block
    assert result.reason is DecisionReason.audit_unavailable
    assert result.outcome is InvocationOutcome.denied
    assert result.decision_audit_sequence is None
    assert store.records() == ()
    assert recorder.events == []


def test_outcome_audit_failure_withholds_the_result() -> None:
    recorder = RecordingAuditRecorder(fail_on_call=2)
    gateway, store = make_gateway(bundle=sink_enabled_bundle(), recorder=recorder)
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal(
                "mock_external_sink.write",
                "write",
                arguments={"destination": DESTINATION, "content": "canary"},
                destination=DESTINATION,
            ),
        )
    )
    assert result.decision is FirewallDecision.allow
    assert result.outcome is InvocationOutcome.audit_failed
    assert result.result is None
    assert result.decision_audit_sequence == 1
    assert result.outcome_audit_sequence is None
    assert len(store.records()) == 1
    assert len(recorder.events) == 1


def test_audit_failure_on_a_denial_keeps_the_denial_reason() -> None:
    recorder = RecordingAuditRecorder(fail_on_call=1)
    gateway, _ = make_gateway(bundle=starter_bundle(), recorder=recorder)
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal(
                "mock_external_sink.write",
                "write",
                arguments={"destination": DESTINATION, "content": "canary"},
                destination=DESTINATION,
            ),
        )
    )
    assert result.reason is DecisionReason.external_egress_disabled
    assert result.outcome is InvocationOutcome.denied


def test_adapter_failure_is_a_typed_outcome_with_an_audit_event() -> None:
    async def hook() -> ToolResult:
        raise RuntimeError("boom")

    registration = custom_registration()
    recorder = RecordingAuditRecorder()
    gateway, _ = make_gateway(
        bundle=custom_bundle(),
        recorder=recorder,
        extra_adapters=(HookAdapter(registration, hook),),
    )
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=custom_proposal(),
        )
    )
    assert result.decision is FirewallDecision.allow
    assert result.outcome is InvocationOutcome.adapter_failed
    assert result.result is None
    assert [event.event_type for event in recorder.events] == [
        AuditEventType.policy_evaluated,
        AuditEventType.tool_execution_failed,
    ]
    assert recorder.events[1].error_type == "RuntimeError"
    assert recorder.events[1].outcome is InvocationOutcome.adapter_failed


def test_execution_timeout_is_reported_and_audited() -> None:
    async def hook() -> ToolResult:
        await asyncio.sleep(0.05)
        return ValueResult(value="late")

    registration = custom_registration(timeout_ms=1)
    recorder = RecordingAuditRecorder()
    gateway, _ = make_gateway(
        bundle=custom_bundle(),
        recorder=recorder,
        extra_adapters=(HookAdapter(registration, hook),),
    )
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=custom_proposal(),
        )
    )
    assert result.outcome is InvocationOutcome.timeout
    assert result.result is None
    assert recorder.events[1].error_type == "TimeoutError"
    assert recorder.events[1].outcome is InvocationOutcome.timeout


def test_oversized_results_are_rejected() -> None:
    async def hook() -> ToolResult:
        return ValueResult(value="x" * 100)

    registration = custom_registration(max_result_bytes=16)
    recorder = RecordingAuditRecorder()
    gateway, _ = make_gateway(
        bundle=custom_bundle(),
        recorder=recorder,
        extra_adapters=(HookAdapter(registration, hook),),
    )
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=custom_proposal(),
        )
    )
    assert result.outcome is InvocationOutcome.result_rejected
    assert result.result is None
    assert recorder.events[1].error_type == "ResultTooLarge"


def test_wrong_result_schema_is_rejected() -> None:
    async def hook() -> ToolResult:
        return ValueResult(value="ok")

    registration = custom_registration(result_schema=OtherResult)
    recorder = RecordingAuditRecorder()
    gateway, _ = make_gateway(
        bundle=custom_bundle(),
        recorder=recorder,
        extra_adapters=(HookAdapter(registration, hook),),
    )
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=custom_proposal(),
        )
    )
    assert result.outcome is InvocationOutcome.result_rejected
    assert recorder.events[1].error_type == "ResultSchemaMismatch"


@dataclass
class ConcurrencyTracker:
    active: int = 0
    max_active: int = 0


def test_per_tool_concurrency_limit_is_enforced() -> None:
    async def hook() -> ToolResult:
        tracker.active += 1
        tracker.max_active = max(tracker.max_active, tracker.active)
        try:
            await asyncio.sleep(0.01)
            return ValueResult(value="ok")
        finally:
            tracker.active -= 1

    tracker = ConcurrencyTracker()
    registration = custom_registration(max_concurrent_invocations=1)
    recorder = RecordingAuditRecorder()
    gateway, _ = make_gateway(
        bundle=custom_bundle(),
        recorder=recorder,
        extra_adapters=(HookAdapter(registration, hook),),
    )

    async def scenario() -> None:
        await asyncio.gather(
            gateway.invoke_tool(
                principal=principal(),
                request_context=context(),
                proposal=custom_proposal(call_id="call-1"),
            ),
            gateway.invoke_tool(
                principal=principal(),
                request_context=context(),
                proposal=custom_proposal(call_id="call-2"),
            ),
        )

    asyncio.run(scenario())
    assert tracker.max_active == 1


def test_policy_engine_exceptions_fail_closed_and_are_audited() -> None:
    class ExplodingEngine:
        def __init__(self, bundle: PolicyBundle) -> None:
            self.bundle = bundle

        def evaluate(self, request: object) -> object:
            raise RuntimeError("engine failed")

    recorder = RecordingAuditRecorder()
    store = SinkStore()
    bundle = starter_bundle()
    registry = build_registry(bundle, mock_adapters(store))
    gateway = ToolGateway(
        registry=registry,
        engine=ExplodingEngine(bundle),  # type: ignore[arg-type]
        recorder=recorder,
        clock=lambda: FIXED_NOW,
    )
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal("mock_email.read", "read", arguments={"email_id": "email-1"}),
        )
    )
    assert result.decision is FirewallDecision.block
    assert result.reason is DecisionReason.policy_evaluation_error
    assert result.outcome is InvocationOutcome.denied
    assert recorder.events[0].reason is DecisionReason.policy_evaluation_error
