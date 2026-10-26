"""Security invariants for the enforced gateway (blueprint sections 1.3, 12, 18).

These tests attack the gateway boundary: no denial, validation failure, deadline
expiry, audit outage, or caller-controlled field may reach an adapter or the sink.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from ai_security.audit.models import AuditEvent, AuditEventType
from ai_security.audit.writer import AuditWriteError
from ai_security.firewall.approval import ApprovalConsumption
from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.firewall.gateway import ToolGateway
from ai_security.firewall.models import InvocationOutcome, ProposedToolCall, RequestContext
from ai_security.firewall.policy_engine import PolicyEngine
from ai_security.identity.models import Principal
from ai_security.persistence.approval_repository import ApprovalConsumptionOutcome
from ai_security.persistence.audit_repository import AppendedAuditEvent
from ai_security.policy.loader import load_policy_bundle
from ai_security.policy.models import (
    PolicyBundle,
    RiskThresholdsDocument,
    Thresholds,
    ToolPolicy,
)
from ai_security.tools.base import ExecutionAuthorizationError, ToolArguments, ToolResult
from ai_security.tools.mock_email import EmailReadArguments, MockEmailAdapter
from ai_security.tools.mock_external_sink import (
    DESTINATION,
    MockExternalSinkAdapter,
    SinkStore,
)
from ai_security.tools.mock_files import MockFilesAdapter
from ai_security.tools.mock_text import MockTextAdapter
from ai_security.tools.registry import build_registry

POLICIES = "config/policies.yaml"
THRESHOLDS = "config/risk_thresholds.yaml"
FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
REQUEST_ID = "req-security"


class Recorder:
    def __init__(self, *, failing: bool = False) -> None:
        self.events: list[AuditEvent] = []
        self._failing = failing

    async def record(self, event: AuditEvent) -> AppendedAuditEvent:
        if self._failing:
            raise AuditWriteError("down")
        self.events.append(event)
        sequence = len(self.events)
        return AppendedAuditEvent(
            chain_id="security",
            sequence_number=sequence,
            previous_hash="0" * 64,
            event_hash=f"{sequence:064x}",
        )


class CountingEmailAdapter(MockEmailAdapter):
    """Spy: counts every call that would actually execute an email action."""

    def __init__(self) -> None:
        super().__init__()
        self.executions = 0
        self.events_seen_at_execution = -1

    async def execute(
        self,
        *,
        tool_id: str,
        action_id: str,
        arguments: ToolArguments,
        authorization: object,
    ) -> ToolResult:
        self.executions += 1
        return await super().execute(
            tool_id=tool_id,
            action_id=action_id,
            arguments=arguments,
            authorization=authorization,  # type: ignore[arg-type]
        )


def starter_bundle() -> PolicyBundle:
    return load_policy_bundle(POLICIES, THRESHOLDS)


def enabled_sink_bundle() -> PolicyBundle:
    return starter_bundle().with_tool_policy(
        "mock_external_sink.write",
        ToolPolicy(
            side_effect_class="EXTERNAL_MUTATION",
            external_egress_enabled=True,
            allowed_destinations=(DESTINATION,),
        ),
    )


def approval_bundle() -> PolicyBundle:
    """ASK_USER for an enabled external write: egress allowed, mid risk band."""
    bundle = enabled_sink_bundle().with_tool_policy(
        "mock_external_sink.write",
        ToolPolicy(
            side_effect_class="EXTERNAL_MUTATION",
            external_egress_enabled=True,
            allowed_destinations=(DESTINATION,),
            approval_eligible=True,
        ),
    )
    return replace(
        bundle,
        risk_thresholds=RiskThresholdsDocument(
            schema_version=1,
            version="security-thresholds",
            thresholds=Thresholds(ask_user_at_or_above=20, block_at_or_above=80),
        ),
    )


class FakeApprovalService:
    """Deterministic approval-consumption stub (no database; gateway contract only)."""

    def __init__(
        self,
        outcome: ApprovalConsumptionOutcome = ApprovalConsumptionOutcome.consumed,
        *,
        raises: bool = False,
    ) -> None:
        self.outcome = outcome
        self.raises = raises
        self.calls = 0

    async def consume(self, approval_id: str, **_: object) -> ApprovalConsumption:
        self.calls += 1
        if self.raises:
            raise RuntimeError("approval storage down")
        return ApprovalConsumption(
            outcome=self.outcome,
            approval_id=approval_id,
            approver_subject_id="approver-1",
        )


def principal(subject_id: str = "dev-user") -> Principal:
    return Principal(
        subject_id=subject_id,
        auth_method="test",
        issuer="test",
        permissions_context_ref="test-ref",
    )


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
) -> ProposedToolCall:
    return ProposedToolCall(
        call_id="call-security",
        request_id=request_id,
        principal_subject_id=principal_subject_id,
        tool_id=tool_id,
        action_id=action_id,
        arguments=arguments or {},
        target_resource_ids=target_resources,
        destination=destination,
        deadline=deadline,
    )


def build(
    *,
    bundle: PolicyBundle,
    recorder: Recorder,
    approval_service: object | None = None,
) -> tuple[ToolGateway, CountingEmailAdapter, SinkStore]:
    email = CountingEmailAdapter()
    store = SinkStore()
    registry = build_registry(
        bundle,
        (
            email,
            MockFilesAdapter(),
            MockExternalSinkAdapter(store),
            MockTextAdapter(),
        ),
    )
    gateway = ToolGateway(
        registry=registry,
        engine=PolicyEngine(bundle),
        recorder=recorder,
        clock=lambda: FIXED_NOW,
        approval_service=approval_service,  # type: ignore[arg-type]
    )
    return gateway, email, store


def invoke(
    gateway: ToolGateway,
    call: ProposedToolCall,
    *,
    approval_id: str | None = None,
) -> object:
    async def scenario() -> object:
        return await gateway.invoke_tool(
            principal=principal(),
            request_context=RequestContext(request_id=REQUEST_ID),
            proposal=call,
            approval_id=approval_id,
        )

    return asyncio.run(scenario())


@pytest.mark.parametrize(
    ("bundle", "call", "reason"),
    [
        (
            starter_bundle(),
            proposal("mock_email.delete", "delete", arguments={}),
            DecisionReason.unknown_tool,
        ),
        (
            starter_bundle(),
            proposal("mock_files.search", "search", arguments={"query": "x"}),
            DecisionReason.unknown_tool,
        ),
        (
            starter_bundle(),
            proposal("mock_email.read", "read", arguments={}),
            DecisionReason.invalid_arguments,
        ),
        (
            starter_bundle(),
            proposal(
                "mock_email.read",
                "read",
                arguments={"email_id": "email-1"},
                target_resources=("email-2",),
            ),
            DecisionReason.invalid_arguments,
        ),
        (
            starter_bundle(),
            proposal(
                "mock_email.read",
                "read",
                arguments={"email_id": "email-1"},
                principal_subject_id="other-user",
            ),
            DecisionReason.binding_mismatch,
        ),
        (
            starter_bundle(),
            proposal(
                "mock_email.read",
                "read",
                arguments={"email_id": "email-1"},
                request_id="req-other",
            ),
            DecisionReason.binding_mismatch,
        ),
        (
            starter_bundle(),
            proposal(
                "mock_email.read",
                "read",
                arguments={"email_id": "email-1"},
                deadline=FIXED_NOW - timedelta(seconds=1),
            ),
            DecisionReason.deadline_exceeded,
        ),
        (
            starter_bundle(),
            proposal(
                "mock_external_sink.write",
                "write",
                arguments={"destination": DESTINATION, "content": "exfil"},
                destination=DESTINATION,
            ),
            DecisionReason.external_egress_disabled,
        ),
    ],
)
def test_denied_paths_never_reach_the_adapter(
    bundle: PolicyBundle,
    call: ProposedToolCall,
    reason: DecisionReason,
) -> None:
    recorder = Recorder()
    gateway, email, store = build(bundle=bundle, recorder=recorder)
    result = invoke(gateway, call)
    assert result.outcome is InvocationOutcome.denied  # type: ignore[attr-defined]
    assert result.decision is FirewallDecision.block  # type: ignore[attr-defined]
    assert result.reason is reason  # type: ignore[attr-defined]
    assert email.executions == 0
    assert store.records() == ()


def test_denied_paths_never_reach_the_adapter_when_audit_is_down() -> None:
    recorder = Recorder(failing=True)
    gateway, email, store = build(bundle=enabled_sink_bundle(), recorder=recorder)
    result = invoke(
        gateway,
        proposal(
            "mock_external_sink.write",
            "write",
            arguments={"destination": DESTINATION, "content": "exfil"},
            destination=DESTINATION,
        ),
    )
    assert result.outcome is InvocationOutcome.denied  # type: ignore[attr-defined]
    assert result.reason is DecisionReason.audit_unavailable  # type: ignore[attr-defined]
    assert result.decision_audit_sequence is None  # type: ignore[attr-defined]
    assert email.executions == 0
    assert store.records() == ()


def test_no_execution_without_a_successfully_recorded_decision() -> None:
    recorder = Recorder()
    gateway, email, _ = build(bundle=starter_bundle(), recorder=recorder)

    original_execute = email.execute

    async def checked_execute(**kwargs: object) -> ToolResult:
        assert [event.event_type for event in recorder.events] == [AuditEventType.policy_evaluated]
        return await original_execute(**kwargs)  # type: ignore[arg-type]

    email.execute = checked_execute  # type: ignore[method-assign]

    result = invoke(
        gateway,
        proposal(
            "mock_email.read",
            "read",
            arguments={"email_id": "email-1"},
            target_resources=("email-1",),
        ),
    )
    assert result.outcome is InvocationOutcome.executed  # type: ignore[attr-defined]
    assert email.executions == 1
    assert [event.event_type for event in recorder.events] == [
        AuditEventType.policy_evaluated,
        AuditEventType.tool_execution_completed,
    ]


def test_executed_results_are_never_returned_when_the_outcome_cannot_be_audited() -> None:
    class SecondCallFails(Recorder):
        async def record(self, event: AuditEvent) -> AppendedAuditEvent:
            if self.events:
                raise AuditWriteError("down")
            return await super().record(event)

    recorder = SecondCallFails()
    gateway, email, _ = build(bundle=starter_bundle(), recorder=recorder)
    result = invoke(
        gateway,
        proposal(
            "mock_email.read",
            "read",
            arguments={"email_id": "email-1"},
            target_resources=("email-1",),
        ),
    )
    assert email.executions == 1
    assert result.outcome is InvocationOutcome.audit_failed  # type: ignore[attr-defined]
    assert result.result is None  # type: ignore[attr-defined]


def test_direct_adapter_execution_without_authorization_fails_closed() -> None:
    adapter = MockEmailAdapter()

    async def scenario() -> None:
        await adapter.execute(
            tool_id="mock_email.read",
            action_id="read",
            arguments=EmailReadArguments(email_id="email-1"),
            authorization=None,  # type: ignore[arg-type]
        )

    with pytest.raises(ExecutionAuthorizationError):
        asyncio.run(scenario())


def approval_call(content: str = "canary") -> ProposedToolCall:
    return proposal(
        "mock_external_sink.write",
        "write",
        arguments={"destination": DESTINATION, "content": content},
        destination=DESTINATION,
    )


def test_ask_user_without_approval_never_executes() -> None:
    recorder = Recorder()
    gateway, _, store = build(bundle=approval_bundle(), recorder=recorder)
    result = invoke(gateway, approval_call())
    assert result.decision is FirewallDecision.ask_user
    assert result.outcome is InvocationOutcome.denied
    assert len(store) == 0
    assert [event.decision for event in recorder.events] == [FirewallDecision.ask_user]


def test_granted_approval_allows_one_ask_user_execution_with_metadata() -> None:
    recorder = Recorder()
    service = FakeApprovalService()
    gateway, _, store = build(bundle=approval_bundle(), recorder=recorder, approval_service=service)
    result = invoke(gateway, approval_call(), approval_id="a" * 32)
    assert result.decision is FirewallDecision.ask_user
    assert result.outcome is InvocationOutcome.executed
    assert result.approval_id == "a" * 32
    assert result.approver_subject_id == "approver-1"
    assert service.calls == 1
    assert len(store) == 1
    decision_event = recorder.events[-2]
    assert decision_event.approval_id == "a" * 32
    assert decision_event.approver_subject_id == "approver-1"


def test_approval_is_not_consulted_without_a_presented_approval() -> None:
    service = FakeApprovalService()
    gateway, _, store = build(
        bundle=approval_bundle(), recorder=Recorder(), approval_service=service
    )
    result = invoke(gateway, approval_call())
    assert result.outcome is InvocationOutcome.denied
    assert service.calls == 0
    assert len(store) == 0


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        (ApprovalConsumptionOutcome.mismatch, DecisionReason.approval_invalid),
        (ApprovalConsumptionOutcome.replay, DecisionReason.approval_invalid),
        (ApprovalConsumptionOutcome.not_approved, DecisionReason.approval_invalid),
        (ApprovalConsumptionOutcome.not_found, DecisionReason.approval_invalid),
        (ApprovalConsumptionOutcome.denied, DecisionReason.approval_denied),
        (ApprovalConsumptionOutcome.expired, DecisionReason.approval_expired),
    ],
)
def test_non_granted_approvals_fail_closed_without_execution(
    outcome: ApprovalConsumptionOutcome, reason: DecisionReason
) -> None:
    recorder = Recorder()
    service = FakeApprovalService(outcome)
    gateway, _, store = build(bundle=approval_bundle(), recorder=recorder, approval_service=service)
    result = invoke(gateway, approval_call(), approval_id="b" * 32)
    assert result.decision is FirewallDecision.block
    assert result.reason is reason
    assert result.outcome is InvocationOutcome.denied
    assert len(store) == 0
    assert recorder.events[-1].approval_id is None


def test_approval_storage_failure_fails_closed_without_execution() -> None:
    recorder = Recorder()
    service = FakeApprovalService(raises=True)
    gateway, _, store = build(bundle=approval_bundle(), recorder=recorder, approval_service=service)
    result = invoke(gateway, approval_call(), approval_id="c" * 32)
    assert result.reason is DecisionReason.approval_invalid
    assert len(store) == 0
    assert recorder.events[-1].decision is FirewallDecision.block


def test_engine_block_never_consults_or_consumes_an_approval() -> None:
    recorder = Recorder()
    service = FakeApprovalService()
    gateway, _, store = build(bundle=starter_bundle(), recorder=recorder, approval_service=service)
    result = invoke(gateway, approval_call(), approval_id="d" * 32)
    assert result.decision is FirewallDecision.block
    assert result.reason is DecisionReason.external_egress_disabled
    assert result.outcome is InvocationOutcome.denied
    assert service.calls == 0
    assert len(store) == 0


def test_approval_service_absent_blocks_an_ask_user_attempt() -> None:
    gateway, _, store = build(bundle=approval_bundle(), recorder=Recorder())
    result = invoke(gateway, approval_call(), approval_id="e" * 32)
    assert result.reason is DecisionReason.approval_invalid
    assert len(store) == 0
