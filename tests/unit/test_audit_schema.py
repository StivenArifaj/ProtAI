"""Audit event taxonomy and schema validation (blueprint section 16.1; ADR-014).

Every event name in section 16.1 has a stable enum member, and fields that only make
sense for some events are enforced per event type instead of being invented. These
tests are the executable form of the schema contract the verifier and producers rely
on.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from ai_security.audit.models import AuditEvent, AuditEventType, DlpAuditRecord
from ai_security.data_security.classification import DataClass
from ai_security.data_security.dlp import DlpOutcome, DlpPhase
from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.firewall.models import InvocationOutcome

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
POLICY_HASH = "a" * 64
CONFIG_HASH = "b" * 64
CONTENT_DIGEST = "c" * 64


def dlp(phase: DlpPhase) -> DlpAuditRecord:
    return DlpAuditRecord(
        phase=phase,
        outcome=DlpOutcome.pass_,
        max_data_class=DataClass.internal,
        version="1.0.1",
        config_hash=CONFIG_HASH,
        content_digest=CONTENT_DIGEST,
        content_bytes=12,
    )


def base_values(event_type: AuditEventType) -> dict[str, Any]:
    return {
        "event_id": "0" * 32,
        "event_type": event_type,
        "occurred_at": NOW,
        "component_version": "0.1.0",
        "request_id": "req-1",
        "principal_subject_id": "dev-user",
        "policy_version": "dev-1",
        "policy_hash": POLICY_HASH,
    }


def build(event_type: AuditEventType, **overrides: Any) -> AuditEvent:
    values = base_values(event_type)
    values.update(overrides)
    return AuditEvent(**values)


def test_every_blueprint_event_name_is_defined() -> None:
    expected = {
        "REQUEST_RECEIVED",
        "PRINCIPAL_RESOLVED",
        "PRINCIPAL_REJECTED",
        "INPUT_INSPECTED",
        "INTENT_CREATED",
        "INTENT_FAILED",
        "TOOL_CALL_PROPOSED",
        "POLICY_EVALUATED",
        "APPROVAL_REQUESTED",
        "APPROVAL_DECIDED",
        "APPROVAL_EXPIRED",
        "TOOL_EXECUTION_STARTED",
        "TOOL_EXECUTION_COMPLETED",
        "TOOL_EXECUTION_FAILED",
        "EGRESS_INSPECTED",
        "OUTPUT_INSPECTED",
        "RESPONSE_RELEASED",
        "RESPONSE_SUPPRESSED",
        "SECURITY_ALERT_RAISED",
        # Required by the approved-action consumption contract (sections 13.2-13.3).
        "APPROVAL_CONSUMED",
    }
    assert {event.value for event in AuditEventType} == expected


def test_principal_is_required_for_every_event_except_rejection() -> None:
    for event_type in AuditEventType:
        if event_type is AuditEventType.principal_rejected:
            event = build(event_type, principal_subject_id=None)
            assert event.principal_subject_id is None
            continue
        with pytest.raises(ValidationError, match="requires principal_subject_id"):
            build(event_type, principal_subject_id=None)


def test_tool_scoped_events_require_tool_and_action_ids() -> None:
    tool_scoped = [
        AuditEventType.tool_call_proposed,
        AuditEventType.policy_evaluated,
        AuditEventType.approval_requested,
        AuditEventType.approval_decided,
        AuditEventType.approval_consumed,
        AuditEventType.approval_expired,
        AuditEventType.tool_execution_started,
        AuditEventType.tool_execution_completed,
        AuditEventType.tool_execution_failed,
        AuditEventType.egress_inspected,
        AuditEventType.output_inspected,
        AuditEventType.response_released,
        AuditEventType.response_suppressed,
    ]
    for event_type in tool_scoped:
        with pytest.raises(ValidationError, match="requires tool_id and action_id"):
            build(event_type)


def test_non_tool_events_do_not_require_tool_ids() -> None:
    for event_type in (
        AuditEventType.request_received,
        AuditEventType.principal_resolved,
        AuditEventType.input_inspected,
        AuditEventType.intent_created,
        AuditEventType.intent_failed,
    ):
        event = build(event_type)
        assert event.tool_id is None
        assert event.action_id is None


@pytest.mark.parametrize(
    "event_type",
    [
        AuditEventType.policy_evaluated,
        AuditEventType.approval_requested,
        AuditEventType.approval_decided,
        AuditEventType.approval_consumed,
        AuditEventType.approval_expired,
        AuditEventType.tool_execution_started,
        AuditEventType.tool_execution_completed,
        AuditEventType.tool_execution_failed,
        AuditEventType.response_released,
        AuditEventType.response_suppressed,
    ],
)
def test_decision_events_require_a_decision_and_reason(event_type: AuditEventType) -> None:
    with pytest.raises(ValidationError, match="requires a decision and reason"):
        build(event_type, tool_id="mock_email.read", action_id="read")


def test_decision_and_reason_are_provided_together() -> None:
    with pytest.raises(ValidationError, match="decision and reason must be provided together"):
        build(
            AuditEventType.request_received,
            decision=FirewallDecision.allow,
        )
    with pytest.raises(ValidationError, match="decision and reason must be provided together"):
        build(
            AuditEventType.request_received,
            reason=DecisionReason.authorized_read,
        )


@pytest.mark.parametrize(
    "event_type",
    [
        AuditEventType.tool_execution_completed,
        AuditEventType.tool_execution_failed,
        AuditEventType.response_released,
        AuditEventType.response_suppressed,
    ],
)
def test_outcome_events_require_an_outcome(event_type: AuditEventType) -> None:
    with pytest.raises(ValidationError, match="requires an outcome"):
        build(
            event_type,
            tool_id="mock_email.read",
            action_id="read",
            decision=FirewallDecision.allow,
            reason=DecisionReason.authorized_read,
        )


def test_execution_started_must_not_carry_an_outcome() -> None:
    with pytest.raises(ValidationError, match="must not carry an outcome"):
        build(
            AuditEventType.tool_execution_started,
            tool_id="mock_email.read",
            action_id="read",
            decision=FirewallDecision.allow,
            reason=DecisionReason.authorized_read,
            outcome=InvocationOutcome.executed,
        )


def test_completed_execution_requires_the_executed_outcome() -> None:
    with pytest.raises(ValidationError, match="requires outcome EXECUTED"):
        build(
            AuditEventType.tool_execution_completed,
            tool_id="mock_email.read",
            action_id="read",
            decision=FirewallDecision.allow,
            reason=DecisionReason.authorized_read,
            outcome=InvocationOutcome.adapter_failed,
        )


def test_failed_execution_rejects_a_success_outcome() -> None:
    with pytest.raises(ValidationError, match="requires a failed execution outcome"):
        build(
            AuditEventType.tool_execution_failed,
            tool_id="mock_email.read",
            action_id="read",
            decision=FirewallDecision.allow,
            reason=DecisionReason.authorized_read,
            outcome=InvocationOutcome.executed,
        )


def test_egress_inspected_requires_egress_dlp_evidence() -> None:
    with pytest.raises(ValidationError, match="requires an EGRESS DLP record"):
        build(
            AuditEventType.egress_inspected,
            tool_id="mock_external_sink.write",
            action_id="write",
        )
    with pytest.raises(ValidationError, match="requires an EGRESS DLP record"):
        build(
            AuditEventType.egress_inspected,
            tool_id="mock_external_sink.write",
            action_id="write",
            dlp=dlp(DlpPhase.output),
        )


def test_output_inspected_requires_output_dlp_evidence() -> None:
    with pytest.raises(ValidationError, match="requires an OUTPUT DLP record"):
        build(
            AuditEventType.output_inspected,
            tool_id="mock_email.read",
            action_id="read",
        )
    with pytest.raises(ValidationError, match="requires an OUTPUT DLP record"):
        build(
            AuditEventType.output_inspected,
            tool_id="mock_email.read",
            action_id="read",
            dlp=dlp(DlpPhase.egress),
        )


def test_response_released_requires_output_evidence_and_the_result_digest() -> None:
    with pytest.raises(ValidationError, match="requires an OUTPUT DLP record"):
        build(
            AuditEventType.response_released,
            tool_id="mock_email.read",
            action_id="read",
            decision=FirewallDecision.allow,
            reason=DecisionReason.authorized_read,
            outcome=InvocationOutcome.executed,
            result_digest=CONTENT_DIGEST,
        )
    with pytest.raises(ValidationError, match="requires outcome EXECUTED"):
        build(
            AuditEventType.response_released,
            tool_id="mock_email.read",
            action_id="read",
            decision=FirewallDecision.allow,
            reason=DecisionReason.authorized_read,
            outcome=InvocationOutcome.response_blocked,
            dlp=dlp(DlpPhase.output),
            result_digest=CONTENT_DIGEST,
        )
    with pytest.raises(ValidationError, match="requires the result digest"):
        build(
            AuditEventType.response_released,
            tool_id="mock_email.read",
            action_id="read",
            decision=FirewallDecision.allow,
            reason=DecisionReason.authorized_read,
            outcome=InvocationOutcome.executed,
            dlp=dlp(DlpPhase.output),
        )


def test_response_suppressed_requires_the_response_blocked_outcome() -> None:
    with pytest.raises(ValidationError, match="requires outcome RESPONSE_BLOCKED"):
        build(
            AuditEventType.response_suppressed,
            tool_id="mock_email.read",
            action_id="read",
            decision=FirewallDecision.allow,
            reason=DecisionReason.authorized_read,
            outcome=InvocationOutcome.executed,
            dlp=dlp(DlpPhase.output),
            result_digest=CONTENT_DIGEST,
        )
    with pytest.raises(ValidationError, match="requires the result digest"):
        build(
            AuditEventType.response_suppressed,
            tool_id="mock_email.read",
            action_id="read",
            decision=FirewallDecision.allow,
            reason=DecisionReason.authorized_read,
            outcome=InvocationOutcome.response_blocked,
            dlp=dlp(DlpPhase.output),
        )


def test_valid_lifecycle_events_build_and_serialize_without_none_fields() -> None:
    received = build(
        AuditEventType.request_received,
        trace_id="trace-1",
        session_id="session-1",
        call_id="call-1",
    )
    payload = received.to_payload()
    assert payload["event_type"] == "REQUEST_RECEIVED"
    assert payload["trace_id"] == "trace-1"
    assert payload["call_id"] == "call-1"
    assert "tool_id" not in payload
    assert "decision" not in payload
    assert all(value is not None for value in payload.values())

    released = build(
        AuditEventType.response_released,
        tool_id="mock_email.read",
        action_id="read",
        decision=FirewallDecision.allow,
        reason=DecisionReason.authorized_read,
        outcome=InvocationOutcome.executed,
        result_digest=CONTENT_DIGEST,
        result_bytes=12,
        dlp=dlp(DlpPhase.output),
    )
    assert released.to_payload()["outcome"] == "EXECUTED"


def test_call_id_must_be_a_stable_identifier() -> None:
    with pytest.raises(ValidationError, match="call_id must be a stable identifier"):
        build(AuditEventType.request_received, call_id="call id with spaces")


def test_audit_payloads_reject_extra_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        build(AuditEventType.request_received, raw_arguments={"content": "secret"})
