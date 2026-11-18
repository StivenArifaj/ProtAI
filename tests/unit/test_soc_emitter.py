"""Alert emission tests (Phase 10).

``SECURITY_ALERT_RAISED`` is emitted only when a rule actually fires, through the
audit recorder, with content-free evidence. A failed emission never changes any
authorization decision and is never treated as authority.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from ai_security.audit.models import AuditEvent, AuditEventType
from ai_security.audit.writer import AuditWriteError
from ai_security.persistence.audit_repository import AppendedAuditEvent
from ai_security.soc.config import AlertRuleFiring, AlertSeverity
from ai_security.soc.emitter import AlertEmitter, content_free_evidence

FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _run(coro) -> object:
    """Run an async coroutine synchronously (pytest-asyncio is not installed)."""
    return asyncio.run(coro)


class RecordingAuditRecorder:
    """In-memory recorder with optional failure injection."""

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


def _firing(rule_id: str = "rule-1", count: int = 5) -> AlertRuleFiring:
    return AlertRuleFiring(
        rule_id=rule_id,
        kind="repeated_blocked_calls",
        severity=AlertSeverity.high,
        count=count,
        window_seconds=3600,
        evidence=("BLOCKED_CALLS_EXCEED_THRESHOLD",),
    )


def test_emitter_emits_security_alert_raised() -> None:
    recorder = RecordingAuditRecorder()
    emitter = AlertEmitter(recorder, clock=lambda: FIXED_NOW)
    emission = _run(emitter.emit(_firing()))

    assert emission.emitted is True
    assert emission.rule_id == "rule-1"
    assert emission.sequence_number == 1
    assert emission.event_hash is not None
    assert len(recorder.events) == 1
    event = recorder.events[0]
    assert event.event_type is AuditEventType.security_alert_raised
    assert event.reason is None  # reason is a DecisionReason enum, not a rule id
    assert event.policy_version == "severity:HIGH"
    assert event.risk_score == 5  # count in stable auditable field
    assert event.risk_version == "rule-1"  # rule id in stable auditable field
    assert event.risk_factor_codes == ("BLOCKED_CALLS_EXCEED_THRESHOLD",)


def test_emitter_content_free_evidence_valid() -> None:
    tokens = content_free_evidence(("TOKEN_A", "TOKEN_B"))
    assert tokens == ("TOKEN_A", "TOKEN_B")


def test_emitter_content_free_evidence_rejects_lowercase() -> None:
    with pytest.raises(ValueError):
        content_free_evidence(("token_a",))  # lowercase not allowed


def test_emitter_content_free_evidence_rejects_control_chars() -> None:
    with pytest.raises(ValueError):
        content_free_evidence(("TOKEN\x07",))


def test_emitter_failed_emission_returns_not_emitted() -> None:
    recorder = RecordingAuditRecorder(fail_on_call=1)
    emitter = AlertEmitter(recorder, clock=lambda: FIXED_NOW)
    emission = _run(emitter.emit(_firing()))

    assert emission.emitted is False
    assert emission.rule_id == "rule-1"
    assert emission.sequence_number is None
    assert emission.event_hash is None
    assert emission.error is not None
    assert "audit write failed" in emission.error
    assert len(recorder.events) == 0


def test_emitter_emit_all_independent() -> None:
    recorder = RecordingAuditRecorder()
    emitter = AlertEmitter(recorder, clock=lambda: FIXED_NOW)
    emissions = _run(emitter.emit_all((_firing("rule-1", 3), _firing("rule-2", 7))))

    assert len(emissions) == 2
    assert all(e.emitted for e in emissions)
    assert emissions[0].rule_id == "rule-1"
    assert emissions[1].rule_id == "rule-2"
    assert len(recorder.events) == 2


def test_emitter_handles_long_rule_ids() -> None:
    """AuditEvent.risk_version caps at 32 chars; long rule ids must still emit."""
    recorder = RecordingAuditRecorder()
    emitter = AlertEmitter(recorder, clock=lambda: FIXED_NOW)
    firing = _firing(rule_id="external-destinations-10-per-hour", count=3)
    emission = _run(emitter.emit(firing))
    assert emission.emitted is True
    assert recorder.events[0].risk_version == "external-destinations-10-per-hou"
    assert emission.rule_id == "external-destinations-10-per-hour"


def test_emitter_no_authority_fields() -> None:
    """The emitted event carries no tool, approval, destination, or authorization fields."""
    recorder = RecordingAuditRecorder()
    emitter = AlertEmitter(recorder, clock=lambda: FIXED_NOW)
    _run(emitter.emit(_firing()))

    event = recorder.events[0]
    assert event.tool_id is None
    assert event.action_id is None
    assert event.decision is None
    assert event.approval_id is None
    assert event.destination is None
    assert event.resource_ids == ()
    assert event.dlp is None
    assert event.input is None
