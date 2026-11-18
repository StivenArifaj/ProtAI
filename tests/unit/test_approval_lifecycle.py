"""Tests for the approval lifecycle (post-v1 additive foundation).

Verifies content-free revocation/resumption audit payloads and fail-closed behavior
when no persistence sink is configured. No approval auto-executes.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from ai_security.identity.models import Principal
from ai_security.soc.approval_lifecycle import (
    APPROVAL_STATUS_RESUMED,
    APPROVAL_STATUS_REVOKED,
    ApprovalResumptionService,
    ApprovalRevocationService,
    ResumptionOutcome,
    RevocationOutcome,
    RevocationRecord,
)

FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _run(coro) -> object:
    return asyncio.run(coro)


def _principal() -> Principal:
    return Principal(
        subject_id="approver-1",
        auth_method="test",
        issuer="test",
        tenant_id="tenant-1",
        permissions_context_ref="test-ref",
    )


class RecordingRecorder:
    def __init__(self) -> None:
        self.events: list[object] = []

    async def record(self, event: object) -> object:
        self.events.append(event)
        return type("Appended", (), {"sequence_number": 1, "event_hash": "0" * 64})()


class MemoryRevocationSink:
    def __init__(self) -> None:
        self.records: list[RevocationRecord] = []

    async def record_revocation(
        self,
        *,
        approval_id: str,
        revoked_by_subject_id: str,
        revoked_by_tenant_id: str | None,
        revoked_at: datetime,
        audit_payload: dict[str, object],
    ) -> RevocationRecord:
        record = RevocationRecord(
            revocation_id="rev-1",
            approval_id=approval_id,
            revoked_by_subject_id=revoked_by_subject_id,
            revoked_by_tenant_id=revoked_by_tenant_id,
            revoked_at=revoked_at,
            reason="compromised",
        )
        self.records.append(record)
        return record


def test_status_constants() -> None:
    assert APPROVAL_STATUS_REVOKED == "revoked"
    assert APPROVAL_STATUS_RESUMED == "resumed"


def test_revocation_no_sink_fails_closed() -> None:
    service = ApprovalRevocationService(
        repository=object(),
        recorder=RecordingRecorder(),
        sink=None,  # type: ignore[arg-type]
    )
    result = _run(service.revoke(approval_id="a" * 32, revoked_by=_principal(), reason="test"))
    assert result is RevocationOutcome.not_found


def test_revocation_with_sink() -> None:
    sink = MemoryRevocationSink()
    recorder = RecordingRecorder()
    service = ApprovalRevocationService(
        repository=object(),
        recorder=recorder,
        sink=sink,  # type: ignore[arg-type]
    )
    result = _run(
        service.revoke(approval_id="a" * 32, revoked_by=_principal(), reason="compromised")
    )

    assert result is RevocationOutcome.revoked
    assert len(sink.records) == 1
    assert sink.records[0].approval_id == "a" * 32
    assert sink.records[0].revoked_by_subject_id == "approver-1"


def test_revocation_audit_payload_is_content_free() -> None:
    sink = MemoryRevocationSink()
    recorder = RecordingRecorder()
    service = ApprovalRevocationService(
        repository=object(),
        recorder=recorder,
        sink=sink,  # type: ignore[arg-type]
    )
    payload = service._revocation_audit_payload("a" * 32, _principal(), "compromised", FIXED_NOW)

    import json

    serialized = json.dumps(payload, default=str)
    assert "compromised" not in serialized  # reason not in content-free payload
    assert "approver-1" in serialized  # subject id is safe identifier


def test_revocation_event_is_security_alert_not_decision() -> None:
    sink = MemoryRevocationSink()
    recorder = RecordingRecorder()
    service = ApprovalRevocationService(
        repository=object(),
        recorder=recorder,
        sink=sink,  # type: ignore[arg-type]
    )
    result = _run(service.revoke(approval_id="a" * 32, revoked_by=_principal(), reason="test"))
    assert result is RevocationOutcome.revoked
    assert len(recorder.events) == 1
    event = recorder.events[0]
    assert event.event_type is not None  # typed audit event emitted


def test_resumption_no_sink_fails_closed() -> None:
    service = ApprovalResumptionService(repository=object(), sink=None)  # type: ignore[arg-type]
    result = _run(
        service.resume(
            source_approval_id="a" * 32,
            new_approval_id="b" * 32,
            action_digest="c" * 64,
            created_by=_principal(),
        )
    )
    assert result is ResumptionOutcome.not_found


def test_resumption_payload_is_content_free() -> None:
    service = ApprovalResumptionService(repository=object(), sink=None)  # type: ignore[arg-type]
    payload = service._resumption_audit_payload(
        "a" * 32, "b" * 32, "c" * 64, _principal(), FIXED_NOW
    )

    import json

    serialized = json.dumps(payload, default=str)
    assert "secret" not in serialized.lower()
    assert "password" not in serialized.lower()
    assert payload["risk_factor_codes"] == ("APPROVAL_RESUMPTION_REQUESTED",)


def test_no_auto_execution() -> None:
    """Revocation/resumption services have no invoke/execute method."""
    from ai_security.soc.approval_lifecycle import (
        ApprovalResumptionService,
        ApprovalRevocationService,
    )

    for cls in (ApprovalRevocationService, ApprovalResumptionService):
        for forbidden in ("invoke", "execute", "call_tool", "run_tool"):
            assert not hasattr(cls, forbidden)
