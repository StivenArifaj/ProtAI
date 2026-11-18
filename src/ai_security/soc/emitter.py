"""Alert emission through the audit recorder (blueprint section 17.1).

``SECURITY_ALERT_RAISED`` is emitted **only when a deterministic rule actually fires**,
through the existing ``AuditRecorder`` / audit chain. Emission is content-free: the
event carries rule id, severity, count, window, and content-free evidence tokens —
never raw audit text, user content, tool output, or exception messages.

Alerts are evidence/notification only. The emitter has no authority: it cannot block,
allow, consume an approval, revoke a session, edit policy, or trigger containment. A
failed alert emission must never cause an alert to be suppressed silently (the caller
logs the failure) and must never change any authorization decision.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from ai_security.audit.models import (
    COMPONENT,
    AuditEvent,
    AuditEventType,
)
from ai_security.audit.writer import AuditRecorder, AuditWriteError
from ai_security.soc.config import AlertRuleFiring

_COMPONENT: COMPONENT = "soc.alert_emitter"

#: Content-free evidence tokens used by alert events.
_ALERT_EVIDENCE_TOKEN_PATTERN = r"^[A-Z][A-Z0-9_]{0,63}$"  # noqa: S105 - regex pattern, not a secret


@dataclass(frozen=True)
class AlertEmission:
    """Result of attempting to emit one alert."""

    rule_id: str
    emitted: bool
    sequence_number: int | None = None
    event_hash: str | None = None
    error: str | None = None


def content_free_evidence(tokens: tuple[str, ...]) -> tuple[str, ...]:
    """Validate that evidence tokens are content-free and return them.

    Raises ``ValueError`` if any token contains lower-case letters, control
    characters, or non-uppercase identifiers — alert evidence must never carry raw
    content.
    """
    import re

    pattern = re.compile(_ALERT_EVIDENCE_TOKEN_PATTERN)
    for token in tokens:
        if pattern.fullmatch(token) is None:
            raise ValueError(f"alert evidence token {token!r} is not content-free")
    return tokens


class AlertEmitter:
    """Emits ``SECURITY_ALERT_RAISED`` audit events for rule firings."""

    def __init__(
        self,
        recorder: AuditRecorder,
        *,
        component_version: str = "0.1.0",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._recorder = recorder
        self._component_version = component_version
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))

    async def emit(self, firing: AlertRuleFiring) -> AlertEmission:
        """Emit one ``SECURITY_ALERT_RAISED`` event for a rule firing.

        Returns an ``AlertEmission`` describing whether the audit append succeeded. A
        failed emission is logged by the caller; it never blocks or changes any
        authorization decision, and it is never treated as authority.
        """
        now = self._clock()
        if now.utcoffset() is None:
            now = now.replace(tzinfo=UTC)

        evidence = content_free_evidence(firing.evidence)
        event = AuditEvent(
            event_id=uuid.uuid4().hex,
            event_type=AuditEventType.security_alert_raised,
            occurred_at=now,
            component=_COMPONENT,
            component_version=self._component_version,
            request_id=f"alert-{firing.rule_id}",
            trace_id=None,
            session_id=None,
            principal_subject_id="soc-system",
            call_id=None,
            tool_id=None,
            action_id=None,
            decision=None,
            reason=None,
            policy_version=f"severity:{firing.severity.value}",
            policy_hash=f"count:{firing.count}:window:{firing.window_seconds}:evidence:{':'.join(evidence)}",
            outcome=None,
            side_effect_class=None,
            data_class=None,
            risk_score=firing.count,
            risk_version=firing.rule_id,
            risk_factor_codes=evidence,
            destination=None,
            resource_ids=(),
            approval_id=None,
            approver_subject_id=None,
            duration_ms=None,
            result_digest=None,
            result_bytes=None,
            error_type=None,
            dlp=None,
            input=None,
        )

        try:
            appended = await self._recorder.record(event)
        except AuditWriteError as exc:
            return AlertEmission(
                rule_id=firing.rule_id,
                emitted=False,
                error=f"audit write failed: {exc}",
            )
        return AlertEmission(
            rule_id=firing.rule_id,
            emitted=True,
            sequence_number=appended.sequence_number,
            event_hash=appended.event_hash,
        )

    async def emit_all(self, firings: tuple[AlertRuleFiring, ...]) -> tuple[AlertEmission, ...]:
        """Emit all firings, returning emissions in the same order.

        Each firing is emitted independently; one failure does not prevent the others.
        """
        emissions: list[AlertEmission] = []
        for firing in firings:
            emissions.append(await self.emit(firing))
        return tuple(emissions)


__all__ = [
    "AlertEmission",
    "AlertEmitter",
    "content_free_evidence",
]
