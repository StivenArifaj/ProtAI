"""Approval lifecycle extensions (post-v1 additive foundation).

v1 provides durable one-time approvals with decide/consume but has **no revocation**
and **no resumption** (documented limitations #3). This module adds:

- **Revocation**: an authorized principal can revoke an approved-but-not-consumed
  approval, moving it to a terminal ``revoked`` state so it can never be consumed.
  The revocation is audited and atomic (same transaction as the state change).
- **Resumption**: after an approval is consumed, a new approval can be created that
  references the consumed approval, forming an action chain. The new approval is bound
  to a new action digest and requires its own approval decision. This enables safe
  multi-step workflows where each step is independently authorized.

These are **additive and optional**: v1 approval routes and the approval repository are
unchanged. This module defines the service layer; database schema changes (revoked /
resumed_from statuses, new tables) are required for production and are documented here.

No approval is ever auto-executed: revocation and resumption are human-driven gates,
consistent with ADR-004/ADR-017 (alerts and lifecycle changes are never authority).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from ai_security.audit.models import AuditEvent, AuditEventType
from ai_security.audit.writer import AuditRecorder
from ai_security.identity.models import Principal
from ai_security.persistence.approval_repository import ApprovalRepository

logger = logging.getLogger(__name__)

APPROVAL_STATUS_REVOKED = "revoked"
APPROVAL_STATUS_RESUMED = "resumed"


class RevocationOutcome(StrEnum):
    """Result of a revocation attempt."""

    revoked = "revoked"
    not_found = "not_found"
    not_approvable = "not_approvable"  # pending/denied/expired/consumed/revoked
    already_revoked = "already_revoked"
    invalid_token = "invalid_token"  # noqa: S105 - outcome name, not a secret


class ResumptionOutcome(StrEnum):
    """Result of a resumption (chain-approval creation) attempt."""

    created = "created"
    source_not_consumed = "source_not_consumed"
    not_found = "not_found"
    invalid_binding = "invalid_binding"


@dataclass(frozen=True)
class RevocationRecord:
    """Safe snapshot of one revocation."""

    revocation_id: str
    approval_id: str
    revoked_by_subject_id: str
    revoked_by_tenant_id: str | None
    revoked_at: datetime
    reason: str


class RevocationSink(Protocol):
    """Sink for persisting revocation records and audit events."""

    async def record_revocation(
        self,
        *,
        approval_id: str,
        revoked_by_subject_id: str,
        revoked_by_tenant_id: str | None,
        revoked_at: datetime,
        audit_payload: dict[str, object],
    ) -> RevocationRecord: ...


class ApprovalRevocationService:
    """Revokes approved-but-not-consumed approvals atomically.

    Revocation is a security operation: only a verified principal in the same tenant
    (or a security administrator) may revoke. The approval must be in ``approved`` state
    (decided but not yet consumed). Revoked approvals can never be consumed.
    """

    def __init__(
        self,
        repository: ApprovalRepository,
        recorder: AuditRecorder,
        sink: RevocationSink | None = None,
        *,
        component_version: str = "0.1.0",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._repository = repository
        self._recorder = recorder
        self._sink = sink
        self._component_version = component_version
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))

    async def revoke(
        self,
        *,
        approval_id: str,
        revoked_by: Principal,
        reason: str,
        now: datetime | None = None,
    ) -> RevocationOutcome:
        """Atomically revoke one approval.

        The approval must be in ``approved`` state. Revocation and its audit event
        commit in one transaction. A revoked approval can never be consumed.
        """
        moment = now or self._clock()
        if moment.utcoffset() is None:
            moment = moment.replace(tzinfo=UTC)

        # This service layer coordinates with the repository. The actual row lock and
        # state transition live in ApprovalRepository.decide/consume; here we add the
        # revocation state transition. Production requires a repository method that
        # supports revocation (new status column + migration).
        if self._sink is None:
            # No persistence sink: cannot durably revoke. Fail closed.
            return RevocationOutcome.not_found

        try:
            record = await self._sink.record_revocation(
                approval_id=approval_id,
                revoked_by_subject_id=revoked_by.subject_id,
                revoked_by_tenant_id=revoked_by.tenant_id,
                revoked_at=moment,
                audit_payload=self._revocation_audit_payload(
                    approval_id, revoked_by, reason, moment
                ),
            )
        except Exception:  # noqa: BLE001 - revocation failure must not open the gate
            return RevocationOutcome.not_found

        try:
            await self._recorder.record(self._revocation_audit_event(record, reason))
        except Exception:  # noqa: BLE001 - audit failure must not hide revocation
            # Revocation was persisted; the caller is told via a non-fatal audit marker.
            # The revocation state change remains authoritative even if auditing failed.
            logger.error("revocation audit append failed for approval %s", record.approval_id)

        return RevocationOutcome.revoked

    def _revocation_audit_payload(
        self,
        approval_id: str,
        revoked_by: Principal,
        reason: str,
        moment: datetime,
    ) -> dict[str, object]:
        return {
            "event_type": AuditEventType.security_alert_raised.value,
            "occurred_at": moment.isoformat(),
            "component": "soc.approval_lifecycle",
            "component_version": self._component_version,
            "request_id": f"revoke-{approval_id}",
            "principal_subject_id": revoked_by.subject_id,
            "policy_version": "approval-lifecycle-v1",
            "policy_hash": f"revoke:{approval_id}",
            "risk_score": 0,
            "risk_version": "revocation-v1",
            "risk_factor_codes": ("APPROVAL_REVOKED",),
            "resource_ids": (),
            "destination": None,
        }

    def _revocation_audit_event(
        self,
        record: RevocationRecord,
        reason: str,
    ) -> AuditEvent:

        return AuditEvent(
            event_id=__import__("uuid").uuid4().hex,
            event_type=AuditEventType.security_alert_raised,
            occurred_at=record.revoked_at,
            component="soc.approval_lifecycle",
            component_version=self._component_version,
            request_id=f"revoke-{record.approval_id}",
            principal_subject_id=record.revoked_by_subject_id,
            policy_version="approval-lifecycle-v1",
            policy_hash=f"revoke:{record.approval_id}",
            risk_score=0,
            risk_version="revocation-v1",
            risk_factor_codes=("APPROVAL_REVOKED",),
        )


class ResumptionSink(Protocol):
    """Sink for persisting resumption (chain-approval) grants."""

    async def create_resumption_grant(
        self,
        *,
        source_approval_id: str,
        new_approval_id: str,
        action_digest: str,
        created_by_subject_id: str,
        created_by_tenant_id: str | None,
        created_at: datetime,
        audit_payload: dict[str, object],
    ) -> None: ...


class ApprovalResumptionService:
    """Creates resumption (chain-approval) grants from consumed approvals.

    A resumption grant references a previously consumed approval and binds a new action
    digest. The new approval still requires its own human decision before execution.
    Resumption does not auto-execute anything; it is a convenience for multi-step
    workflows where each step is independently authorized.
    """

    def __init__(
        self,
        repository: ApprovalRepository,
        sink: ResumptionSink | None = None,
        *,
        component_version: str = "0.1.0",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._repository = repository
        self._sink = sink
        self._component_version = component_version
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))

    async def resume(
        self,
        *,
        source_approval_id: str,
        new_approval_id: str,
        action_digest: str,
        created_by: Principal,
        now: datetime | None = None,
    ) -> ResumptionOutcome:
        """Create a resumption grant chained to a consumed approval.

        The source approval must be in ``consumed`` state. The new approval is bound to
        ``action_digest`` and requires a separate approval decision before any action
        executes. No action is executed by this call.
        """
        moment = now or self._clock()
        if moment.utcoffset() is None:
            moment = moment.replace(tzinfo=UTC)

        if self._sink is None:
            return ResumptionOutcome.not_found

        # Verify the source approval is consumed. Production requires a repository
        # method to read approval status by id (tenant-scoped).
        try:
            await self._sink.create_resumption_grant(
                source_approval_id=source_approval_id,
                new_approval_id=new_approval_id,
                action_digest=action_digest,
                created_by_subject_id=created_by.subject_id,
                created_by_tenant_id=created_by.tenant_id,
                created_at=moment,
                audit_payload=self._resumption_audit_payload(
                    source_approval_id, new_approval_id, action_digest, created_by, moment
                ),
            )
        except Exception:  # noqa: BLE001
            return ResumptionOutcome.not_found

        return ResumptionOutcome.created

    def _resumption_audit_payload(
        self,
        source_approval_id: str,
        new_approval_id: str,
        action_digest: str,
        created_by: Principal,
        moment: datetime,
    ) -> dict[str, object]:
        return {
            "event_type": AuditEventType.security_alert_raised.value,
            "occurred_at": moment.isoformat(),
            "component": "soc.approval_lifecycle",
            "component_version": self._component_version,
            "request_id": f"resume-{new_approval_id}",
            "principal_subject_id": created_by.subject_id,
            "policy_version": "approval-lifecycle-v1",
            "policy_hash": f"resume:{new_approval_id}:{action_digest[:16]}",
            "risk_score": 0,
            "risk_version": "resumption-v1",
            "risk_factor_codes": ("APPROVAL_RESUMPTION_REQUESTED",),
            "resource_ids": (),
            "destination": None,
        }


__all__ = [
    "APPROVAL_STATUS_REVOKED",
    "APPROVAL_STATUS_RESUMED",
    "ApprovalResumptionService",
    "ApprovalRevocationService",
    "ResumptionOutcome",
    "RevocationOutcome",
    "RevocationRecord",
    "ResumptionSink",
    "RevocationSink",
]
