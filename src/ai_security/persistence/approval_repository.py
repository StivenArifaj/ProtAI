"""Transactional approval storage and one-time consumption (blueprint section 13.2).

The repository owns the database state machine; the approval service owns token/rule
semantics and builds audit payloads. Every state transition and its audit event are
committed in one transaction:

- ``create`` inserts a pending request and ``APPROVAL_REQUESTED``;
- ``decide`` locks the row, records token/approver/decision and ``APPROVAL_DECIDED``;
- ``consume`` locks the row, verifies the bound action in the caller-supplied predicate,
  moves ``approved`` -> ``consumed``, and appends ``APPROVAL_CONSUMED``.

No raw arguments/content or plaintext approval token is stored. A token digest is
compared with the project constant-time helper before any state change. Concurrent consumers
serialize on ``SELECT ... FOR UPDATE``; exactly one can observe ``approved``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ai_security.persistence.audit_repository import AuditChainRepository
from ai_security.persistence.models import ApprovalRequest
from ai_security.security.constant_time import constant_time_hex32_equal

APPROVAL_STATUS_PENDING = "pending"
APPROVAL_STATUS_APPROVED = "approved"
APPROVAL_STATUS_DENIED = "denied"
APPROVAL_STATUS_CONSUMED = "consumed"
APPROVAL_STATUS_EXPIRED = "expired"


class ApprovalDecisionOutcome(StrEnum):
    """Result of a token-bearing approve/deny attempt."""

    approved = "approved"
    denied = "denied"
    expired = "expired"
    invalid_token = "invalid_token"  # noqa: S105 - outcome name, not a secret
    not_eligible = "not_eligible"
    self_approval_forbidden = "self_approval_forbidden"
    not_pending = "not_pending"
    not_found = "not_found"


class ApprovalConsumptionOutcome(StrEnum):
    """Result of an execution-time attempt to consume an approved request."""

    consumed = "consumed"
    not_found = "not_found"
    not_approved = "not_approved"
    denied = "denied"
    expired = "expired"
    replay = "replay"
    mismatch = "mismatch"


@dataclass(frozen=True)
class ApprovalRow:
    """Safe in-transaction snapshot of one approval request."""

    approval_id: str
    tenant_id: str | None
    requester_subject_id: str
    request_id: str
    tool_id: str
    action_id: str
    action_digest: str
    resource_ids: tuple[str, ...]
    destination: str | None
    side_effect_class: str
    data_class: str
    risk_score: int
    risk_version: str
    risk_factor_codes: tuple[str, ...]
    policy_version: str
    policy_hash: str
    required_approver_rule: str
    self_approval_allowed: bool
    status: str
    created_at: datetime
    expires_at: datetime
    decided_by_subject_id: str | None
    decided_by_tenant_id: str | None
    token_digest: str


@dataclass(frozen=True)
class ApprovalCreate:
    """Facts persisted for a new pending request (service hashed the token)."""

    approval_id: str
    tenant_id: str | None
    requester_subject_id: str
    request_id: str
    tool_id: str
    action_id: str
    action_digest: str
    resource_ids: tuple[str, ...]
    destination: str | None
    side_effect_class: str
    data_class: str
    risk_score: int
    risk_version: str
    risk_factor_codes: tuple[str, ...]
    policy_version: str
    policy_hash: str
    required_approver_rule: str
    self_approval_allowed: bool
    token_digest: str
    created_at: datetime
    expires_at: datetime


def _row(record: ApprovalRequest) -> ApprovalRow:
    return ApprovalRow(
        approval_id=record.approval_id,
        tenant_id=record.tenant_id,
        requester_subject_id=record.requester_subject_id,
        request_id=record.request_id,
        tool_id=record.tool_id,
        action_id=record.action_id,
        action_digest=record.action_digest,
        resource_ids=tuple(record.resource_ids),
        destination=record.destination,
        side_effect_class=record.side_effect_class,
        data_class=record.data_class,
        risk_score=record.risk_score,
        risk_version=record.risk_version,
        risk_factor_codes=tuple(record.risk_factor_codes),
        policy_version=record.policy_version,
        policy_hash=record.policy_hash,
        required_approver_rule=record.required_approver_rule,
        self_approval_allowed=record.self_approval_allowed,
        status=record.status,
        created_at=record.created_at,
        expires_at=record.expires_at,
        decided_by_subject_id=record.decided_by_subject_id,
        decided_by_tenant_id=record.decided_by_tenant_id,
        token_digest=record.token_digest,
    )


class ApprovalRepository:
    """PostgreSQL approval state machine with same-transaction audit appends."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        audit_chain: AuditChainRepository,
    ) -> None:
        self._session_factory = session_factory
        self._audit_chain = audit_chain

    async def create(
        self,
        data: ApprovalCreate,
        *,
        audit_payload: Mapping[str, Any],
    ) -> None:
        """Insert a pending request and its APPROVAL_REQUESTED audit event."""
        async with self._session_factory() as session:
            async with session.begin():
                session.add(
                    ApprovalRequest(
                        approval_id=data.approval_id,
                        tenant_id=data.tenant_id,
                        requester_subject_id=data.requester_subject_id,
                        request_id=data.request_id,
                        tool_id=data.tool_id,
                        action_id=data.action_id,
                        action_digest=data.action_digest,
                        resource_ids=list(data.resource_ids),
                        destination=data.destination,
                        side_effect_class=data.side_effect_class,
                        data_class=data.data_class,
                        risk_score=data.risk_score,
                        risk_version=data.risk_version,
                        risk_factor_codes=list(data.risk_factor_codes),
                        policy_version=data.policy_version,
                        policy_hash=data.policy_hash,
                        required_approver_rule=data.required_approver_rule,
                        self_approval_allowed=data.self_approval_allowed,
                        status=APPROVAL_STATUS_PENDING,
                        token_digest=data.token_digest,
                        created_at=data.created_at,
                        expires_at=data.expires_at,
                    )
                )
                await self._audit_chain.append_in_session(session, audit_payload)

    async def request_id_for(self, approval_id: str, *, tenant_id: str | None) -> str | None:
        """Return the approval's request correlation id, scoped to one tenant.

        Read-only and deliberately minimal: the HTTP decision route needs the original
        request id so approval events and ingress events share a correlation key, but it
        must never read the token digest or any other row field. A cross-tenant lookup
        returns ``None`` (treated as not found) so approval existence does not leak.
        """
        tenant_condition = (
            ApprovalRequest.tenant_id.is_(None)
            if tenant_id is None
            else ApprovalRequest.tenant_id == tenant_id
        )
        async with self._session_factory() as session:
            result = await session.execute(
                select(ApprovalRequest.request_id).where(
                    ApprovalRequest.approval_id == approval_id,
                    tenant_condition,
                )
            )
            return result.scalar_one_or_none()

    async def decide(
        self,
        approval_id: str,
        *,
        token_digest: str,
        now: datetime,
        approve: bool,
        approver_subject_id: str,
        approver_tenant_id: str | None,
        authorize: Callable[[ApprovalRow], ApprovalDecisionOutcome | None],
        audit_decided: Callable[[ApprovalRow, ApprovalDecisionOutcome, str], Mapping[str, Any]],
        audit_expired: Callable[[ApprovalRow], Mapping[str, Any]],
    ) -> tuple[ApprovalDecisionOutcome, ApprovalRow | None]:
        """Atomically record one verified approve/deny decision."""
        async with self._session_factory() as session:
            async with session.begin():
                record = (
                    await session.execute(
                        select(ApprovalRequest)
                        .where(ApprovalRequest.approval_id == approval_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if record is None:
                    return ApprovalDecisionOutcome.not_found, None
                row = _row(record)

                if record.status == APPROVAL_STATUS_EXPIRED:
                    return ApprovalDecisionOutcome.expired, row
                if record.status != APPROVAL_STATUS_PENDING:
                    return ApprovalDecisionOutcome.not_pending, row
                if now >= record.expires_at:
                    record.status = APPROVAL_STATUS_EXPIRED
                    await self._audit_chain.append_in_session(session, audit_expired(row))
                    return ApprovalDecisionOutcome.expired, row
                if not constant_time_hex32_equal(token_digest, record.token_digest):
                    return ApprovalDecisionOutcome.invalid_token, row

                denial = authorize(row)
                if denial is not None:
                    return denial, row

                outcome = (
                    ApprovalDecisionOutcome.approved if approve else ApprovalDecisionOutcome.denied
                )
                record.status = APPROVAL_STATUS_APPROVED if approve else APPROVAL_STATUS_DENIED
                record.token_consumed_at = now
                record.decided_at = now
                record.decided_by_subject_id = approver_subject_id
                record.decided_by_tenant_id = approver_tenant_id
                await self._audit_chain.append_in_session(
                    session, audit_decided(row, outcome, approver_subject_id)
                )
                return outcome, row

    async def consume(
        self,
        approval_id: str,
        *,
        now: datetime,
        verify: Callable[[ApprovalRow], bool],
        audit_consumed: Callable[[ApprovalRow], Mapping[str, Any]],
        audit_expired: Callable[[ApprovalRow], Mapping[str, Any]],
    ) -> tuple[ApprovalConsumptionOutcome, ApprovalRow | None]:
        """Atomically move one approved request to consumed immediately before execution."""
        async with self._session_factory() as session:
            async with session.begin():
                record = (
                    await session.execute(
                        select(ApprovalRequest)
                        .where(ApprovalRequest.approval_id == approval_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if record is None:
                    return ApprovalConsumptionOutcome.not_found, None
                row = _row(record)

                if record.status == APPROVAL_STATUS_CONSUMED:
                    return ApprovalConsumptionOutcome.replay, row
                if record.status == APPROVAL_STATUS_DENIED:
                    return ApprovalConsumptionOutcome.denied, row
                if now >= record.expires_at:
                    if record.status in (APPROVAL_STATUS_PENDING, APPROVAL_STATUS_APPROVED):
                        record.status = APPROVAL_STATUS_EXPIRED
                        await self._audit_chain.append_in_session(session, audit_expired(row))
                    return ApprovalConsumptionOutcome.expired, row
                if record.status != APPROVAL_STATUS_APPROVED:
                    return ApprovalConsumptionOutcome.not_approved, row
                if not verify(row):
                    return ApprovalConsumptionOutcome.mismatch, row

                record.status = APPROVAL_STATUS_CONSUMED
                record.consumed_at = now
                await self._audit_chain.append_in_session(session, audit_consumed(row))
                return ApprovalConsumptionOutcome.consumed, row
