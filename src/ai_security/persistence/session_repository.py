"""Session security state repository (blueprint section 7.4).

Every operation is bound to ``(tenant_id, subject_id)``; a mismatch behaves exactly like
a missing row (no side channel). Expiry is enforced on read and write, with lazy
deletion so cleanup does not depend on a scheduled job. Rotation creates a new internal
identifier bound to the same tenant/subject with fresh, empty counters — signals are
never inherited or transferred between session identifiers.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast

from sqlalchemy import ColumnElement, delete, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import InstrumentedAttribute

from ai_security.input_defense.sessions import (
    MAX_SIGNAL_COUNTER,
    SessionSecuritySnapshot,
    new_session_id,
)
from ai_security.persistence.models import SessionSecurityState


class SessionSecurityRepository:
    """Tenant/subject-bound session signal storage (PostgreSQL in v1)."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        ttl_seconds: int = 86400,
        max_age_seconds: int = 604800,
    ) -> None:
        self._session_factory = session_factory
        self._ttl = ttl_seconds
        self._max_age = max_age_seconds

    @staticmethod
    def _snapshot(row: SessionSecurityState) -> SessionSecuritySnapshot:
        return SessionSecuritySnapshot(
            session_id=row.session_id,
            tenant_id=row.tenant_id,
            subject_id=row.subject_id,
            created_at=row.created_at,
            last_seen_at=row.last_seen_at,
            override_attempts=row.override_attempts,
            privilege_escalation_signals=row.privilege_escalation_signals,
            blocked_tool_proposals=row.blocked_tool_proposals,
            threat_findings=row.threat_findings,
        )

    @staticmethod
    def _now(value: datetime | None) -> datetime:
        now = value if value is not None else datetime.now(UTC)
        if now.tzinfo is None:
            raise ValueError("session timestamps must be timezone-aware")
        return now

    def _expiry_cutoffs(self, now: datetime) -> tuple[datetime, datetime]:
        return now - timedelta(seconds=self._ttl), now - timedelta(seconds=self._max_age)

    def _is_expired(self, row: SessionSecurityState, now: datetime) -> bool:
        inactivity_cutoff, absolute_cutoff = self._expiry_cutoffs(now)
        return row.last_seen_at < inactivity_cutoff or row.created_at < absolute_cutoff

    async def _delete_expired_bound(
        self, session: AsyncSession, session_id: str, tenant_id: str, subject_id: str, now: datetime
    ) -> None:
        inactivity_cutoff, absolute_cutoff = self._expiry_cutoffs(now)
        await session.execute(
            delete(SessionSecurityState).where(
                SessionSecurityState.session_id == session_id,
                SessionSecurityState.tenant_id == tenant_id,
                SessionSecurityState.subject_id == subject_id,
                (
                    (SessionSecurityState.last_seen_at < inactivity_cutoff)
                    | (SessionSecurityState.created_at < absolute_cutoff)
                ),
            )
        )

    async def create(
        self,
        tenant_id: str,
        subject_id: str,
        *,
        now: datetime | None = None,
    ) -> SessionSecuritySnapshot:
        """Create a new internal session bound to the verified tenant/subject."""
        moment = self._now(now)
        session_id = new_session_id()
        async with self._session_factory() as session:
            async with session.begin():
                await session.execute(
                    insert(SessionSecurityState).values(
                        session_id=session_id,
                        tenant_id=tenant_id,
                        subject_id=subject_id,
                        created_at=moment,
                        last_seen_at=moment,
                        override_attempts=0,
                        privilege_escalation_signals=0,
                        blocked_tool_proposals=0,
                        threat_findings=0,
                    )
                )
        return SessionSecuritySnapshot(
            session_id=session_id,
            tenant_id=tenant_id,
            subject_id=subject_id,
            created_at=moment,
            last_seen_at=moment,
            override_attempts=0,
            privilege_escalation_signals=0,
            blocked_tool_proposals=0,
            threat_findings=0,
        )

    async def read(
        self,
        session_id: str,
        tenant_id: str,
        subject_id: str,
        *,
        now: datetime | None = None,
    ) -> SessionSecuritySnapshot | None:
        """Read bound state; expired rows are lazily deleted and reported as absent."""
        moment = self._now(now)
        async with self._session_factory() as session:
            async with session.begin():
                row = (
                    await session.execute(
                        select(SessionSecurityState).where(
                            SessionSecurityState.session_id == session_id,
                            SessionSecurityState.tenant_id == tenant_id,
                            SessionSecurityState.subject_id == subject_id,
                        )
                    )
                ).scalar_one_or_none()
                if row is None:
                    return None
                if self._is_expired(row, moment):
                    await self._delete_expired_bound(
                        session, session_id, tenant_id, subject_id, moment
                    )
                    return None
                return self._snapshot(row)

    async def record_signals(
        self,
        session_id: str,
        tenant_id: str,
        subject_id: str,
        *,
        override_attempts: int = 0,
        privilege_escalation_signals: int = 0,
        blocked_tool_proposals: int = 0,
        threat_findings: int = 0,
        now: datetime | None = None,
    ) -> SessionSecuritySnapshot | None:
        """Add bounded signal counters; expired or unbound sessions are not extended."""
        moment = self._now(now)
        for value in (
            override_attempts,
            privilege_escalation_signals,
            blocked_tool_proposals,
            threat_findings,
        ):
            if value < 0 or value > MAX_SIGNAL_COUNTER:
                raise ValueError("session signal deltas must be within 0..MAX_SIGNAL_COUNTER")
        inactivity_cutoff, absolute_cutoff = self._expiry_cutoffs(moment)
        bounded = {
            "override_attempts": self._bounded_add(
                SessionSecurityState.override_attempts, override_attempts
            ),
            "privilege_escalation_signals": self._bounded_add(
                SessionSecurityState.privilege_escalation_signals, privilege_escalation_signals
            ),
            "blocked_tool_proposals": self._bounded_add(
                SessionSecurityState.blocked_tool_proposals, blocked_tool_proposals
            ),
            "threat_findings": self._bounded_add(
                SessionSecurityState.threat_findings, threat_findings
            ),
        }
        async with self._session_factory() as session:
            async with session.begin():
                row = (
                    await session.execute(
                        update(SessionSecurityState)
                        .where(
                            SessionSecurityState.session_id == session_id,
                            SessionSecurityState.tenant_id == tenant_id,
                            SessionSecurityState.subject_id == subject_id,
                            SessionSecurityState.last_seen_at >= inactivity_cutoff,
                            SessionSecurityState.created_at >= absolute_cutoff,
                        )
                        .values(last_seen_at=moment, **bounded)
                        .returning(SessionSecurityState)
                    )
                ).scalar_one_or_none()
                if row is None:
                    await self._delete_expired_bound(
                        session, session_id, tenant_id, subject_id, moment
                    )
                    return None
                return self._snapshot(row)

    async def rotate(
        self,
        session_id: str,
        tenant_id: str,
        subject_id: str,
        *,
        now: datetime | None = None,
    ) -> SessionSecuritySnapshot | None:
        """Create a fresh internal session with the same binding and no inherited state."""
        moment = self._now(now)
        current = await self.read(session_id, tenant_id, subject_id, now=moment)
        if current is None:
            return None
        return await self.create(tenant_id, subject_id, now=moment)

    @staticmethod
    def _bounded_add(column: InstrumentedAttribute[int], delta: int) -> ColumnElement[int]:
        if delta == 0:
            return cast(ColumnElement[int], column)
        return func.least(column + delta, MAX_SIGNAL_COUNTER)
