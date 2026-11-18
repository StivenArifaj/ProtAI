"""Read-only audit evidence provider for SOC alerting and summarization.

This provider reads existing audit events from the audit chain repository (read-only
query) and exposes them as plain mappings for alert rule evaluation and summarization.
It is **never a write path** into the production audit chain — it has no ``append``
method and cannot mutate audit records.

Used by:
- ``soc.rules.evaluate_rules`` (deterministic alert evaluation)
- ``soc.summarizer.AuditSummarizer`` (optional read-only hypothesis generation)
"""

from __future__ import annotations

import json
from typing import Protocol, runtime_checkable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ai_security.persistence.audit_repository import AuditChainRepository
from ai_security.persistence.models import AuditEvent as StoredAuditEvent


@runtime_checkable
class AuditEvidenceProvider(Protocol):
    """Read-only protocol for audit evidence.

    Implementations must not write to the audit chain.
    """

    def events(self) -> list[dict[str, object]]:
        """Return audit events as plain mappings, oldest first."""


class ReadOnlyAuditChainProvider:
    """Backs ``AuditEvidenceProvider`` with a read-only query over ``audit_events``.

    Only ``SELECT`` is used; no insert, update, or delete. The underlying repository
    remains the sole writer of ``audit_events`` (ADR-002).
    """

    def __init__(self, repository: AuditChainRepository) -> None:
        self._repository = repository

    def events(self) -> list[dict[str, object]]:
        """Not implemented directly — use ``fetch_events`` with a session.

        The provider is constructed with a repository but the actual read requires an
        async session. Prefer ``ReadOnlyAuditChainReader`` for async usage.
        """
        raise NotImplementedError(
            "use ReadOnlyAuditChainReader.fetch_events(session) with an async session"
        )


class ReadOnlyAuditChainReader:
    """Async read-only reader over the v1 audit chain.

    One consistent snapshot query per call; no writes.
    """

    def __init__(self, repository: AuditChainRepository) -> None:
        self._repository = repository

    async def fetch_events(
        self,
        session: AsyncSession,
        *,
        chain_id: str = "v1",
        limit: int = 50_000,
    ) -> list[dict[str, object]]:
        """Fetch audit events oldest-first, bounded by ``limit``.

        ``session`` is an existing SQLAlchemy async session owned by the caller; this
        reader never opens a transaction or writes.
        """
        rows = list(
            (
                await session.execute(
                    select(StoredAuditEvent)
                    .where(StoredAuditEvent.chain_id == chain_id)
                    .order_by(StoredAuditEvent.sequence_number)
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        events: list[dict[str, object]] = []
        for row in rows:
            payload = row.canonical_event_bytes
            if isinstance(payload, (bytes, bytearray)):
                try:
                    parsed = json.loads(payload.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    parsed = {}
            elif isinstance(payload, dict):
                parsed = payload
            else:
                parsed = {}
            if not isinstance(parsed, dict):
                parsed = {}
            event: dict[str, object] = dict(parsed)
            event["sequence_number"] = row.sequence_number
            event["event_hash"] = row.event_hash
            event["previous_hash"] = row.previous_hash
            events.append(event)
        return events


__all__ = [
    "AuditEvidenceProvider",
    "ReadOnlyAuditChainProvider",
    "ReadOnlyAuditChainReader",
]
