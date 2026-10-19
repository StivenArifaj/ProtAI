"""Audit writer interface used by the enforced gateway (blueprint section 16.4).

The gateway depends on the ``AuditRecorder`` protocol, not on PostgreSQL. Before any
protected side effect the decision event must be durably appended through this
interface; ``ChainAuditRecorder`` delegates to the only module allowed to insert into
``audit_events`` (``persistence/audit_repository.py``).
"""

from __future__ import annotations

from typing import Protocol

from ai_security.audit.models import AuditEvent
from ai_security.persistence.audit_repository import (
    AppendedAuditEvent,
    AuditAppendError,
    AuditChainRepository,
)
from ai_security.security.canonical_json import CanonicalJSONError


class AuditWriteError(RuntimeError):
    """Audit persistence failed; callers must not perform a protected side effect."""


class AuditRecorder(Protocol):
    """Append one structured event and return its chain identifiers."""

    async def record(self, event: AuditEvent) -> AppendedAuditEvent:
        """Persist the event; raise ``AuditWriteError`` on any failure."""
        ...


class ChainAuditRecorder:
    """``AuditRecorder`` backed by the PostgreSQL hash-chain repository."""

    def __init__(self, repository: AuditChainRepository) -> None:
        self._repository = repository

    async def record(self, event: AuditEvent) -> AppendedAuditEvent:
        try:
            return await self._repository.append(event.to_payload())
        except (AuditAppendError, CanonicalJSONError) as exc:
            raise AuditWriteError(
                "audit persistence unavailable; protected execution must not proceed"
            ) from exc


__all__ = ["AuditRecorder", "AuditWriteError", "ChainAuditRecorder"]
