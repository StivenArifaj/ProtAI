"""Audit append scaffolding (blueprint section 16.2; ADR-002).

This repository is the only module allowed to insert into ``audit_events``. The v1
append protocol, inside one ``READ COMMITTED`` transaction:

1. acquire the transaction-scoped advisory lock for the v1 chain (fixed documented key
   below) *before* reading any prior-chain state;
2. read the latest committed ``sequence_number``/``event_hash`` for the chain (genesis:
   sequence 1 with a 32-byte all-zero previous hash);
3. assign the next ``sequence_number``;
4. serialize the caller's event payload as canonical UTF-8 JSON (``prev_hash``/
   ``event_hash``/storage-only fields are not part of the payload);
5. hash with the exact section 16.2 byte formula;
6. insert ``sequence_number``, ``previous_hash``, the exact ``canonical_event_bytes``
   (BYTEA), and ``event_hash``; commit while the lock is still transaction-scoped.

The unique constraint ``(chain_id, sequence_number)`` is the final integrity guard; a
lock/read/insert/commit failure raises ``AuditAppendError`` and the caller must not
perform a protected side effect that requires the audit record (section 16.4). The full
chain verifier and event taxonomy arrive in Phase 7 — this is scaffolding, not the
audit invariant.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ai_security.audit.hash_chain import (
    GENESIS_PREV_HASH,
    compute_event_hash,
    hash_to_hex,
    hex_to_hash,
)
from ai_security.security.canonical_json import canonical_json_bytes

from .models import AuditEvent

#: Fixed signed 64-bit transaction-scoped advisory lock key for the v1 chain.
#: Documented contract: every append to a v1 chain uses exactly this key so multiple
#: worker processes serialize through PostgreSQL. Never change without an ADR.
AUDIT_CHAIN_LOCK_KEY = 3_141_592_653_589_793

#: The single v1 chain id used by every deployed database (blueprint section 16.2).
V1_CHAIN_ID = "v1"


class AuditAppendError(RuntimeError):
    """The audit append failed; callers must not proceed with protected side effects."""


@dataclass(frozen=True)
class AppendedAuditEvent:
    """Identifiers of one committed audit event."""

    chain_id: str
    sequence_number: int
    previous_hash: str
    event_hash: str


class AuditChainRepository:
    """Append routine for one v1 chain per deployed database."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession], *, chain_id: str) -> None:
        if not chain_id:
            raise ValueError("chain_id must be non-empty")
        self._session_factory = session_factory
        self._chain_id = chain_id

    @property
    def chain_id(self) -> str:
        return self._chain_id

    async def append(self, event: Mapping[str, Any]) -> AppendedAuditEvent:
        """Append one event payload as canonical bytes and return its chain identifiers."""
        canonical_event_bytes = canonical_json_bytes(dict(event))
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    await session.execute(select(func.pg_advisory_xact_lock(AUDIT_CHAIN_LOCK_KEY)))
                    latest = (
                        await session.execute(
                            select(AuditEvent.sequence_number, AuditEvent.event_hash)
                            .where(AuditEvent.chain_id == self._chain_id)
                            .order_by(AuditEvent.sequence_number.desc())
                            .limit(1)
                        )
                    ).first()
                    if latest is None:
                        sequence_number = 1
                        previous_hash_bytes = GENESIS_PREV_HASH
                    else:
                        sequence_number = latest.sequence_number + 1
                        previous_hash_bytes = hex_to_hash(latest.event_hash)
                    event_hash_bytes = compute_event_hash(
                        chain_id=self._chain_id,
                        sequence_number=sequence_number,
                        previous_hash=previous_hash_bytes,
                        canonical_event_bytes=canonical_event_bytes,
                    )
                    previous_hash_hex = hash_to_hex(previous_hash_bytes)
                    event_hash_hex = hash_to_hex(event_hash_bytes)
                    session.add(
                        AuditEvent(
                            chain_id=self._chain_id,
                            sequence_number=sequence_number,
                            canonical_event_bytes=canonical_event_bytes,
                            previous_hash=previous_hash_hex,
                            event_hash=event_hash_hex,
                        )
                    )
        except (SQLAlchemyError, OSError) as exc:
            raise AuditAppendError(
                "audit append failed; protected side effects must not proceed (section 16.4)"
            ) from exc
        return AppendedAuditEvent(
            chain_id=self._chain_id,
            sequence_number=sequence_number,
            previous_hash=previous_hash_hex,
            event_hash=event_hash_hex,
        )
