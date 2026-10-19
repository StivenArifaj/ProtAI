"""Mapped tables for Phase 0b (blueprint sections 9.2, 16.2; ADR-002, ADR-005).

Schema changes are made by Alembic migrations only; runtime code never calls
``create_all`` (ADR-006) — tests may create the schema from metadata only in isolated
fixtures where a full migration run is not the subject under test.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Identity,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all mapped tables."""


class HostRequestNonce(Base):
    """Replay-protection nonces (blueprint section 9.2).

    The composite primary key ``(key_id, nonce)`` is the unique constraint; an insert
    conflict on an unexpired row is a replay. Expired rows may be re-registered (the
    acceptance window has passed) and may be deleted by maintenance.
    """

    __tablename__ = "host_request_nonces"

    key_id: Mapped[str] = mapped_column(Text, primary_key=True)
    nonce: Mapped[str] = mapped_column(Text, primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class AuditEvent(Base):
    """Append-only audit events with hash-chain fields (blueprint section 16.2).

    ``canonical_event_bytes`` stores the exact canonical JSON bytes the hash was
    computed over; the future verifier (Phase 7) re-hashes these stored bytes, never a
    reconstructed serialization. ``previous_hash``/``event_hash`` are lowercase
    64-character hex for readability (raw 32-byte form is used for hashing).

    The unique constraint on ``(chain_id, sequence_number)`` is the final integrity
    guard; the append routine additionally serializes appends with a transaction-scoped
    advisory lock (see ``audit_repository``).
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("chain_id", "sequence_number", name="uq_audit_events_chain_sequence"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    chain_id: Mapped[str] = mapped_column(Text, nullable=False)
    sequence_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    canonical_event_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
