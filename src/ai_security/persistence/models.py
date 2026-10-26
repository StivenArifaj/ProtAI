"""Mapped tables for Phase 0b (blueprint sections 9.2, 16.2; ADR-002, ADR-005).

Schema changes are made by Alembic migrations only; runtime code never calls
``create_all`` (ADR-006) — tests may create the schema from metadata only in isolated
fixtures where a full migration run is not the subject under test.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Identity,
    Index,
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


class SessionSecurityState(Base):
    """Bounded multi-turn detection signals (blueprint section 7.4).

    Keyed by the internal CSPRNG session id; the ``(tenant_id, subject_id)`` binding is
    re-checked on every read and write, and a lookup that fails the binding is treated
    as not found. Only counters and timestamps are stored — no raw prompts or model
    context. Expiry (24 h inactivity TTL, 7 d maximum lifetime) is enforced by the
    repository, including lazy cleanup on read.
    """

    __tablename__ = "session_security_state"
    __table_args__ = (
        Index("ix_session_security_state_binding", "tenant_id", "subject_id"),
        CheckConstraint("override_attempts >= 0", name="ck_session_override_nonnegative"),
        CheckConstraint(
            "privilege_escalation_signals >= 0",
            name="ck_session_privilege_nonnegative",
        ),
        CheckConstraint("blocked_tool_proposals >= 0", name="ck_session_blocked_nonnegative"),
        CheckConstraint("threat_findings >= 0", name="ck_session_findings_nonnegative"),
    )

    session_id: Mapped[str] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(Text, nullable=False)
    subject_id: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    override_attempts: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    privilege_escalation_signals: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    blocked_tool_proposals: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    threat_findings: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class ApprovalRequest(Base):
    """Durable human-approval request bound to one canonical action (section 13.2).

    Only the SHA-256 digest of the one-time approval token is stored; the plaintext is
    returned once to the authenticated host at creation. The canonical action digest,
    requester/tenant, policy version/hash, resources, destination, classes, risk
    provenance, and approver rule are snapshotted at creation. The row moves from
    ``pending`` to ``approved``/``denied`` at a verified decision and then to
    ``consumed`` exactly once immediately before execution. No raw arguments, model
    output, or approval secret is stored.
    """

    __tablename__ = "approval_requests"
    __table_args__ = (
        Index("ix_approval_requests_status_expiry", "status", "expires_at"),
        Index("ix_approval_requests_requester", "tenant_id", "requester_subject_id"),
        CheckConstraint(
            "status IN ('pending', 'approved', 'denied', 'consumed', 'expired')",
            name="ck_approval_status",
        ),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_approval_risk_score"),
    )

    approval_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    requester_subject_id: Mapped[str] = mapped_column(Text, nullable=False)
    request_id: Mapped[str] = mapped_column(Text, nullable=False)
    tool_id: Mapped[str] = mapped_column(Text, nullable=False)
    action_id: Mapped[str] = mapped_column(Text, nullable=False)
    action_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    destination: Mapped[str | None] = mapped_column(Text, nullable=True)
    side_effect_class: Mapped[str] = mapped_column(Text, nullable=False)
    data_class: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(BigInteger, nullable=False)
    risk_version: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_factor_codes: Mapped[list[str]] = mapped_column(JSON, nullable=False)

    policy_version: Mapped[str] = mapped_column(Text, nullable=False)
    policy_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    required_approver_rule: Mapped[str] = mapped_column(Text, nullable=False)
    self_approval_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)

    status: Mapped[str] = mapped_column(String(16), nullable=False)
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    token_consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by_subject_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_by_tenant_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
