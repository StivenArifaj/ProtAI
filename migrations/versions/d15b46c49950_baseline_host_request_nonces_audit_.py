"""Phase 0b baseline: host_request_nonces and audit_events.

Revision ID: d15b46c49950

Tables (blueprint sections 9.2, 16.2; ADR-002, ADR-005):

- ``host_request_nonces`` — host-auth replay protection; the composite primary key
  ``(key_id, nonce)`` is the unique constraint, ``expires_at`` is indexed for future
  maintenance pruning.
- ``audit_events`` — append-only hash-chain storage; ``canonical_event_bytes`` holds
  the exact canonical JSON the hash was computed over; the unique
  ``(chain_id, sequence_number)`` constraint is the final integrity guard.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "d15b46c49950"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Create the Phase 0b security-foundation tables."""
    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("chain_id", sa.Text(), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("canonical_event_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("chain_id", "sequence_number", name="uq_audit_events_chain_sequence"),
    )
    op.create_table(
        "host_request_nonces",
        sa.Column("key_id", sa.Text(), nullable=False),
        sa.Column("nonce", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key_id", "nonce"),
    )
    op.create_index(
        op.f("ix_host_request_nonces_expires_at"),
        "host_request_nonces",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    """Drop the Phase 0b security-foundation tables."""
    op.drop_index(op.f("ix_host_request_nonces_expires_at"), table_name="host_request_nonces")
    op.drop_table("host_request_nonces")
    op.drop_table("audit_events")
