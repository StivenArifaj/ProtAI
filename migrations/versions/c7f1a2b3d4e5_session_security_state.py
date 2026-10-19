"""Phase 3: session security state for multi-turn detection signals.

Revision ID: c7f1a2b3d4e5

Table (blueprint section 7.4):

- ``session_security_state`` — bounded per-session detection signals keyed by the
  internal CSPRNG session id, with the ``(tenant_id, subject_id)`` binding re-checked on
  every access. Only counters/timestamps are stored (no raw prompts). Expiry (24 h
  inactivity TTL, 7 d maximum lifetime) is enforced in the repository, including lazy
  cleanup on read.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "c7f1a2b3d4e5"
down_revision: str | None = "d15b46c49950"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Create the session security state table."""
    op.create_table(
        "session_security_state",
        sa.Column("session_id", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("subject_id", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("override_attempts", sa.BigInteger(), nullable=False),
        sa.Column("privilege_escalation_signals", sa.BigInteger(), nullable=False),
        sa.Column("blocked_tool_proposals", sa.BigInteger(), nullable=False),
        sa.Column("threat_findings", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("override_attempts >= 0", name="ck_session_override_nonnegative"),
        sa.CheckConstraint(
            "privilege_escalation_signals >= 0",
            name="ck_session_privilege_nonnegative",
        ),
        sa.CheckConstraint("blocked_tool_proposals >= 0", name="ck_session_blocked_nonnegative"),
        sa.CheckConstraint("threat_findings >= 0", name="ck_session_findings_nonnegative"),
        sa.PrimaryKeyConstraint("session_id"),
    )
    op.create_index(
        "ix_session_security_state_binding",
        "session_security_state",
        ["tenant_id", "subject_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_session_security_state_last_seen_at"),
        "session_security_state",
        ["last_seen_at"],
        unique=False,
    )


def downgrade() -> None:
    """Drop the session security state table."""
    op.drop_index(
        op.f("ix_session_security_state_last_seen_at"),
        table_name="session_security_state",
    )
    op.drop_index(
        "ix_session_security_state_binding",
        table_name="session_security_state",
    )
    op.drop_table("session_security_state")
