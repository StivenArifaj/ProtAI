"""Phase 5: durable approval requests bound to canonical actions.

Revision ID: e5a1c2b3d4f6

Table (blueprint section 13.2):

- ``approval_requests`` — one row per human-approval request. Stores only a SHA-256
  token digest, the canonical action digest, requester/tenant and policy binding,
  canonical resources/destination, class/risk provenance, approver rule, status,
  expiry, and verified-decision/consumption metadata. Raw arguments and approval
  secrets are never stored. The row is transitioned exactly once from ``approved`` to
  ``consumed`` inside the transaction that also appends the audit event.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "e5a1c2b3d4f6"
down_revision: str | None = "c7f1a2b3d4e5"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Create the approval request table."""
    op.create_table(
        "approval_requests",
        sa.Column("approval_id", sa.String(length=32), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=True),
        sa.Column("requester_subject_id", sa.Text(), nullable=False),
        sa.Column("request_id", sa.Text(), nullable=False),
        sa.Column("tool_id", sa.Text(), nullable=False),
        sa.Column("action_id", sa.Text(), nullable=False),
        sa.Column("action_digest", sa.String(length=64), nullable=False),
        sa.Column("resource_ids", sa.JSON(), nullable=False),
        sa.Column("destination", sa.Text(), nullable=True),
        sa.Column("side_effect_class", sa.Text(), nullable=False),
        sa.Column("data_class", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.BigInteger(), nullable=False),
        sa.Column("risk_version", sa.String(length=32), nullable=False),
        sa.Column("risk_factor_codes", sa.JSON(), nullable=False),
        sa.Column("policy_version", sa.Text(), nullable=False),
        sa.Column("policy_hash", sa.String(length=64), nullable=False),
        sa.Column("required_approver_rule", sa.Text(), nullable=False),
        sa.Column("self_approval_allowed", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("token_consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_by_subject_id", sa.Text(), nullable=True),
        sa.Column("decided_by_tenant_id", sa.Text(), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'denied', 'consumed', 'expired')",
            name="ck_approval_status",
        ),
        sa.CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100",
            name="ck_approval_risk_score",
        ),
        sa.PrimaryKeyConstraint("approval_id"),
    )
    op.create_index(
        "ix_approval_requests_status_expiry",
        "approval_requests",
        ["status", "expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_approval_requests_requester",
        "approval_requests",
        ["tenant_id", "requester_subject_id"],
        unique=False,
    )


def downgrade() -> None:
    """Drop the approval request table."""
    op.drop_index("ix_approval_requests_requester", table_name="approval_requests")
    op.drop_index("ix_approval_requests_status_expiry", table_name="approval_requests")
    op.drop_table("approval_requests")
