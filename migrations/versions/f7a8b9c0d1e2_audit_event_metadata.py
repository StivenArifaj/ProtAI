"""Phase 7: queryable audit-event metadata derived from canonical payloads.

Revision ID: f7a8b9c0d1e2

The hash chain is unchanged: ``canonical_event_bytes`` remains the only hashed event
representation and the verifier re-hashes those exact bytes. This migration adds
nullable correlation columns (``event_type``, ``request_id``, ``trace_id``,
``call_id``, ``occurred_at``, ``component``) with indexes, then backfills every
historical row whose canonical payload contains the field.

Backfill uses PostgreSQL JSON extraction over the existing bytes. It is non-destructive
and never rewrites canonical bytes or chain hashes. The backfill is a one-time row loop
whose per-row exception leaves corrupt historical bytes unbackfilled instead of aborting
the upgrade; the verifier then reports those rows as invalid/non-canonical payloads.
Rows appended by raw fixture tests that do not contain these keys remain NULL; the
verifier treats NULL metadata as absent and only compares metadata that exists.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "f7a8b9c0d1e2"
down_revision: str | None = "e5a1c2b3d4f6"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Add and backfill derived audit metadata columns and indexes."""
    op.add_column("audit_events", sa.Column("event_type", sa.String(length=64), nullable=True))
    op.add_column("audit_events", sa.Column("request_id", sa.Text(), nullable=True))
    op.add_column("audit_events", sa.Column("trace_id", sa.Text(), nullable=True))
    op.add_column("audit_events", sa.Column("call_id", sa.Text(), nullable=True))
    op.add_column(
        "audit_events", sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("audit_events", sa.Column("component", sa.String(length=64), nullable=True))

    # Fixed migration SQL over a fixed table/column set; no user input is interpolated.
    # The per-row handler keeps a single corrupt historical payload from blocking the
    # upgrade; such rows stay unbackfilled and are flagged by the verifier.
    op.execute(
        """
        DO $$
        DECLARE
            event_row RECORD;
            payload jsonb;
        BEGIN
            FOR event_row IN SELECT id, canonical_event_bytes FROM audit_events LOOP
                BEGIN
                    payload := convert_from(event_row.canonical_event_bytes, 'UTF8')::jsonb;
                    UPDATE audit_events
                    SET
                        event_type = payload ->> 'event_type',
                        request_id = payload ->> 'request_id',
                        trace_id = payload ->> 'trace_id',
                        call_id = payload ->> 'call_id',
                        component = payload ->> 'component',
                        occurred_at = (payload ->> 'occurred_at')::timestamptz
                    WHERE id = event_row.id;
                EXCEPTION WHEN others THEN
                    NULL;
                END;
            END LOOP;
        END
        $$
        """
    )

    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"], unique=False)
    op.create_index(
        "ix_audit_events_request_sequence",
        "audit_events",
        ["request_id", "chain_id", "sequence_number"],
        unique=False,
    )
    op.create_index(
        "ix_audit_events_trace_sequence",
        "audit_events",
        ["trace_id", "chain_id", "sequence_number"],
        unique=False,
    )
    op.create_index("ix_audit_events_occurred_at", "audit_events", ["occurred_at"], unique=False)


def downgrade() -> None:
    """Drop derived metadata columns and indexes (canonical bytes are untouched)."""
    op.drop_index("ix_audit_events_occurred_at", table_name="audit_events")
    op.drop_index("ix_audit_events_trace_sequence", table_name="audit_events")
    op.drop_index("ix_audit_events_request_sequence", table_name="audit_events")
    op.drop_index("ix_audit_events_event_type", table_name="audit_events")
    op.drop_column("audit_events", "component")
    op.drop_column("audit_events", "occurred_at")
    op.drop_column("audit_events", "call_id")
    op.drop_column("audit_events", "trace_id")
    op.drop_column("audit_events", "request_id")
    op.drop_column("audit_events", "event_type")
