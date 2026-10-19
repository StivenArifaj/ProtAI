# ADR-006: Alembic for all schema changes

- **Status:** Accepted
- **Date:** 2026-10-19
- **Implementation:** Phase 0b

## Context

Schema created implicitly by `Base.metadata.create_all()` at application startup has no
version history, no reviewable diffs, and no safe upgrade path. Replay protection,
approval state transitions, and audit-chain serialization all depend on precise,
reviewed schema.

## Decision

- All deployed schema changes are Alembic migrations (`migrations/`, `alembic.ini`);
  Phase 0b provides the baseline migration and a documented command
  (`uv run alembic upgrade head`).
- `Base.metadata.create_all()` is allowed only in isolated unit-test fixtures, never as
  the deployed schema-management mechanism.
- Migrations are idempotent per Alembic revision state; applying an already-applied
  revision reports "already at head".
- Every migration is reviewed like code and references the ADR/data contract it
  implements where relevant.

## Consequences

- Deployment requires an explicit migration step; startup does not silently alter
  schema — a deliberate fail-fast trade-off.
- Test fixtures and local development use the same migrations to avoid drift.

## References

Blueprint v1.2 sections 5.1, 21 (Phase 0b).
