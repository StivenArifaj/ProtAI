# ADR-005: SQLAlchemy 2.x async persistence with asyncpg

- **Status:** Accepted
- **Date:** 2026-10-19
- **Implementation:** Phase 0b

## Context

The platform persists policy/approval/audit metadata in PostgreSQL and needs
transactional integrity for replay protection and (later) serialized audit appends. The
HTTP stack is async (FastAPI/uvicorn); mixing sync database drivers with async request
handling invites thread-pool stalls and inconsistent transaction boundaries.

## Decision

- Use SQLAlchemy 2.x async ORM/Core with `asyncpg` as the PostgreSQL async driver
  throughout the persistence layer (`src/ai_security/persistence/`).
- `DATABASE_URL` uses the `postgresql+asyncpg://` scheme; settings validation rejects
  other schemes at startup (implemented in Phase 0a).
- Transaction boundaries are explicit and repositories stay thin; domain modules do not
  open ad-hoc connections or mix raw driver calls with ORM calls.
- Phase 0a's readiness probe is the deliberate exception: it uses asyncpg directly
  because the persistence layer does not exist yet. It will be folded into the
  persistence module in Phase 0b.

## Consequences

- One consistent async data-access pattern; easier to reason about locks and
  transactions for replay protection and audit serialization.
- asyncpg is the single supported driver; alternative drivers would require an ADR
  update.
- Unit tests must not require a live database except where explicitly marked
  integration tests.

## References

Blueprint v1.2 sections 5.1, 16, 21 (Phase 0b).
