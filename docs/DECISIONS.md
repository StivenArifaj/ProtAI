# Architecture Decision Records — Index

This index links to one file per ADR under `docs/adr/`. It intentionally contains only
summaries; the full decision text lives in each ADR (blueprint section 21). ADR-001
through ADR-007 are required to be recorded before Phase 1 and were all recorded here on
2026-10-19; ADR-008 records the Phase 1 policy-engine contract; ADR-009 records the
Phase 2 registry/gateway contract; ADR-010 records the Phase 3 advisory input-defense,
trust-label, and session-signal contract; ADR-011 records the Phase 4 server-issued
intent-manifest and constraint contract; ADR-012 records the Phase 5 `risk-v2` and
durable one-time approval contract; ADR-013 records the Phase 6 output-DLP and
destination-aware egress contract.

| ADR | Title | Status | Implementation phase |
|---|---|---|---|
| [ADR-001](adr/ADR-001-host-hmac-authentication.md) | Host-to-gateway HMAC-SHA256 authentication and development-resolver guard | Accepted | Phase 0b |
| [ADR-002](adr/ADR-002-audit-hash-chain.md) | Postgres-serialized audit hash-chain append and exact canonical byte format | Accepted | Phase 7 (append protocol scaffolding in Phase 0b) |
| [ADR-003](adr/ADR-003-no-token-streaming.md) | v1 token streaming disabled: buffer, inspect, then release | Accepted | Phase 6/8 (no streaming route exists before then) |
| [ADR-004](adr/ADR-004-soc-alert-only.md) | AI SOC analyzer treated as an injection target and alert-only | Accepted | Phase 10 |
| [ADR-005](adr/ADR-005-sqlalchemy-async-persistence.md) | SQLAlchemy 2.x async persistence with asyncpg | Accepted | Phase 0b |
| [ADR-006](adr/ADR-006-alembic-migrations.md) | Alembic for all schema changes; `create_all` only in isolated unit-test fixtures | Accepted | Phase 0b |
| [ADR-007](adr/ADR-007-policy-matrix-self-checks.md) | Policy decision matrix mirrored in docs/config with startup self-checks | Accepted | Phase 1 (self-check scaffolding in Phase 0b) |
| [ADR-008](adr/ADR-008-policy-engine-typed-contracts.md) | Deterministic policy engine with strict typed contracts and versioned policy bundle | Accepted | Phase 1 |
| [ADR-009](adr/ADR-009-tool-registry-and-enforced-gateway.md) | Tool registry, execution authorization, and the enforced gateway | Accepted | Phase 2 |
| [ADR-010](adr/ADR-010-advisory-input-defense-and-session-signals.md) | Advisory input threat defense, trust labels, and session signals | Accepted | Phase 3 |
| [ADR-011](adr/ADR-011-server-issued-intent-manifests.md) | Server-issued, sealed intent manifests and concrete action constraints | Accepted | Phase 4 |
| [ADR-012](adr/ADR-012-risk-v2-and-human-approvals.md) | Versioned risk v2 and durable, one-time human approvals | Accepted | Phase 5 |
| [ADR-013](adr/ADR-013-output-dlp-and-egress.md) | Mandatory output DLP, exact destination trust, and complete-response release/suppression | Accepted | Phase 6 |

## Adding a new ADR

1. Copy the format of an existing ADR: Status, Date, Context, Decision, Consequences,
   References.
2. Use the next sequential number; never renumber existing ADRs.
3. Add a row to this index; do not paste the full ADR text here.
4. Superseding an ADR requires setting its status to `Superseded by ADR-NNN` and
   recording the replacement.
