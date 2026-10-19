# Project Context

## What this is

A personal engineering project that builds an **AI Agent Security & Safety Platform**: a
deterministic authorization and safety gateway that sits between an AI agent runtime
(and its users) and any tool execution. The central idea: the model is never an
authority. Every tool action is evaluated by a mandatory firewall gateway
(identity → policy → risk → approval → execution) surrounded by input defense,
output/egress DLP, and a tamper-evident audit trail, so a prompt-injected or manipulated
model can only do what policy already permits.

Authoritative specification: [../AI_Agent_Security_Platform_Master_Blueprint_v1.2.md](../AI_Agent_Security_Platform_Master_Blueprint_v1.2.md)
("blueprint v1.2"). The superseded v1.0 archive is at
[../archive/AI_Agent_Security_Platform_Master_Blueprint_v1.0_superseded.md](../archive/AI_Agent_Security_Platform_Master_Blueprint_v1.0_superseded.md).

## Goals (v1)

- Deterministic, unbypassable authorization at the point of every side effect
  (blueprint §§3–4, 10, 12).
- Host-to-gateway HMAC authentication with no bypass mode, including in development (§9).
- Defense in depth: input threat signals support but never replace enforcement (§§2–3).
- Output and egress DLP with v1 streaming disabled — buffer, inspect, then release (§15).
- Tamper-evident, Postgres-serialized audit hash chain (§16, ADR-002).
- Evaluation-driven claims: no "secure" claim beyond measured, tested evidence
  (§19, §23).

## Non-goals (explicit, from the blueprint)

- No claim of complete prompt-injection prevention, "production-grade",
  "enterprise-ready", or "fully secure" language (§23).
- No real tools, real inboxes, real company data, or cloud model calls in v1; mock tools
  only (§14.1); external model calls disabled by default (§5).
- No arbitrary shell execution, ever, in v1 (§14.2).
- No token streaming in v1 (§15.1, ADR-003).
- No LLM involvement in authorization decisions (§10, §22.2).
- No AI SOC containment actions: the future SOC analyzer is read-only and alert-only
  (§17, ADR-004).

## Fixed technical decisions ("final non-negotiable principle")

These are settled design decisions, not open questions for an implementer to re-litigate:

- Transport contract: HMAC-authenticated host-to-gateway requests (§9.2, ADR-001).
- Persistence contract: SQLAlchemy 2.x async + asyncpg + Alembic (ADR-005, ADR-006).
- Audit chain: appended under a PostgreSQL transaction-scoped advisory lock with exact
  canonical bytes and hash formula defined by ADR-002/§16.2.
- v1 response streaming disabled (ADR-003).
- Approval consumption atomic and one-time (§13, Phase 5).
- SOC analyzer read-only/alert-only; attacker-influenced fields treated as untrusted
  (§17, ADR-004).

## Stack (current, verified in Phase 0a)

- Python `>=3.12,<3.13` (3.12.15 in use), managed with uv 0.13.1.
- FastAPI + uvicorn; pydantic / pydantic-settings; asyncpg (readiness probe today;
  SQLAlchemy async layer in Phase 0b).
- PostgreSQL 17 (Compose image `postgres:17.2-alpine`); Docker Compose for local dev.
- pytest + httpx2 (needed by Starlette 1.9's `TestClient`), ruff, mypy (strict, `src/`).
- `scripts/check.sh` is the local quality gate; no CI system is configured.

## Operator and environment

- Single operator (personal project), macOS (darwin), local development only.
- Working copy: `/Users/stiven/ProtAI`.
- The repository is **not yet under git version control** (operator's decision pending).
- Docker Desktop must be running for the Compose path. The stack is normally stopped
  (`docker compose down`); the `db_data` volume is preserved.
- Local ports: Compose publishes the API on host `127.0.0.1:8080` (host port 8000 is
  commonly occupied by unrelated local emulators) and PostgreSQL on `127.0.0.1:5432`.
  The container itself listens on port 8000.
