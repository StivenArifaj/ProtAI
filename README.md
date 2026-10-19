# AI Agent Security & Safety Platform

Repository foundation for the AI Agent Security & Safety Platform. The authoritative
specification is `AI_Agent_Security_Platform_Master_Blueprint_v1.2.md` in the repository
root; the archived v1.0 is under `archive/` and is superseded.

**Current state: Phase 0a (repository foundation) only.** The application exposes liveness
and readiness endpoints and enforced configuration validation. No security control from
Phase 0b or later (host authentication, policy engine, tool firewall, DLP, audit chain)
is implemented yet, and nothing in this repository should be presented as providing them.
See `docs/IMPLEMENTATION_STATE.md` and `docs/KNOWN_LIMITATIONS.md`.

## Prerequisites

- Python project tooling: [uv](https://docs.astral.sh/uv/) (`uv --version`)
- Docker Desktop (for the Compose database and API container)
- macOS or Linux shell

## Setup and baseline checks (no Docker required)

```bash
uv sync --frozen          # install from the committed lockfile
uv run pytest             # baseline unit + integration tests
bash scripts/check.sh     # full local gate: lockfile, ruff, mypy, pytest, invariant greps
```

`scripts/check.sh` exits non-zero on any failure.

## Local run without Docker

The readiness probe needs a reachable PostgreSQL instance; liveness does not.

```bash
cp .env.example .env      # local development values only; replace `db` with 127.0.0.1
uv run uvicorn ai_security.api.app:app --host 127.0.0.1 --port 8080
curl -s http://127.0.0.1:8080/health/live
curl -s http://127.0.0.1:8080/health/ready
```

## Docker Compose (API + PostgreSQL)

```bash
docker compose up -d db       # start PostgreSQL and wait until healthy
docker compose up api         # start the API (foreground)
curl -s http://127.0.0.1:8080/health/live
```

Expected results:

- `GET /health/live` returns `200 {"status":"alive"}`.
- `GET /health/ready` returns `200 {"status":"ready","checks":{"config":true,"database":true}}`
  when the database is reachable, and `503 {"status":"not_ready",...}` when it is not.
  Neither response contains credentials or stack details.
- `/docs`, `/redoc`, and `/openapi.json` exist only when `APP_ENV` is exactly
  `development` or `test`; they are absent otherwise.

Stop the stack with `docker compose down` (add `-v` to drop the database volume).

## Configuration

All configuration is environment-based; see `.env.example` (blueprint section 5.4). Key
rules enforced at startup:

- `APP_ENV` is required and must be one of `development`, `test`, `staging`, `production`;
  unknown values fail startup.
- `DATABASE_URL` must use the `postgresql+asyncpg://` scheme (ADR-005).
- The sample database password (`firewall_dev_only`) is refused outside
  `development`/`test`.

Configuration errors fail startup with a clear message; the process never starts in a
partially configured state.

## Documentation map

- `docs/ARCHITECTURE.md` — component map and request lifecycle
- `docs/THREAT_MODEL.md` — threat table and trust boundaries with implementation status
- `docs/SECURITY_INVARIANTS.md` — the 25 mandatory invariants and their status
- `docs/POLICY_DECISION_MATRIX.md` — the mandated v1 decision matrix (specification)
- `docs/DECISIONS.md` + `docs/adr/` — architecture decision records
- `docs/IMPLEMENTATION_STATE.md` — what exists, what is verified, what is deferred
- `docs/KNOWN_LIMITATIONS.md` — known gaps of the current phase
