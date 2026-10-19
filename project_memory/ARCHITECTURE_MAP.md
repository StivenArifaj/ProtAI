# Architecture Map

Two views: what is implemented today (verified) and the target v1 architecture from the
blueprint. Full narrative and the per-request lifecycle: [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)
(mark status per component there as well). **Nothing under "Target v1" may be claimed as
existing.**

## Implemented today (Phase 0a — VERIFIED 2026-10-19)

Components:

- `ai_security.settings` (`../src/ai_security/settings.py`): pydantic-settings model.
  `APP_ENV` required (`development`/`test`/`staging`/`production`); `LOG_LEVEL` default
  `INFO`; `DATABASE_URL` `SecretStr`. Fail-closed validation: unknown enum values
  rejected; scheme must be `postgresql+asyncpg://` (ADR-005); the documented sample
  development password is refused outside `development`/`test`. `database_dsn` property
  rewrites the scheme for asyncpg.
- `ai_security.api.app` (`../src/ai_security/api/app.py`): `create_app(settings)` factory
  plus module-level `app`. `/docs`, `/redoc`, `/openapi.json` registered only in
  `development`/`test`. Startup fails on bad configuration (no partially-configured
  process).
- `ai_security.api.routes_health`: `GET /health/live` → 200 `{"status":"alive"}`;
  `GET /health/ready` → 200 `{"status":"ready","checks":{...}}` or 503 `{"status":
  "not_ready",...}`; only booleans, never credentials or stack details.
- `ai_security.api.dependencies`: `get_settings`; `database_ready` FastAPI dependency
  (overridable in tests). The real probe opens a short-lived asyncpg connection, runs
  `SELECT 1`, 2 s timeout, and logs only the exception class on failure.

Request flow today:

```text
uvicorn → FastAPI app → /health/* router → database_ready → asyncpg SELECT 1 → JSON
```

Data: PostgreSQL 17 runs only as the readiness target. No schema, no migrations, no
repositories; the application persists nothing.

## Target v1 (blueprint §§3–4) — NOT IMPLEMENTED

Logical flow (abbreviated; full diagram in [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)):

```text
Host app → HMAC-authenticated /v1/* → intake bounds + provenance labels
  → input signals → typed intent → agent runtime (optional)
  → firewall gateway: principal/session binding, tool + strict schema, hard policy,
    intent constraints, egress/data classification, deterministic risk
    → ALLOW | BLOCK | ASK_USER → controlled adapter execution
  → tool result (untrusted context) → output/egress DLP
  → structured audit events + metrics + alerts
```

Component map with planned phases (status: NOT IMPLEMENTED unless noted):

| Component | Phase | Purpose |
|---|---|---|
| `identity/` (HMAC host auth, resolver guard) | 0b | Authenticate host, verify principal before anything else |
| `security/` (canonical bytes, constant-time helpers) | 0b/1 | Signing message, `hmac.compare_digest` wrappers |
| `persistence/` (SQLAlchemy 2.x async) | 0b | Engine/session, nonce store, later repositories |
| `migrations/` + `alembic.ini` | 0b | Schema management (ADR-006) |
| `config/policy_self_checks.yaml` (+ policy/thresholds later) | 0b/1 | Startup/CI self-check fixtures |
| `input_defense/` | 3 | Heuristics, detector, provenance labels |
| `intent/` | 4 | Bounded intent manifest, constraints, request binding |
| `agent/` + providers | 4/8 | Runtime; mock/local model adapters |
| `firewall/` (gateway, policy, risk, approvals) | 1–5 | The mandatory enforcement chokepoint |
| `tools/` (mock email/files/sink) | 2 | Mock adapters only; no real connectors in v1 |
| `data_security/` (classification, DLP, egress) | 6 | Output and egress inspection |
| `audit/` (hash chain) | 7 (scaffold 0b) | Serialized append, verifier |
| `api/` `/v1/*` routes | 8 | Request/tool/approval endpoints |
| `soc/` (alert-only) | 10 | Deterministic alerts; read-only analyzer |
| `evaluation/` | 9 | Dataset, metrics, reproducible reports |

Requested path today (implemented route surface): only `/health/live` and `/health/ready`.
`/v1/*` routes do not exist; when they arrive (Phase 8 wiring; test contracts earlier),
they MUST enforce HMAC before principal resolution (blueprint §18.2).

## Structural rules that bind every future change

- The firewall gateway is the mandatory execution chokepoint; no component executes a
  tool directly, and the agent never calls real adapters directly (§12.1, §22.2).
- `policy_engine.py` and `risk_engine.py` are deterministic and make no network calls
  ([../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md), import boundaries).
- Development order ≠ runtime order: typed schemas + policy + unbypassable mock gateway
  first; input detection before powerful tools (§21 work-order note).
- Detectors never become the policy authority; model output is never authorization.
- API routers orchestrate; they do not duplicate policy logic.
- Evaluation code is never imported into runtime request processing.
