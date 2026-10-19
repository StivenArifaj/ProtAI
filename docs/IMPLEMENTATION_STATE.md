# Implementation State

Last updated: 2026-10-19 (Phase 0a, blueprint v1.2; Docker verification completed).

Phase 0a is **scaffold- and documentation-complete and fully verified** (including the
Docker Compose path). It does not implement any security control that Phase 0b or later
phases provide; see `docs/SECURITY_INVARIANTS.md` and `docs/KNOWN_LIMITATIONS.md`.

## What exists

| Area | Files | Notes |
|---|---|---|
| Project metadata | `pyproject.toml`, `uv.lock`, `.python-version` (3.12), `.gitignore`, `.env.example`, `README.md`, `Makefile` | Python `>=3.12,<3.13`; runtime deps: fastapi, uvicorn, pydantic, pydantic-settings, asyncpg; dev deps: pytest, httpx2, ruff, mypy |
| Application | `src/ai_security/__init__.py`, `settings.py`, `api/app.py`, `api/dependencies.py`, `api/routes_health.py` | App factory + module-level `app`; validated settings; `/health/live`, `/health/ready` |
| Tests | `tests/conftest.py`, `tests/unit/test_settings.py`, `tests/integration/test_health.py` | 25 tests: settings validation, secret masking, health behavior, docs gating, readiness 200/503 paths |
| Quality gate | `scripts/check.sh` | Lockfile check, ruff format/lint, mypy (src), pytest, invariant greps; exits non-zero on any failure |
| Containers | `Dockerfile`, `docker-compose.yml` | python:3.12.8-slim-bookworm and uv 0.13.1 pinned **by digest**; non-root runtime user (uid 10001 verified); api + postgres:17.2-alpine, ports bound to 127.0.0.1 (API on host port 8080; container port 8000), healthchecks, `depends_on: service_healthy` |
| Docs | `docs/ARCHITECTURE.md`, `THREAT_MODEL.md`, `SECURITY_INVARIANTS.md`, `POLICY_DECISION_MATRIX.md`, `DECISIONS.md`, `KNOWN_LIMITATIONS.md`, `docs/adr/ADR-001..007` | ADR-001..007 recorded per blueprint section 21; status columns are honest (mostly "not implemented") |
| Spec | `AI_Agent_Security_Platform_Master_Blueprint_v1.2.md`, `archive/..._v1.0_superseded.md` | v1.2 authoritative; v1.0 archived |

Deliberately deferred (Phase 0b per blueprint section 21): HMAC host auth, nonce/replay
persistence, SQLAlchemy persistence, Alembic baseline, `DevPrincipalResolver` guard,
policy self-check scaffolding, Gitleaks in `check.sh`. `config/`, `migrations/`, and
`evaluation/` directories do not exist yet; they belong to later phases.

## Decisions taken during implementation (within blueprint constraints)

- **App factory + module-level `app`.** `create_app(settings)` builds the app; a
  module-level `app = create_app()` supports the documented
  `uvicorn ai_security.api.app:app` command (required by the Phase 0b refusal command).
  Tests always pass explicit settings.
- **Required `APP_ENV`, no default.** Missing/unknown environment values fail startup
  rather than defaulting to a permissive mode.
- **Sample-credential refusal is implemented for `DATABASE_URL` in Phase 0a** (part of
  "settings validation"); the HMAC sample-key refusal waits for Phase 0b when
  `HOST_AUTH_KEYS_JSON` is consumed.
- **Readiness probe uses asyncpg directly** (2 s timeout) because SQLAlchemy persistence
  is Phase 0b; it is a FastAPI dependency so tests override it. It never logs or returns
  credentials; only the exception class name is debug-logged.
- **Dev dependency `httpx2` instead of `httpx`.** Starlette 1.9's `TestClient` requires
  `httpx2` and deprecates `httpx`; `httpx2` is the maintained successor in the HTTPX
  family referenced by blueprint section 5.1.
- **`.env.example` carries the full blueprint section 5.4 variable set** with a header
  explaining which values are consumed now (Phase 0a) and which arrive in Phase 0b.
- **Blueprint/archive markdown excluded from ruff** so authoritative documents are
  never reformatted (`extend-exclude` in `pyproject.toml`).
- **API host port is 8080** in Compose because port 8000 is commonly occupied by local
  emulators (DynamoDB Local was running on this machine during verification); the
  container still listens on 8000. Ports bind to 127.0.0.1 only.
- **Base images pinned by digest** (`python:3.12.8-slim-bookworm@sha256:2199a628...`,
  `ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666...`) per blueprint section 5.1.

## Verification record (actual runs, 2026-10-19)

Environment: macOS (darwin), uv 0.13.1, CPython 3.12.15, Docker 29.3.1 / Compose
v5.1.1 (Docker Desktop started for this verification).

| # | Command | Result |
|---|---|---|
| 1 | `uv sync --frozen` | PASS — installs from committed lockfile, 38 packages resolved, no drift |
| 2 | `uv run pytest` | PASS — 25 passed, 0 warnings |
| 3 | `bash scripts/check.sh` (clean) | PASS — exit 0, all six steps |
| 4 | `bash scripts/check.sh` (injected failing test) | PASS (expected failure) — exit 1 at pytest step: "CHECK FAILED: test failures reported"; the injected failure was also caught at the ruff format and lint steps in earlier iterations |
| 5 | `bash scripts/check.sh` (after removing injected test) | PASS — exit 0 |
| 6 | `docker compose config -q` | PASS — syntax valid |
| 7 | `docker compose up -d db` | PASS — `protai-db-1` reports **healthy** (`pg_isready` healthcheck) |
| 8 | `docker compose build api` | PASS — image builds from digest-pinned base images; dependencies from `uv.lock` only |
| 9 | `docker compose up -d api` | PASS — `protai-api-1` reports **healthy**; `depends_on: service_healthy` honored |
| 10 | Host checks against Compose (dev profile) | `/health/live` → 200 `{"status":"alive"}`; `/health/ready` → **200** `{"status":"ready","checks":{"config":true,"database":true}}` against the real PostgreSQL; `/docs` → 200; `/openapi.json` → 200; leak check found 0 occurrences of credentials/DNS/port |
| 11 | Non-root runtime check | `docker compose exec -T api id` → `uid=10001(app)` |
| 12 | Production profile inside the container (`docker compose run` with `APP_ENV=production`, non-sample password) | `/health/live` → 200; `/docs`, `/redoc`, `/openapi.json` → 404; `/health/ready` → 503 `{"status":"not_ready","checks":{"config":true,"database":false}}` — correct: the non-sample password does not match the dev database, and dev credentials are refused in production mode by design, so readiness honestly reports the database as not reachable |
| 13 | In-container startup refusal (production + sample password) | PASS — container exits 1 with `refusing the sample development database password outside development/test` |
| 14 | Live dev run without Docker (uvicorn 127.0.0.1:8011) | `/health/live` → 200; `/health/ready` → 503 (no database); `/docs` → 200 |
| 15 | Startup refusal: `APP_ENV` missing | PASS — exits 1 with `app_env Field required` |
| 16 | Startup refusal: wrong scheme (`postgresql+psycopg://`) | PASS — exits 1 with clear scheme error referencing ADR-005 |
| 17 | Fresh-checkout approximation (clean copy without `.venv`/caches, 34 files) | PASS — `uv sync --frozen` then `bash scripts/check.sh` exit 0 |

The Compose stack was torn down with `docker compose down` after verification (the
database volume is preserved for future local runs).

## Definition of Done checklist (blueprint section 21, Phase 0a)

| DoD item | Status |
|---|---|
| Fresh clone setup succeeds on macOS with Docker using only documented commands | **PASS** — clean-copy setup verified without Docker (row 17); Compose path verified end-to-end (rows 7-11) |
| Configuration errors are clear and fail startup | PASS (rows 13, 15, 16; 25 unit/integration tests) |
| No secrets committed | PASS as far as a non-git tree allows — only documented public sample/placeholder values exist in `.env.example` and `docker-compose.yml` (disposable dev values per blueprint 5.4); automated secret scanning (Gitleaks) arrives in Phase 0b; the repository is not yet a git repository |
| `scripts/check.sh` exits non-zero on any failure | PASS (rows 3-5) |
| Health and OpenAPI checks pass | PASS — dev profile with real database (row 10, readiness 200), production profile gating (row 12), no leaks (row 10) |
| No claim of Phase 0b security controls | PASS (docs status columns; no auth code exists) |

## How to continue (next session)

1. Recommended: initialize git and commit the Phase 0a scaffold so it becomes a
   reviewable baseline.
2. Phase 0b per blueprint section 21: HMAC-SHA256 host auth (§9.2), timestamp/nonce
   replay rejection (`host_request_nonces`), SQLAlchemy 2.x async layer, Alembic
   baseline, `DevPrincipalResolver` startup guard, `config/policy_self_checks.yaml`
   scaffolding wired into readiness, Gitleaks in `scripts/check.sh`, and the
   authentication-failure/startup-invariant tests. All `/v1/*` routes must enforce HMAC
   before principal resolution, including `PRINCIPAL_RESOLVER=dev`.
