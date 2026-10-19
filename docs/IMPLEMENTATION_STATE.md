# Implementation State

Last updated: 2026-10-19 (Phase 0b, blueprint v1.2; Docker verification completed).

Phases 0a (repository foundation) and 0b (security foundation) are **complete and
verified**, including the Docker Compose path. Phase 0b implements host authentication,
replay rejection, persistence + migrations, the development-resolver guard, policy
self-check scaffolding, and pinned secret scanning. It does **not** implement
authorization, the tool gateway, approvals, DLP/egress, or audit event emission; see
`docs/SECURITY_INVARIANTS.md` and `docs/KNOWN_LIMITATIONS.md`.

## What exists

| Area | Files | Notes |
|---|---|---|
| Project metadata | `pyproject.toml`, `uv.lock`, `.python-version` (3.12), `.gitignore`, `.env.example`, `README.md`, `Makefile`, `.gitleaks.toml` | Python `>=3.12,<3.13`; runtime deps: fastapi, uvicorn, pydantic, pydantic-settings, asyncpg, SQLAlchemy 2.x async, Alembic, PyYAML; dev deps: pytest, httpx2, ruff, mypy, types-PyYAML |
| Application | `src/ai_security/__init__.py`, `settings.py`, `api/{app,dependencies,routes_health,middleware}.py` | App factory + module-level `app`; validated settings; `/health/live`, `/health/ready` (now: config, database, policy_self_checks); host-auth ASGI middleware on `/v1/*` |
| Security primitives | `security/{constant_time,canonical_json}.py`, `audit/hash_chain.py` | `hmac.compare_digest` wrappers (confined by the gate); canonical JSON bytes; ADR-002 hash formula + fixed vectors |
| Identity | `identity/{models,signing,host_auth,resolver}.py` | `Principal` (strict, frozen); HMAC signing/verification (exact `v1` message, full rejection surface); `DevPrincipalResolver` guard + fail-closed `HostPrincipalResolver` |
| Persistence | `persistence/{database,models,nonce_repository,audit_repository}.py` | Async engine/session; atomic nonce upsert (`ON CONFLICT ... WHERE ... RETURNING`); ADR-002 advisory-lock audit append |
| Migrations | `alembic.ini`, `migrations/env.py`, `migrations/versions/d15b46c49950_*.py` | Baseline: `host_request_nonces`, `audit_events`; `make migrate`; idempotent; `alembic check` clean |
| Policy scaffolding | `policy/{interim_matrix,self_checks}.py`, `config/policy_self_checks.yaml` | Interim transcription of the v1 matrix (labeled scaffolding; Phase 1 replaces); 16 fixtures; startup + readiness enforcement (ADR-007) |
| Tests | `tests/conftest.py`, `tests/unit/*` (8 files), `tests/integration/*` (6 files incl. helpers) | **231 tests**: settings, primitives, hash chain, verifier matrix, resolver, policy self-checks, health, middleware denial matrix, nonce/audit repositories, migration idempotency |
| Quality gate | `scripts/check.sh` | 8 steps: lockfile, ruff format, ruff lint, mypy, pytest, pinned Gitleaks (dir+git), prohibited-pattern greps, constant-time confinement |
| Containers | `Dockerfile`, `docker-compose.yml` | Digest-pinned bases; non-root uid 10001; COPY `config/ migrations/ alembic.ini`; Compose `api` carries the disposable dev `HOST_AUTH_KEYS_JSON` |
| Docs | `docs/*` (8 files), `docs/adr/ADR-001..007` | Status columns honest; ADR-007 scaffolding now realized in `config/` + startup/readiness |
| Git | baseline `41e10da`; 0b commits `0aa11d9`, `9b3f153`, `42e8b71`, `4d18e27`, `28bede9`, `a5794cc`, `d180b89` | Repository under git since 2026-10-19; linear history on `main` |
| Spec | `AI_Agent_Security_Platform_Master_Blueprint_v1.2.md`, `archive/..._v1.0_superseded.md` | v1.2 authoritative; v1.0 archived |

Deliberately deferred to Phase 1+: authorization/policy engine (replaces the interim
matrix), tool registry + gateway, input defense, intent, risk engine, approvals,
DLP/egress, audit event emission + verifier, `/v1/*` routes, rate limiting, SOC,
evaluation. `evaluation/` does not exist yet.

## Decisions taken during Phase 0b implementation (within blueprint constraints)

- **Pure-ASGI middleware, path-prefix based** (`/v1/*`): enforcement is fail-closed and
  independent of route existence; it runs before routing and identically under
  `PRINCIPAL_RESOLVER=dev`.
- **Exact denial surface** (recorded in tests): malformed target/headers → 400;
  forged/mutated/stale/unknown-key/replayed → 401; oversize → 413; nonce-store failure →
  503. Detail codes are stable strings (`missing_headers`, `replayed_nonce`, ...).
- **Size bound before signature work**: content-length check, then capped body read with
  replay via an ASGI receive wrapper; nothing is buffered beyond `REQUEST_MAX_BYTES`.
- **Atomic replay rejection in one statement** (`INSERT ... ON CONFLICT DO UPDATE ...
  WHERE expires_at < now() RETURNING`): row → fresh; no row → replay. Concurrency test
  proves at most one winner. Store failures (including raw `OSError`/connection errors)
  → 503, never fail-open.
- **Signed host-auth settings strictness**: `HOST_AUTH_KEYS_JSON` required; records
  `extra="forbid"`; secret must be strict base64 ≥32 bytes; the all-zero sample secret is
  refused outside `development`/`test`; duplicate key IDs rejected; nonce TTL must be
  ≥2× timestamp tolerance.
- **Dev-resolver guard in three places** (settings validator, resolver constructor,
  factory); tests include a `model_construct` bypass attempt to prove the constructor
  guard is independent.
- **Audit append scaffold follows ADR-002 exactly**: transaction-scoped advisory lock
  (`pg_advisory_xact_lock`), canonical bytes stored verbatim, unique
  `(chain_id, sequence_number)`, fixed hash vectors in unit tests; integration test
  appends 5 concurrently and asserts a contiguous sequence.
- **Policy self-checks wired to startup + readiness** (ADR-007): mismatching fixture or
  unreadable/invalid file refuses startup; readiness re-evaluates the file live so drift
  flips to 503. `POLICY_SELF_CHECKS_PATH` overridable; default `config/policy_self_checks.yaml`
  relative to CWD (repo root locally, `/app` in the image).
- **Gitleaks pinned to 8.30.1** in `check.sh` (dir + git scans, redacted; missing or
  version-mismatch = `CHECK FAILED`), with `.gitleaks.toml` extending the default ruleset
  and allowlisting exactly the one documented disposable Compose dev key.
- **Migration env reads Settings** (never `alembic.ini` for the URL); the documented
  commands are `make migrate` / `uv run --frozen alembic upgrade head` with the §5.4
  environment in place.
- **Test DB strategy**: integration fixtures auto-create `firewall_test` on the Compose
  PostgreSQL, run `alembic upgrade head`, and skip (with a clear reason) when the server
  is unreachable; tests never require `create_all` in integration paths (ADR-006).

## Phase 0a verification record (actual runs, 2026-10-19; historical)

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

## Phase 0b verification record (actual runs, 2026-10-19)

Rows 18+ continue the numbered record. Detail codes and file references are in
`project_memory/TESTING_AND_VERIFICATION.md` (V18–V28).

| # | Command | Result |
|---|---|---|
| 18 | `uv run --frozen pytest -q` | PASS — **231 passed** (~2.8 s); includes DB-backed integration tests against the Compose PostgreSQL |
| 19 | `uv run --frozen mypy` | PASS — no issues, 25 source files (strict, `src/`) |
| 20 | `uv run --frozen ruff format --check .`; `ruff check .` | PASS — clean (import sorting fixed in `migrations/`) |
| 21 | `uv run --frozen pytest tests/integration -k "host_auth or nonce or principal" -q` | PASS — 18 passed, 19 deselected |
| 22 | `uv run --frozen alembic upgrade head` (run twice) | PASS — first run applies baseline to a fresh database; second run reports already at head (idempotent) |
| 23 | `uv run --frozen alembic check` | PASS — "No new upgrade operations detected" |
| 24 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps: lockfile; ruff format; ruff lint; mypy; 231 tests; Gitleaks 8.30.1 dir+git ("no leaks found"); prohibited-pattern greps clean; `compare_digest` confined to `security/constant_time.py` |
| 25 | `docker compose build api`; `docker compose run --rm api alembic upgrade head` | PASS — image builds incl. `config/`, `migrations/`, `alembic.ini`; baseline applies inside the container |
| 26 | Live Compose stack (`protai-api-1`) | `/health/live` → 200; `/health/ready` → 200 `{"config":true,"database":true,"policy_self_checks":true}`; unsigned `POST /v1/echo` → 400 `{"detail":"missing_headers"}` |
| 27 | Signed-request proof against the container (Compose dev key, fresh timestamp+nonce) | First request: 404 Not Found — auth passed, nonce registered, body replayed (no `/v1` route exists yet, expected); replay of the identical signed request → 401 `{"detail":"replayed_nonce"}` |
| 28 | Live startup refusals | `APP_ENV=production PRINCIPAL_RESOLVER=dev` → ValidationError "PRINCIPAL_RESOLVER=dev is refused outside development/test"; `POLICY_SELF_CHECKS_PATH=/nonexistent.yaml` → `PolicySelfCheckConfigError` — both refuse startup |
| 29 | `gitleaks git --redact --exit-code 1 .` | PASS — no leaks across the full history (baseline + 7 Phase 0b commits) |

The Compose API container was stopped after verification (`docker compose stop api`);
the database container and `db_data` volume are preserved for local runs and tests.

## Definition of Done checklist (blueprint section 21, Phase 0b)

| DoD item | Status |
|---|---|
| Host-auth signing/verification and replay-rejection tests pass | **PASS** — verifier matrix (unit), middleware denial matrix (integration), live container proof (rows 26–27); forged/mutated/stale/unknown-key/replayed all denied with documented codes; DB failure → 503 |
| Migrations apply and re-apply idempotently | PASS (rows 22–23, 25) |
| `DevPrincipalResolver` cannot start outside dev/test | PASS (row 28; settings validator + resolver + factory guard tests; `model_construct` bypass attempt rejected) |
| Policy self-check scaffolding runs at startup and in CI and fails on a deliberately mismatching fixture | PASS — startup refusal on mismatch and on unreadable file; readiness drift → 503; the gate runs the suite that proves it |
| `/docs`, `/redoc`, `/openapi.json` remain absent outside dev/test | PASS — gating tests unchanged and green |
| Gitleaks runs in `check.sh`; fails when unavailable or on a finding | PASS (row 24; pinned 8.30.1; missing/mismatch fails the gate) |
| No secrets committed | PASS (row 29; only documented disposable dev values; one-value allowlist documented in `.gitleaks.toml`) |
| `check.sh` exits non-zero on any failure | PASS — 8 steps; failure path unchanged |
| Phase 0b is not complete merely because the application starts | PASS — all invariant tests above actually ran and are recorded |

## How to continue (next session)

Phase 1 — Typed contracts and deterministic policy engine (blueprint section 21):
strict Pydantic request/response/action contracts, the safe YAML policy loader and
validated policy model, the principal test adapter interface, reason codes, and
canonicalization — replacing `policy/interim_matrix.py` while keeping the
`config/policy_self_checks.yaml` fixture contract (ADR-007). Read blueprint §§6, 10,
11.4; keep every existing test green; extend `docs/SECURITY_INVARIANTS.md` statuses
(#25 becomes fully testable there).
