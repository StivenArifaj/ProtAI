# Testing and Verification

Rules: never claim a result that was not produced by a command actually run. Fresh
re-runs and historical records are kept in separate tables. Evidence IDs (V1–V17) are
referenced from [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and the phase records.

## How to verify (documented commands)

| Command | What it checks | Expected |
|---|---|---|
| `uv sync --frozen` | lockfile/install consistency | installs with no resolution drift |
| `uv run pytest` | 25 unit/integration tests | 25 passed |
| `bash scripts/check.sh` | full local gate (6 steps) | exit 0; prints "All Phase 0a checks passed." |
| `docker compose config -q` | Compose file syntax | exit 0 |
| `docker compose up -d db` | PostgreSQL container | `protai-db-1` healthy |
| `docker compose up -d api` | API container | `protai-api-1` healthy |
| `curl http://127.0.0.1:8080/health/live` | liveness | 200 `{"status":"alive"}` |
| `curl http://127.0.0.1:8080/health/ready` | readiness against real DB | 200 ready (503 not_ready without DB) |
| `docker compose exec -T api id` | non-root runtime | `uid=10001(app)` |
| `docker compose down` | teardown (volume preserved) | stack removed |

Failure behavior: `check.sh` exits non-zero and prints `CHECK FAILED: <reason>`.
The injected-failure proof is described below.

## Fresh evidence (2026-10-19, this session; Docker Desktop running)

| ID | Command / check | Result |
|---|---|---|
| V1 | `uv --version`; `uv run python --version` | uv 0.13.1; Python 3.12.15 |
| V2 | `uv sync --frozen` | PASS — "Checked 36 packages" (see note 1) |
| V3 | `bash scripts/check.sh` | PASS — exit 0: `uv lock` resolved 38 packages; ruff format (24 files) + lint clean; mypy clean (6 source files); pytest **25 passed** in 0.19 s; invariant greps clean |
| V4 | `docker compose config -q` | PASS — exit 0 |
| V5 | `docker info`; `docker compose version` | Docker 29.3.1 daemon running; Compose v5.1.1 |
| V6 | `docker compose up -d db` | PASS — `protai-db-1` healthy (poll 4) |
| V7 | `docker compose up -d api` | PASS — `protai-api-1` healthy (poll 7) |
| V8 | dev-profile HTTP checks (host 127.0.0.1:8080) | live 200; ready 200 `{"config":true,"database":true}` against real PostgreSQL; `/docs` 200; `/openapi.json` 200; leak scan 0 matches |
| V9 | `docker compose exec -T api id` | `uid=10001(app)` (non-root) |
| V10 | production-profile run (port 8001, non-sample password) | live 200; `/docs` `/redoc` `/openapi.json` 404; ready 503 `{"config":true,"database":false}` — the non-sample password does not match the dev DB and dev credentials are refused in production by design (correct fail-closed) |
| V11 | in-container startup refusal (`APP_ENV=production` + sample password) | exit 1, "refusing the sample development database password outside development/test" |
| V12 | `docker compose down` | PASS — stack removed; `db_data` volume preserved |
| V13 | `git rev-parse --is-inside-work-tree` | fatal: not a git repository (exit 128) |

Notes: (1) package counts differ by command — `uv lock` resolves **38 packages**; `uv
sync --frozen` reports **36 packages checked** (installed set). Both expected.

## Historical evidence (Phase 0a session, 2026-10-19; recorded, not all re-run)

| ID | Check | Result |
|---|---|---|
| V14 | Live uvicorn run without Docker (127.0.0.1:8011) | live 200; ready 503 (no database); `/docs` 200 |
| V15 | Startup refusal: `APP_ENV` missing | exit 1 (`app_env Field required`) |
| V16 | Startup refusal: wrong scheme (`postgresql+psycopg://`) | exit 1 with ADR-005 scheme error |
| V17 | Fresh-checkout approximation (clean copy, 34 files at the time) | `uv sync --frozen` then `check.sh` exit 0 |

The full original record (17 rows, including the Docker rows re-verified above) is in
[../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md).

## Injected-failure proof (how `check.sh` was proven to fail)

A deliberately failing test was added and `check.sh` was run: the failure was caught at
the pytest step (`CHECK FAILED: test failures reported`, exit 1) and, in earlier
iterations, at the ruff format and lint steps. Removing the file restored exit 0. Note:
`assert False` trips ruff B011 — use `raise AssertionError(...)` in throwaway probes.

## Test inventory (25 tests)

- `../tests/unit/test_settings.py` — 17 tests: construction; `LOG_LEVEL` default;
  `APP_ENV` and `DATABASE_URL` required; unknown env/log level rejected; non-asyncpg
  scheme rejected (3 parametrized); sample password refused in staging/production (2)
  and allowed in development/test (2); `database_dsn` conversion; secret masking in
  `repr`/`str`; docs flag per environment; conftest fixture validity.
- `../tests/integration/test_health.py` — 8 tests: liveness; readiness 200; readiness
  503 + non-leakage assertions (documented sample password, `postgresql`, `asyncpg`,
  `Traceback` absent); docs present in development/test (3 routes; OpenAPI path set ==
  `{"/health/live", "/health/ready"}`); docs absent in staging/production; factory uses
  provided settings.

## Verification gaps (be honest about these)

- No coverage measurement; no CI system (`check.sh` is the gate).
- No Gitleaks secret scanning yet (Phase 0b); secret hygiene is manual + `.gitignore`.
- No markdown linter is installed in this environment; link checks for the memory files
  are scripted ad hoc (see the memory-system validation record in [CHANGELOG.md](CHANGELOG.md)).
- "Fresh clone" remains an approximation until the repository is under git.
