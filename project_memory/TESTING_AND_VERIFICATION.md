# Testing and Verification

Rules: never claim a result that was not produced by a command actually run. Fresh
re-runs and historical records are kept in separate tables. Evidence IDs (V1–V29) are
referenced from [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and the phase records.

## How to verify (documented commands)

| Command | What it checks | Expected |
|---|---|---|
| `uv sync --frozen` | lockfile/install consistency | installs with no resolution drift |
| `uv run pytest` | 231 unit/integration tests | 231 passed (DB-backed integration skips cleanly if PostgreSQL is unreachable) |
| `bash scripts/check.sh` | full local gate (8 steps) | exit 0; prints "All checks passed." |
| `uv run alembic upgrade head` | migrations (needs §5.4 env; host `db`→`127.0.0.1`) | applies baseline to an empty DB; second run reports already at head |
| `docker compose config -q` | Compose file syntax | exit 0 |
| `docker compose build api` | container build incl. `config/`, `migrations/`, `alembic.ini` | image builds |
| `docker compose run --rm api alembic upgrade head` | in-container migration | baseline applied |
| `docker compose up -d db api` | stack | `protai-db-1` + `protai-api-1` healthy |
| `curl http://127.0.0.1:8080/health/live` | liveness | 200 `{"status":"alive"}` |
| `curl http://127.0.0.1:8080/health/ready` | readiness | 200 ready (503 not_ready without DB or with drifted self-checks) |
| unsigned/signed requests to `/v1/*` | host auth | unsigned → 400 `missing_headers`; valid signature → 404 (no routes yet) with nonce registered; replay → 401 `replayed_nonce` |
| `docker compose down` | teardown (volume preserved) | stack removed |

Failure behavior: `check.sh` exits non-zero and prints `CHECK FAILED: <reason>`.

## Fresh evidence (2026-10-19, Phase 0b session; Docker Desktop running)

| ID | Command / check | Result |
|---|---|---|
| V18 | `uv run --frozen pytest -q` | PASS — **231 passed** (~2.8 s), incl. DB-backed integration against Compose PostgreSQL |
| V19 | `uv run --frozen mypy` | PASS — no issues, 25 source files (strict, `src/`) |
| V20 | `uv run --frozen ruff check .` + `ruff format --check .` | PASS — clean after fixing import sorting in `migrations/` (cosmetic) |
| V21 | `uv run --frozen pytest tests/integration -k "host_auth or nonce or principal" -q` | PASS — 18 passed, 19 deselected |
| V22 | `uv run --frozen alembic upgrade head` ×2 | PASS — first run applies `d15b46c49950` to a fresh DB; second run already at head |
| V23 | `uv run --frozen alembic check` | PASS — "No new upgrade operations detected" |
| V24 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps: lockfile; ruff format; ruff lint; mypy; 231 tests; Gitleaks 8.30.1 dir+git "no leaks found"; prohibited-pattern greps clean; `compare_digest` confined to `security/constant_time.py` |
| V25 | `docker compose build api` + `docker compose run --rm api alembic upgrade head` | PASS — image contains `config/`, `migrations/`, `alembic.ini`; baseline applied in-container |
| V26 | Live compose stack HTTP checks | live 200; ready 200 `{"config":true,"database":true,"policy_self_checks":true}`; unsigned `POST /v1/echo` → 400 `{"detail":"missing_headers"}` |
| V27 | Signed request proof (Compose dev key; fresh timestamp + nonce; urllib) | first call → 404 Not Found (auth passed, nonce registered, body replayed; no `/v1` route exists — expected); replay of identical signed request → 401 `{"detail":"replayed_nonce"}` |
| V28 | Live startup refusals | `APP_ENV=production PRINCIPAL_RESOLVER=dev` → ValidationError "PRINCIPAL_RESOLVER=dev is refused outside development/test"; `POLICY_SELF_CHECKS_PATH=/nonexistent.yaml` → `PolicySelfCheckConfigError` — both refuse startup |
| V29 | `gitleaks git --redact --exit-code 1 .` | PASS — no leaks across full history (baseline + 7 Phase 0b commits) |

Notes: the one expected Gitleaks finding during development was the documented
disposable Compose dev host-auth key; the final `.gitleaks.toml` allowlists exactly that
value (verified: `gitleaks dir` and `gitleaks git` both clean). `check.sh` pins Gitleaks
to exactly 8.30.1.

## Historical evidence (Phase 0a, 2026-10-19; superseded freshness but unchanged code paths)

| ID | Check | Result |
|---|---|---|
| V1 | `uv --version`; `uv run python --version` | uv 0.13.1; Python 3.12.15 |
| V2 | `uv sync --frozen` | PASS — "Checked 36 packages" (see note below) |
| V3 | `bash scripts/check.sh` (0a, 6 steps) | PASS — exit 0; 25 tests |
| V4 | `docker compose config -q` | PASS — exit 0 |
| V5 | `docker info`; `docker compose version` | Docker 29.3.1 running; Compose v5.1.1 |
| V6 | `docker compose up -d db` | PASS — `protai-db-1` healthy |
| V7 | `docker compose up -d api` (0a image) | PASS — `protai-api-1` healthy |
| V8 | 0a dev-profile HTTP checks | live 200; ready 200 `{"config":true,"database":true}`; docs 200; leak scan 0 |
| V9 | `docker compose exec -T api id` | `uid=10001(app)` (non-root) |
| V10 | 0a production-profile run | docs/redoc/openapi 404; ready 503 (non-matching non-sample credential; fail-closed by design) |
| V11 | 0a in-container refusal (production + sample password) | exit 1, clear message |
| V12 | `docker compose down` (0a) | stack removed; `db_data` preserved |
| V13 | `git rev-parse --is-inside-work-tree` | fatal: not a git repository (exit 128 — since resolved) |
| V14 | Live uvicorn run without Docker (0a) | live 200; ready 503 (no DB); docs 200 |
| V15 | Startup refusal: `APP_ENV` missing | exit 1 (`app_env Field required`) |
| V16 | Startup refusal: wrong scheme | exit 1 with ADR-005 scheme error |
| V17 | Fresh-checkout approximation (0a) | `uv sync --frozen` then `check.sh` exit 0 |

Note: package counts differ by command — `uv lock` resolves **38 packages**; `uv sync
--frozen` reports **36 packages checked** (installed set). Both expected.

## Injected-failure proof (how `check.sh` was proven to fail)

A deliberately failing test was added and `check.sh` was run: the failure was caught at
the pytest step (`CHECK FAILED: test failures reported`, exit 1) and, in earlier
iterations, at the ruff format and lint steps. Removing the file restored exit 0. Note:
`assert False` trips ruff B011 — use `raise AssertionError(...)` in throwaway probes.
The Phase 0b gate additionally fails if Gitleaks is missing or version-mismatched
(deliberate pin, 8.30.1).

## Test inventory (231 tests)

Unit (`tests/unit/`):

- `test_settings.py` (51) — 0a validation + masking + docs flag; 0b host-auth key
  schemas, duplicate rejection, sample-secret refusal, resolver guard, TTL/tolerance
  relation, `policy_self_checks_path`.
- `test_constant_time.py` (16) — equality helpers incl. unequal-length and hex paths.
- `test_canonical_json.py` (17) — canonical text/bytes stability and edge cases.
- `test_hash_chain.py` (17) — ADR-002 formula, genesis, fixed vectors, hex conversion.
- `test_host_auth_verifier.py` (~44) — exact signing message vector, header handling,
  full rejection matrix, timestamp-window boundaries, constant-time paths.
- `test_principal_resolver.py` (14) — frozen `Principal` model, timezone validation,
  dev-resolver guard (incl. `model_construct` bypass attempt), fail-closed host resolver.
- `test_policy_self_checks.py` (33) — repo fixture file passes completely; mandated rows
  present; runner detects decision/reason mismatches; loader rejects 12 malformed shapes;
  probe never raises; matrix risk boundaries; hard-constraint dominance.

Integration (`tests/integration/`):

- `test_health.py` (~12) — liveness; readiness 200/503 incl. policy_self_checks; docs
  gating all environments; non-leakage.
- `test_host_auth_middleware.py` (13) — end-to-end denial matrix through the app:
  valid sign → route + context; forged/mutated/stale/unknown-key → 401; replay → 401;
  failing registrar → 503; oversize content-length + chunked → 413; query string → 400;
  non-`/v1` paths unauthenticated.
- `test_nonce_repository.py` (5) — fresh/duplicate/expired re-registration/DB failure
  (incl. raw connection errors) paths.
- `test_audit_append.py` (5) — chain continuity, genesis, canonical bytes recompute,
  5-writer concurrency contiguity, unique-sequence guard.
- `test_migrations.py` (1) — upgrade idempotency on the test database.
- `test_policy_self_checks_wiring.py` (4) — startup refuses on missing file and on
  mismatch; valid file passes startup + readiness; post-startup drift flips to 503.
- `conftest.py` + `db_helpers.py` — auto-create `firewall_test`, run Alembic, skip
  cleanly when PostgreSQL is unreachable; NullPool harness for asyncio.run tests.

## Verification gaps (be honest about these)

- No coverage measurement; no CI system (`check.sh` is the gate).
- "Fresh clone" is now meaningful (git history exists) but a true `git clone` into a new
  directory has not been exercised; the 0a clean-copy approximation is the closest run.
- No markdown linter is installed in this environment; memory-file link checks are
  scripted ad hoc.
- Docker verification used the local Compose project; multi-host/registry pulls are not
  applicable to v1's local-only scope.
