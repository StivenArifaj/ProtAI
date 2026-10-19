# Testing and Verification

Rules: never claim a result that was not produced by a command actually run. Fresh
re-runs and historical records are kept in separate tables. Evidence IDs (V1–V29 for
0a/0b; V30–V35 for Phase 1; V36+ for Phase 2) are referenced from
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and the phase records.

## How to verify (documented commands)

| Command | What it checks | Expected |
|---|---|---|
| `uv sync --frozen` | lockfile/install consistency | installs with no resolution drift |
| `uv run pytest` | unit/integration/security tests | 520 passed (DB-backed integration skips cleanly if PostgreSQL is unreachable) |
| `bash scripts/check.sh` | full local gate (8 steps) | exit 0; prints "All checks passed." |
| `uv run alembic upgrade head` | migrations (needs §5.4 env; host `db`→`127.0.0.1`) | applies baseline to an empty DB; second run reports already at head |
| `docker compose config -q` | Compose file syntax | exit 0 |
| `docker compose build api` | container build incl. `config/`, `migrations/`, `alembic.ini` | image builds |
| `docker compose run --rm api alembic upgrade head` | in-container migration | baseline applied |
| `docker compose up -d db api` | stack | `protai-db-1` + `protai-api-1` healthy |
| `curl http://127.0.0.1:8080/health/live` | liveness | 200 `{"status":"alive"}` |
| `curl http://127.0.0.1:8080/health/ready` | readiness | 200 ready incl. `policy_version`/`policy_hash` (503 not_ready without DB or with drifted self-checks) |
| unsigned/signed requests to `/v1/*` | host auth | unsigned → 400 `missing_headers`; valid signature → 404 (no routes yet) with nonce registered; replay → 401 `replayed_nonce` |
| `uv run python -c "…load_policy_bundle…"` | policy bundle smoke | `version`, per-file hashes, `combined_hash`; 21 fixtures, 0 failures |
| `uv run pytest tests/security tests/unit/test_gateway.py -q` | no-bypass invariants | 31 passed (denied/unknown/audit-failed calls never reach the adapter) |
| `docker compose down` | teardown (volume preserved) | stack removed |

Failure behavior: `check.sh` exits non-zero and prints `CHECK FAILED: <reason>`.

## Fresh evidence (2026-10-19, Phase 2 session)

| ID | Command / check | Result |
|---|---|---|
| V36 | `uv run --frozen pytest -q` | PASS — **520 passed** (461 unit + 47 integration + 12 security), incl. DB-backed gateway integration against Compose PostgreSQL |
| V37 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps: lockfile; ruff format; ruff lint; mypy clean; 520 tests; Gitleaks 8.30.1 dir+git "no leaks found" (13 commits scanned); prohibited-pattern greps clean; `compare_digest` confined |
| V38 | `uv run --frozen pytest tests/security tests/unit/test_gateway.py -q` | PASS — 31 passed (8 parametrized no-byte-denials + audit-down + no-decision-no-exec + outcome-audit-fail + direct-adapter fail-closed + 20 gateway unit tests) |
| V39 | `uv run --frozen pytest tests/integration/test_gateway_end_to_end.py tests/integration/test_gateway_wiring.py -q` | PASS — 5 passed (durable decision→outcome order + linkage + result digest + payload non-leakage; denied egress leaves sink unchanged; audit outage → `BLOCK`/`audit_unavailable`; startup refuses unregistered policy tool) |
| V40 | `uv run --frozen pytest tests/unit/test_policy_self_checks.py tests/integration/test_policy_self_checks_wiring.py -q` | PASS — 41 passed; fixture file now 21 fixtures incl. the 7 mandated names |
| V41 | `uv run --frozen mypy src` + `ruff check src/ tests/` + `ruff format --check src tests` | PASS — clean (45 source files, strict) |

Development-time findings fixed and regression-tested during Phase 2 (recorded for
honesty): `verify_execution_authorization` originally accepted any object passed as the
authorization — a security test now proves a non-authorization value raises
`ExecutionAuthorizationError`; the security spy adapter initially failed because
`MockEmailAdapter` requires `super().__init__()` (its store is an instance attribute);
the integration deny test initially asserted a non-existent `data_class` field on
`RiskAssessment` (the field lives in the audit payload, value `PUBLIC`).

## Fresh evidence (2026-10-19, Phase 1 session)

| ID | Command / check | Result |
|---|---|---|
| V30 | `uv run --frozen pytest -q` | PASS — **406 passed** (364 unit + 42 integration), incl. DB-backed integration against Compose PostgreSQL |
| V31 | `uv run --frozen mypy src` | PASS — no issues, 35 source files (strict) |
| V32 | `uv run --frozen ruff check src/ tests/` + `ruff format src tests` | PASS — clean; format applied to 3 files, then check clean |
| V33 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps: lockfile; ruff format; ruff lint; mypy; 406 tests; Gitleaks 8.30.1 dir+git "no leaks found" (9 commits scanned); prohibited-pattern greps clean; `compare_digest` confined |
| V34 | Policy bundle smoke (`load_policy_bundle` + `check_policy_self_checks`, live run) | PASS — `version: dev-1`; `policies_sha256 35bcd687…`; `thresholds_sha256 3e1d34ae…`; `combined_hash 8a4ba203e3baaf86eabb2e299992166289cae938ec9ea9a7bccadf6e6e068e6a`; 17 fixtures, 0 failures |
| V35 | Policy wiring integration tests (`test_policy_self_checks_wiring.py`, `test_health.py`) | PASS — invalid/missing policy file and mismatching fixture refuse startup; live policy/fixture drift flips readiness to 503; readiness payload carries `policy_version`/`policy_hash` |

Additional Phase 1 development-time findings (fixed and regression-tested, recorded for
honesty): the initially unanchored `TOOL_ID_PATTERN` accepted an invalid tool id (fixed
by anchoring); pydantic's lax int coercion accepted a string or bool `risk_score` (fixed
with `strict=True`); the loader's first duplicate-key approach would have added a
`yaml.load(` call the gate prohibits (restructured to a `yaml.compose` node walk +
`yaml.safe_load`); three files were not ruff-formatted (the gate's format step caught it).

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

## Test inventory (520 tests)

Unit (`tests/unit/`):

- `test_settings.py` (55) — 0a validation + masking + docs flag; 0b host-auth key
  schemas, duplicate rejection, sample-secret refusal, resolver guard, TTL/tolerance
  relation, `policy_self_checks_path`; 1 `policy_path`/`risk_thresholds_path` defaults,
  overrides, empty-path rejection.
- `test_constant_time.py` (16) — equality helpers incl. unequal-length and hex paths.
- `test_canonical_json.py` (17) — canonical text/bytes stability and edge cases.
- `test_hash_chain.py` (17) — ADR-002 formula, genesis, fixed vectors, hex conversion.
- `test_host_auth_verifier.py` (46) — exact signing message vector, header handling,
  full rejection matrix, timestamp-window boundaries, constant-time paths.
- `test_principal_resolver.py` (14) — frozen `Principal` model, timezone validation,
  dev-resolver guard (incl. `model_construct` bypass attempt), fail-closed host resolver.
- `test_principal_test_adapter.py` (8) — test-only constructor guard, factory exclusion.
- `test_urls.py` (36) — scheme/host/port/path/query canonicalization, IDNA hosts,
  percent-encoding, rejection cases (whitespace, controls, userinfo, fragment, zone id,
  trailing dot), exact-match equality.
- `test_policy_models.py` (38) — strict policy/threshold documents, anchored tool ids,
  strict enum/int rejection, bundle hashes, threshold ordering.
- `test_policy_loader.py` (20) — safe loading, duplicate keys, missing/non-UTF-8/malformed
  documents, `PolicyConfigError` behavior.
- `test_policy_engine.py` (64) — table-driven matrix (allowed/forbidden/malformed/
  cross-scope/unknown/error), evaluation-order precedence, thresholds, provenance,
  determinism, malformed requests.
- `test_policy_self_checks.py` (33) — repo fixture file passes completely; mandated rows
  present; runner detects decision/reason mismatches; malformed fixture shapes rejected;
  readiness report behavior.
- `test_action_digest.py` (7) — canonical action digest stability, field sensitivity,
  key-order invariance, hex shape.
- `test_tool_registry.py` (24) — registration validation matrix (DESTRUCTIVE refusal,
  schema strictness, resource/destination annotation checks, bounds, bool rejection),
  duplicate resolution, startup consistency failures (`ToolRegistryConfigError`).
- `test_mock_adapters.py` (14) — mock email/files/sink/text behavior, ownership checks,
  unauthorized-call refusal (`UngatedExecutionError`), digest tamper rejection.
- `test_risk_engine.py` (9) — `risk-v1` weights, cap at 100, external-destination
  requirement, factor codes, version reporting.
- `test_gateway.py` (20) — see the Phase 2 completion record for the full scenario list.

Security (`tests/security/`):

- `test_gateway_no_bypass.py` (12) — denied/unknown/malformed/expired/audit-failed calls
  never execute (spy adapter byte equality on the sink); no execution without a
  successfully recorded decision; result withheld on outcome-audit failure; direct
  adapter invocation without a gateway authorization fails closed.

Integration (`tests/integration/`):

- `test_health.py` (10) — liveness; readiness 200/503 incl. policy readiness override;
  `policy_version`/`policy_hash` assertions; docs gating all environments; non-leakage.
- `test_host_auth_middleware.py` (13) — end-to-end denial matrix through the app:
  valid sign → route + context; forged/mutated/stale/unknown-key → 401; replay → 401;
  failing registrar → 503; oversize content-length + chunked → 413; query string → 400;
  non-`/v1` paths unauthenticated.
- `test_nonce_repository.py` (5) — fresh/duplicate/expired re-registration/DB failure
  (incl. raw connection errors) paths.
- `test_audit_append.py` (5) — chain continuity, genesis, canonical bytes recompute,
  5-writer concurrency contiguity, unique-sequence guard.
- `test_migrations.py` (1) — upgrade idempotency on the test database.
- `test_policy_self_checks_wiring.py` (8) — startup refuses on missing policy/threshold
  file, invalid policy, and fixture mismatch; valid bundle passes startup + readiness
  with version/hash; live policy-version drift flips to 503 while the startup bundle
  stays fixed.
- `test_gateway_end_to_end.py` (3) — real-PostgreSQL chain: durable decision→outcome
  order and hash linkage, result digest = sha256 canonical result, no raw content in
  stored payloads, denied egress leaves the sink empty, audit outage → `BLOCK`/
  `audit_unavailable`.
- `test_gateway_wiring.py` (2) — `create_app` exposes a validated registry + gateway
  (`ChainAuditRecorder`); startup refuses a policy tool with no registration.
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
