# Implementation State

Last updated: 2026-10-19 (Phase 3, blueprint v1.2).

Phases 0a (repository foundation), 0b (security foundation), 1 (typed contracts and
deterministic policy engine), 2 (tool registry and enforced gateway), and 3 (advisory
input defense and context provenance) are **complete and verified**; the Docker Compose
path was verified in 0b. Phase 3 adds strict/versioned detection configuration, bounded
intake, copy-only normalization, deterministic injection heuristics, typed findings and
non-PASS failure semantics, structured trust labels for context assembly, and a
tenant/subject-bound session signal store with bounded counters and TTL/max-age expiry.
Detection is **advisory only**: it has no path into policy facts, the engine, the gateway,
or execution, and no `/v1` route exposes it yet. The codebase still does **not** implement
`/v1` routes, approvals, manifest/intent binding, content DLP, real connectors, process
isolation, rate limiting, model/provider integration, or the full audit taxonomy/verifier.
See `docs/SECURITY_INVARIANTS.md` and `docs/KNOWN_LIMITATIONS.md`.

## What exists

| Area | Files | Notes |
|---|---|---|
| Project metadata | `pyproject.toml`, `uv.lock`, `.python-version` (3.12), `.gitignore`, `.env.example`, `README.md`, `Makefile`, `.gitleaks.toml` | Python `>=3.12,<3.13`; runtime deps: fastapi, uvicorn, pydantic, pydantic-settings, asyncpg, SQLAlchemy 2.x async, Alembic, PyYAML; dev deps: pytest, httpx2, ruff, mypy, types-PyYAML |
| Application | `src/ai_security/__init__.py`, `settings.py`, `api/{app,dependencies,routes_health,middleware}.py` | App factory + module-level `app`; validated settings (incl. `POLICY_PATH`/`RISK_THRESHOLDS_PATH`); `/health/live`, `/health/ready` (config, database, policy_self_checks + `policy_version`/`policy_hash`); host-auth ASGI middleware on `/v1/*` |
| Security primitives | `security/{constant_time,canonical_json,urls}.py`, `audit/hash_chain.py` | `hmac.compare_digest` wrappers (confined by the gate); canonical JSON bytes; ADR-002 hash formula + fixed vectors; destination canonicalization (IDNA, percent-encoding, https-only) |
| Identity | `identity/{models,signing,host_auth,resolver,adapters}.py` | `Principal` (strict, frozen); HMAC signing/verification (exact `v1` message, full rejection surface); `DevPrincipalResolver` guard + fail-closed `HostPrincipalResolver`; test-only `TestPrincipalResolver` (not selectable via settings/factory) |
| Persistence | `persistence/{database,models,nonce_repository,audit_repository,session_repository}.py` | Async engine/session; atomic nonce upsert (`ON CONFLICT ... WHERE ... RETURNING`); ADR-002 advisory-lock audit append; tenant/subject-bound session signals with bounded counters, lazy expiry, and signal-free rotation |
| Migrations | `alembic.ini`, `migrations/env.py`, `migrations/versions/{d15b46c49950,c7f1a2b3d4e5}_*.py` | Baseline: `host_request_nonces`, `audit_events`; Phase 3: `session_security_state` (constraints + binding/last-seen indexes); `make migrate`; upgrade/downgrade/upgrade verified; `alembic check` clean |
| Typed contracts | `tools/base.py` (`SideEffectClass`, `ToolArguments`/`ToolResult`, `ExecutionAuthorization`, `compute_action_digest`, adapters protocol), `data_security/classification.py` (`DataClass`), `firewall/decision.py` (`FirewallDecision`/`DecisionReason`/`DecisionRecord`) | Canonical enums defined exactly once (blueprint §4/§6.1); stable reason-code vocabulary (extended with `binding_mismatch`, `deadline_exceeded`, `policy_evaluation_error`, `audit_unavailable`); sentinel-guarded authorization; strict schemas (`extra="forbid"`, `strict=True`) |
| Tool registry + mock adapters | `tools/registry.py`, `tools/mock_{email,files,external_sink,text}.py` | Immutable validated registrations; exact `(tool_id, action_id)` resolution; startup consistency vs policy (one-directional: policy→capability required; extra registrations stay policy-disabled); deterministic in-memory adapters with ownership checks and digest verification |
| Input defense + provenance | `input_defense/{models,config,normalize,heuristics,service,context_labels,sessions}.py`, `security/safe_yaml.py`, `config/input_defense.yaml` | Advisory only: strict config (every finding code mapped, no PASS mapping), byte/type/UTF-8 intake, copy-only normalization, versioned heuristics with quoted-context downgrade, typed `IntakeReport` with digests/offsets, six trust labels + deterministic JSON context, optional diagnostic classifier, typed `DETECTOR_UNAVAILABLE` failures |
| Gateway + risk engine | `firewall/{gateway,models,risk_engine}.py` | Single `invoke_tool` chokepoint; binding/validation/resource/destination/deadline/engine checks; decision audited before execution; timeouts + per-process concurrency + result bounds; typed outcomes; `risk-v1` scoring (side-effect/destination/data-class factors) |
| Audit emission | `audit/{models,writer}.py` | Phase-2 event subset (`POLICY_EVALUATED`, `TOOL_EXECUTION_COMPLETED`, `TOOL_EXECUTION_FAILED`); schema v1; `AuditRecorder` protocol + `ChainAuditRecorder` over the ADR-002 repository; payload-safe references only |
| Policy engine | `firewall/policy_engine.py`, `policy/{models,loader,self_checks}.py`, `config/{policies,risk_thresholds,policy_self_checks}.yaml` | Deterministic §10.2 evaluation order over validated facts; safe YAML (duplicate-key rejection); versioned bundle with content hashes; 21 fixtures (incl. 7 mandated names and the Phase 2 binding/deadline/inconsistent facts) evaluated at startup + readiness; replaces `policy/interim_matrix.py` (deleted) |
| Tests | `tests/conftest.py`, `tests/unit/*` (22 test files + `_tool_auth.py` helper), `tests/integration/*` (10 test files + `conftest.py`/`db_helpers.py`), `tests/security/*` (2 test files) | **600 tests** (517 unit, 60 integration, 23 security): prior suites plus normalization/heuristics/config/context-label/session math, detector-failure security tests, startup wiring, and real-PostgreSQL session-state tests |
| Quality gate | `scripts/check.sh` | 8 steps: lockfile, ruff format, ruff lint, mypy, pytest, pinned Gitleaks (dir+git), prohibited-pattern greps, constant-time confinement |
| Containers | `Dockerfile`, `docker-compose.yml` | Digest-pinned bases; non-root uid 10001; COPY `config/ migrations/ alembic.ini`; Compose `api` carries the disposable dev `HOST_AUTH_KEYS_JSON` |
| Docs | `docs/*` (9 files), `docs/adr/ADR-001..010` | Status columns honest; ADR-008 records the Phase 1 engine contract, ADR-009 the Phase 2 registry/gateway contract, ADR-010 the Phase 3 advisory-detection/session contract; matrix doc reflects gateway-enforced facts |
| Git | baseline `41e10da`; 0b commits `0aa11d9`…`d180b89`; docs `c95f2a6`; Phase 1 commits `cffdd62`, `eaae462`, `b91729b`; Phase 2 commits `5725256`…`c7a0f8d` | Repository under git since 2026-10-19; linear history on `main`; Phase 3 commits follow this document update |
| Spec | `AI_Agent_Security_Platform_Master_Blueprint_v1.2.md`, `archive/..._v1.0_superseded.md` | v1.2 authoritative; v1.0 archived |

Deliberately deferred beyond Phase 3: manifest/intent binding and semantic intent
(Phase 4), approvals and factor expansion (Phase 5), content DLP/canary (Phase 6), full
audit taxonomy + verifier (Phase 7), `/v1/*` routes + agent runtime + rate limiting
(Phase 8), evaluation (Phase 9), isolation/SOC/SBOM (Phase 10). Detection is not yet
consumed by routes or the model context; `evaluation/` and `data_security/` beyond
`classification.py` do not exist yet.

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

## Decisions taken during Phase 1 implementation (within blueprint constraints; ADR-008)

- **Module layout**: engine in `firewall/policy_engine.py`; policy document models +
  loader in `policy/`; canonical enums defined exactly once (`tools/base.py`,
  `data_security/classification.py`, `firewall/decision.py`).
- **Fact separation**: `PolicyEvaluationRequest` carries upstream facts only
  (`principal_resolved`, `arguments_valid`, `hard_deny`, `resource_authorized`,
  `risk_score`, optional `destination`); policy-derived facts (membership, explicit
  permission, approval eligibility, egress enablement, allowlist) come only from the
  loaded bundle. The engine cannot authorize on caller-supplied policy flags.
- **Evaluation order = blueprint §10.2**: principal → tool membership (`unknown_tool`)
  → side-effect class match → arguments → hard deny → resource scope → destination
  (`invalid_destination` for malformed or misplaced) → matrix rows with configured
  thresholds. Every outcome has a stable `DecisionReason`; the vocabulary is an
  observable contract (renaming is a breaking change).
- **Fail closed everywhere**: `DESTRUCTIVE` never executable in v1 (registration may
  exist; the engine blocks); `RESTRICTED` writes/egress and `CONFIDENTIAL` egress
  blocked; `ASK_USER` only when policy marks the action approval-eligible, otherwise
  `BLOCK`; tool absent from the document → `unknown_tool` BLOCK (deny-by-default).
- **Strict primitives**: `risk_score` is a strict integer 0-100 (string/bool coercion
  rejected); `TOOL_ID_PATTERN` is anchored (`^…$`) because pydantic `pattern=` uses
  search semantics (an unanchored pattern accepted an invalid tool id containing a
  space, e.g. `"bad id"`).
- **Destination canonicalization (option chosen)**: Unicode hosts are supported and
  IDNA-encoded then lowercased (`BÜCHER.example` → `xn--bcher-kva.example`); paths and
  queries must be printable ASCII (percent-encoding normalized); whitespace/control
  characters anywhere, userinfo, fragments, IPv6 zone IDs, and trailing dots are
  rejected; port 443 elided; https-only. Allowlisting is exact-match (no wildcards).
- **Loader without the prohibited call**: duplicate keys are detected via a
  `yaml.compose` node walk (the gate prohibits `yaml.load(` in `src/`), then the
  document is parsed with `yaml.safe_load`; strict Pydantic validation; `PolicyConfigError`
  fails closed. Errors name the file, never dump the document.
- **Bundle provenance**: `PolicyBundle.version` + per-file `sha256` + `combined_hash`
  (`sha256("policies=<h>;thresholds=<h>")`); readiness exposes `policy_version` and
  `policy_hash` (the combined hash) on both 200 and 503 payloads (ADR-007 metadata).
- **Self-check fixtures v2**: each `case` is a full `PolicyEvaluationRequest`; an
  optional fixture-level `tool_policy` override (same strict `ToolPolicy` model) covers
  the §10.5 "dedicated test scenario" (e.g. enabling egress) without weakening the
  starter policy; all 7 mandated fixture names retained; expanded to 17 fixtures.
- **Wiring**: startup loads and self-checks the bundle (invalid policy refuses startup);
  readiness re-evaluates the files live so drift flips to 503; the running process keeps
  its startup-loaded bundle (no hot reload — documented limitation).
- **Test principal adapter**: `TestPrincipalResolver` constructible only under
  `APP_ENV=test`, not selectable via settings or `build_principal_resolver`; the
  dev-resolver guard and HMAC middleware are untouched (denial matrix unchanged).
- **Thresholds 40/80 marked experimental** in the config header; validated
  (`ask_user_at_or_above < block_at_or_above`); calibration defers to Phase 9.

## Decisions taken during Phase 2 implementation (within blueprint constraints; ADR-009)

- **Registry capability vs policy authorization (one-directional consistency)**: every
  tool declared in the policy must have a compatible registration or startup fails; a
  registration absent from the policy is registered but disabled (engine `unknown_tool`).
  This is what allows `mock_files.search` (blueprint section 14.1) while the starter
  policy (section 10.5) enables only `mock_files.read`. Class mismatch, `DESTRUCTIVE`,
  approval metadata inconsistency, enabled-egress-without-capability, and policy
  destinations outside the declared set all refuse startup.
- **Exact action identity, no naming convention**: the registry key is the exact
  `(tool_id, action_id)` pair; `action_id` is not required to equal the final dotted
  segment of `tool_id` (an earlier plan idea, deliberately dropped as unenforced
  convention).
- **Execution authorization is gateway-issued and digest-bound**: `ExecutionAuthorization`
  is sentinel-guarded (direct construction raises `UngatedExecutionError`); the digest is
  SHA-256 over canonical JSON of tool/action/validated arguments/resource IDs/destination/
  principal/request/policy hash. Adapters verify the digest immediately before the side
  effect; a non-authorization value raises `ExecutionAuthorizationError`. In-process
  guardrail, not a sandbox (Phase 10).
- **Gateway may only downgrade the engine**: the engine stays the sole `ALLOW` producer;
  audit-outage, deadline, and evaluation-error paths become BLOCK/DENIED typed outcomes.
  `ASK_USER` returns a no-execution result (no pending approval storage until Phase 5).
- **Audit ordering and failure semantics**: `POLICY_EVALUATED` is appended before any
  protected side effect; an append failure on a would-be `ALLOW` yields
  `BLOCK`/`audit_unavailable` and no adapter call. Post-execution append failure yields
  `AUDIT_FAILED` with no result returned. A denial whose audit append fails keeps the
  denial reason (no side effect to roll back). Audit payloads carry identifiers,
  provenance, risk factors, and result digests/sizes only.
- **`risk-v1` scoring is gateway-computed and versioned**: side-effect class, external
  destination (only for `EXTERNAL_MUTATION`; inconsistent facts raise), and registration
  data class; capped at 100; factor codes recorded in decision and audit payloads;
  zero-weight data-class factor omitted. Weights are initial experimental defaults
  (calibration Phase 9); no caller-supplied score is accepted.
- **Bounds are explicit registration facts**: timeout 1-60 s, per-process concurrency
  1-64 (`asyncio.Semaphore` held per running loop via `WeakKeyDictionary`), result size
  <=1 MiB measured over canonical JSON bytes; results are re-validated for schema identity
  and canonicalizability before being returned.
- **Two new observable reason codes**: `policy_evaluation_error` and `audit_unavailable`
  (gateway fail-closed overrides); `binding_mismatch` and `deadline_exceeded` are engine
  facts added in Phase 2 self-check fixtures (21 total).
- **Strictness tightening**: `ToolArguments`/`ToolResult` are `strict=True`; registration
  validation requires resource/destination argument annotations to be exactly `str`
  (a non-str annotation could smuggle mismatched resource IDs past derivation).

## Decisions taken during Phase 3 implementation (within blueprint constraints; ADR-010)

- **Advisory, not authoritative**: the detector returns evidence only; it never feeds
  `PolicyEvaluationRequest`, the engine, or the gateway, exposes no execution surface, and
  cannot widen permissions. This is what makes invariant #10 true by construction rather
  than by accidental coupling.
- **Disposition configuration is exhaustive and monotonic**: every `FindingCode` must be
  mapped; any mapping to PASS is rejected; duplicate YAML keys and unknown codes refuse
  startup. Detection failure (`DETECTOR_UNAVAILABLE`) is therefore never clean.
- **Intake order** is size → content type → UTF-8 decode → JSON structure → normalization
  → heuristics → optional classifier; each stage's violations become typed findings, and
  oversize/type/encoding failures never reach heuristics.
- **Copy-only normalization**: the original string/bytes are never mutated; zero-width,
  control, escape, Base64, NFKC, and mixed-script signals are returned separately. JSON
  depth uses an iterative walk (no recursion limit attack).
- **Heuristics are versioned, deterministic, and provenance-bearing**: ten named rules
  (`input-heuristics-v1`), offsets only (no raw content in findings), quoted/educational/
  defensive contexts downgrade to `QUOTED_INSTRUCTION_CONTEXT` (FLAG), and assistant-
  directed rules apply only to `EXTERNAL_UNTRUSTED`/`TOOL_RESULT`.
- **Trust labels are structural**: six canonical labels; email/external content is
  `EXTERNAL_UNTRUSTED` even for an authenticated requester; duplicate/empty segment sets
  are refused; rendering is sorted JSON carrying the label.
- **Session state is opt-in and bound**: `(tenant_id, subject_id)` is required for every
  operation; mismatch = not found; 24 h inactivity and 7 d absolute expiry with lazy
  deletion; `LEAST(...)` clamps counters at 1,000,000; rotation never inherits signals;
  no prompts or findings are stored; the state is not an authorization input in Phase 3.
- **Shared strict YAML**: duplicate-key detection lives in `security/safe_yaml.py` and is
  reused by the policy loader; parsing still uses `yaml.safe_load` (gate-compatible).
- **Optional classifier is not wired**: the protocol exists for Phase 4+ experimentation;
  faults/timeouts produce `DETECTOR_UNAVAILABLE`, preserving fail-closed behavior.

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

## Phase 1 verification record (actual runs, 2026-10-19)

Rows 30+ continue the numbered record. Full evidence: `project_memory/TESTING_AND_VERIFICATION.md` (V30+).

| # | Command | Result |
|---|---|---|
| 30 | `uv run --frozen pytest -q` | PASS — **406 passed** (364 unit + 42 integration; DB-backed integration against the Compose PostgreSQL) |
| 31 | `uv run --frozen mypy src` | PASS — no issues, 35 source files (strict) |
| 32 | `uv run --frozen ruff check src/ tests/`; `ruff format src tests` | PASS — clean (format applied to 3 files, then check clean) |
| 33 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps; Gitleaks 8.30.1 `git` scan: 9 commits, no leaks found |
| 34 | Policy bundle smoke check (`load_policy_bundle` + `check_policy_self_checks`) | PASS — `version: dev-1`, `policies_sha256 35bcd687…`, `thresholds_sha256 3e1d34ae…`, `combined_hash 8a4ba203e3baaf86eabb2e299992166289cae938ec9ea9a7bccadf6e6e068e6a`; 17 fixtures, 0 failures |
| 35 | Integration wiring tests (`test_policy_self_checks_wiring.py`, `test_health.py`) | PASS — invalid/missing policy file refuses startup; mismatching fixture refuses startup; live policy/fixture drift flips readiness to 503; readiness payload carries `policy_version`/`policy_hash` |

## Phase 2 verification record (actual runs, 2026-10-19)

Rows 36+ continue the numbered record. Full evidence:
`project_memory/TESTING_AND_VERIFICATION.md` (V36+).

| # | Command | Result |
|---|---|---|
| 36 | `uv run --frozen pytest -q` | PASS — **520 passed** (461 unit + 47 integration + 12 security; DB-backed integration against the Compose PostgreSQL) |
| 37 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps; Gitleaks 8.30.1 `git` scan: 13 commits, no leaks found |
| 38 | `uv run --frozen pytest tests/security tests/unit/test_gateway.py -q` | PASS — **31 passed** (no-bypass + gateway failure-mode suites) |
| 39 | `uv run --frozen pytest tests/integration/test_gateway_end_to_end.py tests/integration/test_gateway_wiring.py -q` | PASS — **5 passed** (real-PostgreSQL decision/outcome chain order and linkage; startup registry/gateway wiring; unregistered-policy-tool startup refusal) |
| 40 | `uv run --frozen pytest tests/unit/test_policy_self_checks.py tests/integration/test_policy_self_checks_wiring.py -q` | PASS — **41 passed** — 21 fixtures against the real engine, startup + readiness wiring |
| 41 | `uv run --frozen mypy src`; `ruff check src tests`; `ruff format --check src tests` | PASS — no issues, 45 source files (strict); lint/format clean (included in gate step 37) |

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

## Definition of Done checklist (blueprint section 21, Phase 1)

| DoD item | Status |
|---|---|
| Table-driven policy tests cover allowed/forbidden/malformed/cross-scope/unknown/error | **PASS** — `tests/unit/test_policy_engine.py` (64 tests; full matrix incl. malformed requests, cross-scope, unknown tool, error/threshold rows) + loader/model/url suites |
| Strict contracts fail closed on unknown/invalid values | PASS — `extra="forbid"`, strict ints, anchored tool-id pattern, canonical enums without aliases/coercions; covered by `test_policy_models.py`, `test_policy_loader.py`, `test_urls.py` |
| ADR-007 self-check fixtures pass against the real engine (startup + readiness) | PASS — 17 fixtures (7 mandated names retained) pass via `check_policy_self_checks` (row 34) and through app startup/readiness (row 35) |
| No LLM involved in authorization (engine imports no model provider; gate greps intact) | PASS — static imports only; `check.sh` prohibited-pattern greps remain clean |
| Quality gate green (`check.sh`, Gitleaks clean) | PASS — rows 32–33 |

## Definition of Done checklist (blueprint section 21, Phase 2)

| DoD item | Status |
|---|---|
| No-bypass tests prove the mock side-effect sink changes only after a valid gateway `ALLOW` | **PASS** — `tests/security/test_gateway_no_bypass.py` (denied paths never execute; sink empty under every denial and under audit outage) + `tests/integration/test_gateway_end_to_end.py` (sink record only after chained decision/outcome events) |
| Unknown or denied actions have no side effect | PASS — unknown tool, registered-but-disabled tool, invalid arguments, resource/destination mismatches, cross-user scope, deadline expiry, disabled egress: all DENIED with adapter call count 0 and empty sink |
| Every adapter invocation originates from the gateway; direct calls fail closed | PASS — sentinel-guarded `ExecutionAuthorization` (direct construction raises); adapters verify the digest and reject non-authorizations; gateway issues authorization only after a durable `ALLOW` decision event |
| Exceptions during policy/validation/audit prerequisites never continue to a side effect | PASS — engine exception yields `policy_evaluation_error` DENIED; audit append failure on a would-be ALLOW yields `audit_unavailable` DENIED; both leave the sink empty |
| Timeouts and bounded result sizes enforced with typed outcomes | PASS — sleeping adapter with 1 ms timeout yields `TIMEOUT`; oversized result yields `RESULT_REJECTED`/`ResultTooLarge`; wrong-schema result yields `RESULT_REJECTED`/`ResultSchemaMismatch`; per-tool concurrency limit == 1 enforced under `gather` |
| Invalid registry/policy configuration refuses startup | PASS — DESTRUCTIVE/duplicate/mismatched/oversized registrations raise at construction; policy tool without adapter refuses `create_app` (`ToolRegistryConfigError`, tested) |
| Post-authorization tool/argument mutation fails the action-digest check | PASS — `tests/unit/test_mock_adapters.py` (changed arguments, different tool/action) and `tests/unit/test_action_digest.py` coverage |
| Policy engine remains the sole `ALLOW` producer; gateway may only downgrade | PASS — the gateway constructs no ALLOW; audit/deadline/evaluation overrides are BLOCK/DENIED; `ASK_USER` never executes |
| Full suite + gate green; docs/memory/ADR updated | PASS — rows 36-41; ADR-009; this file; `SECURITY_INVARIANTS`, `POLICY_DECISION_MATRIX`, `KNOWN_LIMITATIONS`, memory refresh |

## Phase 3 verification record (actual runs, 2026-10-19)

Rows 42+ continue the numbered record. Full evidence:
`project_memory/TESTING_AND_VERIFICATION.md` (V43+).

| # | Command | Result |
|---|---|---|
| 42 | `uv run --frozen pytest -q` | PASS — **600 passed** (517 unit + 60 integration + 23 security; DB-backed integration against the Compose PostgreSQL) |
| 43 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps; ruff format/lint clean (136 files); mypy 55 source files; Gitleaks 8.30.1 dir+git: 19 commits, no leaks found |
| 44 | Phase 3 targeted suites (`test_input_normalization`, `test_input_heuristics`, `test_input_defense_config`, `test_context_labels`, `test_sessions`, `test_input_defense_failure`) | PASS — 64 passed (detector behavior, quoted-context downgrade, strict config, failure semantics) |
| 45 | Phase 3 integration suites (`test_input_defense_wiring`, `test_session_security_state`) | PASS — 13 passed (startup wiring + refusal; binding, guessed-ID, bounded counters, TTL/max-age expiry, rotation isolation against real PostgreSQL) |
| 46 | `uv run --frozen alembic upgrade head` → `downgrade -1` → `upgrade head` → `check` | PASS — `c7f1a2b3d4e5` applies, downgrades, and re-applies cleanly; "No new upgrade operations detected" |
| 47 | Manual service smoke (benign/attack/quoted/external/zero-width/homoglyph) | PASS — PASS / REJECT / FLAG / QUARANTINE / REJECT(OBFUSCATED+DIRECT) / FLAG(HOMOGLYPH_INDICATORS) with documented honest limits |

## Definition of Done checklist (blueprint section 21, Phase 3)

| DoD item | Status |
|---|---|
| Injection attempts on user input and external/tool content raise typed findings | **PASS** — 10 versioned heuristic rules; unit matrix covers direct override, secret/system-prompt extraction, developer mode, jailbreak, external-only assistant-directed instructions; findings carry codes, offsets, and versions |
| Benign and quoted/educational mentions are not treated as attacks | PASS — qualification windows downgrade to `QUOTED_INSTRUCTION_CONTEXT` (FLAG); benign hard-negative parametrized cases raise no findings |
| Detector/provider outage never fails open | PASS — every intake/detector/normalizer/classifier fault yields `DETECTOR_UNAVAILABLE` with the configured non-PASS disposition; no finding code can map to PASS; oversize/unsupported/invalid-encoding rejected before heuristics |
| Trust labels are attached and preserved through context assembly | PASS — six canonical labels; external email forced to `EXTERNAL_UNTRUSTED` for authenticated requesters; duplicate/empty segment sets refused; deterministic JSON rendering includes the label |
| Session signals are bound, bounded, and expire | PASS — every operation requires `(tenant_id, subject_id)` with mismatch = not found; 24 h inactivity/7 d absolute expiry with lazy deletion; counters clamped at 1,000,000; rotation inherits nothing (real-PostgreSQL tests) |
| Detection cannot influence authorization or execution | PASS — no import/wiring path into policy facts, engine, or gateway; service exposes no invocation method (asserted); invariants #10/#11/#15/#23 updated honestly in `docs/SECURITY_INVARIANTS.md` |
| Strict configuration refuses startup when invalid or incomplete | PASS — duplicate keys, missing/unknown finding codes, invalid content types, and PASS mappings all refuse startup (unit + app-wiring tests) |
| Quality gate green; docs/memory/ADR updated | PASS — rows 42-47; ADR-010; this file; `SECURITY_INVARIANTS`, `KNOWN_LIMITATIONS`, `THREAT_MODEL`, `ARCHITECTURE`, README, memory refresh |

## How to continue (next session)

Phase 4 — Intent extraction and action validation (blueprint section 21, sections 8-9):
parse structured intents, bind them to tool/action/resource targets, and validate plan
consistency before execution while keeping the deterministic policy engine as the sole
`ALLOW` producer. Read blueprint sections 8-9; keep the ADR-007/ADR-008 fixture contract,
the ADR-009 gateway contract, ADR-010's advisory-detection boundary, and every existing
test green. Invariants #10, #11, #15, #16, #23 remain at their recorded status; do not
claim end-to-end enforcement before the routes and model context consume these layers.
