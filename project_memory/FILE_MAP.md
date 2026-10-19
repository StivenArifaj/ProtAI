# File Map

Navigation map: purpose, status, related tests, blueprint references. Status labels per
[README.md](README.md). Update when files are added or removed. Paths are relative to the repository
root; entries in tables below use [../](../) where needed for links.

## Root

| File | Purpose | Status | Tests | Blueprint |
|---|---|---|---|---|
| [../AI_Agent_Security_Platform_Master_Blueprint_v1.2.md](../AI_Agent_Security_Platform_Master_Blueprint_v1.2.md) | Authoritative specification (all phases) | authoritative | n/a | all |
| [../archive/AI_Agent_Security_Platform_Master_Blueprint_v1.0_superseded.md](../archive/AI_Agent_Security_Platform_Master_Blueprint_v1.0_superseded.md) | Archived v1.0; do not implement from | archived | n/a | — |
| [../README.md](../README.md) | Setup, run commands, documentation map | VERIFIED | n/a | §21/§24 |
| `../pyproject.toml` | Project metadata, deps, ruff/mypy/pytest config | VERIFIED | n/a | §5.1 |
| `../uv.lock` | Locked dependency graph (38 resolved) | VERIFIED | V2/V3 | §5.1 |
| `../.python-version` | `3.12` | VERIFIED | V1 | §5.1 |
| `../.gitignore` | Ignores `.env`, venv, caches, build artifacts | VERIFIED | n/a | §5.4 |
| `../.env.example` | Full §5.4 env template; public disposable dev values; consumed/validated at startup since 0b | VERIFIED | settings tests | §5.4 |
| `../.gitleaks.toml` | Extends default Gitleaks rules; narrow allowlist for the one documented Compose dev key | VERIFIED | V24/V29 | §20.3 |
| `../Makefile` | `check`/`test`/`migrate`/`up`/`down`/`logs` targets | VERIFIED | V22/V24 | §21 |
| `../Dockerfile` | Digest-pinned app image; uv installs from lock; non-root uid 10001; COPY `config/ migrations/ alembic.ini` | VERIFIED | V25 | §5.1 |
| `../docker-compose.yml` | Local stack: api + `postgres:17.2-alpine`; healthchecks; 127.0.0.1 bindings; API host port 8080; dev `HOST_AUTH_KEYS_JSON` | VERIFIED | V25–V27 | §21 |

## Application ([../src/ai_security/](../src/ai_security/))

| File | Purpose | Status | Tests | Blueprint |
|---|---|---|---|---|
| `__init__.py` | Package marker | VERIFIED | — | — |
| `settings.py` | `AppEnv`/`LogLevel`/`PrincipalResolverKind` StrEnums; fail-closed `Settings` incl. host-auth keys, tolerance/TTL, request bound, self-check path, `policy_path`/`risk_thresholds_path` (Phase 1) | VERIFIED | 55 settings tests | §5.1/§5.4, §9.2, §18.2 |
| `security/constant_time.py` | `constant_time_bytes_equal`, `constant_time_hex32_equal` (confinement enforced by the gate) | VERIFIED | 16 tests | §9.2 |
| `security/canonical_json.py` | Canonical JSON text/bytes | VERIFIED | 17 tests | ADR-002/006 |
| `security/urls.py` | Destination canonicalization: https-only, IDNA host, percent-encoding normalization, exact-match semantics (Phase 1) | VERIFIED | 36 tests | §6.2, §10.4, ADR-008 |
| `audit/hash_chain.py` | ADR-002 hash formula, genesis, fixed vectors | VERIFIED | 17 tests | §16.2, ADR-002 |
| `identity/models.py` | Strict frozen `Principal`; `PrincipalResolutionError` | VERIFIED | principal tests | §9 |
| `identity/signing.py` | Exact `v1` signing message; header constants; `sign_request` | VERIFIED | verifier/signing tests | §9.2, ADR-001 |
| `identity/host_auth.py` | Verification + full rejection surface + `verified_nonce` | VERIFIED | verifier matrix | §9.2 |
| `identity/resolver.py` | `DevPrincipalResolver` (guarded), fail-closed `HostPrincipalResolver`, factory guard | VERIFIED | resolver tests | §9.3, ADR-001 |
| `identity/adapters.py` | `TestPrincipalResolver`/`TestAdapterRefusedError` — test-only, unreachable via settings/factory (Phase 1) | VERIFIED | 8 tests | §9.3, ADR-008 |
| `persistence/database.py` | Async engine/session factory; never-raising `healthy()` | VERIFIED | health + integration | ADR-005 |
| `persistence/models.py` | `host_request_nonces` (unique key+nonce), `audit_events` (unique chain+seq) | VERIFIED | repository tests | §9.2, §16.2 |
| `persistence/nonce_repository.py` | Atomic single-statement nonce registration | VERIFIED | concurrency tests | §9.4 |
| `persistence/audit_repository.py` | ADR-002 advisory-lock append with canonical bytes | VERIFIED | vector + 5-writer tests | §16.2, ADR-002 |
| `tools/base.py` | Canonical `SideEffectClass` enum + tool-id contract (Phase 1; Phase 2 extends) | VERIFIED | policy model/engine tests | §6.1, ADR-008 |
| `data_security/classification.py` | Canonical `DataClass` enum (Phase 1; classification Phase 6) | VERIFIED | policy model/engine tests | §6.1, ADR-008 |
| `firewall/decision.py` | `FirewallDecision`, stable `DecisionReason` codes, `DecisionRecord` (Phase 1) | VERIFIED | 64 engine tests | §6.1, §10.3, ADR-008 |
| `firewall/policy_engine.py` | Deterministic §10.2 evaluation over strict facts; deny-by-default; no I/O (Phase 1) | VERIFIED | 64 engine tests | §10.2, §11.4, ADR-008 |
| `policy/models.py` | Validated policy documents, `ToolPolicy`, `Thresholds`, `PolicyBundle` (version + content hashes) | VERIFIED | 38 tests | §10.4, §10.7, ADR-008 |
| `policy/loader.py` | Safe YAML loader: `yaml.safe_load` + `yaml.compose` duplicate-key detection; `PolicyConfigError` fails closed | VERIFIED | 20 tests | §10.4, ADR-008 |
| `policy/self_checks.py` | Strict fixture loader/runner + `PolicyReadinessReport`/`evaluate_policy_readiness` evaluated against the real engine | VERIFIED | 33 + wiring tests | ADR-007, ADR-008 |
| `api/__init__.py` | Package marker | VERIFIED | — | — |
| `api/app.py` | `create_app` factory + module-level `app`; startup refusals (incl. policy config); middleware + registrar + audit chain wiring | VERIFIED | health + wiring tests | §18.2, ADR-007/008 |
| `api/dependencies.py` | `get_settings`; `database_ready`; `policy_readiness` returning `PolicyReadinessReport` (overridable) | VERIFIED | health tests | §18.1, §20.1 |
| `api/routes_health.py` | `/health/live`, `/health/ready` (config/database/policy_self_checks + `policy_version`/`policy_hash`; booleans + metadata only) | VERIFIED | health tests | §18.1 |
| `api/middleware.py` | `HostAuthMiddleware` on `/v1/*` (size → HMAC → nonce → replay) | VERIFIED | 13 middleware tests + live V26/V27 | §9.2, §18.2 |

## Tests ([../tests/](../tests/))

| File | Purpose | Status | Count |
|---|---|---|---|
| `conftest.py` | Deterministic test env (incl. `HOST_AUTH_KEYS_JSON`); `settings_factory` (`_env_file=None`) | VERIFIED | — |
| `unit/test_settings.py` | Settings validation incl. host-auth keys, resolver guard, TTL relation, self-check/policy paths | VERIFIED | 55 |
| `unit/test_constant_time.py` | Constant-time equality helpers | VERIFIED | 16 |
| `unit/test_canonical_json.py` | Canonical JSON stability | VERIFIED | 17 |
| `unit/test_hash_chain.py` | ADR-002 formula + fixed vectors | VERIFIED | 17 |
| `unit/test_host_auth_verifier.py` | Signing message vector + full rejection matrix | VERIFIED | 46 |
| `unit/test_principal_resolver.py` | `Principal` model + resolver guards | VERIFIED | 14 |
| `unit/test_principal_test_adapter.py` | Test-only adapter: construction guard, factory exclusion | VERIFIED | 8 |
| `unit/test_urls.py` | Destination canonicalization (IDNA, encoding, rejections) | VERIFIED | 36 |
| `unit/test_policy_models.py` | Strict policy/threshold/bundle models + hashes | VERIFIED | 38 |
| `unit/test_policy_loader.py` | Safe loading, duplicate keys, malformed documents | VERIFIED | 20 |
| `unit/test_policy_engine.py` | Table-driven matrix: allowed/forbidden/malformed/cross-scope/unknown/error | VERIFIED | 64 |
| `unit/test_policy_self_checks.py` | Fixture runner/readiness (bundle API) | VERIFIED | 33 |
| `integration/conftest.py` | `migrated_database` fixture: create `firewall_test`, run Alembic, skip if unreachable | VERIFIED | — |
| `integration/db_helpers.py` | `DatabaseHarness` (NullPool) for asyncio.run tests | VERIFIED | — |
| `integration/test_health.py` | Health endpoints, docs gating, non-leakage, readiness incl. policy version/hash | VERIFIED | 10 |
| `integration/test_host_auth_middleware.py` | End-to-end denial matrix through the ASGI app | VERIFIED | 13 |
| `integration/test_nonce_repository.py` | Atomic registration incl. expiry + failure paths | VERIFIED | 5 |
| `integration/test_audit_append.py` | Chain continuity, vectors, 5-writer concurrency | VERIFIED | 5 |
| `integration/test_migrations.py` | Upgrade idempotency | VERIFIED | 1 |
| `integration/test_policy_self_checks_wiring.py` | Startup refusals + readiness drift detection | VERIFIED | 8 |

## Scripts

| File | Purpose | Status | Blueprint |
|---|---|---|---|
| `../scripts/check.sh` | 8-step local gate: `uv lock --check`; ruff format; ruff lint; mypy; pytest (406); **Gitleaks 8.30.1** (`dir` + `git`, redacted, fails if missing/mismatched); prohibited-pattern greps (prohibit `os.system(`, `subprocess`, `shell=True`, `eval(`, `exec(`, `pickle`, `yaml.load(` in `src/`); `compare_digest` confinement grep | VERIFIED | §20.3 |

## Migrations

| File | Purpose | Status | Blueprint |
|---|---|---|---|
| `../alembic.ini` | Alembic config; `script_location` only (URL comes from settings) | VERIFIED | ADR-006 |
| `../migrations/env.py` | Async env reading `Settings`/`DATABASE_URL`; targets `Base.metadata` | VERIFIED | ADR-005/006 |
| `../migrations/versions/d15b46c49950_baseline_host_request_nonces_audit_.py` | Baseline: `host_request_nonces`, `audit_events` | VERIFIED | §9.2, §16.2 |

## Config

| File | Purpose | Status | Blueprint |
|---|---|---|---|
| `../config/policies.yaml` | Starter policy (v1 §10.5): allowed read actions + `mock_external_sink.write` registered with egress disabled; `version: dev-1` | VERIFIED | §10.4–10.5, ADR-008 |
| `../config/risk_thresholds.yaml` | Experimental thresholds 40/80, validated ordering; `version: dev-1` | VERIFIED | §11.4, ADR-008 |
| `../config/policy_self_checks.yaml` | 17 strict fixtures (7 mandated names) evaluated against the real engine at startup + readiness; fixture-level `tool_policy` overrides for the §10.5 egress scenario | VERIFIED | §10.3, ADR-007/008 |

## Docs ([../docs/](../docs/))

| File | Purpose | Status |
|---|---|---|
| [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) | Component map + per-request lifecycle; per-component status marks | VERIFIED (doc) |
| [../docs/THREAT_MODEL.md](../docs/THREAT_MODEL.md) | 16 threats + trust classes/boundaries with implementation status | VERIFIED (doc) |
| [../docs/SECURITY_INVARIANTS.md](../docs/SECURITY_INVARIANTS.md) | 25 mandatory invariants (blueprint §20.2) with statuses (#17/#18/#25 implemented; #3/#4/#5 engine-level partial) | VERIFIED (doc) |
| [../docs/POLICY_DECISION_MATRIX.md](../docs/POLICY_DECISION_MATRIX.md) | Mandated v1 decision matrix (implemented by the Phase 1 engine; reason-code mapping documented) | VERIFIED (doc) |
| [../docs/DECISIONS.md](../docs/DECISIONS.md) | ADR index (summaries + links; no full ADRs) | VERIFIED (doc) |
| [../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md) | Blueprint §22.4 phase-state document; 35-row verification record; 0a/0b/1 DoD checklists | VERIFIED |
| [../docs/KNOWN_LIMITATIONS.md](../docs/KNOWN_LIMITATIONS.md) | Limitations items 1–24 with phase pointers | VERIFIED |
| [../docs/adr/ADR-001-host-hmac-authentication.md](../docs/adr/ADR-001-host-hmac-authentication.md) | HMAC host auth + dev-resolver guard (Phase 0b) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-002-audit-hash-chain.md](../docs/adr/ADR-002-audit-hash-chain.md) | Audit hash-chain append + canonical bytes (Phase 7; scaffold 0b) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-003-no-token-streaming.md](../docs/adr/ADR-003-no-token-streaming.md) | v1 streaming disabled (Phase 6/8) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-004-soc-alert-only.md](../docs/adr/ADR-004-soc-alert-only.md) | SOC analyzer alert-only (Phase 10) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-005-sqlalchemy-async-persistence.md](../docs/adr/ADR-005-sqlalchemy-async-persistence.md) | SQLAlchemy 2.x async persistence (Phase 0b) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-006-alembic-migrations.md](../docs/adr/ADR-006-alembic-migrations.md) | Alembic for schema changes (Phase 0b) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-007-policy-matrix-self-checks.md](../docs/adr/ADR-007-policy-matrix-self-checks.md) | Policy matrix + startup self-checks (Phase 1; scaffold 0b) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-008-policy-engine-typed-contracts.md](../docs/adr/ADR-008-policy-engine-typed-contracts.md) | Deterministic policy engine + strict typed contracts + versioned bundle (Phase 1) | VERIFIED (ADR, Accepted) |

## Memory (`project_memory/`)

| File | Purpose |
|---|---|
| [README.md](README.md) | Entry point, reading order, status labels, update rules |
| [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) | Identity, goals, non-goals, stack, environment |
| [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) | Source of truth for what exists now |
| [NEXT_SESSION.md](NEXT_SESSION.md) | Handoff for Phase 2 |
| [ARCHITECTURE_MAP.md](ARCHITECTURE_MAP.md) | Implemented vs target architecture |
| [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) | Security contract with per-control status |
| [DECISION_LOG.md](DECISION_LOG.md) | ADR links + implementation decisions |
| [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) | Commands, fresh + historical evidence |
| [KNOWN_ISSUES_AND_LIMITATIONS.md](KNOWN_ISSUES_AND_LIMITATIONS.md) | Gaps with severity and next actions |
| [PHASE_ROADMAP.md](PHASE_ROADMAP.md) | Phases 0a–10 + release maturity |
| [FILE_MAP.md](FILE_MAP.md) | This file |
| [AGENT_WORK_PROTOCOL.md](AGENT_WORK_PROTOCOL.md) | Mandatory working rules |
| [CHANGELOG.md](CHANGELOG.md) | Dated history |
| [phases/PHASE_0A_COMPLETE.md](phases/PHASE_0A_COMPLETE.md) | Phase 0a record |
| [phases/PHASE_0B_COMPLETE.md](phases/PHASE_0B_COMPLETE.md) | Phase 0b record |
| [phases/PHASE_0B_PLAN.md](phases/PHASE_0B_PLAN.md) | Phase 0b plan (executed) |
| [phases/PHASE_1_PLAN.md](phases/PHASE_1_PLAN.md) | Phase 1 plan (executed) |
| [phases/PHASE_1_COMPLETE.md](phases/PHASE_1_COMPLETE.md) | Phase 1 record |
| [phases/PHASE_TEMPLATE.md](phases/PHASE_TEMPLATE.md) | Phase-record template |

## Not yet present (planned locations)

`src/ai_security/{input_defense,intent,agent,soc}/`, `evaluation/` — see
[ARCHITECTURE_MAP.md](ARCHITECTURE_MAP.md) for the phase that creates each.
(`identity/`, `security/`, `persistence/`, `policy/`, `audit/`, `firewall/`, `tools/`,
`data_security/`, `migrations/`, `config/` now exist; `firewall/` currently holds the
Phase 1 decision contract + policy engine only — the gateway/risk/approvals land later.)
