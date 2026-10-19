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
| `../.env.example` | Full §5.4 env template; public disposable dev values; 0a-vs-0b notes | VERIFIED | settings tests | §5.4 |
| `../Makefile` | `check`/`test`/`up`/`down`/`logs` targets | VERIFIED | n/a | §21 |
| `../Dockerfile` | Digest-pinned app image; uv installs from lock; non-root uid 10001 | VERIFIED | V7–V9 | §5.1 |
| `../docker-compose.yml` | Local stack: api + `postgres:17.2-alpine`; healthchecks; 127.0.0.1 bindings; API host port 8080 | VERIFIED | V4–V12 | §21 |

## Application ([../src/ai_security/](../src/ai_security/))

| File | Purpose | Status | Tests | Blueprint |
|---|---|---|---|---|
| `__init__.py` | Package marker | VERIFIED | — | — |
| `settings.py` | `AppEnv`/`LogLevel` StrEnums; fail-closed `Settings`; `database_dsn` | VERIFIED | 17 settings tests | §5.1/§5.4, §18.2 |
| `api/__init__.py` | Package marker | VERIFIED | — | — |
| `api/app.py` | `create_app` factory + module-level `app`; docs gating; startup failure on bad config | VERIFIED | test_health | §18.2 |
| `api/dependencies.py` | `get_settings`; `database_ready` probe (asyncpg, 2 s, overridable) | VERIFIED | test_health (dependency override) | §18.1, §20.1 |
| `api/routes_health.py` | `/health/live`, `/health/ready` (200/503, booleans only) | VERIFIED | 8 health tests | §18.1 |

## Tests ([../tests/](../tests/))

| File | Purpose | Status | Count |
|---|---|---|---|
| `conftest.py` | Forces deterministic test env; `settings_factory` fixture (`_env_file=None`) | VERIFIED | — |
| `unit/test_settings.py` | Settings validation, masking, refusal rules | VERIFIED | 17 |
| `integration/test_health.py` | Health endpoints, docs gating, non-leakage | VERIFIED | 8 |

## Scripts

| File | Purpose | Status | Blueprint |
|---|---|---|---|
| `../scripts/check.sh` | 6-step local gate: `uv lock --check`; ruff format; ruff lint; mypy; pytest; invariant greps (prohibit `os.system(`, `subprocess`, `shell=True`, `eval(`, `exec(`, `pickle`, `yaml.load(` in `src/`) | VERIFIED | §20.3 |

## Docs ([../docs/](../docs/))

| File | Purpose | Status |
|---|---|---|
| [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) | Component map + per-request lifecycle; per-component status marks | VERIFIED (doc) |
| [../docs/THREAT_MODEL.md](../docs/THREAT_MODEL.md) | 16 threats + trust classes/boundaries with implementation status | VERIFIED (doc) |
| [../docs/SECURITY_INVARIANTS.md](../docs/SECURITY_INVARIANTS.md) | 25 mandatory invariants (blueprint §20.2) with statuses (#14/#16/#18 partial; rest pending) | VERIFIED (doc) |
| [../docs/POLICY_DECISION_MATRIX.md](../docs/POLICY_DECISION_MATRIX.md) | Mandated v1 decision matrix (specification; not enforced yet) | VERIFIED (doc) |
| [../docs/DECISIONS.md](../docs/DECISIONS.md) | ADR index (summaries + links; no full ADRs) | VERIFIED (doc) |
| [../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md) | Blueprint §22.4 phase-state document; 17-row verification record; DoD checklist | VERIFIED |
| [../docs/KNOWN_LIMITATIONS.md](../docs/KNOWN_LIMITATIONS.md) | Limitations items 1–15 with phase pointers | VERIFIED |
| [../docs/adr/ADR-001-host-hmac-authentication.md](../docs/adr/ADR-001-host-hmac-authentication.md) | HMAC host auth + dev-resolver guard (Phase 0b) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-002-audit-hash-chain.md](../docs/adr/ADR-002-audit-hash-chain.md) | Audit hash-chain append + canonical bytes (Phase 7; scaffold 0b) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-003-no-token-streaming.md](../docs/adr/ADR-003-no-token-streaming.md) | v1 streaming disabled (Phase 6/8) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-004-soc-alert-only.md](../docs/adr/ADR-004-soc-alert-only.md) | SOC analyzer alert-only (Phase 10) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-005-sqlalchemy-async-persistence.md](../docs/adr/ADR-005-sqlalchemy-async-persistence.md) | SQLAlchemy 2.x async persistence (Phase 0b) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-006-alembic-migrations.md](../docs/adr/ADR-006-alembic-migrations.md) | Alembic for schema changes (Phase 0b) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-007-policy-matrix-self-checks.md](../docs/adr/ADR-007-policy-matrix-self-checks.md) | Policy matrix + startup self-checks (Phase 1; scaffold 0b) | VERIFIED (ADR, Accepted) |

## Memory (`project_memory/`)

| File | Purpose |
|---|---|
| [README.md](README.md) | Entry point, reading order, status labels, update rules |
| [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) | Identity, goals, non-goals, stack, environment |
| [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) | Source of truth for what exists now |
| [NEXT_SESSION.md](NEXT_SESSION.md) | Handoff for Phase 0b |
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
| [phases/PHASE_0B_PLAN.md](phases/PHASE_0B_PLAN.md) | Phase 0b plan |
| [phases/PHASE_TEMPLATE.md](phases/PHASE_TEMPLATE.md) | Phase-record template |

## Not yet present (planned locations)

`src/ai_security/{identity,security,persistence,input_defense,intent,agent,firewall,tools,data_security,audit,soc}/`,
`migrations/` + `alembic.ini`, `config/*.yaml`, `evaluation/` — see [ARCHITECTURE_MAP.md](ARCHITECTURE_MAP.md)
for the phase that creates each.
