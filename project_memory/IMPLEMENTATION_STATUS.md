# Implementation Status

**Last inspected: 2026-10-19** (same day as Phase 0a completion, re-verified in this
session). This file is the operational source of truth for what exists. Evidence IDs
(V1–V17) are defined in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md). Keep this file and
[../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md) consistent whenever phase state changes.

## Phase status

| Phase | Status | Evidence |
|---|---|---|
| Phase 0a — Repository foundation | **COMPLETE — VERIFIED** | [phases/PHASE_0A_COMPLETE.md](phases/PHASE_0A_COMPLETE.md); V1–V13 (fresh) + V14–V17 (recorded) |
| Phase 0b — Security foundation | **NOT STARTED** | plan: [phases/PHASE_0B_PLAN.md](phases/PHASE_0B_PLAN.md) |
| Phases 1–10 | **NOT IMPLEMENTED** | [PHASE_ROADMAP.md](PHASE_ROADMAP.md) |

Repository state: **NOT a git repository** (`git rev-parse` → exit 128; no history, no
commits). File count before this memory directory was added: 35 files (excluding
`.venv`/caches); the tool/agent inspection found no discrepancies between the supplied
Phase 0a report and reality.

## What exists (all VERIFIED)

| Area | Files | Notes |
|---|---|---|
| Project metadata | `../pyproject.toml`, `../uv.lock`, `../.python-version`, `../.gitignore`, `../.env.example`, `../Makefile` | Python `>=3.12,<3.13`; lockfile resolves 38 packages |
| Application runtime | `../src/ai_security/__init__.py`, `settings.py`, `api/app.py`, `api/dependencies.py`, `api/routes_health.py` (6 files) | App factory + module-level `app`; strict settings validation; health endpoints |
| Tests | `../tests/conftest.py`, `unit/test_settings.py` (17 tests), `integration/test_health.py` (8 tests) | 25 tests, all passing |
| Quality gate | `../scripts/check.sh` | 6 steps; exits non-zero on failure |
| Containers | `../Dockerfile`, `../docker-compose.yml` | Digest-pinned base images; non-root uid 10001; db + api healthchecks |
| Spec-adjacent docs | [../docs/](../docs/) (ARCHITECTURE, THREAT_MODEL, SECURITY_INVARIANTS, POLICY_DECISION_MATRIX, DECISIONS + `adr/ADR-001..007`, IMPLEMENTATION_STATE, KNOWN_LIMITATIONS) | ADR-001..007 recorded per blueprint §21 |
| Memory (this directory) | `project_memory/*` | Created 2026-10-19; see [README.md](README.md) |

## Security controls — what is actually enforced today

Implemented and tested (Phase 0a scope only):

- **Configuration fail-closed validation:** `APP_ENV` required (unknown values rejected),
  `DATABASE_URL` must use `postgresql+asyncpg://` (ADR-005), the documented sample
  development password in `.env.example`/`docker-compose.yml` is refused outside
  `development`/`test`.
- **Documentation gating:** `/docs`, `/redoc`, `/openapi.json` exist only when `APP_ENV`
  is exactly `development` or `test`.
- **Non-leakage:** health responses contain only status booleans; `DATABASE_URL` is a
  `SecretStr` and does not render in `repr`/`str`; readiness failures log only the
  exception class.

NOT implemented (do not claim otherwise): host authentication, principal resolution,
policy engine, tool registry, firewall gateway, risk engine, approvals, input defense,
DLP/egress, audit chain, rate limits, AI SOC. See [../docs/SECURITY_INVARIANTS.md](../docs/SECURITY_INVARIANTS.md)
(25 invariants; #14/#16/#18 partial, all others pending).

## Current-session verification (2026-10-19, fresh runs)

All PASS — full commands and results in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) (V1–V13):

- `uv sync --frozen` clean; `bash scripts/check.sh` exit 0 (ruff/mypy clean, 25 tests).
- `docker compose config -q` exit 0; Docker daemon 29.3.1 / Compose v5.1.1 available.
- Compose path live: `protai-db-1` + `protai-api-1` healthy; `/health/live` 200;
  `/health/ready` 200 against real PostgreSQL; docs/openapi 200; leak scan 0; runtime
  `uid=10001(app)`.
- Production-profile container: live 200; docs/redoc/openapi 404; ready 503
  (correct fail-closed for a non-matching, non-sample credential).
- In-container startup refusal with the sample password in production: exit 1 with clear
  message.
- Stack torn down (`docker compose down`); `db_data` volume preserved.

## Environment (verified this session)

macOS (darwin); uv 0.13.1; Python 3.12.15; Docker 29.3.1 / Compose v5.1.1 (Docker
Desktop running); git 2.54.0 (repository not initialized); no markdown linter installed.
Current stack state: stopped.

## Discrepancies vs the supplied Phase 0a report

**None found** — the report matches the repository. The file inventory, test counts,
behavior, and Docker claims were independently re-verified in this session (V1–V13).
Two wording notes (not discrepancies):

1. Package counts differ by command: `uv lock`/`uv.lock` resolves **38 packages**;
   `uv sync --frozen` reports **36 packages checked** (the installed set). Both expected.
2. The Phase 0a report says readiness returned 503 "when the test database was
   intentionally unreachable"; the recorded run's cause was a non-matching (non-sample)
   password against the dev database — identical external behavior, documented in
   [../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md) row 12.

One blueprint-conformance note (low severity, documentation only): blueprint §22.4
specifies ADRs include "context, decision, alternatives considered, security
consequences, tests/verification, and status"; the recorded ADRs use
Status/Date/Implementation + Context/Decision/Consequences/References and do not carry
explicit "alternatives considered" or "tests/verification" sections. Not a security gap;
see [phases/PHASE_0A_COMPLETE.md](phases/PHASE_0A_COMPLETE.md) ("Conformance notes"). Decision on whether to enrich
the format belongs to the operator (new ADRs can add the sections without rewriting
history).

## Deferred to Phase 0b (planned, not implemented)

HMAC-SHA256 host auth (§9.2); timestamp tolerance and atomic nonce replay rejection
(`host_request_nonces`, unique `(key_id, nonce)`); SQLAlchemy 2.x async persistence
(ADR-005); Alembic baseline (ADR-006); `DevPrincipalResolver` startup guard (§9.3);
`config/policy_self_checks.yaml` scaffolding wired into readiness (ADR-007); Gitleaks in
`scripts/check.sh`; authentication-failure and startup-invariant tests. The `config/`,
`migrations/`, and `evaluation/` directories do not exist yet.
