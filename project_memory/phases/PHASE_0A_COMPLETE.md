# Phase 0a — Repository Foundation — COMPLETE (VERIFIED)

- **Status:** COMPLETE — technical DoD all PASS, verified 2026-10-19 (including the
  Docker Compose path). Formal operator review/go-ahead remains the gate to Phase 0b
  (blueprint §21/§24).
- **Blueprint:** §21 (Phase 0a), §24 (first task prompt); spec v1.2.

## Scope delivered

| Deliverable (blueprint §21) | Delivered as | Status |
|---|---|---|
| Repository layout and package scaffold | `src/ai_security/` package (`settings.py`, `api/`), `tests/` | VERIFIED |
| `pyproject.toml` / `uv.lock` | hatchling, Python `>=3.12,<3.13`; runtime deps fastapi/uvicorn/pydantic/pydantic-settings/asyncpg; dev deps pytest/httpx2/ruff/mypy; 38 packages resolved | VERIFIED |
| `.gitignore`, `.env.example` | `.env*` ignored except example; full §5.4 variable set with 0a-vs-0b header | VERIFIED |
| Dockerfile + Compose (API + PostgreSQL) | digest-pinned `python:3.12.8-slim-bookworm` + `uv:0.13.1`; non-root uid 10001; `postgres:17.2-alpine`; healthchecks; `depends_on: service_healthy`; API host port 8080 (container 8000) | VERIFIED |
| Settings validation | required `APP_ENV`; `postgresql+asyncpg://` scheme (ADR-005); sample dev password refused outside development/test | VERIFIED |
| Minimal FastAPI app + `/health/live`, `/health/ready` | `create_app` factory + module-level `app`; readiness does a real `SELECT 1` via asyncpg (2 s timeout), overridable dependency | VERIFIED |
| Baseline pytest/HTTPX tests | 25 tests (17 settings + 8 health/gating/non-leakage); `httpx2` per Starlette 1.9 | VERIFIED |
| `scripts/check.sh` initial checks | 6 steps: `uv lock --check`; ruff format; ruff lint; mypy; pytest; invariant greps; exits non-zero on any failure | VERIFIED |
| README setup | prerequisites, no-Docker setup, Compose run, expected results, config rules, docs map | VERIFIED |
| Docs scaffold | [../../docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md), [THREAT_MODEL.md](../../docs/THREAT_MODEL.md), [SECURITY_INVARIANTS.md](../../docs/SECURITY_INVARIANTS.md), [POLICY_DECISION_MATRIX.md](../../docs/POLICY_DECISION_MATRIX.md), [DECISIONS.md](../../docs/DECISIONS.md) (index), [IMPLEMENTATION_STATE.md](../../docs/IMPLEMENTATION_STATE.md), [KNOWN_LIMITATIONS.md](../../docs/KNOWN_LIMITATIONS.md), and `adr/ADR-001..007` | VERIFIED |
| ADR-001..007 recorded before Phase 1 | seven Accepted ADRs in [../../docs/adr/](../../docs/adr/) | VERIFIED |

Deliberately **not** implemented (Phase 0b and beyond): HMAC host auth, nonce/replay,
SQLAlchemy persistence, Alembic, `DevPrincipalResolver` guard, policy self-check
scaffolding, Gitleaks, `/v1/*` routes, every later-phase control.

## Conformance notes / deviations (documented, not hidden)

- `httpx2` substituted for the blueprint's "HTTPX" wording: Starlette 1.9's `TestClient`
  requires `httpx2` (maintained successor in the HTTPX family). Recorded in
  [../../docs/IMPLEMENTATION_STATE.md](../../docs/IMPLEMENTATION_STATE.md) and [../DECISION_LOG.md](../DECISION_LOG.md).
- Readiness probe uses raw asyncpg (SQLAlchemy is Phase 0b); ADR-005 records that it
  folds into the persistence layer in 0b.
- Compose API host port is 8080 (host port 8000 occupied by unrelated local emulators).
- Base images pinned by digest rather than tag only (§5.1 conformance, stricter).
- Blueprint/archive markdown excluded from ruff (`extend-exclude`) so authoritative
  documents are never reformatted.
- **ADR format nuance (low severity):** blueprint §22.4 names "alternatives considered"
  and "tests/verification" as ADR content; ADR-001..007 use
  Status/Date/Implementation + Context/Decision/Consequences/References. Not a security
  gap; new ADRs can include the extra sections (operator decision; do not rewrite
  history silently).

## Verification evidence

- Fresh re-run this session: [../TESTING_AND_VERIFICATION.md](../TESTING_AND_VERIFICATION.md) V1–V13 (uv sync; check.sh
  exit 0 with 25 tests; compose config; live stack db+api healthy; readiness 200 real
  DB; docs 200 dev; uid 10001; production gating 404/503; sample-password refusal exit 1;
  teardown; git exit 128).
- Historical full record (17 rows incl. injected-failure proof and fresh-copy
  approximation): [../../docs/IMPLEMENTATION_STATE.md](../../docs/IMPLEMENTATION_STATE.md); see also
  [../TESTING_AND_VERIFICATION.md](../TESTING_AND_VERIFICATION.md) V14–V17.

## Definition of Done (blueprint §21) — final status

| DoD item | Status |
|---|---|
| Fresh clone setup succeeds on macOS with Docker using only documented commands | **PASS** (clean-copy approximation V17; Compose path V6–V12) |
| Configuration errors are clear and fail startup | PASS (V10/V11/V15/V16; 25 tests) |
| No secrets committed | PASS as far as a non-git tree allows — only documented public sample values exist; Gitleaks arrives in 0b; repo not under git yet |
| `scripts/check.sh` exits non-zero on any failure | PASS (injected-failure proof, [IMPLEMENTATION_STATE.md](../../docs/IMPLEMENTATION_STATE.md) rows 3–5) |
| Health and OpenAPI checks pass | PASS (V8 dev; V10 production gating; leak scan 0) |
| No claim of Phase 0b security controls | PASS (docs status columns; no auth code exists) |

## Limitations added by this phase

See [../KNOWN_ISSUES_AND_LIMITATIONS.md](../KNOWN_ISSUES_AND_LIMITATIONS.md) (items 1–20) and
[../../docs/KNOWN_LIMITATIONS.md](../../docs/KNOWN_LIMITATIONS.md) (items 1–15). Headline: no auth, no authorization, no
input/output protection, no audit, no schema/migrations, no secret scanning, no git.

## Handoff

Next task: **Phase 0b — Security foundation** ([PHASE_0B_PLAN.md](PHASE_0B_PLAN.md)). Preconditions: the
operator's Phase 0a review/go-ahead; recommended `git init` + baseline commit; Docker
Desktop available.
