# Implementation Status

**Last inspected: 2026-10-19** (same day as Phases 0a and 0b completion). This file is the
operational source of truth for what exists. Evidence IDs (V1–V28) are defined in
[TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md). Keep this file and
[../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md) consistent whenever phase state changes.

## Phase status

| Phase | Status | Evidence |
|---|---|---|
| Phase 0a — Repository foundation | **COMPLETE — VERIFIED** | [phases/PHASE_0A_COMPLETE.md](phases/PHASE_0A_COMPLETE.md); V1–V17 |
| Phase 0b — Security foundation | **COMPLETE — VERIFIED** | [phases/PHASE_0B_COMPLETE.md](phases/PHASE_0B_COMPLETE.md); V18–V29 |
| Phase 1 — Typed contracts and deterministic policy engine | **NEXT — NOT STARTED** | plan when started; [PHASE_ROADMAP.md](PHASE_ROADMAP.md) |
| Phases 2–10 | **NOT IMPLEMENTED** | [PHASE_ROADMAP.md](PHASE_ROADMAP.md) |

Repository state: **git repository** since 2026-10-19, branch `main`, linear history:
baseline `41e10da` (Phase 0a, 90 files tracked today) + Phase 0b commits `0aa11d9`,
`9b3f153`, `42e8b71`, `4d18e27`, `28bede9`, `a5794cc`, `d180b89`. No remote configured.

## What exists (all VERIFIED)

| Area | Files | Notes |
|---|---|---|
| Project metadata | `../pyproject.toml`, `../uv.lock`, `../.python-version`, `../.gitignore`, `../.env.example`, `../Makefile`, `../.gitleaks.toml` | Python `>=3.12,<3.13`; SQLAlchemy 2.x async + Alembic + PyYAML added in 0b |
| Application runtime | `../src/ai_security/{__init__,settings}.py`, `api/{app,dependencies,routes_health,middleware}.py` | App factory + module-level `app`; validated settings; health endpoints (config/database/policy_self_checks); host-auth middleware on `/v1/*` |
| Security primitives | `../src/ai_security/security/{constant_time,canonical_json}.py`, `audit/hash_chain.py` | `compare_digest` wrappers (confinement enforced by the gate); canonical JSON; ADR-002 hash formula + fixed vectors |
| Identity | `../src/ai_security/identity/{models,signing,host_auth,resolver}.py` | `Principal`; HMAC signing/verification (exact `v1` message + full rejection surface); dev-resolver guard; fail-closed host resolver |
| Persistence | `../src/ai_security/persistence/{database,models,nonce_repository,audit_repository}.py` | Async engine/session; atomic nonce upsert; ADR-002 advisory-lock audit append |
| Migrations | `../alembic.ini`, `../migrations/` (env + baseline `d15b46c49950`) | `host_request_nonces`, `audit_events`; `make migrate`; idempotent; `alembic check` clean |
| Policy scaffolding | `../src/ai_security/policy/{interim_matrix,self_checks}.py`, `../config/policy_self_checks.yaml` | Interim matrix transcription (labeled; Phase 1 replaces); 16 fixtures; startup + live-readiness enforcement (ADR-007) |
| Tests | `../tests/conftest.py`, `unit/` (8 files), `integration/` (6 files + helpers) | **231 tests**, all passing (V18); DB-backed integration skips cleanly when PostgreSQL is unreachable |
| Quality gate | `../scripts/check.sh` | 8 steps incl. pinned Gitleaks 8.30.1 (dir+git) and constant-time confinement |
| Containers | `../Dockerfile`, `../docker-compose.yml` | Digest pins; non-root uid 10001; COPY `config/ migrations/ alembic.ini`; Compose dev `HOST_AUTH_KEYS_JSON` |
| Git | commits above | `gitleaks git` clean across history (V29) |
| Spec-adjacent docs | [../docs/](../docs/) (8 files + `adr/ADR-001..007`) | Status columns honest; refreshed for 0b |
| Memory (this directory) | `project_memory/*` | Updated 2026-10-19 for Phase 0b completion |

## Security controls — what is actually enforced today

Implemented and tested (Phases 0a + 0b scope):

- **Host authentication (0b):** every request whose path starts with `/v1/` — routes
  exist or not — must carry a valid HMAC-SHA256 signature
  (`X-Gateway-Key-Id/-Timestamp/-Nonce/-Signature`, newline-joined `v1` message, body
  hash included). Forged, mutated, stale, unknown-key, and malformed requests are denied
  before routing; constant-time comparison; enforcement is identical under
  `PRINCIPAL_RESOLVER=dev` (no bypass mode).
- **Replay rejection (0b):** single-statement atomic nonce registration with the unique
  `(key_id, nonce)` row; duplicates → 401 `replayed_nonce`; nonce-store failure → 503
  (reject, never fail-open); concurrent duplicates can never both succeed (tested).
- **Request bounds (0b):** content-length check and capped body read (64 KiB default) →
  413 before signature work.
- **Configuration fail-closed validation (0a/0b):** required `APP_ENV`; asyncpg scheme;
  sample database password and all-zero sample HMAC secret refused outside
  `development`/`test`; strict `HOST_AUTH_KEYS_JSON` (32-byte secrets, duplicate IDs
  rejected, exact fields); nonce TTL ≥ 2× timestamp tolerance.
- **Dev-resolver guard (0b):** constructible only under `development`/`test` (settings +
  constructor + factory); one fixed synthetic principal; live refusal command recorded.
- **Policy self-checks (0b, ADR-007):** startup refuses on any mismatching fixture or
  unreadable/invalid file; `/health/ready` re-evaluates live (drift → 503).
- **Audit append protocol scaffolding (0b):** ADR-002 advisory lock + canonical bytes +
  unique `(chain_id, sequence_number)`; fixed hash vectors; 5-writer contiguity test.
- **Documentation gating + non-leakage (0a):** docs absent outside dev/test; health
  responses only booleans; `SecretStr` masking.
- **Secret scanning (0b):** Gitleaks 8.30.1 pinned in `check.sh` (dir + git, redacted).

NOT implemented (do not claim otherwise): authorization/policy engine (only scaffolding),
principal resolution beyond dev, tool registry/gateway, risk engine, approvals, input
defense, intent, DLP/egress, audit event emission + verifier, `/v1/*` routes, rate
limiting, SOC. See [../docs/SECURITY_INVARIANTS.md](../docs/SECURITY_INVARIANTS.md)
(#17/#18 now implemented; #2/#14/#16/#19/#25 partial; all others pending).

## Current-session verification (2026-10-19, fresh runs)

All PASS — full commands and results in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) (V18–V29):

- `uv run --frozen pytest -q` → 231 passed; mypy clean (25 source files); ruff clean.
- `uv run --frozen pytest tests/integration -k "host_auth or nonce or principal" -q` →
  18 passed, 19 deselected.
- `uv run --frozen alembic upgrade head` (twice) + `alembic check` → idempotent, no drift.
- `bash scripts/check.sh` → exit 0, 8 steps; Gitleaks dir+git "no leaks found".
- Docker: api image rebuilt with `config/`, `migrations/`, `alembic.ini`; baseline
  applied in-container; live ready 200 with all three checks true; unsigned `/v1/echo`
  → 400 `missing_headers`; signed request → 404 (auth passed; no route) and its replay →
  401 `replayed_nonce`; production+dev-resolver and missing-fixture-file refusals both
  raise at startup.

## Environment (verified this session)

macOS (darwin); uv 0.13.1; Python 3.12.15; Docker 29.3.1 / Compose v5.1.1 (Docker
Desktop running); git 2.54.0; Gitleaks 8.30.1 installed; no markdown linter installed.
Current stack state: `db` running (preserved for tests), `api` stopped.

## Deferred to Phase 1 (planned, not implemented)

Typed contracts (strict Pydantic models, canonical `SideEffectClass`/`DataClass`,
request/response schemas); safe YAML policy loader + validated policy model; real
deterministic policy engine replacing `policy/interim_matrix.py` while keeping the
ADR-007 fixture contract; principal test adapter; reason codes; canonicalization.
Read blueprint §§6, 10, 11.4 before starting.
