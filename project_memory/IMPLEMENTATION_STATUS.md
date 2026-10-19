# Implementation Status

**Last inspected: 2026-10-19** (same day as Phases 0a, 0b, and 1 completion). This file is
the operational source of truth for what exists. Evidence IDs (V1–V29 for 0a/0b, V30+ for
Phase 1) are defined in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md). Keep
this file and [../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md)
consistent whenever phase state changes.

## Phase status

| Phase | Status | Evidence |
|---|---|---|
| Phase 0a — Repository foundation | **COMPLETE — VERIFIED** | [phases/PHASE_0A_COMPLETE.md](phases/PHASE_0A_COMPLETE.md); V1–V17 |
| Phase 0b — Security foundation | **COMPLETE — VERIFIED** | [phases/PHASE_0B_COMPLETE.md](phases/PHASE_0B_COMPLETE.md); V18–V29 |
| Phase 1 — Typed contracts and deterministic policy engine | **COMPLETE — VERIFIED** | [phases/PHASE_1_COMPLETE.md](phases/PHASE_1_COMPLETE.md); V30+ |
| Phase 2 — Tool registry and enforced gateway | **NEXT — NOT STARTED** | plan when started; [PHASE_ROADMAP.md](PHASE_ROADMAP.md) |
| Phases 3–10 | **NOT IMPLEMENTED** | [PHASE_ROADMAP.md](PHASE_ROADMAP.md) |

Repository state: **git repository** since 2026-10-19, branch `main`, linear history:
baseline `41e10da` (Phase 0a) + Phase 0b commits `0aa11d9`…`d180b89` + Phase 0b
docs/memory `c95f2a6` + Phase 1 commits `cffdd62` (contracts + canonicalization),
`eaae462` (models/loader/engine + config + fixtures), `b91729b` (wiring + adapter +
env example). No remote configured.

## What exists (all VERIFIED)

| Area | Files | Notes |
|---|---|---|
| Project metadata | `../pyproject.toml`, `../uv.lock`, `../.python-version`, `../.gitignore`, `../.env.example`, `../Makefile`, `../.gitleaks.toml` | Python `>=3.12,<3.13`; SQLAlchemy 2.x async + Alembic + PyYAML since 0b |
| Application runtime | `../src/ai_security/{__init__,settings}.py`, `api/{app,dependencies,routes_health,middleware}.py` | App factory + module-level `app`; validated settings (incl. policy/threshold paths); health endpoints (config/database/policy_self_checks + `policy_version`/`policy_hash`); host-auth middleware on `/v1/*` |
| Security primitives | `../src/ai_security/security/{constant_time,canonical_json,urls}.py`, `audit/hash_chain.py` | `compare_digest` wrappers (gate-confined); canonical JSON; ADR-002 hash formula + vectors; URL/destination canonicalization (Phase 1) |
| Identity | `../src/ai_security/identity/{models,signing,host_auth,resolver,adapters}.py` | `Principal`; HMAC signing/verification (exact `v1` message + rejection surface); dev-resolver guard; fail-closed host resolver; test-only `TestPrincipalResolver` (Phase 1) |
| Persistence | `../src/ai_security/persistence/{database,models,nonce_repository,audit_repository}.py` | Async engine/session; atomic nonce upsert; ADR-002 advisory-lock audit append |
| Migrations | `../alembic.ini`, `../migrations/` (env + baseline `d15b46c49950`) | `host_request_nonces`, `audit_events`; `make migrate`; idempotent; `alembic check` clean |
| Typed contracts | `../src/ai_security/tools/base.py`, `data_security/classification.py`, `firewall/decision.py` | Canonical `SideEffectClass`/`DataClass` defined exactly once; `FirewallDecision`/`DecisionReason`/`DecisionRecord` (Phase 1) |
| Policy engine | `../src/ai_security/firewall/policy_engine.py`, `policy/{models,loader,self_checks}.py`, `../config/{policies,risk_thresholds,policy_self_checks}.yaml` | Deterministic §10.2 engine over validated facts; safe YAML loader with duplicate-key rejection; versioned bundle (sha256 + combined hash); 17 fixtures (7 mandated names) at startup + readiness; `policy/interim_matrix.py` deleted (Phase 1) |
| Tests | `../tests/conftest.py`, `unit/` (12 files), `integration/` (6 files + helpers) | **406 tests** (364 unit + 42 integration), all passing (V30); DB-backed integration skips cleanly when PostgreSQL is unreachable |
| Quality gate | `../scripts/check.sh` | 8 steps incl. pinned Gitleaks 8.30.1 (dir+git) and constant-time confinement |
| Containers | `../Dockerfile`, `../docker-compose.yml` | Digest pins; non-root uid 10001; COPY `config/ migrations/ alembic.ini`; Compose dev `HOST_AUTH_KEYS_JSON` |
| Git | commits above | `gitleaks git` clean across history (V29; re-run in V33) |
| Spec-adjacent docs | [../docs/](../docs/) (8 files + `adr/ADR-001..008`) | Status columns honest; refreshed for Phase 1 (matrix implemented; ADR-008) |
| Memory (this directory) | `project_memory/*` | Updated 2026-10-19 for Phase 1 completion |

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
- **Deterministic policy engine (1):** the §10.2 evaluation order over strict validated
  facts with stable reason codes; deny-by-default unknown tools; hard-deny dominance;
  DESTRUCTIVE/RESTRICTED/CONFIDENTIAL egress blocked; ASK_USER only when policy marks the
  action approval-eligible; strict contracts (`extra="forbid"`, strict ints, anchored
  tool ids, no aliases/coercions); canonical destination handling (IDNA, https-only,
  exact-match allowlist); safe YAML loading with duplicate-key rejection; versioned
  bundle hashes in readiness metadata; startup refusal + live drift detection; 17
  self-check fixtures (7 mandated names retained) — all unit/integration-tested.
- **Test-only principal adapter (1):** `TestPrincipalResolver` constructible only under
  `APP_ENV=test`, unreachable via settings/factory; dev-resolver guard and HMAC
  middleware unchanged (denial matrix still green).

NOT implemented (do not claim otherwise): execution (no tool registry/gateway — the
engine decides but nothing acts), the risk scoring engine (thresholds consume a
caller-supplied score), approvals, input defense, intent, DLP/egress enforcement at a
sink, audit event emission + verifier, `/v1/*` routes, rate limiting, SOC. See
[../docs/SECURITY_INVARIANTS.md](../docs/SECURITY_INVARIANTS.md) (#17/#18/#25 now
implemented; #3/#4/#5 engine-level partial; #2/#14/#16/#19 partial; all others pending).

## Current-session verification (2026-10-19, fresh runs)

All PASS — full commands and results in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) (V18–V29 for 0b; V30+ for Phase 1):

- `uv run --frozen pytest -q` → **406 passed** (364 unit + 42 integration).
- `uv run --frozen mypy src` → clean, 35 source files; `ruff check`/`format` clean.
- `bash scripts/check.sh` → exit 0, 8 steps; Gitleaks dir+git "no leaks found".
- Policy bundle smoke run → `version: dev-1`, `combined_hash 8a4ba203…`, 17 fixtures,
  0 failures; integration wiring proves startup refusal + readiness drift detection.
- Phase 0b evidence retained: live Docker auth/replay proof; migration idempotency;
  production-mode refusals.

## Environment (verified this session)

macOS (darwin); uv 0.13.1; Python 3.12.15; Docker 29.3.1 / Compose v5.1.1 (Docker
Desktop running); git 2.54.0; Gitleaks 8.30.1 installed; no markdown linter installed.
Current stack state: `db` running (preserved for tests), `api` stopped.

## Deferred to Phase 2 (planned, not implemented)

Tool protocol + registry built from the loaded policy document; mock email/files/sink
adapters (no real connectors); the `invoke_tool` gateway enforcing a valid engine `ALLOW`
with no bypass; timeouts and result bounds; the audit interface hook. Read blueprint
§§12, 14 before starting; the no-bypass DoD ("sink changes only after a valid allow;
denied/unknown actions leave no side effect") becomes testable there.
