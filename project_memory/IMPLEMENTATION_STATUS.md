# Implementation Status

**Last inspected: 2026-10-19** (same day as Phases 0a, 0b, 1, and 2 completion). This file
is the operational source of truth for what exists. Evidence IDs (V1–V29 for 0a/0b,
V30–V35 for Phase 1, V36+ for Phase 2) are defined in
[TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md). Keep this file and
[../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md) consistent whenever
phase state changes.

## Phase status

| Phase | Status | Evidence |
|---|---|---|
| Phase 0a — Repository foundation | **COMPLETE — VERIFIED** | [phases/PHASE_0A_COMPLETE.md](phases/PHASE_0A_COMPLETE.md); V1–V17 |
| Phase 0b — Security foundation | **COMPLETE — VERIFIED** | [phases/PHASE_0B_COMPLETE.md](phases/PHASE_0B_COMPLETE.md); V18–V29 |
| Phase 1 — Typed contracts and deterministic policy engine | **COMPLETE — VERIFIED** | [phases/PHASE_1_COMPLETE.md](phases/PHASE_1_COMPLETE.md); V30–V35 |
| Phase 2 — Tool registry and enforced gateway | **COMPLETE — VERIFIED** | [phases/PHASE_2_COMPLETE.md](phases/PHASE_2_COMPLETE.md); V36+ |
| Phase 3 — Input threat defense and provenance | **NEXT — NOT STARTED** | [PHASE_ROADMAP.md](PHASE_ROADMAP.md) |
| Phases 4–10 | **NOT IMPLEMENTED** | [PHASE_ROADMAP.md](PHASE_ROADMAP.md) |

Repository state: **git repository** since 2026-10-19, branch `main`, linear history:
baseline `41e10da` (Phase 0a) + Phase 0b commits `0aa11d9`…`d180b89` + docs/memory
`c95f2a6` + Phase 1 commits `cffdd62` (contracts + canonicalization), `eaae462`
(models/loader/engine + config + fixtures), `b91729b` (wiring + adapter + env example) +
Phase 2 commits `5725256` (contracts/registry/adapters/facts/fixtures), `11740bd`
(risk/audit/gateway + unit tests), `0b935be` (app wiring + no-bypass/integration tests),
`75bd59a` (ADR-009 + docs/memory refresh). No remote configured.

## What exists (all VERIFIED)

| Area | Files | Notes |
|---|---|---|
| Project metadata | `../pyproject.toml`, `../uv.lock`, `../.python-version`, `../.gitignore`, `../.env.example`, `../Makefile`, `../.gitleaks.toml` | Python `>=3.12,<3.13`; SQLAlchemy 2.x async + Alembic + PyYAML |
| Application runtime | `../src/ai_security/{__init__,settings}.py`, `api/{app,dependencies,routes_health,middleware}.py` | App factory + module-level `app`; validated settings incl. policy/threshold paths; health endpoints (config/database/policy_self_checks + `policy_version`/`policy_hash`); host-auth middleware on `/v1/*`; **Phase 2:** registry + gateway constructed/validated at startup and exposed on `app.state` (`tool_registry`, `tool_gateway`) |
| Security primitives | `../src/ai_security/security/{constant_time,canonical_json,urls}.py`, `audit/hash_chain.py` | `compare_digest` wrappers (gate-confined); canonical JSON; ADR-002 hash formula + vectors; destination canonicalization |
| Identity | `../src/ai_security/identity/{models,signing,host_auth,resolver,adapters}.py` | `Principal`; HMAC signing/verification (exact `v1` message + rejection surface); dev-resolver guard; fail-closed host resolver; test-only `TestPrincipalResolver` |
| Persistence | `../src/ai_security/persistence/{database,models,nonce_repository,audit_repository}.py` | Async engine/session; atomic nonce upsert; ADR-002 advisory-lock audit append (now written to by the gateway via `ChainAuditRecorder`) |
| Migrations | `../alembic.ini`, `../migrations/` (env + baseline `d15b46c49950`) | `host_request_nonces`, `audit_events`; `make migrate`; idempotent; `alembic check` clean |
| Typed contracts | `../src/ai_security/tools/base.py`, `data_security/classification.py`, `firewall/decision.py` | Canonical `SideEffectClass`/`DataClass`; strict `ToolArguments`/`ToolResult`; sentinel-guarded `ExecutionAuthorization`; `compute_action_digest`; stable `DecisionReason` codes (extended in Phase 2) |
| Tool registry + mock adapters | `../src/ai_security/tools/registry.py`, `tools/mock_{email,files,external_sink,text}.py` | Immutable validated registrations; exact `(tool_id, action_id)` resolution; one-directional policy consistency; deterministic in-memory adapters with ownership checks + digest verification; `mock_files.search` registered but policy-disabled |
| Gateway + risk engine | `../src/ai_security/firewall/{gateway,models,risk_engine}.py` | Single `invoke_tool` chokepoint (bindings, strict validation, derived resources/destination, resource checks, deadline, real engine, audit-first, timeouts/concurrency/result bounds, typed outcomes); `risk-v1` scoring |
| Audit emission | `../src/ai_security/audit/{models,writer}.py` | Phase-2 subset (`POLICY_EVALUATED`, `TOOL_EXECUTION_COMPLETED`, `TOOL_EXECUTION_FAILED`), schema v1, payload-safe references; `AuditRecorder` protocol + `ChainAuditRecorder` |
| Policy engine | `../src/ai_security/firewall/policy_engine.py`, `policy/{models,loader,self_checks}.py`, `../config/{policies,risk_thresholds,policy_self_checks}.yaml` | Deterministic §10.2 engine over validated facts; safe YAML loader (duplicate-key rejection); versioned bundle (sha256 + combined hash); **21 fixtures** (7 mandated names + Phase 2 rows) at startup + readiness |
| Tests | `../tests/conftest.py`, `unit/` (16 test files + helper), `integration/` (9 test files + helpers), `security/` (1 file) | **520 tests** (461 unit + 47 integration + 12 security), all passing (V36); DB-backed integration skips cleanly when PostgreSQL is unreachable |
| Quality gate | `../scripts/check.sh` | 8 steps incl. pinned Gitleaks 8.30.1 (dir+git) and constant-time confinement |
| Containers | `../Dockerfile`, `../docker-compose.yml` | Digest pins; non-root uid 10001; COPY `config/ migrations/ alembic.ini`; Compose dev `HOST_AUTH_KEYS_JSON` |
| Git | commits above | `gitleaks git` clean across history (V29/V37) |
| Spec-adjacent docs | [../docs/](../docs/) (8 files + `adr/ADR-001..009`) | Status columns honest; matrix doc reflects gateway-enforced facts; ADR-009 records the Phase 2 contract |
| Memory (this directory) | `project_memory/*` | Updated 2026-10-19 for Phase 2 completion |

## Security controls — what is actually enforced today

Implemented and tested (Phases 0a/0b/1/2):

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
  `development`/`test`; strict `HOST_AUTH_KEYS_JSON`; nonce TTL ≥ 2× timestamp tolerance.
- **Dev-resolver guard (0b):** constructible only under `development`/`test` (settings +
  constructor + factory); one fixed synthetic principal; live refusal command recorded.
- **Policy self-checks (0b, ADR-007):** startup refuses on any mismatching fixture or
  unreadable/invalid file; `/health/ready` re-evaluates live (drift → 503).
- **Audit append protocol scaffolding (0b) + emission (2):** ADR-002 advisory lock +
  canonical bytes + unique `(chain_id, sequence_number)`; fixed hash vectors; 5-writer
  contiguity test; the gateway appends decision/outcome events with real PostgreSQL
  order/linkage tests.
- **Documentation gating + non-leakage (0a):** docs absent outside dev/test; health
  responses only booleans; `SecretStr` masking.
- **Secret scanning (0b):** Gitleaks 8.30.1 pinned in `check.sh` (dir + git, redacted).
- **Deterministic policy engine (1):** the §10.2 evaluation order over strict validated
  facts with stable reason codes; deny-by-default unknown tools; hard-deny dominance;
  DESTRUCTIVE/RESTRICTED/CONFIDENTIAL egress blocked; strict contracts; canonical
  destination handling; versioned bundle hashes; 21 self-check fixtures.
- **Test-only principal adapter (1):** `TestPrincipalResolver` constructible only under
  `APP_ENV=test`, unreachable via settings/factory.
- **Enforced gateway (2, ADR-009):** registry + startup consistency; mock adapters only;
  every adapter call requires a gateway-issued, digest-bound execution authorization;
  principal/request bindings, strict argument validation, derived resource/destination
  consistency, adapter resource checks, deadlines, real engine evaluation, decision audit
  **before** execution, per-tool timeouts/concurrency/result bounds, typed outcomes; the
  mock sink changes only after a durable `ALLOW` (unit + security + real-DB integration
  proofs); engine exceptions and audit outages fail closed.
- **Deterministic risk scoring (2):** `risk-v1` (side-effect/destination/registration
  data class; versioned; factor codes in decision/audit payloads; caller scores never
  accepted).

NOT implemented (do not claim otherwise): `/v1/*` routes and agent runtime (the gateway is
in-process/in tests only), approvals (`ASK_USER` never executes), manifest/intent binding,
input defense/provenance labels, content-level DLP/canary inspection, real connectors,
process isolation/sandbox, request rate limiting, audit verifier/retention, SOC. See
[../docs/SECURITY_INVARIANTS.md](../docs/SECURITY_INVARIANTS.md) (#1/#3/#4/#5/#9/#12/#17/
#18/#25 implemented; #2/#14/#16/#19/#21/#23/#24 partial; all others pending).

## Current-session verification (2026-10-19, fresh runs)

All PASS — full commands and results in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md):

- `uv run --frozen pytest -q` → **520 passed** (461 unit + 47 integration + 12
  security).
- `uv run --frozen mypy src` → clean, 45 source files; `ruff check`/`format` clean.
- `bash scripts/check.sh` → exit 0, 8 steps; Gitleaks 13 commits "no leaks found".
- No-bypass suite (`tests/security` + `tests/unit/test_gateway.py`) → **31 passed**;
  gateway integration (`test_gateway_end_to_end.py`, `test_gateway_wiring.py`) → **5
  passed**; self-checks suite → **41 passed** (21 fixtures).
- Phase 0b/1 evidence retained: live Docker auth/replay proof; migration idempotency;
  production-mode refusals; bundle smoke `combined_hash 8a4ba203…`.

## Environment (verified this session)

macOS (darwin); uv 0.13.1; Python 3.12.15; Docker 29.3.1 / Compose v5.1.1 (Docker
Desktop running); git 2.54.0; Gitleaks 8.30.1 installed; no markdown linter installed.
Current stack state: `db` running (preserved for tests), `api` stopped.

## Deferred to Phase 3 (planned, not implemented)

Input threat defense (intake limits, normalization, versioned heuristics, typed
findings), trust labels, context provenance, detector failure behavior. Read blueprint
§§7-8 before starting; invariants #10, #11, #15, #16, #23 become testable there.
