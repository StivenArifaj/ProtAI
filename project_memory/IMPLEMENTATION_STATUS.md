# Implementation Status

**Last inspected: 2026-10-19** (same day as Phases 0a, 0b, 1, 2, and 3 completion). This
file is the operational source of truth for what exists. Evidence IDs (V1–V29 for 0a/0b,
V30–V35 for Phase 1, V36+ for Phase 2, V43+ for Phase 3) are defined in
[TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md). Keep this file and
[../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md) consistent whenever
phase state changes.

## Phase status

| Phase | Status | Evidence |
|---|---|---|
| Phase 0a — Repository foundation | **COMPLETE — VERIFIED** | [phases/PHASE_0A_COMPLETE.md](phases/PHASE_0A_COMPLETE.md); V1–V17 |
| Phase 0b — Security foundation | **COMPLETE — VERIFIED** | [phases/PHASE_0B_COMPLETE.md](phases/PHASE_0B_COMPLETE.md); V18–V29 |
| Phase 1 — Typed contracts and deterministic policy engine | **COMPLETE — VERIFIED** | [phases/PHASE_1_COMPLETE.md](phases/PHASE_1_COMPLETE.md); V30–V35 |
| Phase 2 — Tool registry and enforced gateway | **COMPLETE — VERIFIED** | [phases/PHASE_2_COMPLETE.md](phases/PHASE_2_COMPLETE.md); V36–V42 |
| Phase 3 — Input threat defense and provenance | **COMPLETE — VERIFIED** | [phases/PHASE_3_COMPLETE.md](phases/PHASE_3_COMPLETE.md); V43+ |
| Phases 4–10 | **NOT IMPLEMENTED** | [PHASE_ROADMAP.md](PHASE_ROADMAP.md) |

Repository state: **git repository** since 2026-10-19, branch `main`, linear history:
baseline `41e10da` (Phase 0a) + Phase 0b commits `0aa11d9`…`d180b89` + docs/memory
`c95f2a6` + Phase 1 commits `cffdd62` (contracts + canonicalization), `eaae462`
(models/loader/engine + config + fixtures), `b91729b` (wiring + adapter + env example) +
Phase 2 commits `5725256` (contracts/registry/adapters/facts/fixtures), `11740bd`
(risk/audit/gateway + unit tests), `0b935be` (app wiring + no-bypass/integration tests),
`75bd59a` (ADR-009 + docs/memory refresh), `04b9eb2`/`c7a0f8d` (status + post-commit
gate records), plus Phase 3 commits recorded in the Phase 3 completion record. No remote
configured.

## What exists (all VERIFIED)

| Area | Files | Notes |
|---|---|---|
| Project metadata | `../pyproject.toml`, `../uv.lock`, `../.python-version`, `../.gitignore`, `../.env.example`, `../Makefile`, `../.gitleaks.toml` | Python `>=3.12,<3.13`; SQLAlchemy 2.x async + Alembic + PyYAML |
| Application runtime | `../src/ai_security/{__init__,settings}.py`, `api/{app,dependencies,routes_health,middleware}.py` | App factory + module-level `app`; validated settings incl. policy/threshold/input-defense paths + session TTLs; health endpoints (config/database/policy_self_checks + `policy_version`/`policy_hash`); host-auth middleware on `/v1/*`; registry + gateway on `app.state` (Phase 2); **Phase 3:** `input_defense_config`/`input_defense_service`/`session_security` on `app.state` |
| Security primitives | `../src/ai_security/security/{constant_time,canonical_json,urls}.py`, `audit/hash_chain.py` | `compare_digest` wrappers (gate-confined); canonical JSON; ADR-002 hash formula + vectors; destination canonicalization |
| Identity | `../src/ai_security/identity/{models,signing,host_auth,resolver,adapters}.py` | `Principal`; HMAC signing/verification (exact `v1` message + rejection surface); dev-resolver guard; fail-closed host resolver; test-only `TestPrincipalResolver` |
| Persistence | `../src/ai_security/persistence/{database,models,nonce_repository,audit_repository,session_repository}.py` | Async engine/session; atomic nonce upsert; ADR-002 advisory-lock audit append (written to by the gateway via `ChainAuditRecorder`); **Phase 3:** `session_security_state` repository (binding on every op, bounded `LEAST(...)` counters, 24 h/7 d lazy expiry, signal-free rotation) |
| Migrations | `../alembic.ini`, `../migrations/` (env + `d15b46c49950`, `c7f1a2b3d4e5`) | `host_request_nonces`, `audit_events`, `session_security_state`; `make migrate`; upgrade/downgrade/upgrade verified; `alembic check` clean (V46) |
| Typed contracts | `../src/ai_security/tools/base.py`, `data_security/classification.py`, `firewall/decision.py` | Canonical `SideEffectClass`/`DataClass`; strict `ToolArguments`/`ToolResult`; sentinel-guarded `ExecutionAuthorization`; `compute_action_digest`; stable `DecisionReason` codes (extended in Phase 2) |
| Tool registry + mock adapters | `../src/ai_security/tools/registry.py`, `tools/mock_{email,files,external_sink,text}.py` | Immutable validated registrations; exact `(tool_id, action_id)` resolution; one-directional policy consistency; deterministic in-memory adapters with ownership checks + digest verification; `mock_files.search` registered but policy-disabled |
| Input defense + provenance (advisory) | `../src/ai_security/input_defense/{models,config,normalize,heuristics,service,context_labels,sessions}.py`, `security/safe_yaml.py`, `../config/input_defense.yaml` | Strict exhaustive-disposition config (no PASS mapping, duplicate keys refused); bounded intake; copy-only normalization; 10 versioned heuristics with quoted-context downgrade; typed `IntakeReport` (codes/offsets/digests, no raw content); six trust labels + deterministic JSON context; typed `DETECTOR_UNAVAILABLE`; no path into policy/engine/gateway |
| Gateway + risk engine | `../src/ai_security/firewall/{gateway,models,risk_engine}.py` | Single `invoke_tool` chokepoint (bindings, strict validation, derived resources/destination, resource checks, deadline, real engine, audit-first, timeouts/concurrency/result bounds, typed outcomes); `risk-v1` scoring |
| Audit emission | `../src/ai_security/audit/{models,writer}.py` | Phase-2 subset (`POLICY_EVALUATED`, `TOOL_EXECUTION_COMPLETED`, `TOOL_EXECUTION_FAILED`), schema v1, payload-safe references; `AuditRecorder` protocol + `ChainAuditRecorder` |
| Policy engine | `../src/ai_security/firewall/policy_engine.py`, `policy/{models,loader,self_checks}.py`, `../config/{policies,risk_thresholds,policy_self_checks}.yaml` | Deterministic §10.2 engine over validated facts; safe YAML loader (duplicate-key rejection); versioned bundle (sha256 + combined hash); **21 fixtures** (7 mandated names + Phase 2 rows) at startup + readiness |
| Tests | `../tests/conftest.py`, `unit/` (22 test files + helper), `integration/` (10 test files + helpers), `security/` (2 files) | **600 tests** (517 unit + 60 integration + 23 security), all passing (V43); DB-backed integration skips cleanly when PostgreSQL is unreachable |
| Quality gate | `../scripts/check.sh` | 8 steps incl. pinned Gitleaks 8.30.1 (dir+git) and constant-time confinement |
| Containers | `../Dockerfile`, `../docker-compose.yml` | Digest pins; non-root uid 10001; COPY `config/ migrations/ alembic.ini`; Compose dev `HOST_AUTH_KEYS_JSON` |
| Git | commits above | `gitleaks git` clean across history (V29/V37) |
| Spec-adjacent docs | [../docs/](../docs/) (9 files + `adr/ADR-001..010`) | Status columns honest; matrix doc reflects gateway-enforced facts; ADR-009 records the Phase 2 contract, ADR-010 the Phase 3 advisory-detection/session contract |
| Memory (this directory) | `project_memory/*` | Updated 2026-10-19 for Phase 3 completion |

## Security controls — what is actually enforced today

Implemented and tested (Phases 0a/0b/1/2/3):

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
- **Advisory input defense (3, ADR-010):** strict versioned config that cannot map any
  finding to PASS; bounded intake (bytes/type/UTF-8) before detection; copy-only
  normalization (never mutates or stores input); deterministic heuristics with
  quoted-context downgrade; any detector/normalizer/classifier fault → explicit
  `DETECTOR_UNAVAILABLE` non-PASS finding; trust labels assigned/preserved with external
  content forced `EXTERNAL_UNTRUSTED`; session signals bound to `(tenant_id, subject_id)`
  with bounded counters, TTL/max-age expiry, and signal-free rotation. **Detection has no
  path into policy facts, the engine, the gateway, or execution.**

NOT implemented (do not claim otherwise): `/v1/*` routes and agent runtime (the gateway
and detector are in-process/in tests only), approvals (`ASK_USER` never executes),
manifest/intent binding, semantic intent, content-level DLP/canary inspection, output
sanitization, real connectors, process isolation/sandbox, request rate limiting, model
provider integration, audit verifier/retention, SOC, and any consumer of detector
findings/trust labels. See
[../docs/SECURITY_INVARIANTS.md](../docs/SECURITY_INVARIANTS.md) (#1/#3/#4/#5/#9/#12/#17/
#18/#23/#25 implemented; #2/#10/#11/#14/#15/#16/#19 partial; all others pending; #23 at storage layer with route-level re-verification deferred).

## Current-session verification (2026-10-19, fresh runs)

All PASS — full commands and results in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md):

- `uv run --frozen pytest -q` → **600 passed** (517 unit + 60 integration + 23
  security).
- `uv run --frozen mypy src` → clean, 55 source files; `ruff check`/`format` clean.
- `bash scripts/check.sh` → exit 0, 8 steps; Gitleaks 8.30.1 dir+git "no leaks found"
  (19 commits).
- Phase 3 targeted suites → **64 passed** (normalization/heuristics/config/context/
  sessions/failure semantics); Phase 3 integration → **13 passed** (startup wiring +
  refusals; binding, guessed-ID, counters, TTL/max-age, rotation vs real PostgreSQL).
- Alembic `upgrade head` → `downgrade -1` → `upgrade head` → `check` clean
  (`c7f1a2b3d4e5`).
- Phase 0b/1/2 evidence retained: live Docker auth/replay proof; migration idempotency;
  production-mode refusals; bundle smoke; no-bypass gateway proofs.

## Environment (verified this session)

macOS (darwin); uv 0.13.1; Python 3.12.15; Docker 29.3.1 / Compose v5.1.1 (Docker
Desktop running); git 2.54.0; Gitleaks 8.30.1 installed; no markdown linter installed.
Current stack state: `db` running (preserved for tests), `api` stopped.

## Deferred to Phase 4 (planned, not implemented)

Intent extraction and action validation (mock extractor, local-model adapter interface,
bounded `IntentManifest`, request binding/expiry, constraint validator, ambiguity
behavior). The detector stays advisory; any model usage must remain authority-free. Read
blueprint §§8-9 before starting.
