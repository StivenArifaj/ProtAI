# Implementation Status

**Last inspected: 2026-10-26** (Phase 5 completion; Phases 0a–4 completed earlier).
This file is the operational source of truth for what exists. Evidence IDs (V1–V29 for
0a/0b, V30–V35 for Phase 1, V36–V42 for Phase 2, V43–V50 for Phase 3, V51–V56 for
Phase 4, V57+ for Phase 5) are defined in
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
| Phase 3 — Input threat defense and provenance | **COMPLETE — VERIFIED** | [phases/PHASE_3_COMPLETE.md](phases/PHASE_3_COMPLETE.md); V43–V50 |
| Phase 4 — Intent extraction and action validation | **COMPLETE — VERIFIED** | [phases/PHASE_4_COMPLETE.md](phases/PHASE_4_COMPLETE.md); V51–V56 |
| Phase 5 — Risk engine and approval workflow | **COMPLETE — VERIFIED** | [phases/PHASE_5_COMPLETE.md](phases/PHASE_5_COMPLETE.md); V57–V62 |
| Phases 6–10 | **NOT IMPLEMENTED** | [PHASE_ROADMAP.md](PHASE_ROADMAP.md) |

Repository state: **git repository** since 2026-10-19, branch `main`, linear history:
baseline `41e10da` (Phase 0a) + Phase 0b commits `0aa11d9`…`d180b89` + docs/memory
`c95f2a6` + Phase 1 commits `cffdd62` (contracts + canonicalization), `eaae462`
(models/loader/engine + config + fixtures), `b91729b` (wiring + adapter + env example) +
Phase 2 commits `5725256` (contracts/registry/adapters/facts/fixtures), `11740bd`
(risk/audit/gateway + unit tests), `0b935be` (app wiring + no-bypass/integration tests),
`75bd59a` (ADR-009 + docs/memory refresh), `04b9eb2`/`c7a0f8d` (status + post-commit
gate records) + Phase 3 commits `faafe13` (input defense/context/session implementation +
tests), `3bd5c69` (ADR-010 + docs), `1fe5588` (memory refresh + phase completion record),
and the status/post-commit gate record commit `30c0f41`; Phase 4 commits `2943593`
(implementation/tests), `74c502f` (ADR-011/docs), `786cb08` (memory/completion), and
the V56 status record commit `c018955`; Phase 5 commits `ad9e76a`
(implementation/tests/migration), `0b2f1c9` (ADR-012/docs), `8cce014`
(memory/completion), and the final V62 status record commit. No remote configured.

## What exists (all VERIFIED)

| Area | Files | Notes |
|---|---|---|
| Project metadata | `../pyproject.toml`, `../uv.lock`, `../.python-version`, `../.gitignore`, `../.env.example`, `../Makefile`, `../.gitleaks.toml` | Python `>=3.12,<3.13`; SQLAlchemy 2.x async + Alembic + PyYAML |
| Application runtime | `../src/ai_security/{__init__,settings}.py`, `api/{app,dependencies,routes_health,middleware}.py` | App factory + module-level `app`; validated settings incl. policy/threshold/input-defense paths, session TTLs, `INTENT_MANIFEST_TTL_SECONDS`, and `APPROVAL_TTL_SECONDS`; health endpoints (config/database/policy_self_checks + `policy_version`/`policy_hash`); host-auth middleware on `/v1/*`; registry + gateway on `app.state` (Phase 2); `input_defense_config`/`input_defense_service`/`session_security` (Phase 3); `intent_usage_tracker`/`intent_manifest_service` (Phase 4); **Phase 5:** `approval_service` on `app.state`, gateway constructed with the approval service |
| Security primitives | `../src/ai_security/security/{constant_time,canonical_json,urls}.py`, `audit/hash_chain.py` | `compare_digest` wrappers (gate-confined); canonical JSON; ADR-002 hash formula + vectors; destination canonicalization |
| Identity | `../src/ai_security/identity/{models,signing,host_auth,resolver,adapters,approver_rules}.py` | `Principal`; HMAC signing/verification (exact `v1` message + rejection surface); dev-resolver guard; fail-closed host resolver; test-only `TestPrincipalResolver`; **Phase 5:** strict `role:`/`principal:` approver-rule parser/evaluator |
| Persistence | `../src/ai_security/persistence/{database,models,nonce_repository,audit_repository,session_repository,approval_repository}.py` | Async engine/session; atomic nonce upsert; ADR-002 advisory-lock audit append plus `append_in_session` (written to by the gateway via `ChainAuditRecorder`); **Phase 3:** `session_security_state` repository (binding on every op, bounded `LEAST(...)` counters, 24 h/7 d lazy expiry, signal-free rotation); **Phase 5:** row-locked approval decisions/consumption with same-transaction audit |
| Migrations | `../alembic.ini`, `../migrations/` (env + `d15b46c49950`, `c7f1a2b3d4e5`, `e5a1c2b3d4f6`) | `host_request_nonces`, `audit_events`, `session_security_state`, `approval_requests`; single head; `make migrate`; upgrade/downgrade/upgrade verified; `alembic check` clean (V60) |
| Typed contracts | `../src/ai_security/tools/base.py`, `data_security/classification.py`, `firewall/decision.py` | Canonical `SideEffectClass`/`DataClass`; strict `ToolArguments`/`ToolResult`; sentinel-guarded `ExecutionAuthorization`; `compute_action_digest`; stable `DecisionReason` codes (Phase 2, Phase 4 `intent_*`, Phase 5 `approval_*`) |
| Tool registry + mock adapters | `../src/ai_security/tools/registry.py`, `tools/mock_{email,files,external_sink,text}.py` | Immutable validated registrations; exact `(tool_id, action_id)` resolution; one-directional policy consistency; deterministic in-memory adapters with ownership checks + digest verification; `mock_files.search` registered but policy-disabled |
| Input defense + provenance (advisory) | `../src/ai_security/input_defense/{models,config,normalize,heuristics,service,context_labels,sessions}.py`, `security/safe_yaml.py`, `../config/input_defense.yaml` | Strict exhaustive-disposition config (no PASS mapping, duplicate keys refused); bounded intake; copy-only normalization; 10 versioned heuristics with quoted-context downgrade; typed `IntakeReport` (codes/offsets/digests, no raw content); six trust labels + deterministic JSON context; typed `DETECTOR_UNAVAILABLE`; no path into policy/engine/gateway |
| Intent extraction + manifests | `../src/ai_security/intent/{models,extractors,service,validator,time_window}.py` | Server-only issuer; mock 2-scenario extractor; strict local-model adapter interface (bounded JSON, duplicate-key/unknown-field rejection, 2 retries default, outage/timeout mapping); sentinel-sealed request/principal/tenant/policy-bound manifest with expiry + goal digest; exact action/resource/destination/parameter constraints and bounded uses; trusted-timezone TODAY/THIS_WEEK (DST-tested). No API transport/real provider yet |
| Gateway + risk engine | `../src/ai_security/firewall/{gateway,models,risk_engine,approval}.py` | Single `invoke_tool` chokepoint (bindings, strict validation, derived/deduplicated resources, destination, resource checks, deadline, real engine, audit-first, timeouts/concurrency/result bounds, typed outcomes); **Phase 4:** manifest verification + exact constraint comparison + use reservation after policy `ALLOW`; **Phase 5:** `risk-v2` (all v1 weights + bounded breadth) and one-time approval consumption for engine `ASK_USER`, never overriding `BLOCK` |
| Approval workflow | `../src/ai_security/firewall/approval.py`, `identity/approver_rules.py`, `persistence/approval_repository.py` | Strict request/decision/consumption API; 256-bit token returned once and stored only as SHA-256; verified-principal rule evaluation with tenant/self-approval checks; TTL 60–86,400 s (default 900); lazy expiry; row-locked state machine + same-transaction audit; no routes/UI/token transport/revocation/sweeper |
| Audit emission | `../src/ai_security/audit/{models,writer}.py` | Phase-2 subset (`POLICY_EVALUATED`, `TOOL_EXECUTION_COMPLETED`, `TOOL_EXECUTION_FAILED`) plus Phase 5 `APPROVAL_REQUESTED`/`APPROVAL_DECIDED`/`APPROVAL_CONSUMED`/`APPROVAL_EXPIRED`, schema v1, payload-safe references; `AuditRecorder` protocol + `ChainAuditRecorder` |
| Policy engine | `../src/ai_security/firewall/policy_engine.py`, `policy/{models,loader,self_checks}.py`, `../config/{policies,risk_thresholds,policy_self_checks}.yaml` | Deterministic §10.2 engine over validated facts; safe YAML loader (duplicate-key rejection); versioned bundle (sha256 + combined hash); **21 fixtures** (7 mandated names + Phase 2 rows) at startup + readiness |
| Tests | `../tests/conftest.py`, `unit/` (27 test files + helper), `integration/` (13 test files + helpers), `security/` (3 files) | **734 tests** (613 unit + 80 integration + 41 security), all passing (V57/V58); DB-backed integration skips cleanly when PostgreSQL is unreachable |
| Quality gate | `../scripts/check.sh` | 8 steps incl. pinned Gitleaks 8.30.1 (dir+git) and constant-time confinement |
| Containers | `../Dockerfile`, `../docker-compose.yml` | Digest pins; non-root uid 10001; COPY `config/ migrations/ alembic.ini`; Compose dev `HOST_AUTH_KEYS_JSON` |
| Git | commits above | `gitleaks git` clean across history (V29/V37/V58/V61) |
| Spec-adjacent docs | [../docs/](../docs/) (9 files + `adr/ADR-001..012`) | Status columns honest; matrix doc reflects gateway-enforced facts; ADR-009 records the Phase 2 contract, ADR-010 the Phase 3 advisory-detection/session contract, ADR-011 the Phase 4 manifest/constraint contract, ADR-012 the Phase 5 `risk-v2`/approval contract |
| Memory (this directory) | `project_memory/*` | Updated 2026-10-26 for Phase 5 completion |

## Security controls — what is actually enforced today

Implemented and tested (Phases 0a/0b/1/2/3/4/5):

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
- **Deterministic risk scoring (2, extended 5):** `risk-v2` preserves every `risk-v1`
  weight (side-effect/destination/registration data class) and adds one bounded
  resource-breadth factor (2–4/5–8/9+ distinct resources → +5/+10/+15; cap 100). Factor
  codes/rationale are versioned and recorded in decision/audit payloads; derived resource
  ids are validated/deduplicated; caller scores are never accepted.
- **Advisory input defense (3, ADR-010):** strict versioned config that cannot map any
  finding to PASS; bounded intake (bytes/type/UTF-8) before detection; copy-only
  normalization (never mutates or stores input); deterministic heuristics with
  quoted-context downgrade; any detector/normalizer/classifier fault → explicit
  `DETECTOR_UNAVAILABLE` non-PASS finding; trust labels assigned/preserved with external
  content forced `EXTERNAL_UNTRUSTED`; session signals bound to `(tenant_id, subject_id)`
  with bounded counters, TTL/max-age expiry, and signal-free rotation. **Detection has no
  path into policy facts, the engine, the gateway, or execution.**
- **Intent manifests (4, ADR-011):** the app-built gateway requires a sealed manifest
  bound to the request, principal, tenant, policy version, and policy hash; malformed or
  unavailable extraction, ambiguity, missing trusted timezone, expiry, forgery, rebinding,
  and use exhaustion all deny without execution. Constraints are exact tool/action,
  resources, canonical destination, scalar parameter values, and bounded uses; wildcards
  and prefix scopes are refused. Relative dates resolve server-side from the host-signed
  principal timezone. The manifest cannot enter policy facts and can only narrow the
  engine's `ALLOW`.
- **Human approvals (5, ADR-012):** durable PostgreSQL requests bind requester/tenant,
  request, tool/action, canonical action digest, distinct resources, destination,
  side-effect/data class, risk provenance, and policy version/hash. Tokens are 256-bit,
  returned once, and stored only as SHA-256. Only a verified principal satisfying the
  startup-validated `role:`/`principal:` rule (and tenant) can decide; self-approval is
  default-deny; requester-only unsatisfiable rules are refused. Decisions/consumption use
  `SELECT ... FOR UPDATE` and commit with their audit events in one transaction; replay,
  mutation, denial, pending, and expiry never execute; concurrent consumption has exactly
  one winner. The gateway consults approval only for engine `ASK_USER`; a valid grant
  makes that exact action executable once, while `BLOCK`/hard denials ignore it.

NOT implemented (do not claim otherwise): `/v1/*` business routes and agent runtime (the
gateway, detector, intent service, and approval service are in-process/in tests only),
manifest transport or signed serialization, approval routes/UI/token-delivery transport,
automatic approval-request creation, approver directory/notifications/revocation, a
background expiry sweeper, real model provider/general NLU integration (the app uses the
two-scenario mock extractor), cross-process intent-use limits, content-level DLP/canary
inspection, output sanitization, real connectors, process isolation/sandbox, request rate
limiting, audit verifier/retention, SOC, and any consumer of detector findings/trust
labels. See [../docs/SECURITY_INVARIANTS.md](../docs/SECURITY_INVARIANTS.md) (#6/#7/#8/
#20/#24 are now implemented with #5 extended; #2/#10/#11/#14/#15/#16/#19 remain partial;
the file is authoritative for every row).

## Current-session verification (2026-10-26, fresh runs)

All PASS — full commands and results in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md):

- `uv run --frozen pytest -q` → **734 passed** (613 unit + 80 integration + 41
  security), including real-PostgreSQL approval lifecycle/concurrency tests.
- `uv run --frozen mypy` → clean, 63 source files; `ruff check`/`format` clean.
- `bash scripts/check.sh` → exit 0, all 8 steps; Gitleaks 8.30.1 dir+git "no leaks
  found" (27 commits scanned pre-commit; V58).
- Phase 5 targeted suites → **157 passed** (11 approval lifecycle, 5 gateway approval,
  2 wiring, 1 migration, 30 risk, 24 approver rules, 60 settings, 24 no-bypass; V59).
- Alembic `upgrade head` → `downgrade -1` → `upgrade head` → `check` → clean, single
  head `e5a1c2b3d4f6` (V60).
- Dedup regression → 1 passed (V61). Phase 4/3/0b evidence retained.

## Environment (verified this session)

macOS (darwin); uv 0.13.x; Python 3.12.15; Docker 29.3.1 / Compose v5.1.1 (Docker
Desktop running); PostgreSQL 17.2 (`protai-db-1`) on 127.0.0.1:5432; git 2.54.0;
Gitleaks 8.30.1 installed; no markdown linter installed. The project virtualenv was
recreated at `/Users/stiven/Desktop/ProtAI/.venv` after the repository moved. Current
stack state: `db` running (preserved for tests), `api` stopped.

## Deferred to Phase 6 (planned, not implemented)

Output DLP and egress policy (blueprint §21): test canaries, configurable sensitive
patterns, a data-classification model, destination-aware egress checks, and release
outcomes. Required: canary data never reaches an unauthorized mock sink, DLP logs remain
redacted, and false-positive cases are documented. Intent stays authority-free, the
detector stays advisory, and the approval boundary (ADR-012) must remain intact. Read
blueprint §§6, 12-13 before starting.
