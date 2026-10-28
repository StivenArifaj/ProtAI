# Implementation Status

**Last inspected: 2026-10-28** (Phase 8 completion; Phases 0a–7 completed earlier).
This file is the operational source of truth for what exists. Evidence IDs (V1–V29 for
0a/0b, V30–V35 for Phase 1, V36–V42 for Phase 2, V43–V50 for Phase 3, V51–V56 for
Phase 4, V57–V62 for Phase 5, V63–V66 for Phase 6, V67–V71 for Phase 7, V72+ for
Phase 8) are defined in
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
| Phase 6 — Output DLP and egress policy | **COMPLETE — VERIFIED** | [phases/PHASE_6_COMPLETE.md](phases/PHASE_6_COMPLETE.md); V63–V66 |
| Phase 7 — Audit persistence and verification | **COMPLETE — VERIFIED** | [phases/PHASE_7_COMPLETE.md](phases/PHASE_7_COMPLETE.md); V67–V71 |
| Phase 8 — HTTP ingress, runtime, local model | **COMPLETE — VERIFIED** | [phases/PHASE_8_COMPLETE.md](phases/PHASE_8_COMPLETE.md); V72+ |
| Phases 9–10 | **NOT IMPLEMENTED** | [PHASE_ROADMAP.md](PHASE_ROADMAP.md) |

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
(memory/completion), and the final V62 status record commit `b70bbfb`; Phase 6 commits
`df70cd9` (implementation/tests/config), `e8919cb` (finding-cap fail-closed),
`e586c81` (complete credential-value redaction), `98cfdde` (ADR-013/docs), `9e78933`
(memory/completion), and the V66 status record `3024c29`; Phase 7 commits `0b60ba0`
(implementation/tests/migration) and `d53b0ed` (ADR-014/docs), followed by the
memory/completion commit `5ae9ebe` and the final V71 status record; Phase 8 commits
`5e20075` (ADR-015), `edda8ea` (principal assertion/resolver), `2bdf30f` (input audit
evidence), `b561dd6` (gateway preview support), `2fa66fe` (settings), `f0f9b6b`
(format), `940600e` (signed routes), `b4f8357` (local-provider implementation/settings),
and `2f84269` (docs/memory). `origin` is `https://github.com/StivenArifaj/ProtAI.git`; every stage is
pushed to `origin main`.

## What exists (all VERIFIED)

| Area | Files | Notes |
|---|---|---|
| Project metadata | `../pyproject.toml`, `../uv.lock`, `../.python-version`, `../.gitignore`, `../.env.example`, `../Makefile`, `../.gitleaks.toml` | Python `>=3.12,<3.13`; SQLAlchemy 2.x async + Alembic + PyYAML |
| Application runtime | `../src/ai_security/{__init__,settings}.py`, `api/{app,dependencies,routes_health,middleware,errors,rate_limit,ingress,runtime,schemas,routes_requests}.py` | App factory + module-level `app`; validated settings incl. policy/threshold/input-defense paths, session TTLs, `INTENT_MANIFEST_TTL_SECONDS`, `APPROVAL_TTL_SECONDS`, `OUTPUT_DLP_PATH`, `REQUEST_TIMEOUT_SECONDS`, four `RATE_LIMIT_*` bounds, and the local-model contract; health endpoints (config/database/policy_self_checks + `policy_version`/`policy_hash`); host-auth middleware on `/v1/*`; registry + gateway on `app.state`; input defense/session, intent tracker/service, approval service, output defense, audit chain/recorder wired end-to-end; **Phase 8:** signed `POST /v1/requests`, non-executing `POST /v1/tool-calls/evaluate`, `POST /v1/approvals/{approval_id}/decision`, bounded `DemoRuntime`, and the selected `app.state.intent_extractor` |
| Security primitives | `../src/ai_security/security/{constant_time,canonical_json,urls}.py`, `audit/hash_chain.py` | `compare_digest` wrappers (gate-confined); canonical JSON; ADR-002 hash formula + vectors; destination canonicalization |
| Identity | `../src/ai_security/identity/{models,signing,host_auth,resolver,adapters,approver_rules,assertion}.py` | `Principal`; HMAC signing/verification (exact `v1` message + rejection surface); dev-resolver guard; strict host resolver; test-only `TestPrincipalResolver`; strict approver-rule parser/evaluator; **Phase 8:** host-signed principal assertion with `iss`/`aud`/tenant binding, future-time tolerance, and no unsigned fallback |
| Persistence | `../src/ai_security/persistence/{database,models,nonce_repository,audit_repository,session_repository,approval_repository}.py` | Async engine/session; atomic nonce upsert; ADR-002 advisory-lock audit append plus `append_in_session`; **Phase 7:** the single append path derives and stores indexed metadata columns (`event_type`, `request_id`, `trace_id`, `call_id`, `occurred_at`, `component`) from the exact payload while the hashed bytes remain authoritative; `session_security_state` repository; row-locked approval decisions/consumption with same-transaction audit |
| Migrations | `../alembic.ini`, `../migrations/` (env + `d15b46c49950`, `c7f1a2b3d4e5`, `e5a1c2b3d4f6`, `f7a8b9c0d1e2`) | `host_request_nonces`, `audit_events` (+ Phase 7 derived metadata columns/indexes), `session_security_state`, `approval_requests`; single head `f7a8b9c0d1e2`; non-destructive guarded JSON backfill; `make migrate`; upgrade/downgrade/upgrade verified; `alembic check` clean (V67) |
| Typed contracts | `../src/ai_security/tools/base.py`, `data_security/classification.py`, `firewall/decision.py` | Canonical `SideEffectClass`/`DataClass`; strict `ToolArguments`/`ToolResult`; sentinel-guarded `ExecutionAuthorization`; `compute_action_digest`; stable `DecisionReason` codes (Phase 2, Phase 4 `intent_*`, Phase 5 `approval_*`, Phase 6 `dlp_*`) |
| Tool registry + mock adapters | `../src/ai_security/tools/registry.py`, `tools/mock_{email,files,external_sink,text}.py` | Immutable validated registrations; exact `(tool_id, action_id)` resolution; one-directional policy consistency; deterministic in-memory adapters with ownership checks + digest verification; `mock_files.search` registered but policy-disabled |
| Input defense + provenance (advisory) | `../src/ai_security/input_defense/{models,config,normalize,heuristics,service,context_labels,sessions}.py`, `security/safe_yaml.py`, `../config/input_defense.yaml` | Strict exhaustive-disposition config (no PASS mapping, duplicate keys refused); bounded intake; copy-only normalization; 10 versioned heuristics with quoted-context downgrade; typed `IntakeReport` (codes/offsets/digests, no raw content); six trust labels + deterministic JSON context; typed `DETECTOR_UNAVAILABLE`; no path into policy/engine/gateway |
| Intent extraction + manifests | `../src/ai_security/intent/{models,extractors,providers,service,validator,time_window}.py` | Server-only issuer; mock 2-scenario extractor; strict local-model adapter plus the Phase 8 Ollama-compatible provider (fixed `/api/generate`, non-streaming JSON, no redirects/proxy trust, 1 MiB envelope/64 KiB output caps, typed failures); sentinel-sealed request/principal/tenant/policy-bound manifest with expiry + goal digest; exact action/resource/destination/parameter constraints and bounded uses; trusted-timezone TODAY/THIS_WEEK (DST-tested); best-effort `INTENT_CREATED`/`INTENT_FAILED` audit with status/error codes only |
| Gateway + risk engine | `../src/ai_security/firewall/{gateway,models,risk_engine,approval}.py` | Single `invoke_tool` chokepoint (bindings, strict validation, derived/deduplicated resources, destination, resource checks, deadline, real engine, audit-first, timeouts/concurrency/result bounds, typed outcomes); manifest verification + exact constraint comparison + use reservation after policy `ALLOW`; `risk-v2`; one-time approval consumption for engine `ASK_USER`, never overriding `BLOCK`; mandatory egress DLP and complete-response release/redaction/suppression; mandatory ordered audit lifecycle; **Phase 8:** preview evaluation path that never executes/consumes |
| Output DLP + egress | `../src/ai_security/data_security/dlp.py`, `../config/output_dlp.yaml` | Strict versioned config (`1.0.1`): five deterministic detectors, bounded patterns/limits, exact-canonical destination trust with startup coverage; findings hold code/category/count/bounded field paths only; `PASS`/`REDACT`/`BLOCK`/`REVIEW`; span-preserving idempotent redaction; oversize/error fail-closed; no classifier/entropy/semantic detection |
| Approval workflow | `../src/ai_security/firewall/approval.py`, `identity/approver_rules.py`, `persistence/approval_repository.py` | Strict request/decision/consumption API; 256-bit token returned once and stored only as SHA-256; verified-principal rule evaluation with tenant/self-approval checks; TTL 60–86,400 s (default 900); lazy expiry; row-locked state machine + same-transaction audit; consumption binds the effective side-effect/data class; `APPROVAL_REQUESTED`/`_DECIDED`/`_CONSUMED`/`_EXPIRED` audit events; no routes/UI/token transport/revocation/sweeper |
| Audit emission + verification | `../src/ai_security/audit/{models,writer,verifier}.py` | **Phase 7:** full §16.1 taxonomy (+`APPROVAL_CONSUMED`) with event-specific required fields; mandatory gateway lifecycle (`REQUEST_RECEIVED`→`TOOL_CALL_PROPOSED`→`EGRESS_INSPECTED`→`POLICY_EVALUATED`→`APPROVAL_CONSUMED` when granted→`TOOL_EXECUTION_STARTED`→completed/failed→`OUTPUT_INSPECTED`→response) plus approval/intent producers; first-class redacted `EGRESS_INSPECTED`/`OUTPUT_INSPECTED`/`RESPONSE_*` records; read-only `verify_chain` over exact stored bytes with typed content-free failures; **Phase 8:** ingress emits one `REQUEST_RECEIVED`, `PRINCIPAL_RESOLVED`/`PRINCIPAL_REJECTED` (rejection only), and redacted `INPUT_INSPECTED`; `SECURITY_ALERT_RAISED` remains producerless until Phase 10; no external anchor/retention automation/query API |
| Policy engine | `../src/ai_security/firewall/policy_engine.py`, `policy/{models,loader,self_checks}.py`, `../config/{policies,risk_thresholds,policy_self_checks}.yaml` | Deterministic §10.2 engine over validated facts; safe YAML loader (duplicate-key rejection); versioned bundle (sha256 + combined hash); **21 fixtures** (7 mandated names + Phase 2 rows) at startup + readiness |
| Tests | `../tests/conftest.py`, `unit/` (32 test files + helper), `integration/` (15 test files + conftest/helpers), `security/` (4 files) | **949 tests** (782 unit + 122 integration + 45 security), all passing (V72); DB-backed integration skips cleanly when PostgreSQL is unreachable |
| Quality gate | `../scripts/check.sh` | 8 steps incl. pinned Gitleaks 8.30.1 (dir+git) and constant-time confinement |
| Containers | `../Dockerfile`, `../docker-compose.yml` | Digest pins; non-root uid 10001; COPY `config/ migrations/ alembic.ini`; Compose dev `HOST_AUTH_KEYS_JSON` |
| Git | commits above | `gitleaks git` clean across history (V29/V37/V58/V61/V70/V73) |
| Spec-adjacent docs | [../docs/](../docs/) (10 files + `adr/ADR-001..015`) | Status columns honest; `API_INTEGRATION.md` is the signed-route contract; matrix doc reflects gateway-enforced facts; ADR-014 records the Phase 7 taxonomy/verifier; ADR-015 records the Phase 8 assertion/routes/local-model contract; `AUDIT_RETENTION_AND_DATA_HANDLING.md` records stored/excluded fields, retention/export/backup/deletion, and integrity guarantees |
| Memory (this directory) | `project_memory/*` | Updated 2026-10-28 for Phase 8 completion |

## Security controls — what is actually enforced today

Implemented and tested (Phases 0a/0b/1/2/3/4/5/6/7):

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
- **Audit append protocol + lifecycle (0b/2/5/7):** ADR-002 advisory lock + canonical
  bytes + unique `(chain_id, sequence_number)`; fixed hash vectors; 5-writer contiguity
  test; gateway/approval/intent events append through the single repository. Phase 7
  makes the gateway lifecycle mandatory: each pre-execution event gates execution and a
  mandatory append failure returns `BLOCK`/`audit_unavailable`; a post-execution failure
  withholds the result (`AUDIT_FAILED`). `TOOL_EXECUTION_COMPLETED` always carries
  `EXECUTED`; DLP suppression is represented by `RESPONSE_SUPPRESSED`.
- **Audit verification (7, ADR-014):** `verify_chain` reads one consistent snapshot,
  recomputes ADR-002 hashes from exact stored `canonical_event_bytes`, and checks
  sequence contiguity, previous-hash linkage, canonical form, and derived metadata
  agreement. Real-PostgreSQL tests detect payload/hash mutation, reordering, middle
  deletion, malformed/non-canonical JSON, malformed hashes, metadata tampering, and
  chain isolation. **Honest limit:** newest-event truncation and a consistent full-chain
  rewrite need an external checkpoint; no anchor is deployed.
- **Audit/log privacy (7):** privacy tests feed canary, email, credential, private-key,
  and API-key shapes through egress denial, adapter failure, response suppression, and
  intent extraction at DEBUG logging and assert the raw values are absent from serialized
  payloads and logs; approval tests also assert tokens/content never enter the chain.
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
- **Output DLP and egress policy (6, ADR-013):** every gateway requires an
  `OutputDefenseService` built from the strict versioned `config/output_dlp.yaml`; there
  is no no-op default. Egress inspects validated arguments after intent/argument checks
  and before resource/risk/policy/approval/execution; five deterministic detectors
  (canary, private-key header, `sk-` API key, credential assignment, email) can only
  raise the registry data class. Canary/private-key/API-key/blocking-credential content
  is denied with `dlp_egress_blocked` and an unchanged sink; inspection failure is
  `dlp_inspection_failed`. An exact-canonical destination trust map must cover every
  registered `EXTERNAL_MUTATION` destination at startup (missing/dead entries refuse
  startup); the mock sink is `PUBLIC`-only. Complete buffered results are released,
  redacted, or suppressed as a whole (`PASS`/`REDACT`/`BLOCK`/`REVIEW`); `BLOCK`/`REVIEW`/
  failure return `response_blocked` with no result. Findings/audit evidence contain
  stable codes/categories/counts/bounded field paths, config version/hash, digests, and
  sizes — never matched text, raw arguments, or result bodies. Approval consumption is
  bound to the effective side-effect/data class. False positives/negatives are documented
  in `../docs/OUTPUT_DLP_FALSE_POSITIVES.md`.
- **Signed HTTP ingress and principal binding (8, ADR-015):** every `/v1` route requires
  the Phase 0b HMAC headers plus a host-signed principal assertion in the exact signed
  body. `iss` must equal the key's `host_id`, `aud` its `audience`, and `tenant_id` must
  be present/member iff the key has an allowed-tenant list; future `authenticated_at`
  beyond tolerance is rejected. Failures return `403 principal_rejected`, audit one
  `PRINCIPAL_REJECTED` with a stable `error_type`, and run no other step. There is no
  unsigned fallback and the dev resolver remains HMAC-gated.
- **One execution surface (8):** only `POST /v1/requests` can execute. The preview route
  returns validation/egress/risk/policy facts without execution, manifest use, approval
  consumption, or authorization; the approval-decision route records a token-bound,
  tenant/rule-checked, row-locked one-time decision and never resumes the action. No
  route accepts a client decision/risk/policy fact/request id/deadline/resource/
  destination.
- **Bounded runtime and ingress controls (8):** `DemoRuntime` receives only a
  `ToolExecutor`, executes exactly `mock_email.read` + `text.summarize` with
  `max_uses=1`, returns `NO_ACTION` for time windows/unsupported shapes, and reserves all
  planned tool-call rate-limit slots before executing. Four per-process per-principal
  fixed-window buckets (60/120/30/30 default) and `REQUEST_TIMEOUT_SECONDS` (1–120,
  default 30) fail closed; authenticated invalid bodies are charged, unverifiable
  principals are not. Input `REJECT`/`QUARANTINE` stops before intent.
- **Optional local model (8):** `MODEL_PROVIDER=mock` is the offline default. `local`
  uses a strict Ollama-compatible client (origin-only URL, exact model name, fixed
  non-streaming `/api/generate`, `format=json`/`temperature=0`, no redirects, no proxy
  trust, 1 MiB envelope/64 KiB output caps, 1–60 s per attempt, duplicate-key rejection).
  Any provider failure yields no manifest and `503 model_unavailable` with no tool
  events; a successful path still passes every gateway gate. No cloud adapter exists;
  `ALLOW_EXTERNAL_MODEL_CALLS=true` refuses startup.

NOT implemented (do not claim otherwise): general agent planning (the runtime executes
only the fixed two-call demo plan), real connectors, approved-action resumption through
HTTP, approval delivery/UI/notifications/revocation/background expiry, a shared or
distributed rate-limit store, cross-process intent-use limits,
classifier/entropy/semantic/multilingual DLP, per-resource classification metadata,
model-prompt or adapter-internal content inspection, response-review transport, process
isolation/sandbox, an **external audit checkpoint/anchor**, automated audit
retention/purging, an audit query API/UI, per-event signatures, a producer for
`SECURITY_ALERT_RAISED`, cloud model calls, streaming, SOC, and a consumer that feeds
detector findings/trust labels into a model prompt. See
[../docs/SECURITY_INVARIANTS.md](../docs/SECURITY_INVARIANTS.md) (the file is authoritative
for every row).

## Current-session verification (2026-10-28, fresh runs)

All PASS — full commands and results in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md):

- `uv run --frozen pytest -q` → **949 passed** (782 unit + 122 integration + 45
  security), including 28 signed `/v1` route tests, 9 API-support unit tests, 36
  provider tests, and local-provider failure/success integration against real
  PostgreSQL (V72).
- `uv run --frozen mypy` → clean, 73 source files; `ruff check`/`format --check` clean
  (188 files formatted; V73).
- `uv lock --check` → consistent after moving `httpx2` to runtime dependencies; 44
  packages resolved (V73).
- Full `bash scripts/check.sh` (pre-commit) → exit 0, all 8 steps; **949 passed**;
  Gitleaks 8.30.1 dir+git "no leaks found" (48 commits scanned); prohibited-pattern and
  constant-time-confinement checks clean (V74).
- Targeted Phase 8 suites (`test_api_requests`, `test_api_support`,
  `test_intent_providers`, `test_principal_assertion`, `test_principal_resolver`,
  `test_settings`) → PASS (route contracts, rate limits, approval decisions, preview
  non-execution, provider strictness/failure mapping, assertion binding, settings
  bounds; V75).
- Phase 7 evidence (V67–V71) and Phase 6 evidence (V63–V66) retained; Phase 8 adds no
  migration (head remains `f7a8b9c0d1e2`).

## Environment (verified this session)

macOS (darwin); uv 0.13.x; Python 3.12.15; Docker 29.3.1 / Compose v5.1.1 (Docker
Desktop running); PostgreSQL 17.2 (`protai-db-1`) on 127.0.0.1:5432; git 2.54.0;
Gitleaks 8.30.1 installed; no markdown linter installed. The project virtualenv was
recreated at `/Users/stiven/Desktop/ProtAI/.venv` after the repository moved. Current
stack state: `db` running (preserved for tests), `api` stopped.

## Deferred to Phase 9 (planned, not implemented)

Evaluation and calibration (blueprint §20 and §21 Phase 9): build `evaluation/` with
labeled fixtures and honest metrics for injection-detection precision/recall, DLP false
positives/negatives, and risk-score calibration; document measured results and adjust
thresholds only with evidence. Do not add real connectors, cloud model calls, streaming,
approved-action resumption, a distributed rate-limit store, or any new authority path as
part of calibration. Policy remains the sole `ALLOW` producer; the gateway remains the
only execution path; input defense/intent/DLP stay advisory or narrowing; approval stays
a gate; audit is never an authorization input. Preserve ADR-008 through ADR-015 and keep
all suites/gate green. Read blueprint §21 Phase 9 before starting.
