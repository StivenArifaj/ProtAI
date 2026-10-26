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
| `settings.py` | `AppEnv`/`LogLevel`/`PrincipalResolverKind` StrEnums; fail-closed `Settings` incl. host-auth keys, tolerance/TTL, request bound, self-check/policy/threshold paths, `input_defense_path`, session TTL/max-age (Phase 3), `intent_manifest_ttl_seconds` (Phase 4), and `approval_ttl_seconds` (Phase 5, 60-86,400 s) | VERIFIED | 60 settings tests | §5.1/§5.4, §7.4, §9.2, §13, §18.2 |
| `security/constant_time.py` | `constant_time_bytes_equal`, `constant_time_hex32_equal` (confinement enforced by the gate) | VERIFIED | 16 tests | §9.2 |
| `security/canonical_json.py` | Canonical JSON text/bytes | VERIFIED | 17 tests | ADR-002/006 |
| `security/urls.py` | Destination canonicalization: https-only, IDNA host, percent-encoding normalization, exact-match semantics (Phase 1) | VERIFIED | 36 tests | §6.2, §10.4, ADR-008 |
| `security/safe_yaml.py` | Duplicate-key-safe YAML parsing (`yaml.compose` walk + `yaml.safe_load`); `SafeYamlError` (Phase 3, shared by policy + input-defense loaders) | VERIFIED | loader/config tests | §10.4, §7.2, ADR-010 |
| `audit/hash_chain.py` | ADR-002 hash formula, genesis, fixed vectors | VERIFIED | 17 tests | §16.2, ADR-002 |
| `identity/models.py` | Strict frozen `Principal`; `PrincipalResolutionError` | VERIFIED | principal tests | §9 |
| `identity/signing.py` | Exact `v1` signing message; header constants; `sign_request` | VERIFIED | verifier/signing tests | §9.2, ADR-001 |
| `identity/host_auth.py` | Verification + full rejection surface + `verified_nonce` | VERIFIED | verifier matrix | §9.2 |
| `identity/resolver.py` | `DevPrincipalResolver` (guarded), fail-closed `HostPrincipalResolver` (typed host assertion still pending), factory guard | VERIFIED | resolver tests | §9.3, ADR-001 |
| `identity/adapters.py` | `TestPrincipalResolver`/`TestAdapterRefusedError` — test-only, unreachable via settings/factory (Phase 1) | VERIFIED | 8 tests | §9.3, ADR-008 |
| `persistence/database.py` | Async engine/session factory; never-raising `healthy()` | VERIFIED | health + integration | ADR-005 |
| `persistence/models.py` | `host_request_nonces` (unique key+nonce), `audit_events` (unique chain+seq), `session_security_state` (4 check constraints, binding + last-seen indexes, Phase 3), `approval_requests` (status/score constraints, expiry/requester indexes, Phase 5) | VERIFIED | repository/session/approval tests | §7.4, §9.2, §13, §16.2 |
| `persistence/nonce_repository.py` | Atomic single-statement nonce registration | VERIFIED | concurrency tests | §9.4 |
| `persistence/audit_repository.py` | ADR-002 advisory-lock append with canonical bytes, plus `append_in_session` for same-transaction approval audit | VERIFIED | vector + 5-writer + approval tests | §16.2, ADR-002, ADR-012 |
| `persistence/session_repository.py` | Tenant/subject-bound session signals: create/read/record/rotate, `LEAST(...)` bounded counters, 24 h/7 d lazy expiry, mismatch = not found (Phase 3) | VERIFIED | 9 integration tests | §7.4, §20.2 #23, ADR-010 |
| `persistence/approval_repository.py` | Row-locked approval decisions/consumption (`SELECT ... FOR UPDATE`), digest-only token check, lazy expiry, same-transaction audit; exactly-once consumption (Phase 5) | VERIFIED | 11 approval + 5 gateway-approval integration tests | §13, §20.2 #20/#24, ADR-012 |
| `tools/base.py` | Canonical `SideEffectClass`, tool-id contract, strict `ToolArguments`/`ToolResult`, `ToolAdapter`, `ToolExecutionError`, sentinel-guarded `ExecutionAuthorization` + `compute_action_digest` + `verify_execution_authorization` (Phases 1-2) | VERIFIED | policy + digest/adapter/security tests | §6.1, §12.4, §13.2, ADR-008/009 |
| `tools/registry.py` | `ToolRegistration` (validated, immutable) + `ToolRegistry`; `build_registry` startup policy/capability consistency (`ToolRegistryConfigError`) | VERIFIED | 24 registry tests + wiring | §6.1, §14.1, ADR-009 |
| `tools/mock_email.py` | Deterministic in-memory email adapter (email-1/2 `dev-user`, email-3 `other-user`); digest-guarded calls | VERIFIED | adapter + gateway tests | §14.1, ADR-009 |
| `tools/mock_files.py` | Deterministic in-memory file adapter (file-1/2 `dev-user`, file-3 `other-user`); read + registered-but-disabled search | VERIFIED | adapter + gateway tests | §14.1, ADR-009 |
| `tools/mock_external_sink.py` | `SinkStore`/`SinkRecord` mock egress adapter storing digest/size only; content ≤ 8192 bytes | VERIFIED | adapter/security/integration tests | §14.1, §16.3, ADR-009 |
| `tools/mock_text.py` | Deterministic `text.summarize` adapter | VERIFIED | adapter tests | §14.1, ADR-009 |
| `input_defense/models.py` | `TrustLabel` (6 §2.2 labels), `Disposition` (+rank, `strongest_disposition`), `FindingCode` (14), `DetectorFinding`, `IntakeReport`, `content_digest`; detector/heuristics versions (Phase 3) | VERIFIED | input-defense suites | §2.2, §7.2, ADR-010 |
| `input_defense/config.py` | Strict input-defense config: exhaustive dispositions (no PASS mapping), limits (bytes/depth/evaluation budget), content types (Phase 3) | VERIFIED | 9 config tests + wiring | §7.2, ADR-010 |
| `input_defense/normalize.py` | Copy-only normalization: UTF-8 decode, iterative JSON depth, control/zero-width/escape/Base64/NFKC/mixed-script signals (Phase 3) | VERIFIED | 12 tests | §7.2, ADR-010 |
| `input_defense/heuristics.py` | 10 versioned deterministic rules; quoted/educational downgrade; external-only rules for assistant-directed instructions (Phase 3) | VERIFIED | 20 tests | §7.3, ADR-010 |
| `input_defense/service.py` | `InputDefenseService.inspect` pipeline: intake → decode → structure → normalize → heuristics → optional classifier; typed `DETECTOR_UNAVAILABLE` on any fault (Phase 3) | VERIFIED | failure suite + smoke | §7.2-7.3, §7.6, ADR-010 |
| `input_defense/context_labels.py` | `ContextSegment`/`AgentContext` + builders; unique segment IDs; deterministic sorted-JSON render with trust labels; external content forced `EXTERNAL_UNTRUSTED` (Phase 3) | VERIFIED | 7 tests | §2.2, §7.3, ADR-010 |
| `input_defense/sessions.py` | Session-id generation + expiry math (`SESSION_SIGNAL_TTL_SECONDS`, `SESSION_MAX_AGE_SECONDS`, `MAX_SIGNAL_COUNTER`) (Phase 3) | VERIFIED | 5 tests | §7.4, ADR-010 |
| `data_security/classification.py` | Canonical `DataClass` enum (Phase 1; classification Phase 6) | VERIFIED | policy model/engine tests | §6.1, ADR-008 |
| `intent/models.py` | Strict `IntentExtraction`/`IntentConstraint`/`IntentManifest`/`ResolvedTimeWindow`; sentinel-sealed server issuance; full binding verifier; bounded limits (Phase 4) | VERIFIED | 14 model tests | §8, §11.1, ADR-011 |
| `intent/time_window.py` | Trusted-timezone `TODAY`/`THIS_WEEK` → exact UTC instants; DST-safe (Phase 4) | VERIFIED | time-window tests | §8, ADR-011 |
| `intent/extractors.py` | `IntentExtractor` protocol; two-scenario `MockIntentExtractor`; strict `LocalModelIntentExtractor` over an injected client (bounded JSON, duplicate-key/unknown-field rejection, retries, outage mapping) (Phase 4) | VERIFIED | 13 extractor tests | §8, ADR-011 |
| `intent/service.py` | `IntentManifestService.extract_and_issue`: registry/policy constraint validation, trusted-time relative dates, clarification/rejection/outage paths, TTL bounds (Phase 4) | VERIFIED | 13 service tests | §8, §11.1, ADR-011 |
| `intent/validator.py` | Exact constraint matching + per-process bounded `IntentUsageTracker` (capacity/expiry/uses, fail closed) (Phase 4) | VERIFIED | 10 validation/tracker tests | §11.1, ADR-011 |
| `firewall/decision.py` | `FirewallDecision`, stable `DecisionReason` codes (incl. Phase 4 intent and Phase 5 approval codes), `DecisionRecord` | VERIFIED | engine + gateway + intent/approval tests | §6.1, §10.3, ADR-008/009/011/012 |
| `firewall/policy_engine.py` | Deterministic §10.2 evaluation over strict facts; deny-by-default; no I/O (Phase 1) | VERIFIED | 64 engine tests | §10.2, §11.4, ADR-008 |
| `firewall/models.py` | `RequestContext`, `ProposedToolCall`, `InvocationOutcome`, `ToolInvocationResult` (with approval metadata), `ToolExecutor` with optional manifest (Phase 2/4/5) | VERIFIED | gateway + intent/approval tests | §12.2, §13, ADR-009/011/012 |
| `firewall/risk_engine.py` | Versioned deterministic `risk-v2` scoring: every `risk-v1` weight plus one bounded distinct-resource breadth factor; strict `resource_count` (Phase 5) | VERIFIED | 30 risk tests + gateway tests | §11.3-11.4, ADR-012 |
| `firewall/gateway.py` | Single `invoke_tool` chokepoint: bindings, strict validation, deduplicated resources/destination, adapter checks, deadline, engine, manifest verification/constraint/use enforcement (Phase 4), one-time approval consumption for engine `ASK_USER` (Phase 5), audit-first, authorization, bounded execution, typed outcomes | VERIFIED | gateway unit/security/integration incl. intent/approval no-grant | §12.3, §13, ADR-009/011/012 |
| `firewall/approval.py` | Strict approval request/decision/consumption specs; 256-bit token returned once, SHA-256 stored; verified-principal rule evaluation; TTL and lazy expiry (Phase 5) | VERIFIED | 11 lifecycle + 5 gateway-approval tests | §13, ADR-012 |
| `policy/models.py` | Validated policy documents, `ToolPolicy` (incl. approval eligibility/rule/self-approval), `Thresholds`, `PolicyBundle` (version + content hashes) | VERIFIED | 40 tests | §10.4, §10.7, §13, ADR-008/012 |
| `policy/loader.py` | Safe YAML loader: `yaml.safe_load` + `yaml.compose` duplicate-key detection; `PolicyConfigError` fails closed | VERIFIED | 20 tests | §10.4, ADR-008 |
| `policy/self_checks.py` | Strict fixture loader/runner + `PolicyReadinessReport`/`evaluate_policy_readiness` evaluated against the real engine | VERIFIED | 33 + wiring tests | ADR-007, ADR-008 |
| `audit/models.py` | Audit event subset (Phase 2 plus Phase 5 approval events), schema v1 constants, payload-safe `AuditEvent.to_payload()` | VERIFIED | gateway/approval/integration tests | §16.1-16.2, ADR-009/012 |
| `audit/writer.py` | `AuditRecorder` protocol + `ChainAuditRecorder` over the ADR-002 repository; `AuditWriteError` | VERIFIED | gateway/integration tests | §16.2, §16.4, ADR-009 |
| `api/__init__.py` | Package marker | VERIFIED | — | — |
| `api/app.py` | `create_app` factory + module-level `app`; startup refusals (incl. policy and input-defense config); middleware + registrar + audit chain + registry/intent/approval/gateway + input-defense/session wiring on `app.state`; gateway receives the intent tracker and approval service | VERIFIED | health + wiring/intent/approval tests | §7.2, §13, §18.2, ADR-007/008/009/010/011/012 |
| `api/dependencies.py` | `get_settings`; `database_ready`; `policy_readiness` returning `PolicyReadinessReport` (overridable) | VERIFIED | health tests | §18.1, §20.1 |
| `api/routes_health.py` | `/health/live`, `/health/ready` (config/database/policy_self_checks + `policy_version`/`policy_hash`; booleans + metadata only) | VERIFIED | health tests | §18.1 |
| `api/middleware.py` | `HostAuthMiddleware` on `/v1/*` (size → HMAC → nonce → replay) | VERIFIED | 13 middleware tests + live V26/V27 | §9.2, §18.2 |

## Tests ([../tests/](../tests/))

| File | Purpose | Status | Count |
|---|---|---|---|
| `conftest.py` | Deterministic test env (incl. `HOST_AUTH_KEYS_JSON`); `settings_factory` (`_env_file=None`) | VERIFIED | — |
| `unit/test_settings.py` | Settings validation incl. host-auth keys, resolver guard, TTL relation, self-check/policy paths, intent/approval TTL bounds | VERIFIED | 60 |
| `unit/test_constant_time.py` | Constant-time equality helpers | VERIFIED | 16 |
| `unit/test_canonical_json.py` | Canonical JSON stability | VERIFIED | 17 |
| `unit/test_hash_chain.py` | ADR-002 formula + fixed vectors | VERIFIED | 17 |
| `unit/test_host_auth_verifier.py` | Signing message vector + full rejection matrix | VERIFIED | 46 |
| `unit/test_principal_resolver.py` | `Principal` model + resolver guards | VERIFIED | 14 |
| `unit/test_principal_test_adapter.py` | Test-only adapter: construction guard, factory exclusion | VERIFIED | 8 |
| `unit/test_urls.py` | Destination canonicalization (IDNA, encoding, rejections) | VERIFIED | 36 |
| `unit/test_policy_models.py` | Strict policy/threshold/bundle models + hashes, approval-flag consistency | VERIFIED | 40 |
| `unit/test_policy_loader.py` | Safe loading, duplicate keys, malformed documents | VERIFIED | 20 |
| `unit/test_policy_engine.py` | Table-driven matrix: allowed/forbidden/malformed/cross-scope/unknown/error | VERIFIED | 71 |
| `unit/test_policy_self_checks.py` | Fixture runner/readiness (bundle API) | VERIFIED | 33 |
| `unit/_tool_auth.py` | Test helper issuing gateway-style execution authorizations | VERIFIED | — |
| `unit/test_action_digest.py` | Canonical action digest stability/sensitivity | VERIFIED | 14 |
| `unit/test_tool_registry.py` | Registration validation matrix + startup consistency + approver-rule validation | VERIFIED | 28 |
| `unit/test_mock_adapters.py` | Mock adapter behavior + unauthorized-call/tamper refusal | VERIFIED | 15 |
| `unit/test_risk_engine.py` | `risk-v2` parity, breadth boundaries, rationale/codes, invalid counts, cap/version | VERIFIED | 30 |
| `unit/test_gateway.py` | Gateway flow, failure ordering, audit outages, timeouts, bounds, concurrency, resource-id dedup | VERIFIED | 21 |
| `unit/test_input_normalization.py` | Copy-only normalization + JSON structure signals | VERIFIED | 12 |
| `unit/test_input_heuristics.py` | Attack matrix, quoted-context downgrade, external-only rules, benign hard negatives | VERIFIED | 20 |
| `unit/test_input_defense_config.py` | Strict config: duplicates, missing/unknown codes, PASS mapping, content types | VERIFIED | 9 |
| `unit/test_context_labels.py` | Trust labels, context assembly, rendering, refusals | VERIFIED | 7 |
| `unit/test_sessions.py` | Session-id properties + TTL/max-age expiry math | VERIFIED | 5 |
| `unit/test_intent_models.py` | Sealed/forged manifests, strict constraints, binding/status/expiry/resolution invariants | VERIFIED | 18 |
| `unit/test_approver_rules.py` | Strict role/principal grammar, verified-principal evaluation, tenant/self-approval/unsatisfiable rules | VERIFIED | 24 |
| `unit/test_intent_extractors.py` | Mock scenarios + strict local-model parsing/retry/outage/timeout/unsafe target | VERIFIED | 15 |
| `unit/test_intent_validation.py` | Exact constraint matching, tracker uses/expiry/capacity, DST/relative-date math | VERIFIED | 9 |
| `unit/test_intent_service.py` | Issuance/bindings/TTL, clarification/rejection, unenforceable constraints, failures | VERIFIED | 8 |
| `integration/test_input_defense_wiring.py` | Startup wiring + invalid-config refusals | VERIFIED | 4 |
| `integration/test_session_security_state.py` | Binding, guessed IDs, bounded counters, TTL/max-age, rotation, lazy delete (real PostgreSQL) | VERIFIED | 9 |
| `integration/test_intent_wiring.py` | App state/tracker identity/TTL, end-to-end allow + use limit, clarification, wrong-request denial (real PostgreSQL) | VERIFIED | 4 |
| `security/test_input_defense_failure.py` | Intake violations, detector/normalizer/classifier faults never PASS; no raw content in reports; no execution surface | VERIFIED | 11 |
| `security/test_intent_no_grant.py` | Forged/missing/expired/rebound manifests, action/resource/parameter/destination mismatch, use limit, legacy fail-closed | VERIFIED | 6 |
| `integration/conftest.py` | `migrated_database` fixture: create `firewall_test`, run Alembic, skip if unreachable | VERIFIED | — |
| `integration/db_helpers.py` | `DatabaseHarness` (NullPool) for asyncio.run tests | VERIFIED | — |
| `integration/test_health.py` | Health endpoints, docs gating, non-leakage, readiness incl. policy version/hash | VERIFIED | 10 |
| `integration/test_host_auth_middleware.py` | End-to-end denial matrix through the ASGI app | VERIFIED | 13 |
| `integration/test_nonce_repository.py` | Atomic registration incl. expiry + failure paths | VERIFIED | 5 |
| `integration/test_audit_append.py` | Chain continuity, vectors, 5-writer concurrency | VERIFIED | 5 |
| `integration/test_migrations.py` | Upgrade idempotency | VERIFIED | 1 |
| `integration/test_policy_self_checks_wiring.py` | Startup refusals + readiness drift detection | VERIFIED | 8 |
| `integration/test_gateway_end_to_end.py` | Real-Postgres chain order/linkage, result digest, non-leakage, denied egress, audit outage | VERIFIED | 3 |
| `integration/test_gateway_wiring.py` | `create_app` registry/gateway/approval wiring + unregistered-tool startup refusal | VERIFIED | 2 |
| `integration/test_approval_flow.py` | Real-PostgreSQL approval lifecycle, digest-only storage, replay/mutation/expiry/denial, five-way concurrency, same-transaction audit | VERIFIED | 11 |
| `integration/test_gateway_approval.py` | Real-PostgreSQL ASK_USER gating, approved execution metadata, no-execution matrix, BLOCK precedence | VERIFIED | 5 |
| `security/test_gateway_no_bypass.py` | Denied/unknown/audit-failed calls never execute; no decision → no execution; direct-adapter fail-closed; approval absent/granted/non-granted/storage-error paths; BLOCK ignores approval | VERIFIED | 24 |

## Scripts

| File | Purpose | Status | Blueprint |
|---|---|---|---|
| `../scripts/check.sh` | 8-step local gate: `uv lock --check`; ruff format; ruff lint; mypy; pytest (734); **Gitleaks 8.30.1** (`dir` + `git`, redacted, fails if missing/mismatched); prohibited-pattern greps (prohibit `os.system(`, `subprocess`, `shell=True`, `eval(`, `exec(`, `pickle`, `yaml.load(` in `src/`); `compare_digest` confinement grep | VERIFIED | §20.3 |

## Migrations

| File | Purpose | Status | Blueprint |
|---|---|---|---|
| `../alembic.ini` | Alembic config; `script_location` only (URL comes from settings) | VERIFIED | ADR-006 |
| `../migrations/env.py` | Async env reading `Settings`/`DATABASE_URL`; targets `Base.metadata` | VERIFIED | ADR-005/006 |
| `../migrations/versions/d15b46c49950_baseline_host_request_nonces_audit_.py` | Baseline: `host_request_nonces`, `audit_events` | VERIFIED | §9.2, §16.2 |
| `../migrations/versions/c7f1a2b3d4e5_session_security_state.py` | `session_security_state`: binding/expiry constraints, bounded counters (Phase 3) | VERIFIED | §7.4, §20.2 #23 |
| `../migrations/versions/e5a1c2b3d4f6_approval_requests.py` | `approval_requests`: status/score constraints, expiry/requester indexes, digest-only token (Phase 5) | VERIFIED | §13, ADR-012 |

## Config

| File | Purpose | Status | Blueprint |
|---|---|---|---|
| `../config/policies.yaml` | Starter policy (v1 §10.5): allowed read actions + `mock_external_sink.write` registered with egress disabled; `version: dev-1` | VERIFIED | §10.4–10.5, ADR-008 |
| `../config/risk_thresholds.yaml` | Experimental thresholds 40/80, validated ordering; `version: dev-1` | VERIFIED | §11.4, ADR-008 |
| `../config/policy_self_checks.yaml` | 21 strict fixtures (7 mandated names + Phase 2 binding/deadline/inconsistent-facts rows) evaluated against the real engine at startup + readiness; fixture-level `tool_policy` overrides for the §10.5 egress scenario | VERIFIED | §10.3, ADR-007/008/009 |
| `../config/input_defense.yaml` | `version: dev-1`; limits (64 KiB/8 depth/5000 ms); 4 content types; 14 finding codes mapped with no PASS (overrides/secret/oversize/type/encoding/structure/depth/unavailable REJECT; untrusted QUARANTINE; obfuscated/quoted/control/homoglyph/excessive FLAG) | VERIFIED | §7.2, ADR-010 |

## Docs ([../docs/](../docs/))

| File | Purpose | Status |
|---|---|---|
| [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) | Component map + per-request lifecycle; per-component status marks | VERIFIED (doc) |
| [../docs/THREAT_MODEL.md](../docs/THREAT_MODEL.md) | 16 threats + trust classes/boundaries with implementation status | VERIFIED (doc) |
| [../docs/SECURITY_INVARIANTS.md](../docs/SECURITY_INVARIANTS.md) | 25 mandatory invariants (blueprint §20.2) with Phase 5 statuses (#6/#7/#8/#20/#24 implemented; #9 partial pending content DLP; scope statement 0a-5) | VERIFIED (doc) |
| [../docs/POLICY_DECISION_MATRIX.md](../docs/POLICY_DECISION_MATRIX.md) | Mandated v1 decision matrix (implemented by the Phase 1 engine and consumed by the Phase 2 gateway; reason-code mapping documented) | VERIFIED (doc) |
| [../docs/DECISIONS.md](../docs/DECISIONS.md) | ADR index (summaries + links; no full ADRs) | VERIFIED (doc) |
| [../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md) | Blueprint §22.4 phase-state document; 58-row verification record; 0a/0b/1/2/3/4/5 DoD checklists | VERIFIED |
| [../docs/KNOWN_LIMITATIONS.md](../docs/KNOWN_LIMITATIONS.md) | Limitations items 1-32 with phase pointers | VERIFIED |
| [../docs/adr/ADR-001-host-hmac-authentication.md](../docs/adr/ADR-001-host-hmac-authentication.md) | HMAC host auth + dev-resolver guard (Phase 0b) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-002-audit-hash-chain.md](../docs/adr/ADR-002-audit-hash-chain.md) | Audit hash-chain append + canonical bytes (Phase 7; scaffold 0b) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-003-no-token-streaming.md](../docs/adr/ADR-003-no-token-streaming.md) | v1 streaming disabled (Phase 6/8) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-004-soc-alert-only.md](../docs/adr/ADR-004-soc-alert-only.md) | SOC analyzer alert-only (Phase 10) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-005-sqlalchemy-async-persistence.md](../docs/adr/ADR-005-sqlalchemy-async-persistence.md) | SQLAlchemy 2.x async persistence (Phase 0b) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-006-alembic-migrations.md](../docs/adr/ADR-006-alembic-migrations.md) | Alembic for schema changes (Phase 0b) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-007-policy-matrix-self-checks.md](../docs/adr/ADR-007-policy-matrix-self-checks.md) | Policy matrix + startup self-checks (Phase 1; scaffold 0b) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-008-policy-engine-typed-contracts.md](../docs/adr/ADR-008-policy-engine-typed-contracts.md) | Deterministic policy engine + strict typed contracts + versioned bundle (Phase 1) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-009-tool-registry-and-enforced-gateway.md](../docs/adr/ADR-009-tool-registry-and-enforced-gateway.md) | Tool registry, execution authorization, and the enforced gateway (Phase 2) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-010-advisory-input-defense-and-session-signals.md](../docs/adr/ADR-010-advisory-input-defense-and-session-signals.md) | Advisory input threat defense, trust labels, and session signals (Phase 3) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-011-server-issued-intent-manifests.md](../docs/adr/ADR-011-server-issued-intent-manifests.md) | Server-issued, sealed intent manifests and concrete action constraints (Phase 4) | VERIFIED (ADR, Accepted) |
| [../docs/adr/ADR-012-risk-v2-and-human-approvals.md](../docs/adr/ADR-012-risk-v2-and-human-approvals.md) | `risk-v2` breadth factor and durable one-time human approvals (Phase 5) | VERIFIED (ADR, Accepted) |

## Memory (`project_memory/`)

| File | Purpose |
|---|---|
| [README.md](README.md) | Entry point, reading order, status labels, update rules |
| [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) | Identity, goals, non-goals, stack, environment |
| [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) | Source of truth for what exists now |
| [NEXT_SESSION.md](NEXT_SESSION.md) | Handoff for Phase 6 |
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
| [phases/PHASE_2_PLAN.md](phases/PHASE_2_PLAN.md) | Phase 2 plan (executed) |
| [phases/PHASE_2_COMPLETE.md](phases/PHASE_2_COMPLETE.md) | Phase 2 record |
| [phases/PHASE_3_PLAN.md](phases/PHASE_3_PLAN.md) | Phase 3 plan (executed) |
| [phases/PHASE_3_COMPLETE.md](phases/PHASE_3_COMPLETE.md) | Phase 3 record |
| [phases/PHASE_4_PLAN.md](phases/PHASE_4_PLAN.md) | Phase 4 plan (executed) |
| [phases/PHASE_4_COMPLETE.md](phases/PHASE_4_COMPLETE.md) | Phase 4 record |
| [phases/PHASE_5_PLAN.md](phases/PHASE_5_PLAN.md) | Phase 5 plan (executed) |
| [phases/PHASE_5_COMPLETE.md](phases/PHASE_5_COMPLETE.md) | Phase 5 record |
| [phases/PHASE_TEMPLATE.md](phases/PHASE_TEMPLATE.md) | Phase-record template |

## Not yet present (planned locations)

`src/ai_security/{agent,soc}/`, `evaluation/` — see
[ARCHITECTURE_MAP.md](ARCHITECTURE_MAP.md) for the phase that creates each.
(`identity/`, `security/`, `persistence/`, `policy/`, `audit/`, `firewall/`, `tools/`,
`data_security/`, `input_defense/`, `intent/`, `migrations/`, `config/` exist; `firewall/`
holds the decision contract, policy engine, risk engine, approval service, and enforced
gateway; `input_defense/` is advisory with no consumers yet; `intent/` is in-process
with a mock extractor; approvals are durable but have no route/transport.)
