# Architecture Map

Two views: what is implemented today (verified) and the target v1 architecture from the
blueprint. Full narrative and the per-request lifecycle: [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)
(mark status per component there as well). **Nothing under "Target v1" may be claimed as
existing.**

## Implemented today (Phases 0a–4 — VERIFIED 2026-10-19)

Components:

- `ai_security.settings` (`../src/ai_security/settings.py`): pydantic-settings model.
  `APP_ENV` required (`development`/`test`/`staging`/`production`); `LOG_LEVEL` default
  `INFO`; `DATABASE_URL` `SecretStr`. Fail-closed validation: unknown enum values
  rejected; scheme must be `postgresql+asyncpg://` (ADR-005); the documented sample
  development password **and the all-zero HMAC sample secret** are refused outside
  `development`/`test`; `HOST_AUTH_KEYS_JSON` required with strict per-key records
  (base64 ≥32-byte secrets, allowed tenants, duplicate IDs rejected); timestamp
  tolerance 60 s, nonce TTL 300 s (≥2×tolerance), request bound 64 KiB;
  `POLICY_SELF_CHECKS_PATH`, `POLICY_PATH`, `RISK_THRESHOLDS_PATH`, and
  `INPUT_DEFENSE_PATH` (Phase 3) with defaults under `config/`; session TTL 86400 s with
  max age 604800 s (validator enforces TTL ≤ max age); `INTENT_MANIFEST_TTL_SECONDS`
  default 300 s, bounded 1–3600 s (Phase 4).
- `ai_security.security` (`constant_time.py`, `canonical_json.py`, `urls.py`,
  `safe_yaml.py`) and `ai_security.audit.hash_chain`: `hmac.compare_digest` wrappers
  (confinement enforced by the gate), canonical JSON bytes, destination
  canonicalization (https-only, IDNA host, percent-encoding normalization, exact-match),
  duplicate-key-safe YAML parsing used by both loaders, and the ADR-002 hash formula +
  fixed vectors.
- `ai_security.identity` (`models`, `signing`, `host_auth`, `resolver`, `adapters`):
  `Principal` (strict, frozen, IANA timezone validated); HMAC signing/verification with
  the exact newline-joined `v1` message and the full rejection surface;
  `DevPrincipalResolver` (constructible only in dev/test), fail-closed
  `HostPrincipalResolver`, and the test-only `TestPrincipalResolver`.
- `ai_security.api.middleware.HostAuthMiddleware`: pure-ASGI, keyed on the `/v1/` path
  prefix; enforces content-length/capped body → signature/timestamp/replay → replays the
  buffered body; denial codes `missing_headers`/…/`replayed_nonce`/`request_too_large`
  with 400/401/413/503; puts `VerifiedHostContext` in `scope["state"]["host_auth"]`.
- `ai_security.persistence` (`database`, `models`, `nonce_repository`,
  `audit_repository`, `session_repository`): async engine/session (`pool_pre_ping`, 2 s
  connect timeout, never-raising `healthy()`); atomic nonce upsert
  (`ON CONFLICT ... WHERE expires_at < now() RETURNING`); ADR-002 advisory-lock audit
  append (canonical bytes stored, unique `(chain_id, sequence_number)`); Phase 3
  `session_security_state` repository — every operation bound to
  `(tenant_id, subject_id)`, bounded `LEAST(...)` counters, 24 h inactivity / 7 d
  absolute lazy expiry, signal-free rotation.
- `ai_security.policy` (`models`, `loader`, `self_checks`) + `../config/{policies,risk_thresholds,policy_self_checks}.yaml`:
  the validated policy document model (`ToolPolicy`, `PolicyBundle` with `version` +
  sha256 content hashes), the safe YAML loader (`yaml.safe_load` + duplicate-key
  detection via `security/safe_yaml.py`; `PolicyConfigError` fails closed), and the
  ADR-007 self-check suite — 21 strict fixtures (7 mandated names + Phase 2 rows)
  evaluated against the real engine at startup (refusal) and on every readiness probe
  (live drift detection).
- `ai_security.firewall` (`decision`, `policy_engine`, `risk_engine`, `models`,
  `gateway`): stable decision contract (`FirewallDecision`, `DecisionReason` codes,
  `DecisionRecord` with policy version/hash); the deterministic engine implementing the
  blueprint §10.2 order over strict validated facts (deny-by-default, no I/O, no model
  calls, ADR-008); `risk-v1` deterministic scoring (side-effect/destination/registration
  data class, capped, factor codes audited); and the single `invoke_tool` gateway
  chokepoint (bindings → strict validation → derived resources/destination → adapter
  resource check → risk → deadline → engine → **manifest verification/constraint match**
  (Phase 4) → digest-bound authorization → audit-first → bounded execution → typed
  outcome, ADR-009/011).
- `ai_security.tools` (`base.py`, `registry.py`, `mock_{email,files,external_sink,text}.py`):
  canonical `SideEffectClass` + strict `ToolArguments`/`ToolResult`; sentinel-guarded,
  digest-bound `ExecutionAuthorization`; immutable validated registrations with
  one-directional policy consistency (`mock_files.search` registered but policy-disabled);
  deterministic in-memory adapters that verify the digest immediately before the side
  effect.
- `ai_security.data_security.classification`: canonical `DataClass` enum (exactly once).
- `ai_security.intent` (`models`, `extractors`, `service`, `validator`, `time_window`):
  Phase 4 server-only intent pipeline. `IntentManifestService` validates extractor
  proposals against registry/policy and issues a sentinel-sealed manifest bound to the
  request/principal/tenant/policy version+hash with expiry and a goal digest. The mock
  extractor supports two demo scenarios (rejects send/forward/delete/upload/share,
  clarifies the rest); `LocalModelIntentExtractor` is a strict injected-client interface
  (65,536-byte bound, duplicate-key/unknown-field rejection, ≤3 attempts, timeout/outage
  mapping) with no provider wired. Exact action/resource/destination/parameter
  constraints and bounded uses are enforced by the gateway after policy `ALLOW`;
  trusted-timezone `TODAY`/`THIS_WEEK` resolve to UTC (DST-tested). No transport/routes.
- `ai_security.input_defense` (`models`, `config`, `normalize`, `heuristics`, `service`,
  `context_labels`, `sessions`) + `../config/input_defense.yaml`: **advisory** detection.
  Strict exhaustive-disposition config (every `FindingCode` mapped, no PASS mapping,
  duplicate keys refused); bounded intake (bytes → content type → UTF-8 → JSON
  structure); copy-only normalization (zero-width/control/escape/Base64/NFKC/
  mixed-script signals, iterative JSON depth); 10 versioned heuristic rules with
  quoted/educational downgrade to `QUOTED_INSTRUCTION_CONTEXT`; six trust labels and a
  deterministic JSON context assembler (external content forced `EXTERNAL_UNTRUSTED`);
  any detector/normalizer/classifier fault → explicit `DETECTOR_UNAVAILABLE` non-PASS
  finding; optional `LocalClassifier` protocol (not configured); session-id/expiry math.
  No path into policy facts, the engine, the gateway, or execution (ADR-010).
- `ai_security.api.app` (`../src/ai_security/api/app.py`): `create_app(settings)` factory
  plus module-level `app`. Startup refuses bad configuration, dev-resolver misuse,
  policy-configuration errors, self-check mismatch, registry/policy inconsistency, and
  invalid/incomplete input-defense config; builds `Database` + nonce registrar + audit
  chain + registry + intent service/tracker + gateway + input-defense service + session
  store; the gateway is constructed with the intent tracker; adds the middleware;
  `/docs`, `/redoc`, `/openapi.json` only in `development`/`test`. `app.state` exposes
  `tool_registry`, `tool_gateway`, `input_defense_config`, `input_defense_service`,
  `session_security`, `intent_usage_tracker`, `intent_manifest_service`.
- `ai_security.api.routes_health`: `GET /health/live` → 200 `{"status":"alive"}`;
  `GET /health/ready` → 200/503 with `checks: {config, database, policy_self_checks}`
  plus `policy_version`/`policy_hash`; only booleans and version metadata, never
  credentials or stack details.
- `ai_security.api.dependencies`: `get_settings`, `get_database`, `database_ready`,
  `policy_self_checks_ok` (both probes overridable in tests).
- `migrations/` + `alembic.ini`: async env reading settings; `d15b46c49950`
  (`host_request_nonces`, `audit_events`) and `c7f1a2b3d4e5` (`session_security_state`);
  `make migrate`; upgrade/downgrade/upgrade + `alembic check` verified.

Request flow today:

```text
uvicorn → FastAPI app
  ├─ /health/* → dependencies (database_ready via SQLAlchemy, policy_self_checks_ok) → JSON
  │               (+ policy_version / policy_hash from the startup-loaded bundle)
  └─ /v1/*     → HostAuthMiddleware (size bound → HMAC/timestamp → atomic nonce register
                  → replay body) → (no routes yet) → 404 after successful auth
```

Data: PostgreSQL 17 holds the three tables; nonces are registered per signed request and
gateway calls write decision/outcome events (in tests and in-process callers). The policy
engine produces decisions consumed only by the gateway; a valid intent manifest is
required by the app-built gateway and is compared with the derived action before
execution (manifest uses are tracked in memory). The input-defense service and session
store are available on `app.state` but no route or model path consumes them yet. Nothing
in a live request path uses detector findings or trust labels.

## Target v1 (blueprint §§3–4) — NOT IMPLEMENTED

Logical flow (abbreviated; full diagram in [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)):

```text
Host app → HMAC-authenticated /v1/* → intake bounds + provenance labels
  → input signals → typed intent (implemented in-process, no route) → agent runtime (optional)
  → firewall gateway: principal/session binding, tool + strict schema, hard policy,
    intent constraints, egress/data classification, deterministic risk
    → ALLOW | BLOCK | ASK_USER → controlled adapter execution
  → tool result (untrusted context) → output/egress DLP
  → structured audit events + metrics + alerts
```

Component map with planned phases:

| Component | Phase | Status | Purpose |
|---|---|---|---|
| `identity/` (HMAC host auth, resolver guard) | 0b | **VERIFIED (0b)** | Authenticate host, verify principal before anything else |
| `security/` (canonical bytes, constant-time helpers, safe YAML, URLs) | 0b/1/3 | **VERIFIED (0b/1/3)** | Signing message, `hmac.compare_digest` wrappers, canonical JSON, duplicate-key-safe YAML, destinations |
| `persistence/` (SQLAlchemy 2.x async) | 0b/3 | **VERIFIED (0b/3)** | Engine/session, nonce store, audit append, bound session signals |
| `migrations/` + `alembic.ini` | 0b/3 | **VERIFIED (0b/3)** | Schema management (ADR-006); baseline + session table |
| `config/*.yaml` | 0b/1/2/3 | **VERIFIED (1-3)** — policies, thresholds, 21 self-check fixtures, input-defense dispositions | Startup/CI self-check fixtures and strict runtime config |
| `input_defense/` | 3 | **VERIFIED (3, advisory)** — heuristics, labels, context assembly, session math; no consumers | Input signals and provenance labels |
| `intent/` | 4 | NOT IMPLEMENTED | Bounded intent manifest, constraints, request binding |
| `agent/` + providers | 4/8 | NOT IMPLEMENTED | Runtime; mock/local model adapters |
| `firewall/policy_engine.py` + `decision.py` | 1 | **VERIFIED (1)** — deterministic §10.2 evaluation, stable reason codes, no I/O (ADR-008) | Policy evaluation over validated facts |
| `firewall/` gateway + risk | 2 | **VERIFIED (2)** — single `invoke_tool` chokepoint, digest-bound authorization, audit-first, `risk-v1` (ADR-009); approvals Phase 5 | The mandatory execution chokepoint |
| `tools/` (canonical enums in `base.py`; registry + mock adapters) | 1/2 | **VERIFIED (2)** — validated registry + deterministic mock adapters; no real connectors in v1 | Mock adapters only |
| `data_security/` (`DataClass` in 1; DLP, egress in 6) | 1/6 | **PARTIAL (1)** — canonical `DataClass`; classification/DLP/egress Phase 6 | Output and egress inspection |
| `audit/` (hash chain) | 7 (scaffold 0b, emission 2) | **PARTIAL (0b/2)** — formula + append protocol + vectors + gateway emission verified; taxonomy/verifier Phase 7 | Serialized append, verifier |
| `api/` `/v1/*` routes | 8 | NOT IMPLEMENTED (middleware path enforced; services on `app.state`) | Request/tool/approval endpoints |
| `soc/` (alert-only) | 10 | NOT IMPLEMENTED | Deterministic alerts; read-only analyzer |
| `evaluation/` | 9 | NOT IMPLEMENTED | Dataset, metrics, reproducible reports |

Requested path today (implemented route surface): only `/health/live` and `/health/ready`.
`/v1/*` routes do not exist, but the path prefix is already guarded: the host-auth
middleware denies unauthenticated/forged/replayed requests before routing (verified live
in 0b), and a correctly signed request currently reaches 404 with no side effects.

## Structural rules that bind every future change

- The firewall gateway is the mandatory execution chokepoint; no component executes a
  tool directly, and the agent never calls real adapters directly (§12.1, §22.2).
- `policy_engine.py` and `risk_engine.py` are deterministic and make no network calls
  ([../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md), import boundaries).
- The input detector is advisory: findings and trust labels never become policy facts or
  authorization inputs (§7, ADR-010).
- Development order ≠ runtime order: typed schemas + policy + unbypassable mock gateway
  first; input detection before powerful tools (§21 work-order note).
- Detectors never become the policy authority; model output is never authorization.
- API routers orchestrate; they do not duplicate policy logic.
- Evaluation code is never imported into runtime request processing.
