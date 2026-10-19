# Architecture Map

Two views: what is implemented today (verified) and the target v1 architecture from the
blueprint. Full narrative and the per-request lifecycle: [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)
(mark status per component there as well). **Nothing under "Target v1" may be claimed as
existing.**

## Implemented today (Phases 0a–1 — VERIFIED 2026-10-19)

Components:

- `ai_security.settings` (`../src/ai_security/settings.py`): pydantic-settings model.
  `APP_ENV` required (`development`/`test`/`staging`/`production`); `LOG_LEVEL` default
  `INFO`; `DATABASE_URL` `SecretStr`. Fail-closed validation: unknown enum values
  rejected; scheme must be `postgresql+asyncpg://` (ADR-005); the documented sample
  development password **and the all-zero HMAC sample secret** are refused outside
  `development`/`test`; `HOST_AUTH_KEYS_JSON` required with strict per-key records
  (base64 ≥32-byte secrets, allowed tenants, duplicate IDs rejected); timestamp
  tolerance 60 s, nonce TTL 300 s (≥2×tolerance), request bound 64 KiB,
  `POLICY_SELF_CHECKS_PATH` (default `config/policy_self_checks.yaml`).
- `ai_security.security` (`constant_time.py`, `canonical_json.py`) and
  `ai_security.audit.hash_chain`: `hmac.compare_digest` wrappers (confinement enforced by
  the gate), canonical JSON bytes, ADR-002 hash formula + fixed vectors.
- `ai_security.identity` (`models`, `signing`, `host_auth`, `resolver`): `Principal`
  (strict, frozen, IANA timezone validated); HMAC signing/verification with the exact
  newline-joined `v1` message and the full rejection surface;
  `DevPrincipalResolver` (constructible only in dev/test) and `HostPrincipalResolver`
  (fails closed until Phase 1).
- `ai_security.api.middleware.HostAuthMiddleware`: pure-ASGI, keyed on the `/v1/` path
  prefix; enforces content-length/capped body → signature/timestamp/replay → replays the
  buffered body; denial codes `missing_headers`/…/`replayed_nonce`/`request_too_large`
  with 400/401/413/503; puts `VerifiedHostContext` in `scope["state"]["host_auth"]`.
- `ai_security.persistence` (`database`, `models`, `nonce_repository`,
  `audit_repository`): async engine/session (`pool_pre_ping`, 2 s connect timeout,
  never-raising `healthy()`); atomic nonce upsert (`ON CONFLICT ... WHERE expires_at <
  now() RETURNING`); ADR-002 advisory-lock audit append (canonical bytes stored,
  unique `(chain_id, sequence_number)`).
- `ai_security.policy` (`models`, `loader`, `self_checks`) + `../config/{policies,risk_thresholds,policy_self_checks}.yaml`:
  the validated policy document model (`ToolPolicy`, `PolicyBundle` with `version` +
  sha256 content hashes), the safe YAML loader (`yaml.safe_load` + duplicate-key
  detection; `PolicyConfigError` fails closed), and the ADR-007 self-check suite —
  21 strict fixtures (7 mandated names + Phase 2 rows) evaluated against the real engine at startup
  (refusal) and on every readiness probe (live drift detection). The Phase 0b interim
  transcription (`policy/interim_matrix.py`) is deleted.
- `ai_security.firewall` (`decision`, `policy_engine`): stable decision contract
  (`FirewallDecision`, `DecisionReason` codes, `DecisionRecord` with policy
  version/hash) and the deterministic engine implementing the blueprint §10.2 order
  over strict validated facts; deny-by-default; no I/O, no model calls (ADR-008).
- `ai_security.tools.base` (`SideEffectClass`, strict contracts, execution
  authorization, action digest) and `ai_security.data_security.classification`
  (`DataClass`): canonical enums defined exactly once; `tools/registry.py` and the
  deterministic mock adapters implement the Phase 2 capability layer.
- `ai_security.security.urls`: destination canonicalization (https-only, IDNA host,
  percent-encoding normalization, no userinfo/fragment/zone-ids; exact-match semantics).
- `ai_security.identity.adapters`: `TestPrincipalResolver` — constructible only under
  `APP_ENV=test`, not selectable via settings/factory; the dev-resolver guard and the
  HMAC middleware are untouched.
- `ai_security.api.app` (`../src/ai_security/api/app.py`): `create_app(settings)` factory
  plus module-level `app`. Startup refuses bad configuration, dev-resolver misuse,
  policy-configuration errors, and self-check mismatch; builds `Database` + nonce
  registrar + audit chain; adds the middleware; `/docs`, `/redoc`, `/openapi.json` only
  in `development`/`test`.
- `ai_security.api.routes_health`: `GET /health/live` → 200 `{"status":"alive"}`;
  `GET /health/ready` → 200/503 with `checks: {config, database, policy_self_checks}`
  plus `policy_version`/`policy_hash`; only booleans and version metadata, never
  credentials or stack details.
- `ai_security.api.dependencies`: `get_settings`, `get_database`, `database_ready`,
  `policy_self_checks_ok` (both probes overridable in tests).
- `migrations/` + `alembic.ini`: async env reading settings; baseline `d15b46c49950`
  (`host_request_nonces`, `audit_events`); `make migrate`.

Request flow today:

```text
uvicorn → FastAPI app
  ├─ /health/* → dependencies (database_ready via SQLAlchemy, policy_self_checks_ok) → JSON
  │               (+ policy_version / policy_hash from the startup-loaded bundle)
  └─ /v1/*     → HostAuthMiddleware (size bound → HMAC/timestamp → atomic nonce register
                  → replay body) → (no routes yet) → 404 after successful auth
```

Data: PostgreSQL 17 holds the two baseline tables; nonces are registered per signed
request; nothing writes audit events yet. The policy engine produces decisions as data
(`DecisionRecord`), but nothing consumes them yet (no execution surface).

## Target v1 (blueprint §§3–4) — NOT IMPLEMENTED

Logical flow (abbreviated; full diagram in [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)):

```text
Host app → HMAC-authenticated /v1/* → intake bounds + provenance labels
  → input signals → typed intent → agent runtime (optional)
  → firewall gateway: principal/session binding, tool + strict schema, hard policy,
    intent constraints, egress/data classification, deterministic risk
    → ALLOW | BLOCK | ASK_USER → controlled adapter execution
  → tool result (untrusted context) → output/egress DLP
  → structured audit events + metrics + alerts
```

Component map with planned phases (status: **VERIFIED in 0b** unless noted; 0a components
listed above):

| Component | Phase | Status | Purpose |
|---|---|---|---|
| `identity/` (HMAC host auth, resolver guard) | 0b | **VERIFIED (0b)** | Authenticate host, verify principal before anything else |
| `security/` (canonical bytes, constant-time helpers) | 0b/1 | **VERIFIED (0b)** | Signing message, `hmac.compare_digest` wrappers |
| `persistence/` (SQLAlchemy 2.x async) | 0b | **VERIFIED (0b)** | Engine/session, nonce store, audit append; later repositories |
| `migrations/` + `alembic.ini` | 0b | **VERIFIED (0b)** | Schema management (ADR-006); baseline only |
| `config/{policies,risk_thresholds,policy_self_checks}.yaml` | 0b/1 | **VERIFIED (1)** — validated versioned bundle + 17 self-check fixtures | Startup/CI self-check fixtures |
| `input_defense/` | 3 | NOT IMPLEMENTED | Heuristics, detector, provenance labels |
| `intent/` | 4 | NOT IMPLEMENTED | Bounded intent manifest, constraints, request binding |
| `agent/` + providers | 4/8 | NOT IMPLEMENTED | Runtime; mock/local model adapters |
| `firewall/policy_engine.py` + `decision.py` | 1 | **VERIFIED (1)** — deterministic §10.2 evaluation, stable reason codes, no I/O (ADR-008) | Policy evaluation over validated facts |
| `firewall/` gateway + risk + approvals | 2/5 | NOT IMPLEMENTED | The mandatory execution chokepoint |
| `tools/` (canonical enums in `base.py`; mock email/files/sink) | 1/2 | **PARTIAL (1)**: `SideEffectClass` + tool-id contract; registry/adapters Phase 2 | Mock adapters only; no real connectors in v1 |
| `data_security/` (`DataClass` in 1; DLP, egress in 6) | 1/6 | **PARTIAL (1)**: canonical `DataClass`; classification/DLP/egress Phase 6 | Output and egress inspection |
| `audit/` (hash chain) | 7 (scaffold 0b) | **PARTIAL (0b)**: formula + append protocol + vectors verified; emission/verifier Phase 7 | Serialized append, verifier |
| `api/` `/v1/*` routes | 8 | NOT IMPLEMENTED (middleware path enforced) | Request/tool/approval endpoints |
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
- Development order ≠ runtime order: typed schemas + policy + unbypassable mock gateway
  first; input detection before powerful tools (§21 work-order note).
- Detectors never become the policy authority; model output is never authorization.
- API routers orchestrate; they do not duplicate policy logic.
- Evaluation code is never imported into runtime request processing.
