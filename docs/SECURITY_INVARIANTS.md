# Security Invariants

The 25 mandatory invariants from blueprint v1.2 section 20.2, with honest status as of
**Phase 2**. An invariant may only be marked implemented when its tests exist and pass.

Legend: **Implemented** (tests written and passing) / **Partial** (only the listed part)
/ **Not implemented** (planned phase noted).

| # | Invariant (abbreviated) | Status |
|---|---|---|
| 1 | Unknown tool/action -> no execution | **Implemented (Phase 2):** the gateway resolves the exact `(tool_id, action_id)` pair against the startup-validated registry; a miss yields `unknown_tool` DENIED and no adapter is called. Registrations absent from the policy are registered-but-disabled and denied the same way. Tested in `tests/unit/test_gateway.py`, `tests/security/test_gateway_no_bypass.py`, and startup/wiring tests. |
| 2 | Missing/invalid principal -> no protected action | **Partial (0b):** every `/v1/*` request is HMAC-authenticated before any processing (verified in the middleware denial matrix); there is no protected action surface yet, and principal resolution outside dev deliberately fails closed (`HostPrincipalResolver` raises until Phase 1). |
| 3 | Policy evaluation error -> no execution | **Implemented (Phases 1-2):** the deterministic engine has no error path that yields `ALLOW` (invalid/missing facts block; invalid policy config refuses startup), and the gateway catches engine exceptions and returns `BLOCK`/`policy_evaluation_error` without calling an adapter (tested with an exploding engine). Audit prerequisite failures on a would-be `ALLOW` likewise become `BLOCK`/`audit_unavailable` before execution. |
| 4 | Invalid arguments or unexpected fields -> no execution | **Implemented (Phases 1-2):** strict argument schemas (`extra="forbid"`, `strict=True`, no aliases/coercions) plus canonicalizability checks in the gateway; missing/extra/wrong-typed fields and declared-vs-derived resource/destination mismatches yield `invalid_arguments` DENIED before adapter invocation (tested). |
| 5 | Hard deny -> no execution regardless of risk score or model confidence | **Implemented (Phases 1-2):** `hard_deny=true` → BLOCK dominates every score (mandated low-risk fixture included); model confidence never enters the engine; the gateway executes only on an engine `ALLOW` and may only downgrade it (tested). |
| 6 | Missing approval -> no execution | Not implemented (Phase 5) |
| 7 | Changed approved arguments -> no execution | Not implemented (Phase 5) |
| 8 | Reused/expired approval -> no execution | Not implemented (Phase 5) |
| 9 | Egress/DLP block -> sink is unchanged | **Partial (Phase 2):** the in-memory mock sink is unchanged on every egress denial (`external_egress_disabled`, destination mismatch/allowlist, `CONFIDENTIAL`/`RESTRICTED` egress), invalid call, deadline, audit outage, and timeout (unit, security, and real-DB integration tests). Egress is enforced for registered mock tools only; real content-level DLP/canary inspection is Phase 6. |
| 10 | Detector false negative -> firewall still enforces permissions | Not implemented (Phase 2-3) |
| 11 | Detector/provider outage -> no automatic fail-open | Not implemented (Phase 3-4) |
| 12 | Every adapter call has a correlated gateway decision event | **Implemented (Phase 2, subset):** the gateway appends `POLICY_EVALUATED` before any protected side effect and `TOOL_EXECUTION_COMPLETED`/`TOOL_EXECUTION_FAILED` after, all correlated by `call_id`, through the ADR-002 chain (real-PostgreSQL test asserts order/linkage). The full event taxonomy and verifier remain Phase 7. |
| 13 | Audit-chain tampering is detected by the verifier | Not implemented (Phase 7; append protocol + fixed vectors already tested in 0b) |
| 14 | Secrets and full private payloads do not appear in default logs or API error messages | **Partial (0a/0b/2):** settings rendering masks `DATABASE_URL` and key material; readiness returns only booleans and logs only the exception class; auth failures return stable detail codes, never key material or payloads; gateway audit payloads carry identifiers/digests/sizes only (tested: message bodies and argument contents absent), and gateway failure logs name only the tool and exception class. No `/v1/*` payload handling exists yet; full coverage with later phases. |
| 15 | Tool output fed to the model is labeled untrusted | Not implemented (Phase 2-3) |
| 16 | Local/mock operation works with no internet access and no API keys | **Partial (0a/0b/2):** the full test suite, health endpoints, middleware, migrations, registry, gateway, and all mock adapters run offline with no API keys; mock tools are in-memory only. Full mock-agent operation (routes/agent runtime) arrives with Phases 3-8. |
| 17 | Invalid HMAC signature, signed-body mutation, stale timestamp, unknown key ID, replayed nonce, or nonce-registration DB failure -> no protected processing | **Implemented (0b)** — the complete denial matrix is unit- and integration-tested: forged/mutated/stale/unknown-key → 401 with no route processing; replayed nonce → 401 `replayed_nonce` (atomic single-statement registration; concurrent duplicate can never succeed twice); nonce-store failure → 503 (reject, never fail-open); malformed target/headers → 400; oversized → 413 before signature work. |
| 18 | `DevPrincipalResolver` cannot start outside dev/test; it never bypasses HMAC; `/docs`, `/redoc`, `/openapi.json` absent outside dev/test | **Implemented (0b)** — dev resolver constructible only under `development`/`test` (settings validator, constructor guard, factory guard; a `model_construct` bypass attempt is rejected by test); host-auth middleware is path-based on `/v1/*` and identical under `PRINCIPAL_RESOLVER=dev` (integration-tested), so the dev resolver cannot bypass HMAC; documentation gating tested for all four environments; live refusal command recorded. |
| 19 | Concurrent audit appends produce one contiguous sequence; canonicalization vectors stable | **Partial (0b):** the ADR-002 append protocol is implemented (transaction-scoped advisory lock + unique `(chain_id, sequence_number)`) with fixed hash vectors and a 5-writer concurrency test asserting a contiguous sequence; the verifier and event emission are Phase 7. |
| 20 | Concurrent approval consumption allows at most one consumer; altered target/nonce/digest -> no execution | Not implemented (Phase 5) |
| 21 | No response bytes released before full DLP inspection; oversized/DLP-blocked outputs fully suppressed | Not implemented (Phase 6) |
| 22 | AI SOC analysis cannot call tools, change policies, edit logs, or trigger containment | Not implemented (Phase 10; decision recorded in ADR-004) |
| 23 | Session security state bound to verified tenant/subject; guessed/borrowed/rotated/cross-user references cannot read, extend, or create another session's signals | Not implemented (Phase 3/5) |
| 24 | Only a verified principal satisfying `required_approver_rule` can approve; self-approval requires explicit policy; unsatisfiable rule -> `BLOCK` | Not implemented (Phase 5) |
| 25 | Unknown/missing/invalid `SideEffectClass` or `DataClass` fail closed; no aliases or coercions | **Implemented (Phase 1):** canonical enums are defined exactly once (`tools/base.py`, `data_security/classification.py`); strict models reject unknown/missing values and extra fields (`extra="forbid"`) with no aliases or coercions; `risk_score` is a strict integer 0-100 (string/bool coercion rejected); the engine denies on any unknown/invalid state with stable reason codes; all covered by unit tests (model, engine, url canonicalization). |

## Phase 0a scope statement

Phase 0a contributes only these testable properties:

- configuration errors fail startup with clear messages (unknown `APP_ENV`, missing
  required values, non-`postgresql+asyncpg` scheme, sample password outside dev/test);
- health endpoints reveal only status booleans and never credentials or stack traces;
- `/docs`, `/redoc`, and `/openapi.json` are absent outside `development`/`test`.

## Phase 0b scope statement

Phase 0b makes invariants #17 and #18 (as split across #2 and #14/#19 partially) actually
testable and enforced:

- every `/v1/*` request requires a valid HMAC-SHA256 signature within the timestamp
  window with an unseen nonce, enforced before routing and identically in every
  environment (no bypass mode); signature comparison is constant-time;
- replay rejection is atomic (single-statement upsert) and fails closed on store errors;
- request bodies are capped before buffering (413);
- the development resolver cannot start outside dev/test and cannot bypass HMAC;
- audit appends follow the ADR-002 lock protocol with fixed canonical byte vectors and a
  concurrency test (verifier still Phase 7);
- startup refuses any configuration or policy self-check mismatch (ADR-007).

Everything not listed above remains future work; the repository must not claim it.

## Phase 1 scope statement

Phase 1 makes invariant #25 implemented and advances #3/#4/#5 to engine-level
partial status:

- the deterministic policy engine evaluates the blueprint section 10.2 order with
  stable reason codes and provenance (`policy_version`/`policy_hash`); invalid,
  unknown, or missing state never yields `ALLOW`;
- strict typed contracts fail closed on unknown/invalid values with no aliases or
  coercions (canonical enums defined exactly once);
- policy documents load safely (no `yaml.load`; duplicate keys rejected) and invalid
  policy refuses startup; readiness detects live policy/fixture drift;
- the ADR-007 self-check fixtures (7 mandated names retained, 17 total) pass against
  the real engine at startup and on readiness;
- destination canonicalization (IDNA, percent-encoding, https-only, no userinfo/
  fragment) supports exact-match allowlisting; no wildcards in v1.

Everything beyond these statements (execution guarantees, gateway no-bypass, risk
scoring engine, DLP/egress enforcement at a sink) remains future work.
