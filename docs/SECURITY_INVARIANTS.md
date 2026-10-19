# Security Invariants

The 25 mandatory invariants from blueprint v1.2 section 20.2, with honest status as of
**Phase 1**. An invariant may only be marked implemented when its tests exist and pass.

Legend: **Implemented** (tests written and passing) / **Partial** (only the listed part)
/ **Not implemented** (planned phase noted).

| # | Invariant (abbreviated) | Status |
|---|---|---|
| 1 | Unknown tool/action -> no execution | Not implemented (Phase 2) |
| 2 | Missing/invalid principal -> no protected action | **Partial (0b):** every `/v1/*` request is HMAC-authenticated before any processing (verified in the middleware denial matrix); there is no protected action surface yet, and principal resolution outside dev deliberately fails closed (`HostPrincipalResolver` raises until Phase 1). |
| 3 | Policy evaluation error -> no execution | **Partial (Phase 1):** the deterministic engine (`firewall/policy_engine.py`) has no error path that yields `ALLOW`: invalid/missing facts block, unknown tool states block, and invalid policy configuration refuses startup (`PolicyConfigError`); there is no execution surface yet, so the end-to-end guarantee arrives with the Phase 2 gateway. |
| 4 | Invalid arguments or unexpected fields -> no execution | **Partial (Phase 1):** strict contracts (`extra="forbid"`, strict types; unknown enum values rejected with no aliases/coercions) and the `arguments_valid=false` fact → `invalid_arguments` BLOCK are tested; the execution-side guarantee is Phase 2 (gateway). |
| 5 | Hard deny -> no execution regardless of risk score or model confidence | **Partial (Phase 1):** `hard_deny=true` → BLOCK takes precedence over every score (tested, incl. the mandated low-risk hard-deny fixture); model confidence never enters the engine. Execution side: Phase 2. |
| 6 | Missing approval -> no execution | Not implemented (Phase 5) |
| 7 | Changed approved arguments -> no execution | Not implemented (Phase 5) |
| 8 | Reused/expired approval -> no execution | Not implemented (Phase 5) |
| 9 | Egress/DLP block -> sink is unchanged | Not implemented (Phase 6). The Phase 1 engine already denies disallowed external destinations at decision level (`external_egress_disabled`, `destination_not_allowlisted`, `confidential_egress_blocked`, `restricted_egress_blocked`); there is no sink yet whose invariance could be proven. |
| 10 | Detector false negative -> firewall still enforces permissions | Not implemented (Phase 2-3) |
| 11 | Detector/provider outage -> no automatic fail-open | Not implemented (Phase 3-4) |
| 12 | Every adapter call has a correlated gateway decision event | Not implemented (Phase 2/7) |
| 13 | Audit-chain tampering is detected by the verifier | Not implemented (Phase 7; append protocol + fixed vectors already tested in 0b) |
| 14 | Secrets and full private payloads do not appear in default logs or API error messages | **Partial (0a/0b):** settings rendering masks `DATABASE_URL` and key material (tested); readiness returns only booleans and logs only the exception class; auth failures return stable detail codes (`missing_headers`, `replayed_nonce`, ...), never key material or payloads; no `/v1/*` payload handling exists yet. Full coverage with later phases. |
| 15 | Tool output fed to the model is labeled untrusted | Not implemented (Phase 2-3) |
| 16 | Local/mock operation works with no internet access and no API keys | **Partial (0a/0b):** the full test suite, health endpoints, middleware, and migrations run offline with no API keys. Full mock-agent operation arrives with Phases 2-8. |
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
