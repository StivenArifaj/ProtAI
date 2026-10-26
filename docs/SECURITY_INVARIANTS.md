# Security Invariants

The 25 mandatory invariants from blueprint v1.2 section 20.2, with honest status as of
**Phase 5**. An invariant may only be marked implemented when its tests exist and pass.

Legend: **Implemented** (tests written and passing) / **Partial** (only the listed part)
/ **Not implemented** (planned phase noted).

| # | Invariant (abbreviated) | Status |
|---|---|---|
| 1 | Unknown tool/action -> no execution | **Implemented (Phase 2):** the gateway resolves the exact `(tool_id, action_id)` pair against the startup-validated registry; a miss yields `unknown_tool` DENIED and no adapter is called. Registrations absent from the policy are registered-but-disabled and denied the same way. Tested in `tests/unit/test_gateway.py`, `tests/security/test_gateway_no_bypass.py`, and startup/wiring tests. |
| 2 | Missing/invalid principal -> no protected action | **Partial (0b):** every `/v1/*` request is HMAC-authenticated before any processing (verified in the middleware denial matrix); there is no protected action surface yet, and principal resolution outside dev deliberately fails closed (`HostPrincipalResolver` raises until Phase 1). |
| 3 | Policy evaluation error -> no execution | **Implemented (Phases 1-2):** the deterministic engine has no error path that yields `ALLOW` (invalid/missing facts block; invalid policy config refuses startup), and the gateway catches engine exceptions and returns `BLOCK`/`policy_evaluation_error` without calling an adapter (tested with an exploding engine). Audit prerequisite failures on a would-be `ALLOW` likewise become `BLOCK`/`audit_unavailable` before execution. |
| 4 | Invalid arguments or unexpected fields -> no execution | **Implemented (Phases 1-2):** strict argument schemas (`extra="forbid"`, `strict=True`, no aliases/coercions) plus canonicalizability checks in the gateway; missing/extra/wrong-typed fields and declared-vs-derived resource/destination mismatches yield `invalid_arguments` DENIED before adapter invocation (tested). |
| 5 | Hard deny -> no execution regardless of risk score or model confidence | **Implemented (Phases 1-2, extended 5):** `hard_deny=true` → BLOCK dominates every score (mandated low-risk fixture included); model confidence never enters the engine; the gateway executes only on an engine `ALLOW` or a valid one-time approval of an engine `ASK_USER`, and may only downgrade. A presented approval never overrides `BLOCK`/hard deny and is not consumed (Phase 5 unit/security/integration tests). |
| 6 | Missing approval -> no execution | **Implemented (Phase 5):** an engine `ASK_USER` returns DENIED with no adapter call unless the caller presents an `approval_id` that is atomically consumed as an approved, unexpired, action-bound grant. The app-built gateway always has approval storage; a missing service/malformed id/pending record fails closed (`approval_invalid`). Tested in unit, security, real-PostgreSQL integration, and app-wiring tests. |
| 7 | Changed approved arguments -> no execution | **Implemented (Phase 5):** the gateway recomputes the canonical action digest from validated arguments, derived resource ids, canonical destination, request, principal, tool/action, and the combined policy hash; the stored approval must match it plus policy version/hash. Any mutation maps to `approval_invalid` with no adapter call (unit, security, and real-PostgreSQL mismatch tests). |
| 8 | Reused/expired approval -> no execution | **Implemented (Phase 5):** consumption locks the row and moves `approved` → `consumed` exactly once; replay returns `replay` → `approval_invalid`, expiry returns `approval_expired` and transitions the row/audits it. Denied approvals can never be consumed. Concurrent consumers yield exactly one winner (real-PostgreSQL concurrency tests + gateway no-execution tests). |
| 9 | Egress/DLP block -> sink is unchanged | **Partial (Phase 2):** the in-memory mock sink is unchanged on every egress denial (`external_egress_disabled`, destination mismatch/allowlist, `CONFIDENTIAL`/`RESTRICTED` egress), invalid call, deadline, audit outage, and timeout (unit, security, and real-DB integration tests). Egress is enforced for registered mock tools only; real content-level DLP/canary inspection is Phase 6. |
| 10 | Detector false negative -> firewall still enforces permissions | **Partial (Phases 3-4, by construction):** detection is advisory only and has no path into `PolicyEvaluationRequest`, the engine, or the gateway; intent extraction is also untrusted and can only narrow execution. The Phase 2 permission checks therefore remain in force when the detector or extractor misses content (tests assert neither service exposes an invocation surface; malformed/ambiguous extraction yields no manifest). End-to-end proof over `/v1` routes awaits Phase 8. |
| 11 | Detector/provider outage -> no automatic fail-open | **Partial (Phases 3-4):** any detector, normalization, intake, or optional-classifier fault yields an explicit `DETECTOR_UNAVAILABLE` finding with a non-PASS configured disposition (REJECT in `dev-1`); configuration cannot map any finding code to PASS. Phase 4 adds an extractor/provider boundary: timeout, outage, malformed output, and duplicate/oversized JSON produce no manifest, and the app-wired gateway denies a missing manifest (unit + security + integration tests). |
| 12 | Every adapter call has a correlated gateway decision event | **Implemented (Phase 2, subset):** the gateway appends `POLICY_EVALUATED` before any protected side effect and `TOOL_EXECUTION_COMPLETED`/`TOOL_EXECUTION_FAILED` after, all correlated by `call_id`, through the ADR-002 chain (real-PostgreSQL test asserts order/linkage). The full event taxonomy and verifier remain Phase 7. |
| 13 | Audit-chain tampering is detected by the verifier | Not implemented (Phase 7; append protocol + fixed vectors already tested in 0b) |
| 14 | Secrets and full private payloads do not appear in default logs or API error messages | **Partial (0a/0b/2/4):** settings rendering masks `DATABASE_URL` and key material; readiness returns only booleans and logs only the exception class; auth failures return stable detail codes, never key material or payloads; gateway audit payloads carry identifiers/digests/sizes only (tested: message bodies and argument contents absent), and gateway failure logs name only the tool and exception class. Intent manifests store only a SHA-256 goal digest, never raw request text. No `/v1/*` payload handling exists yet; full coverage with later phases. |
| 15 | Tool output fed to the model is labeled untrusted | **Partial (Phase 3):** the context assembler carries structured trust labels for every segment (`SYSTEM_POLICY`, `AUTHENTICATED_USER`, `MODEL_GENERATED`, `EXTERNAL_UNTRUSTED`, `TOOL_RESULT`, `SECURITY_METADATA`), forces external email content to `EXTERNAL_UNTRUSTED` regardless of the requesting principal, refuses duplicate/empty segments, and renders labels in deterministic JSON (unit-tested). No model call path consumes the context yet (Phase 8). |
| 16 | Local/mock operation works with no internet access and no API keys | **Partial (0a/0b/2/4):** the full test suite, health endpoints, middleware, migrations, registry, gateway, all mock adapters, the mock intent extractor, and the local-model adapter interface run offline with no API keys; tools are in-memory only and no real provider is wired. Full mock-agent operation (routes/agent runtime) arrives with Phase 8. |
| 17 | Invalid HMAC signature, signed-body mutation, stale timestamp, unknown key ID, replayed nonce, or nonce-registration DB failure -> no protected processing | **Implemented (0b)** — the complete denial matrix is unit- and integration-tested: forged/mutated/stale/unknown-key → 401 with no route processing; replayed nonce → 401 `replayed_nonce` (atomic single-statement registration; concurrent duplicate can never succeed twice); nonce-store failure → 503 (reject, never fail-open); malformed target/headers → 400; oversized → 413 before signature work. |
| 18 | `DevPrincipalResolver` cannot start outside dev/test; it never bypasses HMAC; `/docs`, `/redoc`, `/openapi.json` absent outside dev/test | **Implemented (0b)** — dev resolver constructible only under `development`/`test` (settings validator, constructor guard, factory guard; a `model_construct` bypass attempt is rejected by test); host-auth middleware is path-based on `/v1/*` and identical under `PRINCIPAL_RESOLVER=dev` (integration-tested), so the dev resolver cannot bypass HMAC; documentation gating tested for all four environments; live refusal command recorded. |
| 19 | Concurrent audit appends produce one contiguous sequence; canonicalization vectors stable | **Partial (0b):** the ADR-002 append protocol is implemented (transaction-scoped advisory lock + unique `(chain_id, sequence_number)`) with fixed hash vectors and a 5-writer concurrency test asserting a contiguous sequence; the verifier and event emission are Phase 7. |
| 20 | Concurrent approval consumption allows at most one consumer; altered target/nonce/digest -> no execution | **Implemented (Phase 5):** PostgreSQL `SELECT ... FOR UPDATE` serializes consumption; one of five concurrent attempts consumes and the rest observe `replay`. Altered request/tool/action/digest/resources/destination/policy version/hash fails `verify` before the state transition. Decision/consumption and their audit events commit in one transaction (ADR-012; real-PostgreSQL tests). |
| 21 | No response bytes released before full DLP inspection; oversized/DLP-blocked outputs fully suppressed | Not implemented (Phase 6) |
| 22 | AI SOC analysis cannot call tools, change policies, edit logs, or trigger containment | Not implemented (Phase 10; decision recorded in ADR-004) |
| 23 | Session security state bound to verified tenant/subject; guessed/borrowed/rotated/cross-user references cannot read, extend, or create another session's signals | **Implemented (Phase 3, storage layer):** every repository operation requires `(tenant_id, subject_id)`; mismatch behaves as not-found on read/write/rotate; guessed IDs create nothing; rotation returns a fresh ID with zero inherited signals; inactivity (24 h) and absolute (7 d) expiry are enforced with lazy deletion and no write extends an expired row (real-PostgreSQL tests). No route exposes the repository yet, so route-level binding is re-verified in Phase 8. |
| 24 | Only a verified principal satisfying `required_approver_rule` can approve; self-approval requires explicit policy; unsatisfiable rule -> `BLOCK` | **Implemented (Phase 5):** rules use a strict `role:<role>` / `principal:<subject>` grammar parsed at registry startup; decisions evaluate the stored rule only against the verified `Principal` and require equal tenant. Self-approval is denied unless the policy entry sets `self_approval_allowed` (valid only with `approval_eligible`). A requester-only principal rule with self-approval disabled is refused before storage (`ApprovalNotApprovable`). Unit/integration tests cover role, principal, tenant, malformed, self-approval, and unsatisfiable cases. |
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

## Phase 5 scope statement

Phase 5 adds `risk-v2` and the durable approval workflow without creating a new policy
authority:

- every `risk-v1` weight is preserved; one bounded resource-breadth factor adds
  5/10/15 for 2-4/5-8/9+ resources, with stable codes/rationale; counts are validated
  and scores capped at 100; a caller cannot supply a score;
- approval tokens are 256-bit CSPRNG values returned once and stored only as SHA-256
  digests; decisions/consumption use PostgreSQL row locks and commit their audit events
  in the same transaction; concurrent consumption has exactly one winner;
- only a verified principal satisfying the startup-validated rule (and tenant) may
  decide; self-approval requires explicit policy; unsatisfiable requester-only rules are
  refused; pending/denied/expired/replayed/mutated approvals never execute;
- the gateway consults approval only for engine `ASK_USER`; `ALLOW` needs none and
  `BLOCK`/hard denials ignore it. The engine decision remains `ASK_USER`; approval never
  becomes an `ALLOW` producer.
- approval rows store no raw arguments/content/token; audit events carry only ids,
  decisions, policy/risk provenance, resources, and the approver subject.

Not claimed in Phase 5: `/v1/approvals` routes/UI/token-delivery transport, automatic
request creation, a real approver directory or notifications, an explicit revocation
operation, a background expiry sweeper, or risk calibration. The app exposes
`ApprovalService` in-process for the Phase 8 host workflow.

## Phase 4 scope statement

Phase 4 adds server-issued intent manifests and concrete action validation (blueprint
§§8, 11.1) without granting the extractor any authority:

- only the server-side issuer can create a sealed `IntentManifest`; direct construction
  raises, and verification checks request, principal, tenant, policy version/hash,
  creation, and expiry;
- extractor output is strict, bounded, duplicate-key-rejecting JSON; malformed output is
  retried at most a small configured number of times; provider outage/timeout yields no
  manifest;
- the mock extractor supports only two clearly documented demo requests; ambiguity yields
  clarification and no manifest; relative dates require a trusted principal timezone and
  resolve to exact UTC instants (DST-tested);
- manifests contain concrete tool/action, resource, canonical destination, parameter, and
  use limits; wildcards/prefix scopes are refused; a manifest can only narrow policy;
- the app-built gateway requires a valid manifest before registry/policy work and compares
  the derived action to the manifest before execution; exhaustion, mismatch, expiry, and
  rebinding all deny without an adapter call;
- policy remains the sole `ALLOW` producer; intent never enters `PolicyEvaluationRequest`.

Not claimed in Phase 4: a `/v1` route or signed manifest transport, general-purpose NLU,
a real local/cloud model provider, cross-process use counters, or a sandbox. The app uses
the mock extractor until Phase 8.

## Phase 3 scope statement

Phase 3 adds advisory input-threat detection and provenance (blueprint sections 7.2-7.4)
without granting the detector any authority:

- strict, versioned detection config (`config/input_defense.yaml`) rejects duplicate
  keys, unknown/missing finding codes, invalid content types, and any mapping to PASS;
  invalid config refuses startup;
- intake enforces byte size, content-type allowlist, and UTF-8 decoding before
  detection; oversize/unsupported/invalid-encoding inputs are explicit REJECT findings;
- normalization works on a copy only and reports zero-width/control/escape/base64/
  homoglyph signals; deterministic heuristics report typed findings with offsets but
  never carry raw content in reports or logs;
- quoted/educational/defensive mentions are downgraded to `QUOTED_INSTRUCTION_CONTEXT`
  (FLAG), not treated as proof of an attack;
- every detector/normalizer/classifier fault yields `DETECTOR_UNAVAILABLE` with a
  non-PASS disposition — detection failure is never clean;
- context assembly preserves structured trust labels, labels external email as
  `EXTERNAL_UNTRUSTED` even for authenticated requesters, and rejects duplicate or
  empty segment sets;
- session security state is stored bound to `(tenant_id, subject_id)` with 24 h
  inactivity and 7 d absolute expiry, bounded counters, and signal-free rotation.

Not claimed in Phase 3: complete prompt-injection detection, general semantic intent
understanding or a real model/provider integration (Phase 8), content DLP (Phase 6),
`/v1` routes and rate limits (Phase 8), or any detector influence on authorization
(deliberately absent).
