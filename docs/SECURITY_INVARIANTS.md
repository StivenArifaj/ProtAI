# Security Invariants

The 25 mandatory invariants from blueprint v1.2 section 20.2, with honest status as of
**Phase 7**. An invariant may only be marked implemented when its tests exist and pass.

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
| 9 | Egress/DLP block -> sink is unchanged | **Implemented (Phases 2/6, mock scope):** the in-memory mock sink is unchanged on every policy denial (`external_egress_disabled`, destination mismatch/allowlist, `CONFIDENTIAL`/`RESTRICTED` egress), invalid call, deadline, audit outage, and timeout, and since Phase 6 on every deterministic output-DLP egress denial. Inspection runs on validated arguments before resource/risk/policy work; a canary, private key, API key, or blocking credential assignment yields `dlp_egress_blocked`/DENIED with zero adapter calls and an unchanged sink (unit, security, approval, and real-PostgreSQL integration tests). Content inspection is pattern-based, not a classifier, and only registered mock external-mutation tools have destinations. |
| 10 | Detector false negative -> firewall still enforces permissions | **Partial (Phases 3-4, by construction):** detection is advisory only and has no path into `PolicyEvaluationRequest`, the engine, or the gateway; intent extraction is also untrusted and can only narrow execution. The Phase 2 permission checks therefore remain in force when the detector or extractor misses content (tests assert neither service exposes an invocation surface; malformed/ambiguous extraction yields no manifest). End-to-end proof over `/v1` routes awaits Phase 8. |
| 11 | Detector/provider outage -> no automatic fail-open | **Partial (Phases 3-4):** any detector, normalization, intake, or optional-classifier fault yields an explicit `DETECTOR_UNAVAILABLE` finding with a non-PASS configured disposition (REJECT in `dev-1`); configuration cannot map any finding code to PASS. Phase 4 adds an extractor/provider boundary: timeout, outage, malformed output, and duplicate/oversized JSON produce no manifest, and the app-wired gateway denies a missing manifest (unit + security + integration tests). |
| 12 | Every adapter call has a correlated gateway decision event | **Implemented (Phases 2/7):** the gateway durably emits the full lifecycle — `REQUEST_RECEIVED`, `TOOL_CALL_PROPOSED`, `EGRESS_INSPECTED`, `POLICY_EVALUATED`, `TOOL_EXECUTION_STARTED`, `TOOL_EXECUTION_COMPLETED`/`_FAILED`, `OUTPUT_INSPECTED`, `RESPONSE_RELEASED`/`_SUPPRESSED` — correlated by `request_id` and `call_id` and queryable from derived columns (real-PostgreSQL order/linkage tests). Every mandatory pre-execution append failure denies (`audit_unavailable`) with no adapter call; a post-execution append failure withholds the result (`AUDIT_FAILED`). A parametrized unit test covers each position. |
| 13 | Audit-chain tampering is detected by the verifier | **Implemented (Phase 7):** `audit/verifier.py` reads one consistent snapshot and recomputes ADR-002 hashes from the exact stored `canonical_event_bytes`, checking sequence contiguity, previous-hash linkage, canonical JSON form, and derived metadata. Real-PostgreSQL tests cover payload/hash mutation, reordering, middle deletion, invalid/non-canonical JSON, malformed hashes, metadata tampering, chain isolation, and concurrent writers. **Honest limit:** truncation of the newest events is undetectable without an external anchor (tested/documented in ADR-014 and `docs/AUDIT_RETENTION_AND_DATA_HANDLING.md`). |
| 14 | Secrets and full private payloads do not appear in default logs or API error messages | **Partial (0a/0b/2/4/6/7):** settings rendering masks `DATABASE_URL` and key material; readiness returns only booleans and logs only the exception class; auth failures return stable detail codes, never key material or payloads; gateway audit payloads carry identifiers/digests/sizes only, failure logs name only the tool and exception class, and intent audits carry status/error codes rather than request text. Phase 7 adds a privacy suite that feeds canary, email, credential, private-key, and API-key shapes through egress, adapter-failure, response-suppression, and intent paths and asserts the raw values are absent from serialized payloads and DEBUG logs. Phase 7 DLP events remain redacted (stable codes/categories/counts, bounded field paths, digests/sizes). No `/v1/*` business payload handling exists yet; route/error-envelope coverage awaits Phase 8. |
| 15 | Tool output fed to the model is labeled untrusted | **Partial (Phase 3):** the context assembler carries structured trust labels for every segment (`SYSTEM_POLICY`, `AUTHENTICATED_USER`, `MODEL_GENERATED`, `EXTERNAL_UNTRUSTED`, `TOOL_RESULT`, `SECURITY_METADATA`), forces external email content to `EXTERNAL_UNTRUSTED` regardless of the requesting principal, refuses duplicate/empty segments, and renders labels in deterministic JSON (unit-tested). No model call path consumes the context yet (Phase 8). |
| 16 | Local/mock operation works with no internet access and no API keys | **Partial (0a/0b/2/4):** the full test suite, health endpoints, middleware, migrations, registry, gateway, all mock adapters, the mock intent extractor, and the local-model adapter interface run offline with no API keys; tools are in-memory only and no real provider is wired. Full mock-agent operation (routes/agent runtime) arrives with Phase 8. |
| 17 | Invalid HMAC signature, signed-body mutation, stale timestamp, unknown key ID, replayed nonce, or nonce-registration DB failure -> no protected processing | **Implemented (0b)** — the complete denial matrix is unit- and integration-tested: forged/mutated/stale/unknown-key → 401 with no route processing; replayed nonce → 401 `replayed_nonce` (atomic single-statement registration; concurrent duplicate can never succeed twice); nonce-store failure → 503 (reject, never fail-open); malformed target/headers → 400; oversized → 413 before signature work. |
| 18 | `DevPrincipalResolver` cannot start outside dev/test; it never bypasses HMAC; `/docs`, `/redoc`, `/openapi.json` absent outside dev/test | **Implemented (0b)** — dev resolver constructible only under `development`/`test` (settings validator, constructor guard, factory guard; a `model_construct` bypass attempt is rejected by test); host-auth middleware is path-based on `/v1/*` and identical under `PRINCIPAL_RESOLVER=dev` (integration-tested), so the dev resolver cannot bypass HMAC; documentation gating tested for all four environments; live refusal command recorded. |
| 19 | Concurrent audit appends produce one contiguous sequence; canonicalization vectors stable | **Implemented (0b/2/7):** the ADR-002 append protocol uses a transaction-scoped advisory lock plus unique `(chain_id, sequence_number)`; fixed hash/canonicalization vectors are frozen, concurrent writers produce a contiguous, verifiable chain (5-writer append test and an 8-writer verifier test), and gateway/approval/intent events append through it. The Phase 7 verifier recomputes each hash from the exact stored bytes. |
| 20 | Concurrent approval consumption allows at most one consumer; altered target/nonce/digest -> no execution | **Implemented (Phase 5):** PostgreSQL `SELECT ... FOR UPDATE` serializes consumption; one of five concurrent attempts consumes and the rest observe `replay`. Altered request/tool/action/digest/resources/destination/policy version/hash fails `verify` before the state transition. Decision/consumption and their audit events commit in one transaction (ADR-012; real-PostgreSQL tests). |
| 21 | No response bytes released before full DLP inspection; oversized/DLP-blocked outputs fully suppressed | **Implemented (Phases 6/7, gateway path):** token streaming remains disabled, so the gateway buffers the complete bounded result, inspects it, then releases, redacts, or suppresses it as a whole. `BLOCK`, `REVIEW`, and every inspection failure return `result=None` with `InvocationOutcome.response_blocked`; oversize content fails closed; a redaction that becomes schema-invalid or oversized also suppresses the whole response. `PASS` releases the original bytes; `REDACT` is span-preserving and records `dlp.released_digest` while retaining the original result digest. Phase 7 records the inspection and outcome as first-class `OUTPUT_INSPECTED`/`RESPONSE_RELEASED`/`RESPONSE_SUPPRESSED` events. No `/v1` streaming route exists, so this is verified at the single `invoke_tool` result boundary. |
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

## Phase 6 scope statement

Phase 6 makes invariants #9 and #21 actually testable and enforced at the gateway, and
extends #14 with redacted DLP evidence:

- every `ToolGateway` requires an `OutputDefenseService` built from a strict,
  versioned configuration; missing/invalid/ambiguous configuration refuses startup and
  there is no no-op default;
- egress inspection runs on validated arguments after principal/binding/intent checks
  and before resource authorization, risk, policy, approval, or execution; a non-`PASS`
  report is a pre-execution denial with `dlp_egress_blocked` or `dlp_inspection_failed`;
- detection is deterministic and content-only (canary, private-key header, `sk-` API key,
  credential assignment, email address); matches may only raise the registry data class,
  never lower it, and findings never contain matched text;
- external-mutation destinations are checked against an exact canonical trust map that
  must cover every registered external destination at startup (missing or dead entries
  refuse startup); `BLOCK`-scope patterns deny regardless of destination and `CLASSIFY`
  patterns defer to the destination's maximum class;
- response release inspects the complete buffered result and returns `PASS`, `REDACT`,
  `BLOCK`, or `REVIEW`; `BLOCK`/`REVIEW`/inspection failure suppress the entire response,
  redaction is span-preserving and idempotent, and released bytes are digest-linked;
- DLP audit evidence is an optional additive `dlp` field on existing events under schema
  v1 (no new event types yet), and approval consumption is additionally bound to the
  effective side-effect/data class so a DLP-raised class cannot reuse a stale approval.

Not claimed in Phase 6: real connectors or per-resource classification metadata; a
classifier, entropy scan, semantic-leak detection, or multilingual PII support; a review
queue/UI or release token for `REVIEW`; local-write destination mapping; inspection of
model prompts/streams or content fetched inside a future adapter; Phase 7 DLP event types
or a chain verifier; or any live `/v1` DLP route. False positives/negatives are documented
in `docs/OUTPUT_DLP_FALSE_POSITIVES.md`.

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

## Phase 7 scope statement

Phase 7 makes invariants #12, #13, and #19 implemented, completes the §16.1 taxonomy, and
extends #14/#21 with first-class audit events and a privacy suite:

- every event name in §16.1 is a stable `AuditEventType`; fields are required per event
  type instead of invented, and `APPROVAL_CONSUMED` remains stable from Phase 5;
- producers emit only events for work that occurred; `PRINCIPAL_RESOLVED`/`_REJECTED`,
  `INPUT_INSPECTED`, and `SECURITY_ALERT_RAISED` have no producer until Phase 8/10 and
  are never faked;
- the gateway lifecycle is mandatory: request receipt and proposal before validation,
  egress inspection before policy, execution-started before the adapter, execution outcome
  before output inspection/release, and a response event before returning a result. Any
  mandatory append failure fails closed (deny before execution; withhold after it);
- `EGRESS_INSPECTED`, `OUTPUT_INSPECTED`, `RESPONSE_RELEASED`, and `RESPONSE_SUPPRESSED`
  carry the redacted DLP record; unrelated events no longer duplicate it;
- `audit_events` gains derived, indexed metadata columns (`event_type`, `request_id`,
  `trace_id`, `call_id`, `occurred_at`, `component`) backfilled by
  `f7a8b9c0d1e2` from stored JSON without rewriting bytes/hashes; the verifier checks
  agreement;
- the verifier recomputes ADR-002 hashes from exact stored bytes and detects mutation,
  reordering, middle deletion, malformed/non-canonical payloads, and metadata tampering;
  truncation of the newest events is honestly documented as undetectable without an
  external anchor;
- the intent service can emit `INTENT_CREATED`/`INTENT_FAILED` with status/error codes
  only; audit failure is best-effort there and can never grant authority;
- privacy tests prove canary, email, credential, private-key, and API-key values are
  absent from serialized audit payloads and DEBUG logs on egress, adapter-failure,
  response-suppression, and intent paths.

Not claimed in Phase 7: an external chain anchor/checkpoint, automatic retention or
purging, a query/API surface over audit rows, per-event signatures, producers for the
Phase 8/10 event names, or any `/v1` business route. The verifier is read-only and does
not repair rows. Full retention/data-handling guidance is in
`docs/AUDIT_RETENTION_AND_DATA_HANDLING.md`.
