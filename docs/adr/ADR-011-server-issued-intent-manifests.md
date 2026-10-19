# ADR-011: Server-issued, sealed intent manifests and concrete action constraints

- **Status:** Accepted
- **Date:** 2026-10-19
- **Phase:** 4 (intent extraction and action validation)
- **Blueprint:** §§8, 11.1, 12.3, 20.2 #3/#5; Phase 4 in §21

## Context

The agent runtime needs a structured description of the user's goal so the gateway can
reject an action that policy would technically allow but the request did not ask for.
Intent extraction is model-assisted and therefore untrusted: malformed output, an
ambiguous request, or a provider outage must never create authority. The manifest also
must not become a second permission system; the deterministic policy engine remains the
sole producer of `ALLOW`.

A client or model must not be able to submit a manifest as if the server issued it, and
a manifest issued for one request/principal/policy must not be replayable in another
context.

## Decision

### 1. Extraction proposes; the server issues

- `IntentExtractor` is an async protocol implemented by `MockIntentExtractor` (clearly
  marked test/demo implementation) and `LocalModelIntentExtractor` (strict adapter over
  an injected local-model client; the provider wiring is Phase 8).
- Extractors return a validated `IntentExtraction` or raise a typed extractor error.
  They never create manifests and never receive policy authority.
- `IntentManifestService.extract_and_issue` is the only manifest issuer. It validates
  every proposed constraint against the startup-loaded registry and policy bundle before
  issuing anything.

### 2. Strict, bounded extractor output

`LocalModelIntentExtractor`:

- bounds model output to 65,536 UTF-8 bytes before parsing;
- rejects duplicate JSON keys and non-object documents;
- forbids unknown fields (including provider-supplied extractor version or bindings);
- retries malformed/invalid output at most `max_attempts` (default 2, hard cap 3);
- maps timeout/provider exceptions to `IntentExtractorUnavailable`;
- emits the extractor version from code, never from model output.

Any extraction failure, malformed output, provider outage, or missing trusted timezone
yields no manifest. It cannot yield an `ALLOW`.

### 3. Concrete, enforceable constraints only

`IntentConstraint` supports exact tool/action ids, exact resource ids, exact canonical
destinations, exact allowed scalar parameter values, and `max_uses`. Wildcards, prefix
scopes, float values, duplicate values, unknown parameters, resource/destination
constraints on actions that have no such arguments, and destinations outside the
adapter's declared capability are rejected before issuance. Limits: 16 constraints,
32 total uses, 32 resources and 8 destinations per constraint, 8 values per parameter,
32,768-byte extraction text.

A manifest can only narrow what the policy engine later permits. It is never passed
into `PolicyEvaluationRequest` and cannot turn a policy `BLOCK` into an `ALLOW`.

### 4. Binding, sealing, and expiry

`IntentManifest` is a frozen dataclass sealed with a module-private sentinel. Direct
construction raises `IntentManifestError(forged_or_unsealed)`; only the private issuer
used by `IntentManifestService` can create one. The manifest carries:

- a random server `manifest_id`;
- `request_id`, principal subject id, and tenant id;
- policy version and combined policy hash;
- extractor version and creation/expiry timestamps (default 300 s, max 3,600 s);
- a SHA-256 digest of the goal text (raw text is never stored);
- the concrete constraints and an optional server-resolved UTC time window.

`verify_intent_manifest` re-checks the seal, clock validity, request, principal, tenant,
policy version, and policy hash. The gateway treats every verification failure as
`intent_manifest_invalid` with no execution.

### 5. Relative dates use a trusted timezone only

`TODAY` and `THIS_WEEK` are resolved once on the server from the verified principal's
IANA timezone (a host-signed assertion), never from prompt text, model output, IP, or
browser headers. Missing timezone → clarification with no manifest; invalid timezone →
typed failure. Windows are stored as exact UTC start/end instants and tests cover
daylight-saving transitions (23-hour and 25-hour days).

### 6. Gateway enforcement

- The app-built gateway always receives an `IntentUsageTracker`, so a missing or invalid
  manifest is denied before registry resolution or policy evaluation.
- A supplied manifest is verified against the gateway's server-side policy bundle and the
  verified principal/request.
- After arguments/resources/destination are derived and validated, the gateway compares
  them with the manifest: exact action, exact resource set, exact canonical destination,
  and exact parameter values. Failures map to `intent_action_not_allowed` /
  `intent_constraint_violation`.
- `max_uses` is reserved only after policy would `ALLOW`, and before the decision audit
  write. Exhaustion maps to `intent_limit_exceeded`; a later audit/execution failure
  conservatively keeps the reservation.
- The tracker is in-memory and per process; expiry purging and capacity (10,000
  manifests) fail closed.

Phase 2 in-process tests may construct a gateway without the optional tracker. That is a
documented legacy/test mode; production app wiring does not expose it.

## Consequences

- Policy remains the sole `ALLOW` producer; intent can only deny or narrow.
- Malformed output, ambiguity, outages, and forged/expired/rebound manifests cannot
  execute anything.
- The demo app uses the mock extractor and supports only two documented demo requests;
  arbitrary natural-language goals receive clarification. This is honest and prevents
  the mock from pretending to be general understanding.
- The manifest is an in-process sealed object, not a signed transport token. A future
  `/v1` route must either keep issuance and validation in the same process or add a
  server-signed serialization before accepting client-carried manifests. No route
  accepts a manifest today.
- Use limits are per-process; multi-worker deployments need a shared store (later
  operational phase).
- This is an integrity guardrail, not a sandbox against malicious in-process code
  (Phase 10), consistent with ADR-009.

## Verification

- `tests/unit/test_intent_models.py`
- `tests/unit/test_intent_extractors.py`
- `tests/unit/test_intent_validation.py`
- `tests/unit/test_intent_service.py`
- `tests/security/test_intent_no_grant.py`
- `tests/integration/test_intent_wiring.py`
- Fresh full suite and gate evidence in
  `project_memory/TESTING_AND_VERIFICATION.md` (V51+).

## References

- Blueprint v1.2 §§8, 11.1, 12.3, 20.2, 21 (Phase 4).
- ADR-008 (deterministic policy engine), ADR-009 (registry/gateway), ADR-010 (advisory
  detection boundary).
- `src/ai_security/intent/`, `src/ai_security/firewall/gateway.py`.
