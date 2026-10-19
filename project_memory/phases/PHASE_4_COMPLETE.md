# Phase 4 — Intent Extraction and Action Validation: COMPLETE — VERIFIED

**Completed:** 2026-10-19
**Blueprint:** v1.2 §§8-9, 11.1, 12.3, 20.2 #3/#5, §21 Phase 4
**ADR:** [../../docs/adr/ADR-011-server-issued-intent-manifests.md](../../docs/adr/ADR-011-server-issued-intent-manifests.md)
**Evidence:** V51-V56 in [../TESTING_AND_VERIFICATION.md](../TESTING_AND_VERIFICATION.md)
**Commits:** `2943593` (implementation/tests/gateway), `74c502f` (ADR-011/docs),
`786cb08` (memory/completion); final V56 status record commit follows.

## Definition of Done — verdict

| Criterion | Status | Evidence |
|---|---|---|
| Malformed model output / outage grant no permission | PASS | `test_intent_extractors.py` (malformed, duplicate key, oversized, unknown fields, retry, outage, timeout, unsafe destination); service tests; no manifest on every failure |
| Ambiguous intent grants no permission | PASS | Service clarification tests; `test_intent_wiring.py` (clarification → no manifest, no execution); mock greeting smoke |
| Tool arguments/action compared with concrete intent limits | PASS | `test_intent_validation.py`; gateway exact action/resource/destination/parameter tests; `test_intent_no_grant.py` |
| Execution still occurs only through the gateway | PASS | Gateway remains the single adapter path; legacy and new no-bypass suites green |
| Mutation/replay/expiry/rebinding cannot execute | PASS | Sealed manifest + verifier; 6 no-grant security tests; wrong-request/wrong-principal/wrong-tenant/wrong-policy tests |
| Full quality gate | PASS | V54: 661 tests, 8/8 gate steps, mypy 60 files, Gitleaks clean |
| ADR-008/009/010 contracts untouched | PASS | Policy remains sole `ALLOW`; detector and intent have no policy-fact path; existing suites green |

## Delivered

### Intent package (`src/ai_security/intent/`)

- `models.py` — `IntentStatus` (`ACTIVE`/`REQUIRES_CLARIFICATION`/`REJECTED`),
  strict frozen `IntentExtraction`/`IntentConstraint`/`IntentManifest`/
  `ResolvedTimeWindow`, private sentinel issuance, `IntentManifestError` codes,
  `verify_intent_manifest`, `boot_id` generation.
- `time_window.py` — `TODAY`/`THIS_WEEK` resolution from the verified principal's IANA
  timezone to UTC, DST-safe (`zoneinfo`).
- `extractors.py` — `IntentExtractor` protocol, `MockIntentExtractor`
  (`mock-intent-v1`, two demo scenarios, rejects send/forward/delete/upload/share,
  clarifies everything else), `LocalModelIntentExtractor`
  (`local-model-intent-v1`, injected `IntentModelClient`, 65,536-byte bound,
  duplicate-key/unknown-field rejection, retry default 2/max 3, 5 s timeout,
  `IntentExtractorUnavailable`).
- `service.py` — `IntentManifestService.extract_and_issue`; validates all constraints
  against registry and policy before issuance; missing timezone clarifies; invalid
  output/outage/ambiguity yields no manifest; TTL 1-3,600 s (default 300).
- `validator.py` — `validate_intent_constraints` and `IntentUsageTracker`
  (per-process, 10,000 manifests, expiry purge, fail-closed capacity/limit).

### Gateway and app changes

- `firewall/decision.py`: `intent_manifest_invalid`, `intent_requires_clarification`,
  `intent_action_not_allowed`, `intent_constraint_violation`, `intent_limit_exceeded`.
- `firewall/models.py`: `ToolExecutor.invoke_tool(..., manifest=None)` protocol extension;
  `ExecutionAuthorization` sentinel/digest checks unchanged.
- `firewall/gateway.py`: optional `intent_tracker`; app path requires a manifest;
  verifies binding before registry/policy; compares exact action/resource/destination/
  parameter after validation; reserves `max_uses` after policy `ALLOW` and before audit;
  every failure maps to a deny with no adapter call.
- `api/app.py`: `app.state.intent_usage_tracker`, `app.state.intent_manifest_service`;
  gateway constructed with `intent_tracker=app.state.intent_usage_tracker`; uses
  `MockIntentExtractor` with the shared policy bundle TTL.
- `settings.py` / `.env.example`: `intent_manifest_ttl_seconds` (default 300, 1-3,600);
  `INTENT_MANIFEST_TTL_SECONDS=300`.

### Tests

- `tests/unit/test_intent_models.py` — sealing/forgery, strict fields, binding mismatch,
  expiry/not-yet-valid, status/payload consistency, resolution invariants.
- `tests/unit/test_intent_extractors.py` — mock scenarios, strict provider JSON,
  malformed/oversize/duplicate-key/unknown fields, retry, outage, timeout, unsafe target.
- `tests/unit/test_intent_validation.py` — exact matching, tracker limits/expiry/
  capacity/purge, DST TODAY (23 h), THIS_WEEK Monday start, invalid/naive timezone.
- `tests/unit/test_intent_service.py` — bindings/digest/TTL, relative dates, missing
  timezone, ambiguity/rejection, 7 unenforceable-constraint cases, outage/malformed,
  invalid/empty/oversized/future requests, TTL bounds.
- `tests/security/test_intent_no_grant.py` — forged/missing/expired/wrong-principal/
  wrong-request manifests, other action/resource/parameter, unlisted destination, use
  limit, legacy no-tracker fail-closed.
- `tests/integration/test_intent_wiring.py` — app state, tracker identity, TTL, allow +
  limit exceeded, clarification, wrong-request manifest denial against real PostgreSQL.
- `tests/unit/test_settings.py` — TTL default and bounds.

Totals: **661 passed** (568 unit + 64 integration + 29 security).

## Decisions and limitations (honest)

- The app uses the mock extractor only; no real model/provider is wired and general NLU
  accuracy is unmeasured (Phase 8/9).
- The manifest is an in-process sentinel-sealed object, not a signed transport token; no
  route issues/accepts one. A future API must stay in-process or add signing.
- `IntentUsageTracker` is per process/in memory; multi-worker deployments need shared
  state. Reservations are conservatively consumed if a later audit write fails.
- `intent_requires_clarification` is defined but the gateway reports missing manifests as
  `intent_manifest_invalid`; clarification is resolved before gateway invocation.
- `received_at` is caller-supplied; the Phase 8 route must pass server time.
- Mock “summarize” has `max_uses=1`; multi-email orchestration is future work.
- Legacy `ToolGateway(intent_tracker=None)` remains constructible for in-process tests;
  production app wiring always supplies a tracker.
- Intent constraints are exact-match only (no wildcards/prefixes/ranges/floats).

## Verification (V51-V56)

- V51 targeted intent unit + security: **56 passed**.
- V52 app wiring + settings: **63 passed**.
- V53 static: mypy clean 60 source files; ruff clean; 151 files formatted.
- V54 full suite + `bash scripts/check.sh`: **661 passed**; exit 0; 8/8 steps; Gitleaks
  8.30.1 clean at 23 commits.
- V55 manual service smoke: ACTIVE/ACTIVE/REJECTED/REQUIRES_CLARIFICATION as expected.
- V56 post-commit gate: PASS — exit 0, all 8 steps; 661 tests; 151 files formatted;
  mypy 60 source files; Gitleaks 8.30.1 dir+git clean across 26 commits.

## Next

Phase 5 — risk engine and approval workflow (blueprint §21): see
[../NEXT_SESSION.md](../NEXT_SESSION.md).
