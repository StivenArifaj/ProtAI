# Next Session Handoff

**Last updated: 2026-10-19.** Read [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) first if you have not.

## Where we are

Phases 0a (repository foundation), 0b (security foundation), 1 (typed contracts and
deterministic policy engine), 2 (tool registry and enforced gateway), and 3 (advisory
input defense and context provenance) are **COMPLETE — VERIFIED** — see
[phases/PHASE_3_COMPLETE.md](phases/PHASE_3_COMPLETE.md) and evidence V43+ in
[TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md). The repository is under git
with a linear history; the Compose `db` container and volume are preserved for tests
(`api` stopped).

What exists now: host HMAC authentication + replay rejection on the `/v1/*` path prefix
(routes do not exist yet), async persistence + migrations, dev-resolver guard + test-only
principal adapter, strict typed contracts, canonical destination handling, the safe
versioned policy loader, the deterministic §10.2 policy engine with provenance and 21
self-check fixtures wired into startup/readiness, the typed tool registry + four mock
adapters, the digest-bound execution authorization, `risk-v1`, the single `invoke_tool`
gateway with audit-first ordering/bounds, and — new in Phase 3 — strict versioned
input-defense config, bounded intake, copy-only normalization, 10 versioned heuristics
with quoted-context downgrade, typed `IntakeReport` findings with non-PASS failure
semantics, structured trust labels/context assembly, and a tenant/subject-bound session
signal store with TTL/max-age expiry and signal-free rotation. 600 tests pass; the gate
is green (8/8). **Detection is advisory:** it has no path into policy facts, the engine,
the gateway, or execution, and no route/model consumes it yet.

## The next task: Phase 4 — Intent extraction and action validation (blueprint §21)

No blocking preconditions; Phase 3 passed its DoD, so proceed per the autonomy mandate.
Read first: blueprint §§8-9 (intent extraction, manifests, constraint validation) and
§21 (Phase 4); then ADR-008 (facts the engine consumes), ADR-009 (the gateway), and
ADR-010 (the advisory-detection boundary). Formalize `phases/PHASE_4_PLAN.md` when
starting.

Expected deliverables (condensed from blueprint §21):

1. A mock/deterministic intent extractor plus a local-model adapter interface that is
   not required for tests and never grants authority.
2. A bounded, strict `IntentManifest` (proposed action, targets, constraints) with
   request binding and expiry.
3. A constraint validator that compares validated arguments/targets to the intent and
   produces typed facts for the engine; ambiguity fails closed.
4. Explicit behavior for malformed model output, model outage, and ambiguous intent: no
   permission is granted and no execution occurs outside the gateway.
5. Tests: intent/argument mismatch, manifest mutation/expiry, malformed/out-of-contract
   model output, ambiguity, and no-bypass; keep every existing suite green.

## Verification commands and expected results

| Command | Expected |
|---|---|
| `uv run --frozen pytest -q` | All tests pass (≥600; new intent suites added) |
| `bash scripts/check.sh` | exit 0, all 8 steps (Gitleaks must stay clean) |
| Policy self-checks | startup and `/health/ready` still pass (21 fixtures) |
| No-bypass suites | `tests/security` + gateway integration still green (gateway contract untouched) |
| Input-defense suites | still green; detector remains advisory (no policy/gateway imports) |

## Security constraints that must hold throughout Phase 4

- Invariants #17/#18/#25 stay green; keep `compare_digest` confined to
  `security/constant_time.py`; do not weaken the HMAC denial matrix.
- Model output is untrusted data, never authority: malformed/unavailable/ambiguous
  extraction must not produce `ALLOW`; the deterministic engine and gateway remain the
  only enforcement path (ADR-008/ADR-009).
- Detector findings and trust labels stay advisory (ADR-010); no detector influence on
  authorization.
- No raw payloads in logs/audit; typed/bounded fields only.
- Mock/local only; no network calls by default; no real model dependency in tests.
- Update `docs/SECURITY_INVARIANTS.md`, both status files, `ARCHITECTURE_MAP.md`,
  `FILE_MAP.md`, `CHANGELOG.md`, and this file in the same task.

## Definition of Done (blueprint §21, Phase 4 condensed)

Malformed model output/outage and ambiguous intent grant no permission; intent/arguments
are compared before execution; execution still occurs only via the gateway; quality gate
remains green; ADR-007/ADR-008/ADR-009/ADR-010 contracts untouched.

## Open decisions / notes for the operator

- None blocking. `check.sh` pins Gitleaks to exactly 8.30.1 by design; a mismatch fails
  the gate.
- Carried-forward limits (documented): no policy hot-reload; exact-match destination
  allowlisting; `risk-v1` uncalibrated; per-process concurrency only; mock-only tools;
  in-process guardrail (no sandbox) until Phase 10; detector heuristics are modest and
  homoglyphs are not normalized before matching.
