# Next Session Handoff

**Last updated: 2026-10-19.** Read [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) first if you have not.

## Where we are

Phases 0a (repository foundation), 0b (security foundation), 1 (typed contracts and
deterministic policy engine), and 2 (tool registry and enforced gateway) are **COMPLETE —
VERIFIED** — see [phases/PHASE_2_COMPLETE.md](phases/PHASE_2_COMPLETE.md) and evidence
V36+ in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md). The repository is
under git with a linear history; the Compose `db` container and volume are preserved for
tests (`api` stopped).

What exists now: host HMAC authentication + replay rejection on the `/v1/*` path prefix
(routes do not exist yet), async persistence + Alembic baseline, dev-resolver guard +
test-only principal adapter, strict typed contracts, canonical destination handling, the
safe versioned policy loader, the deterministic §10.2 policy engine with provenance and
21 self-check fixtures wired into startup/readiness, and — new in Phase 2 — the typed
tool registry with startup consistency checks, four deterministic mock adapters, the
gateway-issued digest-bound `ExecutionAuthorization`, the `risk-v1` scoring engine, the
single `invoke_tool` chokepoint (bindings → strict validation → resource/destination →
real engine → audit-first → bounded execution → typed outcome), the audit recorder over
the ADR-002 chain, and `create_app` wiring (`app.state.tool_registry` /
`app.state.tool_gateway`). 520 tests pass; the gate is green (8/8). **Nothing outside the
gateway executes:** denied/unknown/malformed/expired/audit-failed calls leave the mock
sink unchanged (proven in unit, security, and real-PostgreSQL integration tests).

## The next task: Phase 3 — Input threat defense and context provenance (blueprint §21)

No blocking preconditions; Phase 2 passed its DoD, so proceed per the autonomy mandate.
Read first: blueprint §§7-8 (input threat signals, trust labels, context assembly) and
§21 (Phase 3); then ADR-008 (facts the engine consumes) and ADR-009 (the gateway the
signals will feed). Formalize `phases/PHASE_3_PLAN.md` when starting.

Expected deliverables (condensed from blueprint §21):

1. Intake limits and a normalization copy (never mutate the original input).
2. Versioned deterministic heuristics producing typed findings (direct/indirect
   injection, canary/known-bad patterns) — no LLM in the decision path.
3. Trust labels (`EXTERNAL_UNTRUSTED` etc.) that survive into agent context; provenance
   records attached to context.
4. Explicit detector failure behavior: a detector outage is a typed failure mode, never a
   silent bypass of the gateway.
5. Tests: direct/indirect attack fixtures + benign hard negatives; labels/provenance
   reach context; detector failure cannot authorize anything.

## Verification commands and expected results

| Command | Expected |
|---|---|
| `uv run --frozen pytest -q` | All tests pass (≥520; new input-defense suites added) |
| `bash scripts/check.sh` | exit 0, all 8 steps (Gitleaks must stay clean) |
| Policy self-checks | startup and `/health/ready` still pass (21 fixtures) |
| No-bypass suites | `tests/security` + gateway integration still green (gateway contract untouched) |

## Security constraints that must hold throughout Phase 3

- Invariants #17/#18/#25 stay green; keep `compare_digest` confined to
  `security/constant_time.py`; do not weaken the HMAC denial matrix.
- Detectors never become the policy authority: findings/labels feed facts; the engine
  and gateway remain the only enforcement path (ADR-008/ADR-009).
- No raw payloads in logs/audit; findings are typed with bounded fields.
- Mock/local only; no network calls in the detection path; no model calls by default.
- Update `docs/SECURITY_INVARIANTS.md` (#10/#11/#15/#16/#23), both status files,
  `ARCHITECTURE_MAP.md`, `FILE_MAP.md`, `CHANGELOG.md`, and this file in the same task.

## Definition of Done (blueprint §21, Phase 3 condensed)

Direct/indirect attack + benign hard-negative tests pass; labels and provenance survive
to agent context; detector failure behavior is explicit and cannot bypass the gateway;
quality gate remains green; ADR-007/ADR-008/ADR-009 contracts untouched.

## Open decisions / notes for the operator

- None blocking. `check.sh` pins Gitleaks to exactly 8.30.1 by design; a mismatch fails
  the gate.
- Carried-forward limits (documented): no policy hot-reload; exact-match destination
  allowlisting; `risk-v1` uncalibrated; per-process concurrency only; mock-only tools;
  in-process guardrail (no sandbox) until Phase 10.
