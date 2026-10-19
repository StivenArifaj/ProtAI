# Next Session Handoff

**Last updated: 2026-10-19.** Read [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) first if you have not.

## Where we are

Phases 0a (repository foundation), 0b (security foundation), 1 (typed contracts and
deterministic policy engine), 2 (tool registry and enforced gateway), 3 (advisory input
defense and context provenance), and 4 (intent extraction and action validation) are
**COMPLETE — VERIFIED** — see [phases/PHASE_4_COMPLETE.md](phases/PHASE_4_COMPLETE.md)
and evidence V51+ in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md). The
repository is under git with a linear history; the Compose `db` container and volume are
preserved for tests (`api` stopped).

What exists now: host HMAC authentication + replay rejection on the `/v1/*` path prefix
(routes do not exist yet), async persistence + migrations, dev-resolver guard + test-only
principal adapter, strict typed contracts, canonical destination handling, the safe
versioned policy loader, the deterministic §10.2 policy engine with provenance and 21
self-check fixtures wired into startup/readiness, the typed tool registry + four mock
adapters, the digest-bound execution authorization, `risk-v1`, the single `invoke_tool`
gateway with audit-first ordering/bounds, strict advisory input detection with trust
labels/session signals, and — new in Phase 4 — server-issued sealed intent manifests
with exact action/resource/destination/parameter/use constraints, trusted-timezone
relative dates, a strict local-model adapter interface, and a two-scenario mock
extractor wired into the app gateway. **661 tests pass; the gate is green (8/8).**
Intent can only narrow policy; raw model output never grants authority. No route or real
model provider consumes intent yet.

## The next task: Phase 5 — Risk engine and approval workflow (blueprint §21)

No blocking preconditions; Phase 4 passed its DoD, so proceed per the autonomy mandate.
Read first: blueprint §§11-13 (risk, approvals, `ASK_USER` semantics) and §21 (Phase 5);
ADR-008 (engine facts), ADR-009 (gateway), ADR-011 (intent boundary); then audit the
existing `risk-v1` implementation against the Phase 5 deliverables. Formalize
`phases/PHASE_5_PLAN.md` when starting.

Expected deliverables (condensed from blueprint §21):

1. Deterministic, versioned risk factors and threshold configuration as required by
   Phase 5; document what `risk-v1` already covers and extend only the missing factors.
2. Approval request storage with durable state, expiry, and canonical-action-digest
   binding (approval cannot be replayed, mutated, or reused for another action).
3. One-time approval consumption that is atomic under concurrency and audited; an
   `ASK_USER` decision must never execute without a valid unconsumed approval.
4. Hard denies remain dominant and cannot be overridden by risk scores or approvals;
   execution still occurs only through `invoke_tool`.
5. Tests: risk-factor units/threshold edges; approval mutation/replay/expiry/concurrent
   double-consume; hard-deny non-override; no execution on missing/expired approval;
   keep every existing suite green.

## Verification commands and expected results

| Command | Expected |
|---|---|
| `uv run --frozen pytest -q` | All tests pass (≥661; new risk/approval suites added) |
| `bash scripts/check.sh` | exit 0, all 8 steps (Gitleaks must stay clean) |
| Policy/intent self-checks and gateway suites | still green; policy remains sole `ALLOW` producer |
| No-bypass suites | `tests/security` + gateway/integration still green (gateway contract preserved) |
| Input-defense/intent suites | still green; detector and intent remain authority-free |

## Security constraints that must hold throughout Phase 5

- Invariants #17/#18/#25 stay green; keep `compare_digest` confined to
  `security/constant_time.py`; do not weaken the HMAC denial matrix.
- Hard denies (`DESTRUCTIVE`, restricted/confidential egress, unknown tools) cannot be
  overridden by risk thresholds or approvals; approval is not an authorization bypass.
- Approval consumption must be atomic and one-time under real PostgreSQL concurrency;
  bind it to the canonical action digest plus request/principal/tenant and expiry.
- No raw payloads in logs/audit; typed/bounded fields only.
- Mock/local only; no network calls by default; no real model dependency in tests.
- Update `docs/SECURITY_INVARIANTS.md`, both status files, `ARCHITECTURE_MAP.md`,
  `FILE_MAP.md`, `CHANGELOG.md`, and this file in the same task.

## Definition of Done (blueprint §21, Phase 5 condensed)

Risk calculations are unit tested; hard denies cannot be overridden; approval
mutation/replay/expiry tests prove no unauthorized execution; execution still occurs only
via the gateway; quality gate remains green; ADR-008/ADR-009/ADR-011 contracts untouched.

## Open decisions / notes for the operator

- None blocking. `check.sh` pins Gitleaks to exactly 8.30.1 by design; a mismatch fails
  the gate.
- Carried-forward limits (documented): no policy hot-reload; exact-match destination
  allowlisting; `risk-v1` uncalibrated; per-process concurrency and intent-use tracking;
  mock-only tools and mock intent extractor; no manifest transport/real model provider;
  in-process guardrail (no sandbox) until Phase 10.
