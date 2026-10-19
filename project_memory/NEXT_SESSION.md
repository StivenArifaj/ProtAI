# Next Session Handoff

**Last updated: 2026-10-19.** Read [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) first if you have not.

## Where we are

Phases 0a (repository foundation), 0b (security foundation), and 1 (typed contracts and
deterministic policy engine) are **COMPLETE and VERIFIED** — see
[phases/PHASE_1_COMPLETE.md](phases/PHASE_1_COMPLETE.md) and evidence V30+ in
[TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md). The repository is under git
with a linear history; the Compose `db` container and volume are preserved for tests
(`api` stopped).

What exists now: host HMAC authentication + replay rejection on the `/v1/*` path prefix
(routes do not exist yet), async persistence + Alembic baseline, the dev-resolver guard +
test-only principal adapter, strict typed contracts (canonical `SideEffectClass`/
`DataClass`), canonical destination handling, the safe versioned policy loader with
duplicate-key rejection, the deterministic §10.2 policy engine with stable reason codes
and provenance, ADR-007 self-check fixtures (17, incl. the 7 mandated names) wired into
startup + readiness with `policy_version`/`policy_hash`, pinned Gitleaks, and 406 passing
tests. **Nothing executes:** there is no tool registry, gateway, or adapter, so decisions
have no side effects yet.

## The next task: Phase 2 — Tool registry and enforced gateway (blueprint §21)

No blocking preconditions; Phase 1 passed its DoD, so proceed per the autonomy mandate.
Read first: blueprint §§12 (firewall gateway + no-bypass), 14 (tool isolation/mock
tools), §21 (Phase 2), and ADR-008 (fact separation: the registry and call validator
produce the facts the Phase 1 engine consumes); then [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md).

Expected deliverables (condensed; formalize a `phases/PHASE_2_PLAN.md` when starting):

1. Tool protocol + registry derived from the loaded policy document (`config/policies.yaml`);
   unknown/undeclared tools stay `unknown_tool`-deniable and unexecutable.
2. Mock adapters only: email (search/read), files (read under a sandbox root via
   resource IDs), external sink (write; egress disabled by default) — no real
   connectors, no shell, no arbitrary network.
3. The `invoke_tool` gateway chokepoint: construct the engine request from validated
   facts, evaluate policy **before execution**, execute only on `ALLOW`, capture
   decisions for later audit, enforce timeouts + result bounds.
4. No-bypass tests: sink state changes only after a gateway `ALLOW`; denied/unknown/
   invalid actions leave no side effect; adapters are never invoked directly.

Runtime order reminder (blueprint work-order note): the unbypassable gateway lands
**before** input detection (Phase 3) and before any powerful tools.

## Verification commands and expected results

| Command | Expected |
|---|---|
| `uv run --frozen pytest -q` | All tests pass (≥406; new registry/gateway/no-bypass tests added) |
| `bash scripts/check.sh` | exit 0, all 8 steps (Gitleaks must stay clean) |
| Policy self-checks | startup and `/health/ready` still pass; fixtures keep working against the engine |
| No-bypass proof | denied/unknown action leaves the mock sink unchanged (new Phase 2 tests) |

## Security constraints that must hold throughout Phase 2

- Invariants #17/#18/#25 stay green: never touch the middleware/policy contracts without
  proving the denial matrix and policy suites still pass; keep `compare_digest` confined
  to `security/constant_time.py`.
- The gateway must call the real engine — never re-implement or bypass policy logic in
  adapters; adapters never see raw host requests.
- Mock tools only; egress stays disabled in the starter policy; file access stays within
  the sandbox root by resource ID.
- No execution without an `ALLOW` `DecisionRecord` for that exact call; decisions are
  data and must be reproducible (same facts → same decision).
- Update `docs/SECURITY_INVARIANTS.md` (#1/#9/#10/#12 become testable), both status
  files, `ARCHITECTURE_MAP.md`, `FILE_MAP.md`, `CHANGELOG.md`, and this file in the same
  task.

## Definition of Done (blueprint §21, Phase 2 condensed)

No-bypass tests: the mock sink changes only after a valid gateway `ALLOW`; denied and
unknown actions have no side effect; timeouts/result bounds enforced; the quality gate
remains green; ADR-007/ADR-008 contracts untouched.

## Open decisions / notes for the operator

- None blocking. `check.sh` pins Gitleaks to exactly 8.30.1 by design; a mismatch fails
  the gate.
- Known Phase 1 limits carried forward: no policy hot-reload (readiness detects drift);
  destination allowlisting is exact-match only; the `risk_score` fact still comes from
  the caller until the Phase 5 risk engine (Phase 2 supplies a placeholder deterministic
  value or keeps it caller-supplied — decide and document in `PHASE_2_PLAN.md`).
