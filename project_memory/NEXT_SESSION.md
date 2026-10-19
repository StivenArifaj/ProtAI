# Next Session Handoff

**Last updated: 2026-10-19.** Read [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) first if you have not.

## Where we are

Phases 0a (repository foundation) and 0b (security foundation) are **COMPLETE and
VERIFIED**, including the Docker Compose path — see
[phases/PHASE_0B_COMPLETE.md](phases/PHASE_0B_COMPLETE.md) and evidence V18–V29 in
[TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md). The repository is under git
with a linear Phase 0b commit series. The Compose `api` container is stopped; the `db`
container and volume are preserved for tests.

What exists now: host HMAC authentication + replay rejection enforced on the `/v1/*` path
prefix (routes do not exist yet), async persistence + Alembic baseline, the dev-resolver
guard, policy self-check scaffolding wired into startup and readiness, pinned Gitleaks in
the gate, and 231 passing tests. Nothing else: no authorization, no tool gateway, no
approvals, no DLP, no audit event emission.

## The next task: Phase 1 — Typed contracts and deterministic policy engine (blueprint §21)

No blocking preconditions; Phase 0b passed its DoD, so proceed per the autonomy mandate.
Read first: blueprint §§6 (typed contracts), §10 (policy engine + matrix), §11.4 (risk
thresholds interplay), §20.2 #25, and ADR-007; then [../docs/POLICY_DECISION_MATRIX.md](../docs/POLICY_DECISION_MATRIX.md).

Expected deliverables (condensed; formalize a `phases/PHASE_1_PLAN.md` when starting):

1. Strict Pydantic request/response/action contracts (`extra="forbid"`, frozen where
   appropriate) with canonical `SideEffectClass`/`DataClass` enums — unknown/missing/
   invalid values fail closed with no aliases or coercions.
2. A safe YAML policy loader (the only sanctioned YAML entry point is
   `yaml.safe_load`; the Phase 0b gate already prohibits bare `yaml.load(`) and a
   validated, versioned policy model with explicit reason codes and documented
   evaluation order (hard constraints first).
3. The real deterministic policy engine replacing `policy/interim_matrix.py` while
   keeping the `config/policy_self_checks.yaml` fixture contract intact (ADR-007):
   the self-checks must still pass at startup and in readiness, and the fixtures may be
   extended to cover the full engine.
4. A principal test adapter (explicitly test-scoped) without weakening the dev-resolver
   guard or the HMAC middleware.
5. Canonicalization utilities/tests where the contracts require them.

Runtime order reminder (blueprint work-order note): typed schemas + policy land before the
tool gateway; input detection before any powerful tools.

## Verification commands and expected results

| Command | Expected |
|---|---|
| `uv run --frozen pytest -q` | All tests pass (≥231; new contract/policy tests added) |
| `bash scripts/check.sh` | exit 0, all 8 steps (Gitleaks must stay clean) |
| `uv run --frozen ruff check .` / `mypy` | clean / no issues |
| Policy self-checks | startup and `/health/ready` still pass with the fixtures; a deliberately mismatching fixture still refuses startup |

## Security constraints that must hold throughout Phase 1

- Invariants #17/#18 must stay green: never touch the middleware path without proving the
  denial matrix still passes; keep `compare_digest` confined to `security/constant_time.py`.
- The policy engine is deterministic and makes no network calls; no LLM in authorization.
- Never weaken the fixture contract to make room for the engine — extend fixtures instead.
- Do not add executables or side effects: Phase 1 has no action surface; reason codes and
  decisions are data.
- Update `docs/SECURITY_INVARIANTS.md` (#25 becomes fully testable) and both status files
  in the same task; keep `docs/IMPLEMENTATION_STATE.md` and
  [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) consistent; append to
  [CHANGELOG.md](CHANGELOG.md); refresh this file at the end.

## Definition of Done (blueprint §21, Phase 1 condensed)

Table-driven policy tests covering allowed/forbidden/malformed/cross-scope/unknown/error
cases; strict contracts fail closed on unknown/invalid values; the ADR-007 self-check
fixtures pass against the real engine; no LLM involvement; the quality gate remains green.

## Open decisions / notes for the operator

- None blocking. The Phase 0a ADR-format nuance remains open (new ADRs may include
  "alternatives considered"/"tests/verification" sections); no new ADR was created in 0b.
- `check.sh` pins Gitleaks to exactly 8.30.1 by design; a mismatch fails the gate.
