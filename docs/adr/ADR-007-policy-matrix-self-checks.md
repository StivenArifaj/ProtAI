# ADR-007: Policy decision matrix mirrored in docs/config with startup self-checks

- **Status:** Accepted
- **Date:** 2026-10-19
- **Implementation:** Phase 1 (self-check scaffolding in Phase 0b)

## Context

The policy decision matrix (blueprint section 10.3) is the v1 authorization baseline.
If the running policy drifts from the matrix — or from what the documentation claims —
the security posture is misrepresented even when the code "works". Configuration is
also where subtle weakening happens (weaker rules, missing approvals, aliased enums).

## Decision

- `docs/POLICY_DECISION_MATRIX.md` mirrors the matrix exactly (recorded in Phase 0a);
  `config/risk_thresholds.yaml` must mirror it when created, and rules may be stricter
  but never weaken a hard denial.
- `config/policy_self_checks.yaml` contains deterministic, side-effect-free fixtures
  (at minimum: one allowed mock read; one forbidden external egress; one cross-user
  resource denial; one unknown tool denial; one invalid-argument denial; one
  restricted-data egress block; one hard-deny case with low risk proving score cannot
  override). The startup/readiness path and CI evaluate these fixtures against the
  actual loaded policy; any mismatch fails readiness/startup.
- The loaded policy version/hash is exposed in health metadata and audit events.
- Policy files are validated into strict Pydantic models (safe YAML loading only, no
  mini-language or dynamic expressions); unknown/missing/invalid `SideEffectClass` or
  `DataClass` fails closed.
- The AI SOC cannot mutate policy in v1; policy changes go through the host's
  controlled administration flow.

## Consequences

- Startup fails on policy/documentation drift — deliberate fail-fast behavior.
- Every policy change requires updating self-check fixtures; this is the mechanism that
  makes "we tested the matrix" a verifiable claim rather than a statement.

## References

Blueprint v1.2 sections 10.3-10.7, 20.2 (5, 25), 21 (Phase 1).
