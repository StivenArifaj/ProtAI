# ADR-008: Deterministic policy engine with strict typed contracts and versioned policy bundle

- **Status:** Accepted
- **Date:** 2026-10-19
- **Implementation:** Phase 1

## Context

Blueprint section 10 requires the policy decision matrix (`docs/POLICY_DECISION_MATRIX.md`)
to be enforced by a deterministic engine with a documented evaluation order, and section
6.1 requires strict typed contracts. Invariant #25 (section 20.2) requires
unknown/missing/invalid `SideEffectClass`/`DataClass` values to fail closed; ADR-007
requires self-checks against the actually loaded policy. Phase 0b shipped
`policy/interim_matrix.py` as explicitly labeled scaffolding; Phase 1 replaces it with the
real engine. This ADR records the contract-level decisions taken while implementing it.

## Decision

- **Canonical enums, defined exactly once:** `SideEffectClass` in
  `src/ai_security/tools/base.py`; `DataClass` in
  `src/ai_security/data_security/classification.py`; the decision contract
  (`FirewallDecision`, `DecisionReason`, `DecisionRecord`) in
  `src/ai_security/firewall/decision.py`.
- **Module layout:** the engine lives in `firewall/policy_engine.py` (blueprint section 4
  layout); policy document models and the loader live in `policy/models.py` /
  `policy/loader.py`.
- **Fact separation:** `PolicyEvaluationRequest` carries upstream-determined facts only
  (`principal_resolved`, `arguments_valid`, `hard_deny`, `resource_authorized`,
  `risk_score`, optional `destination`) plus the action description. All policy-derived
  facts (tool membership, explicit permission, approval eligibility, egress enablement,
  destination allowlist) come from the loaded `PolicyBundle`; they can never be
  caller-supplied.
- **Evaluation order = blueprint section 10.2 steps:** principal → tool membership
  (`unknown_tool`) → side-effect class match → arguments → hard deny → resource scope →
  destination (only `EXTERNAL_MUTATION` may carry one; malformed or misplaced =
  `invalid_destination`) → matrix rows with configured thresholds.
- **Fail closed everywhere:** hard deny dominates every score; `DESTRUCTIVE` is never
  executable in v1; `RESTRICTED` writes/egress and `CONFIDENTIAL` egress are blocked;
  `ASK_USER` is valid only when the policy explicitly marks the action approval-eligible,
  otherwise unresolved risk becomes `BLOCK`; a tool absent from the policy document is
  `unknown_tool` BLOCK (deny-by-default).
- **Risk score is a strict integer 0-100** (rejects string/bool coercion); thresholds are
  validated (`ask_user_at_or_above < block_at_or_above`), default 40/80 per section 11.4.
- **Destination canonicalization (`security/urls.py`):** https-only, IDNA-encoded
  lowercased host, percent-encoding normalized, no userinfo/fragment, default port 443
  elided, IPv6 kept bracketed; IPv6 zone IDs, whitespace/control characters anywhere, and
  non-ASCII paths/queries are rejected. Allowlisting is exact-match only; no wildcards
  in v1.
- **Safe loading:** policy YAML loads through `yaml.safe_load` only, with duplicate-key
  detection via a `yaml.compose` node walk (the gate prohibits bare `yaml.load(`), and
  strict Pydantic validation. `PolicyConfigError` fails closed. The bundle exposes
  `version` plus sha256 content hashes (`combined_hash`), surfaced in readiness metadata.
- **Self-check fixtures v2:** each fixture `case` is a full `PolicyEvaluationRequest`;
  an optional fixture-level `tool_policy` override (same strict `ToolPolicy` model) covers
  matrix rows the starter policy must not enable by default (the "dedicated test
  scenario" of section 10.5). The seven mandated fixture names from ADR-007 remain, and
  the starter policy keeps egress disabled.
- **Principal test adapter:** `TestPrincipalResolver` is constructible only under
  `APP_ENV=test` and is not reachable through settings or the resolver factory; the
  dev-resolver guard and the HMAC middleware are untouched.

## Consequences

- Authorization decisions are deterministic data (decision, reason, policy version/hash),
  not model outputs: no LLM, no network, no side effects in the engine path.
- Any policy change requires updating self-check fixtures; startup/readiness fail on
  drift (ADR-007), and readiness reports the loaded `policy_version`/`policy_hash`.
- Later phases (intent constraints, approvals, DLP) extend the fact set and matrix rows
  without changing this contract shape.
- Known limits (documented, not defects): no policy hot-reload (the process keeps its
  startup-loaded bundle; readiness detects file drift); destinations are exact-match only.

## References

Blueprint v1.2 sections 6, 10, 11.4, 20.2 (#25), 21 (Phase 1); ADR-007;
`docs/POLICY_DECISION_MATRIX.md`; `project_memory/phases/PHASE_1_PLAN.md`.
