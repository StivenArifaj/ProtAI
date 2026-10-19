# Changelog

Concise, dated history of project activity. Newest first.

## 2026-10-19

- **Phase 1 (typed contracts and deterministic policy engine) implemented and verified**
  (same day as 0a/0b): canonical enums defined exactly once (`tools/base.py`,
  `data_security/classification.py`, `firewall/decision.py`); strict contracts
  (`extra="forbid"`, strict int `risk_score`, anchored tool-id pattern, no aliases);
  destination canonicalization (`security/urls.py`); safe YAML loader with duplicate-key
  rejection (`policy/loader.py`); validated policy model + versioned bundle with content
  hashes (`policy/models.py`); deterministic §10.2 engine (`firewall/policy_engine.py`)
  replacing `policy/interim_matrix.py` (deleted); starter policy + experimental
  thresholds (`config/policies.yaml`, `config/risk_thresholds.yaml`); self-check fixtures
  v2 (17 fixtures, 7 mandated names retained, fixture-level `tool_policy` overrides);
  test-only principal adapter (`identity/adapters.py`); startup refusal + readiness
  `policy_version`/`policy_hash` + live drift detection. Contract recorded in ADR-008.
  Commits `cffdd62` (contracts + canonicalization), `eaae462` (models/loader/engine +
  config + fixtures), `b91729b` (wiring + adapter + env example) on top of `c95f2a6`.
  Evidence V30+ in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) — **406
  tests** (364 unit + 42 integration), 8-step gate green, bundle smoke check
  `combined_hash 8a4ba203…` with 17/17 fixtures passing. Phase record:
  [phases/PHASE_1_COMPLETE.md](phases/PHASE_1_COMPLETE.md).
- **Phase 0b (security foundation) implemented and verified end-to-end** (same day as
  0a): settings extensions; security primitives; identity package; async persistence +
  Alembic baseline; `/v1/*` host-auth ASGI middleware; policy self-check scaffolding;
  pinned Gitleaks + invariant steps in the gate; container runtime assets and Compose
  dev key. Commits `0aa11d9`, `9b3f153`, `42e8b71`, `4d18e27`, `28bede9`, `a5794cc`,
  `d180b89` on baseline `41e10da`. Evidence V18–V29 in
  [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) (231 tests; 8-step gate;
  live Docker auth/replay proof; startup refusals; `gitleaks git` clean). Phase record:
  [phases/PHASE_0B_COMPLETE.md](phases/PHASE_0B_COMPLETE.md).
- **Created the persistent project memory system** (`project_memory/`, this directory):
  13 core files + [phases/](phases/) records, per the memory-system task. Validation: all
  16 files present; 163 relative links checked, 0 broken; secret scan clean (no
  credential values; the sample password is referenced by location only); no files
  outside `project_memory/` created, deleted, or edited (35-file pre-existing inventory
  unchanged). No markdown linter is installed in this environment (checked; not installed).
- **Re-verified Phase 0a end-to-end in a fresh session:** `uv sync --frozen` clean;
  `bash scripts/check.sh` exit 0 (ruff, mypy, 25 tests, invariant greps);
  `docker compose config -q` exit 0; live Compose stack healthy with readiness 200
  against real PostgreSQL; non-root `uid=10001`; production gating 404s + fail-closed
  503; in-container startup refusal exit 1; stack torn down (volume preserved).
  Recorded as V1–V13 in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md).
- **Phase 0a (repository foundation) implemented and verified** (prior session, same
  day): full scaffold (35 files before this memory directory), settings validation, `/health/live` +
  `/health/ready`, 25 tests, `scripts/check.sh` (6 steps), digest-pinned Dockerfile +
  Compose (API on host port 8080), and the documentation scaffold under
  [../docs/](../docs/) (ARCHITECTURE, THREAT_MODEL, SECURITY_INVARIANTS,
  POLICY_DECISION_MATRIX, DECISIONS, IMPLEMENTATION_STATE, KNOWN_LIMITATIONS, and
  `ADR-001..007`).
  Full record: [../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md); phase record:
  [phases/PHASE_0A_COMPLETE.md](phases/PHASE_0A_COMPLETE.md).
- **Blueprint corrections v1.1 → v1.2 completed** (prior session): documentation-only
  validation pass over the master blueprint (archived v1.0 superseded).

## Template for future entries

```text
## YYYY-MM-DD
- <what changed> (<phase>, files) — <evidence: command/result or record reference>.
- <decisions made> — <ADR link if contract-level>.
- <blockers opened/closed>.
```
