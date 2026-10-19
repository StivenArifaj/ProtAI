# Changelog

Concise, dated history of project activity. Newest first.

## 2026-10-19

- **Phase 4 (intent extraction and action validation) implemented and verified** (same
  day as 0a-3): new `intent/` package with a server-only manifest issuer, two-scenario
  mock extractor, strict local-model adapter interface (bounded/duplicate-key-safe JSON,
  bounded retries, outage/timeout mapping), sentinel-sealed request/principal/tenant/
  policy-bound manifests with short expiry and goal digest, exact action/resource/
  destination/parameter constraints with bounded uses, and trusted-timezone
  `TODAY`/`THIS_WEEK` resolution (DST-tested). Gateway gains manifest verification,
  exact constraint comparison, and post-policy use reservation; app wiring exposes
  `intent_usage_tracker`/`intent_manifest_service`, adds `INTENT_MANIFEST_TTL_SECONDS`,
  and constructs the gateway with the tracker. Contract recorded in ADR-011. Evidence
  V51+ in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) — **661 tests**
  (568 unit + 64 integration + 29 security), 8-step gate green. Commits `2943593`
  (implementation/tests), `74c502f` (ADR-011/docs), `786cb08` (memory/completion).
  Phase record: [phases/PHASE_4_COMPLETE.md](phases/PHASE_4_COMPLETE.md).
- **Phase 3 (input threat defense and provenance) implemented and verified** (same day as
  0a-3): shared strict YAML helper (`security/safe_yaml.py`, reused by the policy loader);
  advisory input-defense package (`input_defense/{models,config,normalize,heuristics,
  service,context_labels,sessions}.py`) with strict exhaustive-disposition config
  (`config/input_defense.yaml`, duplicate-key rejection, no PASS mapping), bounded intake,
  copy-only normalization (zero-width/control/escape/Base64/NFKC/mixed-script signals,
  iterative JSON depth), 10 versioned heuristic rules with quoted-context downgrade,
  typed non-PASS failure semantics (`DETECTOR_UNAVAILABLE`), structured trust-labelled
  context assembly, and session-signal math; tenant/subject-bound
  `session_security_state` repository + migration `c7f1a2b3d4e5` (bounded counters, 24 h
  inactivity/7 d absolute lazy expiry, signal-free rotation); settings
  (`INPUT_DEFENSE_PATH`, `SESSION_SIGNAL_TTL_SECONDS`, `SESSION_MAX_AGE_SECONDS`);
  `create_app` exposes `app.state.input_defense_config`/`input_defense_service`/
  `session_security`. Contract recorded in ADR-010. Evidence V43+ in
  [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) — **600 tests** (517 unit +
  60 integration + 23 security), 8-step gate green. Phase record:
  [phases/PHASE_3_COMPLETE.md](phases/PHASE_3_COMPLETE.md).
- **Phase 2 (tool registry and enforced gateway) implemented and verified** (same day as
  0a/0b/1): strict `ToolArguments`/`ToolResult` + sentinel-guarded, digest-bound
  `ExecutionAuthorization` (`tools/base.py`); immutable validated `ToolRegistration` +
  one-directional policy/capability consistency (`tools/registry.py`); deterministic mock
  adapters (`tools/mock_{email,files,external_sink,text}.py`); single `invoke_tool`
  chokepoint with bindings, strict validation, derived resources/destination, resource
  checks, deadlines, audit-first ordering, timeouts, per-process concurrency, and result
  bounds (`firewall/{models,gateway}.py`); `risk-v1` scoring engine
  (`firewall/risk_engine.py`); audit event subset + `ChainAuditRecorder`
  (`audit/{models,writer}.py`); reason codes `binding_mismatch`, `deadline_exceeded`,
  `policy_evaluation_error`, `audit_unavailable`; `create_app` wiring exposing
  `app.state.tool_registry`/`app.state.tool_gateway`; self-check fixtures extended to 21.
  Contract recorded in ADR-009. Evidence V36+ in
  [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) — **520 tests** (461 unit +
  47 integration + 12 security), 8-step gate green. Phase record:
  [phases/PHASE_2_COMPLETE.md](phases/PHASE_2_COMPLETE.md).
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
