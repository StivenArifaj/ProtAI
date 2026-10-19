# Phase 2 — Tool Registry and Enforced Gateway — COMPLETE (VERIFIED)

- **Status:** COMPLETE — technical DoD all PASS, verified 2026-10-19. Typed tool registry
  with startup consistency checks, four deterministic mock adapters, gateway-issued
  digest-bound execution authorization, the `risk-v1` scoring engine, the single
  `invoke_tool` chokepoint (bindings → strict validation → resource/destination →
  engine → audit-first → bounded execution → outcome), the audit recorder interface over
  the ADR-002 chain, and `create_app` wiring are implemented and tested (**520 tests**).
- **Blueprint:** §21 (Phase 2), §§6.1, 11.3-11.4, 12.1-12.4, 14.1, 16.1, 16.3-16.4;
  ADR-009 (new, this phase); ADR-002/ADR-007/ADR-008 contracts kept.

## Scope delivered

| Deliverable (blueprint §21) | Delivered as | Status |
|---|---|---|
| Adapter protocol, typed results, execution authorization, action digest | `tools/base.py` — strict `ToolArguments`/`ToolResult`; sentinel-guarded `ExecutionAuthorization`; `compute_action_digest` / `verify_execution_authorization`; `UngatedExecutionError` / `ExecutionAuthorizationError` | VERIFIED |
| Registry + startup consistency | `tools/registry.py` — immutable validated `ToolRegistration` (IDs, schemas, annotations, destinations, bounds, approval metadata); exact `(tool_id, action_id)` resolution; `build_registry` policy-consistency checks; `ToolRegistryConfigError` refuses startup | VERIFIED |
| Mock adapters only (§14.1) | `tools/mock_email.py`, `mock_files.py`, `mock_external_sink.py`, `mock_text.py` — in-memory, deterministic, ownership checks, digest re-verification; sink egress disabled in the starter policy; `mock_files.search` registered but policy-disabled | VERIFIED |
| `invoke_tool` gateway (§12.3 steps 1-12) | `firewall/models.py` + `firewall/gateway.py` — principal/request bindings; strict argument validation; derived resources/destination with declared-match requirement; adapter resource check; deadline; real engine evaluation; decision event **before** execution; timeout + per-process concurrency + result bounds; typed outcomes | VERIFIED |
| First deterministic risk factors (§11.3) | `firewall/risk_engine.py` — `risk-v1` (side-effect, external-destination, registration data-class factors; cap 100; factor codes in decision/audit) | VERIFIED |
| Reason vocabulary + fixtures | `firewall/decision.py` / `policy_engine.py` — `binding_mismatch`, `deadline_exceeded`; gateway-only `policy_evaluation_error`, `audit_unavailable`; `config/policy_self_checks.yaml` now 21 fixtures | VERIFIED |
| Audit interface + DB recorder | `audit/models.py` (schema v1 subset: `POLICY_EVALUATED`, `TOOL_EXECUTION_COMPLETED`, `TOOL_EXECUTION_FAILED`; payload-safe references only), `audit/writer.py` (`AuditRecorder`, `ChainAuditRecorder`) | VERIFIED |
| Startup wiring | `api/app.py` — registry + gateway constructed and validated at startup; exposed on `app.state`; no `/v1` routes yet | VERIFIED |
| Tests | 50 new tests across `tests/unit` (registry, digest, adapters, risk, gateway), `tests/security` (no-bypass), `tests/integration` (real-PostgreSQL end-to-end, wiring) | VERIFIED |

## Security properties actually enforced now (do not overstate)

- **No bypass:** the gateway is the only path that evaluates and executes; adapters
  require a sentinel-guarded, digest-bound `ExecutionAuthorization` issued only after a
  durable `ALLOW` decision event. Direct/forged calls fail closed (`UngatedExecutionError`
  / `ExecutionAuthorizationError`).
- **Fail closed:** unknown/disabled tools, invalid/binding/deadline/destination/resource
  failures, engine exceptions, and audit outages all produce typed no-execution outcomes;
  the engine remains the sole `ALLOW` producer and the gateway may only downgrade.
- **Audit-first:** `POLICY_EVALUATED` is durable before any protected side effect;
  `TOOL_EXECUTION_COMPLETED`/`_FAILED` follows, correlated by `call_id` in the ADR-002
  chain (real-PostgreSQL order/linkage test). An outcome-append failure withholds the
  result (`AUDIT_FAILED`).
- **Bounded execution:** per-tool timeout, per-process concurrency limit, strict result
  schema/canonicalizability/≤1 MiB size checks; typed outcomes `TIMEOUT`,
  `RESULT_REJECTED`, `ADAPTER_FAILED`.
- **No raw payloads in audit:** payloads carry identifiers, provenance, risk factors,
  destination, and result digests/sizes only; message/file contents are absent (tested).
- **Still absent (do not claim):** `/v1` routes and agent runtime (the gateway is
  in-process/in tests only), approvals (`ASK_USER` never executes), manifest/intent
  binding, content DLP, real connectors, process isolation, request rate limiting, full
  audit taxonomy/verifier.

## Conformance notes (documented, not hidden)

- Registry/policy consistency is one-directional: every policy tool requires a
  registration (else startup fails); registrations absent from the policy are
  registered-but-disabled and denied `unknown_tool` (this is how `mock_files.search`
  stays available to policy but off by default).
- `risk-v1` weights are initial experimental defaults; data class is a registration fact
  until Phase 6 content classification; calibration is Phase 9.
- Concurrency bounds and the in-memory sink are per process (and per event loop); no
  cross-worker coordination exists yet.
- The execution authorization is an in-process guardrail, not a sandbox against
  malicious in-process code (Phase 10).

## Verification evidence (fresh runs 2026-10-19; detail in ../TESTING_AND_VERIFICATION.md V36-V40)

1. `uv run --frozen pytest -q` → **520 passed** (461 unit + 47 integration + 12
   security; DB-backed integration against the Compose PostgreSQL).
2. `bash scripts/check.sh` → exit 0, all 8 steps; Gitleaks 8.30.1 `git` scan: 13
   commits, no leaks.
3. `uv run --frozen pytest tests/security tests/unit/test_gateway.py -q` → **31 passed**
   (no-bypass + gateway failure modes).
4. `uv run --frozen pytest tests/integration/test_gateway_end_to_end.py
   tests/integration/test_gateway_wiring.py -q` → **5 passed** (real-PostgreSQL
   decision/outcome ordering and linkage; startup wiring; unregistered-policy-tool
   startup refusal).
5. `uv run --frozen pytest tests/unit/test_policy_self_checks.py
   tests/integration/test_policy_self_checks_wiring.py -q` → **41 passed** — 21
   fixtures against the real engine at startup + readiness.
6. `uv run --frozen mypy src` → Success, 45 source files (strict); ruff lint/format
   clean (covered by the gate).

## Definition of Done (blueprint §21, Phase 2) — final status

All nine DoD items **PASS**; item-by-item evidence is in
[`../../docs/IMPLEMENTATION_STATE.md`](../../docs/IMPLEMENTATION_STATE.md) (Phase 2 DoD
checklist) and the test files cited above.

## Limitations added by this phase (honest list)

- Execution is in-process and mock-only; no sandbox, no real connectors.
- `ASK_USER` yields a no-execution result (approvals Phase 5); no manifest/intent binding
  (Phase 4); no content DLP (Phase 6); audit taxonomy is a Phase 2 subset (full taxonomy +
  verifier Phase 7).
- Per-process concurrency only; in-memory sink not shared across processes.
- `risk-v1` uncalibrated; exact-match destination allowlisting unchanged; no policy
  hot-reload.

## Handoff

Next task: **Phase 3 — Input threat defense, trust labels, and context provenance**
(blueprint §21, §§7-8). Preconditions: none blocking — Phase 2 passed its DoD; proceed
per the autonomy mandate.
