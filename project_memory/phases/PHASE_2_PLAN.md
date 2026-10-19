# Phase 2 — Tool Registry and Enforced Gateway — COMPLETE (2026-10-19)

- **Status:** COMPLETE — VERIFIED (started and completed 2026-10-19). Completion record:
  [PHASE_2_COMPLETE.md](PHASE_2_COMPLETE.md).
- **Blueprint:** §12 (gateway chokepoint, registry, execution flow, no-bypass), §14 (tools
  and execution isolation), §6.1 (`ProposedToolCall`, `ToolExecutionResult` domain),
  §16.1/§16.4 (audit interface + fail-closed operational failures), §11.3/§11.4 (first
  deterministic risk factors), §21 Phase 2 gate.

## Objective

Make decisions executable — and only executable — through one enforced chokepoint. Phase
1 produced deterministic `ALLOW`/`BLOCK`/`ASK_USER` records with no side effects. Phase 2
adds a typed tool registry, mock-only adapters, the single `invoke_tool` gateway that
evaluates the real engine before every adapter call, timeouts/result bounds, and an audit
recorder interface. The proof obligation is negative space: unknown, denied, malformed,
expired, or audit-failed calls must leave the external sink unchanged, and no adapter may
be invoked outside the gateway.

## Deliverables (blueprint §21)

| Deliverable | Delivered as (files) | Status |
|---|---|---|
| Adapter protocol, results, execution authorization, action digest | `tools/base.py` | DELIVERED — sentinel-guarded `ExecutionAuthorization`, `compute_action_digest`/`verify_execution_authorization`, strict `ToolArguments`/`ToolResult`, `UngatedExecutionError`/`ExecutionAuthorizationError` |
| Registry + startup consistency checks | `tools/registry.py` | DELIVERED — immutable validated `ToolRegistration`; `ToolRegistry.resolve`; `build_registry` startup checks (policy→capability required; extra registrations policy-disabled; class/approval/egress/allowlist consistency) |
| Mock email/files/sink/summarize adapters | `tools/mock_email.py`, `tools/mock_files.py`, `tools/mock_external_sink.py`, `tools/mock_text.py` | DELIVERED — deterministic in-memory; ownership checks; digest re-verification; `mock_files.search` registered but policy-disabled |
| Gateway models + chokepoint | `firewall/models.py`, `firewall/gateway.py` | DELIVERED — `invoke_tool` with bindings, strict validation, derived resources/destination, resource check, deadline, engine, audit-first, timeout/concurrency, typed outcomes |
| First deterministic risk factors | `firewall/risk_engine.py` | DELIVERED — `risk-v1`; side-effect/destination/data-class factors; cap 100; `RiskScoringError` on inconsistent facts |
| Decision vocabulary extensions + engine facts | `firewall/decision.py`, `firewall/policy_engine.py`, `config/policy_self_checks.yaml` | DELIVERED — `binding_mismatch`, `deadline_exceeded` (engine), `policy_evaluation_error`, `audit_unavailable` (gateway); 21 fixtures total |
| Audit interface + DB recorder | `audit/models.py`, `audit/writer.py` | DELIVERED — `AuditEvent` schema v1 subset; `AuditRecorder` protocol; `ChainAuditRecorder` over the ADR-002 repository |
| Startup wiring | `api/app.py` | DELIVERED — `app.state.tool_registry` + `app.state.tool_gateway`; `ToolRegistryConfigError` refuses startup |
| Tests | `tests/unit/{test_action_digest,test_tool_registry,test_mock_adapters,test_risk_engine,test_gateway}.py`, `tests/security/test_gateway_no_bypass.py`, `tests/integration/{test_gateway_end_to_end,test_gateway_wiring}.py`, `tests/unit/_tool_auth.py` | DELIVERED — 50 new tests; full suite **520 passed** |

## Decisions (recorded; ADR-009)

| Decision / deviation | Rationale | Recorded in |
|---|---|---|
| `risk_score` is computed by a minimal deterministic, versioned factor set (`risk-v1`), never caller-supplied | §12.3 step 7 requires the gateway to compute deterministic risk factors; §6.1 forbids model-supplied scores. Weights are initial experimental defaults; Phase 5 extends factors and adds approvals; Phase 9 calibrates. | ADR-009, `DECISION_LOG` |
| Mock sink registration declares `data_class: PUBLIC`; data class is a registration fact in Phase 2 | §6.1 allows classification from configured metadata. Per-content classification and DLP are Phase 6. | ADR-009, KNOWN_LIMITATIONS |
| Every adapter call requires a gateway-issued `ExecutionAuthorization` carrying a canonical action digest | §12.4 "every registered adapter invocation originated from the gateway"; §13.2 digest binding pre-built for Phase 5. In-process guardrail, not a sandbox (Phase 10). | ADR-009 |
| `ASK_USER` is returned as a typed no-execution result; no approval storage until Phase 5 | §21 places approvals in Phase 5; the starter policy has no approval-eligible tools. | ADR-009, KNOWN_LIMITATIONS |
| Audit write required before every execution; failed decision-event append on a would-be `ALLOW` becomes `BLOCK`/`audit_unavailable` | §16.4 default: no protected side effect without its decision record. Denials keep their reason when their audit append fails (no side effect exists). | ADR-009 |
| **Corrected during implementation:** registry/policy consistency is one-directional — policy→capability required at startup; registrations absent from the policy remain registered but disabled (`unknown_tool`) | §12.2 requires unknown/missing/invalid capability configuration to fail startup, but the capability inventory (§14.1 `mock_files.search`) intentionally exceeds the starter policy's enabled set (§10.5). Split capability vs authorization holds; policy drift into capability still fails closed. | ADR-009 |
| **Corrected during implementation:** `action_id` is not required to equal the final dotted segment of `tool_id` | Enforcing a naming convention added no security value; the exact `(tool_id, action_id)` pair is the registry key and the policy/audit identifier. | ADR-009 |
| Strictness tightening: strict argument/result models; resource/destination argument annotations must be exactly `str` | A non-`str` annotation could smuggle type-mismatched resource IDs past gateway derivation/registration checks. | ADR-009 |

## Explicit non-goals (later phases)

- Phase 3: input threat defense, trust labels, context provenance.
- Phase 4: intent extraction/manifest binding and action-constraint validation.
- Phase 5: approval storage/consumption, expanded risk factors and calibration.
- Phase 6: content-level DLP/canary inspection and per-content classification.
- Phase 7: full audit event taxonomy/schema, verifier, retention.
- Phase 8: `/v1` routes, agent runtime, rate limiting; Phase 10: process isolation.

## Verification evidence (actual runs, 2026-10-19)

| ID | Command / check | Result |
|---|---|---|
| V36 | `uv run --frozen pytest -q` | **PASS** — 520 passed (461 unit + 47 integration + 12 security) |
| V37 | `bash scripts/check.sh` | **PASS** — exit 0, all 8 steps; Gitleaks 13 commits, no leaks |
| V38 | `uv run --frozen pytest tests/security tests/unit/test_gateway.py -q` | **PASS** — 31 passed |
| V39 | `uv run --frozen pytest tests/integration/test_gateway_end_to_end.py tests/integration/test_gateway_wiring.py -q` | **PASS** — 5 passed |
| V40 | `uv run --frozen pytest tests/unit/test_policy_self_checks.py tests/integration/test_policy_self_checks_wiring.py -q` | **PASS** — 41 passed; 21 fixtures, 0 failures |

## Definition of Done checklist (blueprint §21 Phase 2)

See `PHASE_2_COMPLETE.md` — all nine DoD items PASS with file/test evidence.

## Handoff

Next eligible phase: **Phase 3 — Input threat defense and context provenance**
(blueprint §21, §§7-8). No blocking preconditions.
