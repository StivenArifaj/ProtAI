# ADR-009: Tool registry, execution authorization, and the enforced gateway

- **Status:** Accepted
- **Date:** 2026-10-19
- **Implementation:** Phase 2

## Context

Blueprint section 12 requires exactly one execution chokepoint: every tool call is
resolved against an explicit registry, evaluated by the deterministic policy engine, and
either denied before any side effect or authorized and executed within bounded limits.
Section 12.4 requires proof of the negative space (unknown/denied/malformed/expired calls
leave the sink unchanged, adapters cannot be invoked outside the gateway); section 14
restricts Phase 2 to mock adapters; section 16.4 requires a durable decision record before
a protected side effect; section 11.3 requires the first deterministic risk factors.
Phase 1 produced decision records over caller-supplied facts; nothing executed. This ADR
records the Phase 2 contract.

## Decision

- **Single chokepoint:** `ToolGateway.invoke_tool` is the only path that evaluates and
  executes. The policy engine remains the sole producer of `ALLOW`; the gateway may only
  downgrade (e.g. an ALLOW whose decision event cannot be persisted becomes
  `BLOCK`/`audit_unavailable`). API routes and the agent runtime (later phases) must call
  the gateway, never an adapter.
- **Registry model:** `ToolRegistration` is immutable and validates at construction:
  stable `tool_id`/`action_id`; strict `ToolArguments`/`ToolResult` subclasses with
  `extra="forbid"`; non-`DESTRUCTIVE` side-effect class; resource-id argument names
  annotated `str`; optional destination argument only for `EXTERNAL_MUTATION`; canonical,
  unique declared destinations; explicit timeout (1-60 s), per-process concurrency bound
  (1-64), and result-size bound (≤1 MiB); approval metadata consistency. The registry
  key is the exact `(tool_id, action_id)` pair; no naming convention is imposed on
  `action_id`.
- **Registry/policy consistency is one-directional:** every tool declared in the policy
  bundle must have a compatible registration, otherwise startup fails. A registration
  absent from the policy is **registered but disabled** — the engine denies it as
  `unknown_tool`. This preserves capability/authorization separation while allowing the
  blueprint's adapter inventory (§14.1, including `mock_files.search`) to exceed the
  starter policy's enabled set (§10.5). Class mismatch, approval-required-without-
  eligibility, enabled egress without declared capability, and policy destinations outside
  the registration's declared set also fail startup.
- **Execution authorization:** adapters require an `ExecutionAuthorization` object that
  can only be created through a private issuer. It carries principal, request, tool,
  action, canonical resource IDs, destination, policy hash, and a SHA-256 action digest
  over the canonical JSON of those fields plus the validated arguments. Adapters recompute
  the digest immediately before the side effect, so post-authorization mutation of any
  bound field fails closed. This is an in-process guardrail, not process isolation against
  malicious code (Phase 10).
- **Gateway flow:** principal/request binding check → exact registration → strict schema
  validation (must also be canonicalizable) → derive resource IDs and destination from
  validated arguments and require caller-declared targets to match → adapter resource
  check (exceptions are treated as not authorized) → `risk-v1` scoring → deadline check
  → real engine evaluation → issue digest → append the `POLICY_EVALUATED` event → on
  `ALLOW` only, execute under the tool timeout and per-process concurrency limit →
  validate result type/canonicalizability/size → append the outcome event. Any engine or
  validation exception becomes a typed no-execution outcome, never a partial result.
- **Risk engine (`risk-v1`):** deterministic weights for side-effect class, external
  destination, and declared data class; sums are capped at 100 and factor codes are
  recorded in the decision/audit payload. No caller-supplied score is accepted. The data
  class is a registration fact in Phase 2; content-level classification/DLP is Phase 6,
  and weight calibration is Phase 9.
- **Audit interface:** `AuditRecorder` is a protocol; `ChainAuditRecorder` delegates to
  the ADR-002 append repository. Events are a typed subset (`POLICY_EVALUATED`,
  `TOOL_EXECUTION_COMPLETED`, `TOOL_EXECUTION_FAILED`) with schema version 1, correlated
  by `call_id`, and carry identifiers, provenance, risk factors, destination, and result
  digests/sizes only — never raw arguments, content, exception messages, or secrets.
  Decision event failure before execution → `BLOCK`/`audit_unavailable`; outcome event
  failure after an executed side effect → `AUDIT_FAILED` with no result returned. A
  denial is kept even if its audit event cannot be written (there is no side effect).
- **Bounds:** per-tool `asyncio.timeout`; per-tool `asyncio.Semaphore` held per running
  event loop (a `WeakKeyDictionary` avoids cross-loop binding); result schema identity,
  canonicalizability, and byte-size checks before any result is returned.
- **Failure vocabulary:** gateway operational failures use `policy_evaluation_error` and
  `audit_unavailable` (added to the observable reason-code contract); typed outcomes are
  `DENIED`, `EXECUTED`, `ADAPTER_FAILED`, `TIMEOUT`, `RESULT_REJECTED`, `AUDIT_FAILED`.
  `ASK_USER` never executes in Phase 2 (approvals are Phase 5).
- **Mock semantics:** all adapters are in-memory and deterministic; email/file reads
  re-check ownership against the gateway-authorization principal; the external sink
  records a content digest and size only, and its egress is disabled in the starter
  policy (enabled only in dedicated test scenarios).

## Consequences

- The no-bypass property is testable and tested: denied, unknown, malformed, expired,
  audit-failed, and unauthorized-direct calls leave the mock sink unchanged; every
  executed call has a durable decision event recorded first and a completed/failed
  outcome event after.
- Registry and policy are both required at startup; drift fails closed. Adding a new
  action requires a registration, a policy entry (or accepting it as disabled), and
  matrix/self-check coverage where applicable.
- The gateway is process-local: it cannot enforce concurrency across workers, and the
  in-memory sink is not shared between processes. Real network isolation and sandboxing
  remain Phase 10; `/v1` routes and rate limiting remain Phase 8.
- `manifest`/intent binding, approvals, content DLP, and the full audit taxonomy/verifier
  are later phases; the digest shape leaves room for approval binding without changing
  the adapter contract.

## References

Blueprint v1.2 sections 11.3-11.4, 12.1-12.4, 14.1, 16.1, 16.3-16.4, 21 (Phase 2);
ADR-002 (audit chain), ADR-007 (self-checks), ADR-008 (policy engine); `tools/base.py`,
`tools/registry.py`, `firewall/gateway.py`, `firewall/risk_engine.py`,
`audit/{models,writer}.py`; `project_memory/phases/PHASE_2_PLAN.md`.
