# Phase 8 — HTTP Ingress, Bounded Runtime, and Local Model: COMPLETE — VERIFIED

**Completed:** 2026-10-28
**Blueprint:** v1.2 §§7, 8, 11, 18, 20.2 #2/#10/#11/#14/#16/#21, §21 Phase 8
**ADR:** [../../docs/adr/ADR-015-fastapi-ingress-principal-and-local-model.md](../../docs/adr/ADR-015-fastapi-ingress-principal-and-local-model.md)
**Integration contract:** [../../docs/API_INTEGRATION.md](../../docs/API_INTEGRATION.md)
**Evidence:** V72–V75 in [../TESTING_AND_VERIFICATION.md](../TESTING_AND_VERIFICATION.md)
**Commits:** `5e20075` (ADR-015), `edda8ea` (principal assertion/resolver),
`2bdf30f` (input audit evidence), `b561dd6` (gateway preview support), `2fa66fe`
(settings), `f0f9b6b` (format), `940600e` (signed routes), `b4f8357` (local provider + settings wiring), and
`2f84269` (docs/memory).

## Definition of Done — verdict

| Criterion | Status | Evidence |
|---|---|---|
| Local/mock path works offline | PASS | `MODEL_PROVIDER=mock` is the default and performs no network I/O; the full suite and gate run offline with mock adapters, the mock extractor, and the local PostgreSQL container. The optional local provider is opt-in and startup performs no provider I/O |
| No route trusts client-supplied decisions | PASS | Requests accept only the signed principal and text; the preview accepts tool/action/arguments and returns facts; the decision route accepts only the assertion, one-time token, and boolean. Request/call ids, deadlines, decisions, risk facts, approval outcomes, resources, and destinations are server-derived; strict bodies reject unknown fields |
| Optional model-provider failures do not bypass policy | PASS | Provider timeout/connection/non-200/malformed envelope/output yields no manifest; `/v1/requests` returns `503 model_unavailable` with `INTENT_FAILED` and no `TOOL_CALL_PROPOSED`/execution events. A successful provider path still runs the full gateway (integration test asserts policy and execution events) |
| Policy remains the sole `ALLOW` producer; the gateway is the only execution path | PASS | Ingress, input defense, intent, DLP, and approvals can only reject/narrow/gate/raise sensitivity; `DemoRuntime` receives only a `ToolExecutor`; the preview route never executes or consumes |
| Approval decision is one-time, bound, and audited | PASS | Token only in the signed body, digest comparison, tenant/requester/rule checks, `SELECT ... FOR UPDATE`, same-transaction `APPROVAL_DECIDED`, replay/expiry/not-pending conflicts |
| Ingress audit events are emitted once and are redacted | PASS | Accepted request: exactly one `REQUEST_RECEIVED` then `PRINCIPAL_RESOLVED`, `INPUT_INSPECTED`; rejected assertion: only `PRINCIPAL_REJECTED`; raw text/email/token values never appear in audit payloads |
| Rate limits and request deadlines fail closed | PASS | Four per-principal buckets; authenticated invalid bodies are charged and exhaustion returns `429`; unverifiable principals are never charged; tool-call slots are reserved atomically before a plan runs |
| All prior suites and the 8-step gate stay green | PASS | V72–V74: **949 passed** (782 unit + 122 integration + 45 security), mypy 73 files, ruff clean (188 files), Gitleaks clean (48 commits), no migration added |
| ADR-008 through ADR-015 boundaries untouched | PASS | Policy remains the sole `ALLOW` producer; the gateway remains the only execution path; intent/input defense/DLP only narrow/gate/raise; approval only makes an engine `ASK_USER` executable; audit is never an authorization input; no client-supplied decision is trusted |

## Delivered

### Host-signed principal assertion (`src/ai_security/identity/assertion.py`)

- Strict `PrincipalAssertion` in the exact signed body with fields `iss`, `aud`, `sub`,
  `tenant_id`, `roles`, `authenticated_at`, `timezone`, and optional
  `permissions_context_ref`; `extra="forbid"`.
- `iss` must equal the signing key's `host_id`; `aud` must equal its `audience`;
  `tenant_id` is required and must be allowed when the key has `allowed_tenants`, and must
  be absent when the key has none. A future `authenticated_at` beyond tolerance is
  rejected.
- Every rejection is `403 principal_rejected`, audited once as `PRINCIPAL_REJECTED` with
  a stable `error_type`; no unsigned fallback. `DevPrincipalResolver` remains HMAC-gated
  and ignores the assertion.

### Signed routes (`src/ai_security/api/routes_requests.py`)

- `POST /v1/requests` is the only execution surface. It validates the body, resolves the
  principal, emits exactly one receipt then `PRINCIPAL_RESOLVED`, runs input inspection
  (recording redacted `INPUT_INSPECTED`), issues an in-process intent manifest, creates
  an approval in-process for an approval-eligible `ASK_USER`, and executes only the
  bounded plan through the gateway.
- `POST /v1/tool-calls/evaluate` runs the same validation/egress/risk/policy facts but
  never executes, consumes a manifest use, consumes an approval, or issues an
  authorization. It does not require a manifest.
- `POST /v1/approvals/{approval_id}/decision` accepts the token only in the signed body,
  enforces the approver rule/tenant/self-approval checks, locks the row, and audits the
  decision in the same transaction; it never resumes or executes the action.
- States: `COMPLETED`, `NO_ACTION`, `REQUIRES_CLARIFICATION`, `REJECTED`,
  `APPROVAL_REQUIRED` (HTTP 202), `DENIED`, `FAILED`.
- New-route errors use `{"error": {"code", "message", "request_id"}}` (some add
  `state`); middleware denials keep `{"detail": "<stable_code>"}`.

### Bounded runtime (`src/ai_security/api/runtime.py`)

- Receives only a `ToolExecutor`; never an adapter, registry, policy engine, or approval
  service.
- Executes exactly `mock_email.read` for one `email-N` followed by `text.summarize`;
  both constraints must have `max_uses=1`. A time window or any unsupported constraint
  shape returns `NO_ACTION`.
- Reserves every planned tool-call rate-limit slot before the first call so a partially
  available bucket cannot execute an unbounded prefix.

### Ingress controls (`errors.py`, `rate_limit.py`, `schemas.py`, `ingress.py`)

- Four per-process, per-verified-principal fixed-window buckets (requests, tool calls,
  authenticated invalid requests, approval decisions) default to 60/120/30/30 per minute.
- Only authenticated schema-invalid bodies are charged to the invalid-request bucket;
  unverifiable principals are never charged; exhaustion returns `429 rate_limited`.
- `REQUEST_TIMEOUT_SECONDS` (1–120, default 30) bounds the tool proposal deadline.
- Input `REJECT`/`QUARANTINE` stops before intent; `FLAG`/`PASS` continue.

### Optional local model (`src/ai_security/intent/providers.py`)

- `MODEL_PROVIDER=mock` is the offline default. `local` selects
  `OllamaIntentModelClient` behind `LocalModelIntentExtractor`.
- Origin-only `LOCAL_MODEL_BASE_URL` (HTTPS outside development unless loopback), exact
  `LOCAL_MODEL_NAME`, fixed non-streaming `POST /api/generate` with `format=json` and
  `temperature=0`, no redirects, no environment proxy trust, 1 MiB envelope cap, 64 KiB
  output cap, and a 1–60 s per-attempt timeout.
- Strict UTF-8/content-type/envelope parsing with duplicate-key rejection.
- Every provider failure yields no manifest and `503 model_unavailable`; no tool,
  policy, DLP, approval, or execution step is reached. No cloud adapter exists;
  `ALLOW_EXTERNAL_MODEL_CALLS=true` refuses startup.

### Documentation

- New `docs/API_INTEGRATION.md` documents host signing, the principal assertion, all
  three routes, states, error codes, rate-limit buckets, local-model setup, audit
  correlation, and known limitations.
- Updated `README.md`, `ARCHITECTURE.md`, `KNOWN_LIMITATIONS.md`, `THREAT_MODEL.md`,
  `IMPLEMENTATION_STATE.md`, `SECURITY_INVARIANTS.md`, `DECISIONS.md`, and memory.

## Decisions and limitations (honest)

- The runtime is a fixed two-call demo plan, not a planner. There is no general tool
  chaining, retry-with-model, or real connector.
- Approved actions are **not resumable** through `/v1/requests` in Phase 8; the decision
  route records a durable, audited decision and gateway consumption input, but no route
  carries an approval id into execution.
- Rate limits are per process and in memory; N workers multiply each limit by N.
- The local model is optional, uncalibrated, and never an authorization input. It
  receives inspected request text only; tool output is not fed back into a prompt.
- No cloud model adapter, streaming, approval delivery/UI, revocation, background expiry
  sweeper, distributed limiter, model-prompt DLP, process sandbox, or external audit
  anchor exists.

## Verification (V72–V75)

- V72: full suite — **949 passed** (782 unit + 122 integration + 45 security).
- V73: `uv lock --check`; mypy clean (73 source files); ruff lint clean; 188 files
  formatted.
- V74: pre-commit `bash scripts/check.sh` — PASS, exit 0, all 8 steps; 949 tests;
  Gitleaks 8.30.1 dir+git "no leaks found" (48 commits scanned); prohibited-pattern and
  constant-time-confinement checks clean.
- V75: targeted Phase 8 suites — PASS (route contracts, rate limits, approval decisions,
  preview non-execution, provider strictness/failure mapping, assertion binding, settings
  bounds).
- Phase 8 adds no migration; Alembic head remains `f7a8b9c0d1e2`.

## Next

Phase 9 — evaluation and calibration (blueprint §§20–21): labeled fixtures and honest
metrics for injection detection, DLP false positives/negatives, and risk-score
calibration. See [../NEXT_SESSION.md](../NEXT_SESSION.md).
