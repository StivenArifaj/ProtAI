# ADR-015: FastAPI ingress, host-signed principal assertions, and the local model provider

- **Status:** Accepted
- **Date:** 2026-10-28
- **Phase:** 8 (FastAPI integration and local model)
- **Blueprint:** §§8.1-8.4, 9.1-9.4, 16.1, 18.1-18.2, 21 (Phase 8)
- **References:** ADR-001 (host HMAC and resolver guard), ADR-002 (audit chain),
  ADR-003 (no token streaming), ADR-008 (policy authority), ADR-009 (gateway),
  ADR-010 (advisory input defense), ADR-011 (intent manifests), ADR-012 (approvals),
  ADR-013 (output DLP), ADR-014 (audit taxonomy)

## Context

Through Phase 7 every security control existed in-process but no `/v1` business route
called it. Phase 8 must expose the request/tool/approval surface without creating a
second execution path, without trusting client-supplied authority, and without making
the optional local model a policy dependency. The host already authenticates each
`/v1/*` request with the §9.2 HMAC contract and one-time nonce; the principal assertion
that travels inside that signed body still had no typed contract, and the ingress events
in §16.1 still had no producer.

## Decision

### Host-signed principal assertion

`POST /v1/requests`, `POST /v1/tool-calls/evaluate`, and
`POST /v1/approvals/{approval_id}/decision` accept a `principal` object in the exact
signed body:

```json
{
  "iss": "<configured host_id>",
  "aud": "<configured audience>",
  "sub": "<user subject>",
  "tenant_id": "<tenant or null>",
  "roles": ["<role>"],
  "authenticated_at": "<RFC 3339 timestamp>",
  "timezone": "<IANA zone or null>",
  "permissions_context_ref": "<stable host context reference or null>"
}
```

Rules enforced by `identity.assertion` before any principal exists:

- the object is strict (`extra="forbid"`, frozen); there is no `permissions`,
  `decision`, `risk`, or `approval` field, and one is rejected as unknown;
- `iss` must equal the verified key's configured `host_id` and `aud` must equal its
  configured `audience`;
- when the key declares `allowed_tenants`, `tenant_id` is required and must be a
  member; when the list is empty, the key is single-tenant and `tenant_id` must be
  absent;
- `authenticated_at` must be timezone-aware and must not be in the future beyond the
  host-auth timestamp tolerance; freshness of the request itself remains the outer HMAC
  timestamp and nonce, not this evidence timestamp;
- subject/roles/tenant/timezone are validated by the existing `Principal` model
  (control-free text, IANA timezone via `zoneinfo`);
- `permissions_context_ref` defaults to the stable reference
  `host:<host_id>:<subject>`; it is an audit reference, not a permission set.

Rejection is typed and fail-closed: no unsigned fallback, no "best effort" principal,
and no caller-controlled override. The HTTP response is `403` with the stable error code
`principal_rejected`; the specific rejection code is audited as `PRINCIPAL_REJECTED`'s
`error_type`, never reflected with internals. `DevPrincipalResolver` still requires the
HMAC middleware to pass and then ignores every assertion field, so `PRINCIPAL_RESOLVER=dev`
is not an HTTP authentication bypass.

### Ingress audit and one receipt per request

The ingress emits events with the new truthful component `api.ingress`:

1. after the assertion verifies: `REQUEST_RECEIVED`, then `PRINCIPAL_RESOLVED`, both
   bound to the resolved principal and the startup policy version/hash;
2. on assertion rejection: only `PRINCIPAL_REJECTED` (it may omit the unverified
   subject); a failed rejection audit is logged and does not change the denial;
3. after bounded input inspection: `INPUT_INSPECTED` carrying a redacted
   `InputAuditRecord` (trust label, disposition, detector/config versions and hashes,
   content digest/size, finding codes/segments/sources only — never raw text).

If either accepted-request event cannot be persisted, the request is denied with
`503 dependency_unavailable`: an accepted request that cannot be correlated must not
reach intent, policy, or a tool. `ToolGateway.invoke_tool` gains
`receipt_already_audited: bool = False`; the ingress passes `True` so one HTTP request
produces exactly one `REQUEST_RECEIVED` even when the demo runtime makes several tool
calls. The gateway keeps its default behavior for direct in-process callers.

### Routes and response contract

- `POST /v1/requests` is the **sole execution surface**. It generates the server
  `request_id`, verifies the assertion, records the one receipt/resolution pair, runs
  bounded input defense, issues a manifest through `IntentManifestService` only, and
  executes at most the concrete constraints in that manifest through a deterministic,
  bounded demo runtime that receives only `ToolExecutor`.
- Response `state` is one of `COMPLETED`, `NO_ACTION`, `REQUIRES_CLARIFICATION`,
  `REJECTED`, `APPROVAL_REQUIRED`, `DENIED`, or `FAILED`. Approval required is `202`;
  malformed input, denial, rate limit, and dependency failures use explicit non-2xx
  statuses. A clarification/rejection never creates a manifest or executes a tool.
- When a gateway `ASK_USER` action is approval-eligible, the ingress creates the
  approval through `ApprovalService.request` using gateway-produced facts (digest,
  risk, effective data class, resources, destination) and returns the one-time token
  only to the signed host. No approval-creation HTTP route is invented. A risk-based
  `ASK_USER` on a non-approval-eligible registration returns `DENIED`; it is never
  presented as approvable.
- `POST /v1/tool-calls/evaluate` is a **preview**. It runs the same validation, egress
  inspection, risk, and policy steps, records `TOOL_CALL_PROPOSED`,
  `EGRESS_INSPECTED`, and `POLICY_EVALUATED`, and returns the decision/risk. It never
  executes, never consumes an approval, never reserves manifest uses, never issues an
  execution authorization, and never accepts a client decision/risk/approval outcome.
  It does not require a manifest and is not an execution grant.
- `POST /v1/approvals/{approval_id}/decision` accepts only `principal`, `approval_token`
  (in the signed body), and `approve`; it uses the existing row-locked
  `ApprovalService.decide`. The token never appears in a URL, header, log, or audit
  payload. Unknown approvals are `404`, non-pending/expired/self-approval/rule failures
  are `409`, malformed tokens are `400`; every attempt that reaches the service is
  audited by the service. The route uses a read-only safe lookup of the approval's
  `request_id` so ingress and approval events share one correlation id.

### Deadlines, rate limits, and errors

- Every proposal carries `deadline = received_at + REQUEST_TIMEOUT_SECONDS` (default
  30 s, bounded 1-120 s). The gateway closes each tool under its registered timeout;
  the shared deadline prevents a multi-call request from running indefinitely.
- A per-process, per-verified-principal fixed-window limiter covers request creation,
  tool proposals, invalid authenticated requests, and approval decisions
  (`RATE_LIMIT_*_PER_MINUTE`, 1-600). It is explicitly not distributed; a multi-worker
  deployment needs a shared limiter. Exceeding a bucket returns `429 rate_limited`
  without executing anything.
- New route errors use
  `{"error": {"code": "<stable_code>", "message": "<safe text>", "request_id": "<id>"}}`
  and never include stack traces, exception text, signatures, bodies, or secrets.
  Existing middleware denials keep `{"detail": "<stable_code>"}` because that is the
  documented transport-level contract and is asserted by the Phase 0b tests.

### Local model provider

`MODEL_PROVIDER=mock` is the default and requires no network. `MODEL_PROVIDER=local`
opts into an Ollama-compatible client behind the existing `LocalModelIntentExtractor`:

- `LOCAL_MODEL_BASE_URL` must be an origin (no credentials, query, fragment, or
  non-root path); `LOCAL_MODEL_NAME` must be an exact installed model name and must not
  be the placeholder when local is selected;
- outside development/test, a non-loopback base URL must be HTTPS;
- requests are non-streaming, `format=json`, `temperature=0`, bounded output, bounded
  timeout, no redirects, no environment proxy trust, and a fixed `/api/generate`
  path; the response body is size-bounded and parsed as strict JSON;
- every timeout, connection failure, non-200 response, malformed envelope, malformed
  model JSON, or schema violation yields **no manifest** and a typed
  `EXTRACTOR_UNAVAILABLE`/`INVALID_EXTRACTION` result. It can never turn into `ALLOW`,
  skip input/policy/DLP, or supply a decision;
- there is no cloud adapter in v1. `ALLOW_EXTERNAL_MODEL_CALLS=true` refuses startup
  rather than implying a capability that does not exist.

## Alternatives considered

- **Accept a plain `user_id`/`role` body field.** Rejected: §9.1/§9.3 forbid unsigned
  identity and caller-supplied permissions as authority.
- **Let `/v1/tool-calls/execute` exist as a second path.** Rejected: it invites a
  client-supplied decision/approval and duplicates the gateway contract. Preview-only
  evaluation plus `/v1/requests` preserves one execution path.
- **Let the route evaluate policy itself for approvals.** Rejected: the policy engine
  must remain the sole `ALLOW` producer and the gateway must remain the only execution
  path.
- **Treat a missing local model as "use mock".** Rejected: silent fallback hides an
  outage and changes behavior; an unavailable optional provider yields no manifest.
- **Use a distributed rate limiter now.** Deferred: v1 is single-process; the
  limitation is documented and the interface is replaceable.

## Consequences

- The HTTP surface now has a complete, signed request→intent→gateway→response path and
  two non-executing support routes.
- `AuditEvent.component` gains `api.ingress`; `INPUT_INSPECTED` gains a redacted input
  record. Both are additive within `schema_version=1`; canonical bytes and the hash
  formula are unchanged.
- `/v1/requests` can return an approval token once; token delivery to the end user and
  approval UI/notification remain host responsibilities (known limitation).
- The mock runtime is intentionally narrow (documented demo intents only). General
  agent planning is not implemented; the local model only extracts intent and cannot
  execute.
- Multi-worker rate limiting, shared approval delivery, and real connectors remain
  future work.

## Verification

- Unit/integration tests prove: valid signed assertion resolves; wrong issuer,
  audience, tenant, future auth time, malformed/extra fields, and unsigned fallbacks
  are rejected; rejection produces only `PRINCIPAL_REJECTED`; accepted request
  produces exactly one `REQUEST_RECEIVED` regardless of tool-call count; client
  `decision`/`risk`/`approval` fields are rejected; input inspection is audited with
  no raw text; offline mock request completes; provider failure yields no manifest and
  no execution; rate limits return `429` without side effects; approval decision is
  row-locked, token-bound, and audited; preview creates no execution/approval
  consumption.
- `bash scripts/check.sh` remains the release gate (pytest, mypy, ruff, Alembic,
  Gitleaks, prohibited patterns).
