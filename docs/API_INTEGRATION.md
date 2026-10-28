# API Integration Guide (Phase 8)

This guide describes the signed HTTP surface implemented in Phase 8 (blueprint §18.1,
ADR-015). It is an integration contract for a trusted host application; it is not a
public API and it does not add a second execution path.

## Ground rules

- **Only `POST /v1/requests` can execute a tool.** `POST /v1/tool-calls/evaluate` is a
  non-executing policy preview. `POST /v1/approvals/{approval_id}/decision` records a
  human decision but never resumes or executes the approved action.
- **Every `/v1/*` request is host-authenticated and body-signed.** The application
  generates the request id, call ids, deadlines, decisions, risk facts, and approval
  outcomes. A client cannot submit any of those fields; unknown fields are rejected.
- **The principal assertion is inside the signed body.** It is verified against the
  host key record that signed the request. There is no unsigned fallback and no
  dev-resolver bypass in a host-configured deployment.
- **The gateway remains the only execution path.** Policy is the sole `ALLOW` producer;
  input defense, intent extraction, DLP, and approvals can only reject, narrow, gate, or
  raise sensitivity. `/v1/tool-calls/evaluate` never creates an execution grant.
- **New route errors use one envelope:**
  `{"error": {"code": "<stable_code>", "message": "<safe text>", "request_id": "<id>"}}`.
  Some outcomes also include `state`. Transport-level middleware denials keep the older
  `{"detail": "<stable_code>"}` shape.

## Host authentication

Every route under `/v1/` requires four headers and a one-time nonce:

| Header | Value |
|---|---|
| `X-Gateway-Key-Id` | Configured key id |
| `X-Gateway-Timestamp` | Unix seconds, ASCII digits |
| `X-Gateway-Nonce` | 32-128 characters from `[A-Za-z0-9_-]` |
| `X-Gateway-Signature` | Lowercase HMAC-SHA256 hex |

The signed message is newline-joined UTF-8 with no trailing newline:

```text
v1
<key_id>
<METHOD>
<PATH>
<timestamp>
<nonce>
<sha256_hex(exact raw body bytes)>
```

`Content-Type` must be `application/json`. The signature covers the exact bytes sent;
re-serializing the JSON after signing invalidates it. Replay, stale timestamps, unknown
keys, a mutated body, and an oversized body are rejected before routing.

Python host example:

```python
import json

from ai_security.identity.signing import sign_request

key_id = "host-key-1"
body = json.dumps(
    {
        "principal": {
            "iss": "host-service",
            "aud": "ai-agent-security-gateway",
            "sub": "user-123",
            "tenant_id": "tenant-a",
            "roles": ["analyst"],
            "authenticated_at": "2026-10-28T10:00:00Z",
            "timezone": "Europe/Berlin",
        },
        "text": "read email-1 and summarize it",
    },
    separators=(",", ":"),
).encode("utf-8")

signature = sign_request(
    secret,
    key_id=key_id,
    method="POST",
    path="/v1/requests",
    body=body,
)
headers = {**signature.as_headers(), "Content-Type": "application/json"}
# POST body to /v1/requests with these headers.
```

## Principal assertion

The `principal` object has exactly these fields (`extra="forbid"`):

| Field | Required | Rule |
|---|---|---|
| `iss` | yes | Must equal the signing key's configured `host_id`. |
| `aud` | yes | Must equal the signing key's configured `audience`. |
| `sub` | yes | Host's stable subject id (1-256 chars). |
| `tenant_id` | conditional | Required and allowed by the key when `allowed_tenants` is non-empty; must be absent when it is empty. |
| `roles` | yes | List of role strings; input to local policy/approver rules, never a permission grant. |
| `authenticated_at` | yes | ISO-8601 timestamp with timezone; a future time beyond tolerance is rejected. |
| `timezone` | yes | IANA timezone name; used only for relative-date resolution. |
| `permissions_context_ref` | no | Opaque bounded host reference; not an authorization input. |

A rejected assertion returns `403 principal_rejected` and emits exactly one
`PRINCIPAL_REJECTED` audit event with a stable `error_type`. No tool, intent, or policy
step runs.

## `POST /v1/requests` — the sole execution surface

Request body:

```json
{
  "principal": { "...": "signed assertion" },
  "text": "read email-1 and summarize it"
}
```

`text` is 1-32 KiB of UTF-8, must not be blank, and is inspected by input defense before
intent extraction. Content that is rejected or quarantined returns `403` with
`input_rejected` or `input_quarantined` and never reaches the model or a tool.

The installed runtime is deliberately narrow. It executes exactly one supported plan:
`mock_email.read` for one `email-N` resource, followed by `text.summarize`; both
constraints must have `max_uses=1`. A manifest with a relative time window or any other
constraint shape returns `NO_ACTION` (nothing executes). This is a demo runtime, not a
general planner.

Success and application states:

| HTTP | `state` | Meaning |
|---|---|---|
| 200 | `COMPLETED` | The supported read-then-summarize plan executed; `result` contains `email_id`, `summary`, `original_chars`, `truncated`. |
| 200 | `NO_ACTION` | A valid intent produced no supported executable plan. |
| 200 | `REQUIRES_CLARIFICATION` | The request was not concrete enough; `clarification` explains what is missing. Nothing executed. |
| 202 | `APPROVAL_REQUIRED` | A policy `ASK_USER` action is approval-eligible. `approval` contains the approval id, one-time token, expiry, and required approver rule. Nothing executed. |
| 403 | error | Rejected, denied, or not approval-eligible. |
| 424/429/5xx | error | See the error table. |

The approval token is returned **once** in the 202 response. The host must deliver it to
the approver over a trusted channel; it is stored only as a SHA-256 digest. There is no
approval-creation route.

## `POST /v1/tool-calls/evaluate` — preview only

Request body:

```json
{
  "principal": { "...": "signed assertion" },
  "tool_id": "mock_email.read",
  "action_id": "read",
  "arguments": {"email_id": "email-1"}
}
```

This runs the same registry/binding/argument/egress/risk/policy evaluation as the gateway,
but it never executes, never consumes a manifest use, never consumes an approval, and
never issues an execution authorization. It does not require a manifest. The response
contains the decision, reason, risk summary, policy version/hash, effective data class,
side-effect class, and approval eligibility facts. `decision=ALLOW` here is **not** an
execution grant; only `/v1/requests` executes.

## `POST /v1/approvals/{approval_id}/decision`

Request body:

```json
{
  "principal": { "...": "signed assertion" },
  "approval_token": "one-time token from the 202 response",
  "approve": true
}
```

The token travels only in the signed body — never in a header, URL, log, or audit field.
The deciding principal must satisfy the approval's configured approver rule and tenant
scope; self-approval is refused unless policy explicitly allows it. The decision is
row-locked, one-time, and audited (`APPROVAL_DECIDED`), and the route reuses the original
approval `request_id` for correlation without emitting a second `REQUEST_RECEIVED`.

| HTTP | `error.code` | Meaning |
|---|---|---|
| 200 | — | Recorded as `approved` or `denied`. |
| 400 | `approval_token_invalid` | Token does not match the stored digest. |
| 404 | `approval_not_found` | Unknown id, or an id outside the principal's tenant scope. |
| 409 | `approval_expired` | The approval TTL elapsed. |
| 409 | `approval_not_pending` | Already decided or consumed. |
| 409 | `approval_not_eligible` | Principal does not satisfy the approver rule. |
| 409 | `self_approval_forbidden` | Requester tried to approve their own action. |

**Approved actions are not resumable through `/v1/requests` in Phase 8.** The route has
no client-supplied approval field, so an approval is a durable, audited decision record
and gateway consumption input, but re-running the approved action requires an
in-process caller that supplies the approval id to the gateway. Automatic resumption is
future work.

## Error codes

| HTTP | Code | Notes |
|---|---|---|
| 400 | `invalid_request` | Schema failure; validation details are not reflected. |
| 400 | `approval_token_invalid` | Decision route only. |
| 403 | `principal_rejected` | Signed assertion failed verification. |
| 403 | `input_rejected` | Input inspection disposition `REJECT`. |
| 403 | `input_quarantined` | Input inspection disposition `QUARANTINE`. |
| 403 | `request_rejected` | Intent extractor rejected the request. |
| 403 | `policy_denied` | Gateway/policy denied; nothing executed. |
| 403 | `approval_not_allowed` | `ASK_USER` action is not approval-eligible. |
| 404 | `approval_not_found` | Decision route only. |
| 409 | `approval_expired` / `approval_not_pending` / `approval_not_eligible` / `self_approval_forbidden` | Decision route only. |
| 409 | `approval_not_approvable` | No eligible approver can satisfy the rule; no approval was created. |
| 415 | `unsupported_media_type` | Body was not `application/json`. |
| 429 | `rate_limited` | A per-principal fixed-window bucket is exhausted. |
| 500 | `internal_error` | Safe internal failure; no details. |
| 502 | `model_invalid_response` | Extractor returned no usable result. |
| 502 | `response_blocked` | Output inspection suppressed the complete result. |
| 502 | `tool_execution_failed` | Adapter failure, timeout, or rejected result. |
| 502 | `invalid_tool_result` | Adapter returned an unexpected result type. |
| 502 | `tool_evaluation_failed` | Approval/preview facts were incomplete internally. |
| 503 | `model_unavailable` | Local model/provider unavailable; no manifest. |
| 503 | `audit_unavailable` | Required audit persistence failed; execution/result withheld. |
| 503 | `dependency_unavailable` | Approval storage or limiter failed closed. |
| 504 | `request_timeout` | The request deadline was exceeded before execution. |

Rate-limit buckets (per process, per verified principal, fixed 60 s window):

- `RATE_LIMIT_REQUESTS_PER_MINUTE` (default 60)
- `RATE_LIMIT_TOOL_CALLS_PER_MINUTE` (default 120; a two-call plan reserves both slots
  atomically)
- `RATE_LIMIT_INVALID_REQUESTS_PER_MINUTE` (default 30; only authenticated invalid bodies)
- `RATE_LIMIT_APPROVAL_DECISIONS_PER_MINUTE` (default 30)

`REQUEST_TIMEOUT_SECONDS` (1-120, default 30) bounds the tool proposal deadline for a
request. The local-model timeout is a separate per-attempt budget.

## Local model configuration

`MODEL_PROVIDER=mock` is the default and requires no network. `MODEL_PROVIDER=local`
selects a strict Ollama-compatible client behind `LocalModelIntentExtractor`:

```bash
MODEL_PROVIDER=local
LOCAL_MODEL_BASE_URL=http://127.0.0.1:11434   # origin only, no path/query/fragment
LOCAL_MODEL_NAME=llama3.2:3b                  # exact installed model, never the placeholder
LOCAL_MODEL_TIMEOUT_SECONDS=10                # per attempt, 1-60
```

The client sends one non-streaming `POST {origin}/api/generate` with
`{"model", "prompt", "format": "json", "stream": false, "options": {"temperature": 0}}`,
refuses redirects and environment proxies, bounds the envelope (1 MiB) and model output
(64 KiB), and parses strict JSON with duplicate-key rejection. Every timeout, connection
failure, non-200 response, malformed envelope, malformed model JSON, or schema violation
yields no manifest. The request route maps that to `503 model_unavailable`; no tool,
policy step, DLP step, or approval is reached.

`ALLOW_EXTERNAL_MODEL_CALLS=true` is refused at startup: v1 has no cloud adapter, so the
setting would imply a capability that does not exist.

## Audit and correlation

- One accepted `POST /v1/requests` emits exactly one `REQUEST_RECEIVED`, then
  `PRINCIPAL_RESOLVED`, `INPUT_INSPECTED`, and `INTENT_CREATED`/`INTENT_FAILED`.
- Each executed tool call emits `TOOL_CALL_PROPOSED`, `EGRESS_INSPECTED`,
  `POLICY_EVALUATED`, `TOOL_EXECUTION_STARTED`, `TOOL_EXECUTION_COMPLETED`, and
  `OUTPUT_INSPECTED`, then `RESPONSE_RELEASED` or `RESPONSE_SUPPRESSED`.
- Raw request text, email content, approval tokens, and exception text never appear in
  audit payloads. Input evidence carries redacted findings/digests only.
- The `request_id` in the response is the audit correlation key. The preview route emits
  receipt/principal/proposal/egress/policy events without execution events. The decision
  route reuses the approval's original request id.

## Known limitations

See `docs/KNOWN_LIMITATIONS.md`. In particular: the runtime is a two-tool demo; there are
no real connectors; rate limits are per process (no shared store); approval token
delivery and UI are host responsibilities; approved actions are not resumable through
HTTP; streaming is disabled; and the local model is optional, uncalibrated, and never an
authorization input.
