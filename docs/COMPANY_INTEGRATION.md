# ProtAI Company Integration Architecture

**Status:** Architecture and requirements document — v1 boundary respected.
**Scope:** Describes how a real company would connect an existing AI agent to ProtAI.
Compares integration patterns, explains security property preservation, identifies what
is implemented vs. what needs development, and includes an incremental pilot deployment.
No frontend, no invented API routes, no claimed capabilities that do not exist.

## 1. Integration Patterns

Three integration patterns are compared. Pattern (a) is the v1 reference implementation
(mock adapters, bounded demo runtime). Patterns (b) and (c) require additional
development for real company connectors.

### Pattern A: Agent-Framework Adapter (in-process library)

The company's agent framework (e.g., LangChain, AutoGen, Semantic Kernel, or a custom
planner) links against a ProtAI client library that wraps every tool call. The agent
does not call tools directly; it calls through the adapter, which forwards to ProtAI's
enforced gateway.

```
Agent Framework
       |
       v
ProtAI Client Adapter  <-- proposed library; not implemented
       |
       v
ProtAI Enforced Gateway (invoke_tool)
       |
       v
Mock Adapter / Real Connector
```

**How security properties are preserved:**

| Property | Mechanism |
|---|---|
| Identity | Host-signed principal assertion binds `iss`/`aud`/`tenant`/`sub`/`roles` |
| Tenant binding | Principal's `tenant_id` is checked on every gateway/approval operation |
| Authorization | Policy engine is the sole `ALLOW` producer; adapter cannot bypass |
| Tool validation | Exact `(tool_id, action_id)` registry resolution; strict argument schemas |
| Deterministic policy | Engine evaluation is deterministic, versioned, and audited |
| DLP | Mandatory output DLP on arguments and results; egress inspection before execution |
| Auditing | Full structured audit lifecycle; hash-chained append |
| Fail-closed | Audit outage, engine error, invalid state → BLOCK; no adapter call |

**v1 status:** The gateway and mock adapters exist and are tested. A production
agent-framework adapter library does not exist; it must be built per company framework.

**Bypass prevention:** The adapter is a client-side convenience only. The gateway
re-validates everything; a malicious or compromised adapter cannot forge an `ALLOW`
because the engine is server-side and the adapter never produces authorization.

---

### Pattern B: Centralized Enforcement Service

ProtAI runs as a centralized service (the current `ai_security.api.app` FastAPI
application). The company's agent application calls ProtAI over HTTP (the signed
`/v1` API). ProtAI enforces policy and calls the company's tools through registered
adapters.

```
Company Agent Application
       |
       v  (signed HTTP /v1/requests)
ProtAI Enforcement Service
       |
       v  (registered adapter)
Company Tool / Connector
```

**How security properties are preserved:**

| Property | Mechanism |
|---|---|
| Identity | Host HMAC auth + signed principal assertion on every `/v1/*` request |
| Tenant binding | Principal `tenant_id` enforced in gateway, approval, and audit |
| Authorization | Policy engine sole `ALLOW` producer; service is the only execution path |
| Tool validation | Registry resolution + strict arguments before any adapter call |
| Deterministic policy | Versioned policy bundle with startup self-checks |
| DLP | Output DLP before result release; egress DLP before execution |
| Auditing | Every request → proposal → decision → execution → output → response is audited |
| Fail-closed | Middleware, nonce store, and audit failures → 401/403/503; never fail-open |

**v1 status:** Fully implemented as the reference deployment. The signed `/v1` API,
host auth, gateway, mock adapters, audit chain, and approval workflow all exist.

**Bypass prevention:** The agent application never calls tools directly; all tool
execution goes through `POST /v1/requests` → gateway → adapter. The gateway validates
the action digest, policy, manifest constraints, and DLP before any adapter is invoked.

---

### Pattern C: Tool-Server / Protocol Integration

The company exposes tools through a tool server or protocol (e.g., MCP, OpenAPI, or a
custom RPC). ProtAI's gateway calls the tool server, which performs the actual side
effect. ProtAI enforces policy before the call and DLP after the result.

```
Company Agent
       |
       v  (/v1/requests)
ProtAI Gateway
       |
       v  (adapter → tool server)
Tool Server / Protocol (MCP, OpenAPI, RPC)
       |
       v  (actual side effect)
Company Tool / System
```

**How security properties are preserved:**

| Property | Mechanism |
|---|---|
| Identity | Principal assertion propagated to tool server (via adapter) |
| Tenant binding | Tenant checked in gateway; tool server should also enforce |
| Authorization | Gateway policy must `ALLOW` before adapter calls tool server |
| Tool validation | Gateway validates `(tool_id, action_id)` + arguments; tool server validates its own protocol |
| Deterministic policy | Gateway engine decision is deterministic and audited |
| DLP | Gateway DLP on arguments before call; output DLP on result before release |
| Auditing | Full lifecycle audited at gateway; tool server logs are separate |
| Fail-closed | Gateway denies on any failure; tool server failure → `ADAPTER_FAILED`, result suppressed |

**v1 status:** Not implemented. No MCP, OpenAPI, or RPC tool-server adapter exists. The
mock adapters (`mock_email.read`, `mock_files.read`, `text.summarize`,
`mock_external_sink.write`) are in-process, deterministic, and have no network access.

**Bypass prevention:** The tool server must not accept direct calls that bypass ProtAI.
Network segmentation, authentication between ProtAI and the tool server, and tool-server
enforcement of the same principal/tenant are required. This is company-specific
development work (post-v1).

---

### Pattern Comparison

| Criterion | Pattern A (Adapter) | Pattern B (Centralized Service) | Pattern C (Tool Server) |
|---|---|---|---|
| v1 implemented? | Partially (gateway + mocks) | **Yes** (reference) | **No** |
| Best for | In-process agent frameworks | HTTP-integrated agent apps | Distributed tool ecosystems |
| Bypass risk | Adapter must not be the only enforcement | Low — gateway is the chokepoint | Medium — tool server must enforce too |
| Network dependency | None (in-process) | HTTP to ProtAI | HTTP to tool server |
| Company dev effort | Build adapter library | Integrate with `/v1` API | Build tool server + adapter |
| Trust boundary | Process boundary | HTTP boundary | HTTP + protocol boundary |

**Recommendation:** Pattern B (centralized enforcement service) is the v1 reference and
the recommended starting point for company integration. Pattern A is appropriate when
the agent framework runs in the same process as ProtAI. Pattern C requires the most
company-specific development and should only be adopted after Pattern B is validated.

---

## 2. Preserving Identity, Tenant Binding, Authorization, and Fail-Closed Behavior

### Identity

ProtAI authenticates the **host**, not the end user. The host-signed principal assertion
contains `iss` (host_id), `aud` (audience), `sub` (subject), `tenant_id`, `roles`,
and `authenticated_at`. The host owns end-user authentication; ProtAI trusts the
host's assertion after HMAC verification.

**Company integration requirement:** The company's host application must authenticate
its end users and assert the verified principal to ProtAI. ProtAI does not provide
end-user login, OAuth, or session management.

### Tenant Binding

Every `Principal` carries a `tenant_id`. The gateway, approval service, and audit
repository all enforce tenant matching:

- Gateway: resource authorization checks tenant scope
- Approval: `row.tenant_id != approver.tenant_id` → `not_eligible`; `requester_subject_id` must match
- Audit: `principal_subject_id` is recorded on every event

**Company integration requirement:** The company's host must provision tenants and bind
principals to tenants. ProtAI does not manage tenants.

### Authorization

Policy is the sole `ALLOW` producer. The engine evaluates:

1. Principal resolved → tool membership → side-effect class match → arguments → hard deny →
   resource scope → destination → matrix rows with thresholds

No caller-supplied `ALLOW`, risk score, or approval outcome can override policy.
Approval is a gate for `ASK_USER` decisions only; it never produces `ALLOW`.

**Company integration requirement:** The company's security administrator authors policy
documents (`config/policies.yaml`) that define which tools/actions are allowed for which
principals/roles. ProtAI does not provide a policy editor UI in v1.

### DLP

Mandatory output DLP inspects:

- Tool-bound arguments before execution (egress DLP)
- Complete buffered results before release (output DLP)

Findings are deterministic pattern matches (canary, private key, API key, credential
assignment, email). Outcomes: `PASS` (release), `REDACT` (span-preserving), `BLOCK` /
`REVIEW` / inspection failure (suppress).

**Company integration requirement:** The company configures DLP patterns and the
destination trust map in `config/output_dlp.yaml`. No classifier/entropy/semantic
detection exists in v1.

### Auditing

Every action produces a structured audit event: `REQUEST_RECEIVED` →
`PRINCIPAL_RESOLVED` → `INPUT_INSPECTED` → `TOOL_CALL_PROPOSED` →
`POLICY_EVALUATED` → (`APPROVAL_CONSUMED` if applicable) →
`TOOL_EXECUTION_STARTED` → `TOOL_EXECUTION_COMPLETED`/`_FAILED` →
`OUTPUT_INSPECTED` → `RESPONSE_RELEASED`/`_SUPPRESSED`.

Events are hash-chained (ADR-002) and verifiable (`verify_chain`). Payloads carry
identifiers, digests, and sizes only — never raw content or secrets.

**Company integration requirement:** The company queries `audit_events` directly (read-only
SQL) or uses `verify_chain()`. No audit query API exists in v1. No external checkpoint
exists; truncation of newest events is undetectable without one (documented limitation).

### Fail-Closed Behavior

- Host auth failure → 401/403; no route processing
- Nonce store failure → 503 (never fail-open)
- Audit append failure on would-be `ALLOW` → `BLOCK`/`audit_unavailable`; no adapter call
- Engine error → `BLOCK`/`policy_evaluation_error`
- Detector/provider outage → `DETECTOR_UNAVAILABLE` / `503 model_unavailable`
- DLP inspection failure → `BLOCK`/`dlp_inspection_failed`
- Invalid arguments → `BLOCK`/`invalid_arguments`

**Company integration requirement:** The company must treat `503` responses as
"do not execute" and not implement retry logic that could bypass enforcement.

---

## 3. What Is Implemented vs. What Needs Development

### Implemented in v1

| Component | Status |
|---|---|
| Host HMAC authentication + replay rejection | Implemented (Phase 0b/8) |
| Signed principal assertion | Implemented (Phase 8) |
| Deterministic policy engine | Implemented (Phase 1) |
| Enforced gateway (`invoke_tool`) | Implemented (Phase 2) |
| Tool registry + mock adapters | Implemented (Phase 2) |
| Risk-v2 scoring | Implemented (Phase 5) |
| Durable one-time approvals | Implemented (Phase 5) |
| Output DLP + egress policy | Implemented (Phase 6) |
| Hash-chained audit + verifier | Implemented (Phase 7) |
| Signed `/v1` routes | Implemented (Phase 8) |
| Bounded demo runtime | Implemented (Phase 8) |
| Deterministic alert rules | Implemented (Phase 10) |
| Optional read-only summarizer | Implemented (Phase 10, opt-in) |
| Abuse/load tests | Implemented (Phase 10) |
| Incident runbooks | Implemented (Phase 10) |
| CycloneDX SBOM | Implemented (Phase 10) |
| Release gate | Implemented (Phases 0a-10) |

### Needs Development (Post-v1)

| Component | Effort | Notes |
|---|---|---|
| Real company connectors (email, files, databases, SaaS) | High | Each connector needs a threat-model review, permission design, secret handling, egress policy |
| Agent-framework adapter library | Medium | Per framework (LangChain, AutoGen, etc.) |
| Approval delivery/UI/notification | High | No UI exists in v1; company must build |
| Audit query API | Medium | No query API in v1; direct SQL only |
| Alert dashboard/UI | High | No UI exists in v1 |
| Approval revocation | Medium | Lazy expiry only in v1 |
| Approved-action resumption | High | No client approval field in v1 |
| Distributed/shared rate limiter | Medium | Per-process only in v1 |
| External audit checkpoint | High | For tamper-proofing beyond local chain |
| Process isolation/sandbox | High | In-process guardrail only in v1 |

### Preventing Direct Tool-Call Bypass

The gateway is the **only** execution path. To prevent bypass:

1. **No direct adapter access:** Tool adapters are only invocable through `ToolGateway.invoke_tool()`.
2. **Execution authorization is digest-bound:** `ExecutionAuthorization` is sentinel-guarded; adapters verify the digest before side effects.
3. **No client-supplied authority:** The API rejects `decision`, `risk`, `approval`, `call_id`, `target_resource_ids`, `destination`, `deadline`, or `request_id` from clients.
4. **Policy is the sole `ALLOW` producer:** Input detection, intent, DLP, and approvals can only narrow/gate/raise sensitivity — never authorize.
5. **Registry consistency:** Every policy-declared tool must have a compatible registration at startup; unregistered tools are `unknown_tool` → denied.

**Company responsibility:** When building real connectors (Pattern C), the company must ensure
tool servers cannot be called directly without ProtAI authorization. Network segmentation,
mutual TLS, and tool-server-side principal/tenant enforcement are required.

---

## 4. Incremental Pilot Deployment

### Pilot Scope

**One agent + one narrowly scoped tool:**

- **Agent:** A company-internal assistant that reads employee directory entries
- **Tool:** `directory.read` — reads one employee record by ID (READ_ONLY, no external
  destination, no egress)
- **Policy:** Allow `directory.read` for authenticated employees in their own tenant;
  deny all other tools
- **Runtime:** ProtAI enforcement service (Pattern B) + company host application

### Pilot Plan

| Phase | Activity | Owner | Exit Criteria |
|---|---|---|---|
| P1 | Provision ProtAI (Docker Compose, PostgreSQL) | Platform operator | `GET /health/ready` returns 200 |
| P2 | Configure host-auth key + principal resolver | Security administrator | HMAC signing/verification works |
| P3 | Register `directory.read` tool + policy | Security administrator | Startup self-checks pass; tool allowed in policy |
| P4 | Build host application (Pattern B) | Agent developer | Host can sign and send `POST /v1/requests` |
| P5 | Test allow path (valid directory read) | Agent developer + security | Tool executes; result DLP-inspected and released |
| P6 | Test deny path (unauthorized tool) | Agent developer + security | 403 denial; no adapter call; audit event recorded |
| P7 | Test approval path (if ASK_USER configured) | Authorized approver + agent developer | 202 `APPROVAL_REQUIRED`; token delivery out-of-band; decision consumed |
| P8 | Run abuse/load tests | Platform operator | `scripts/check.sh` passes; rate limits enforced |
| P9 | Verify audit chain | Security operations analyst | `verify_chain()` returns verified |
| P10 | Handoff to operations | Platform operator | Runbooks reviewed; on-call rotation established |

### Authentication

- Host-auth key: 32+ random bytes, strict Base64, in `HOST_AUTH_KEYS_JSON`
- Principal assertion: `iss`/`aud`/`tenant`/`sub`/`roles`/`authenticated_at`/`timezone`
- Host owns end-user authentication; ProtAI trusts the assertion

### Secrets

- Database password: not the sample value; refused outside dev/test
- Host-auth secret: not the all-zero sample; refused outside dev/test
- No plaintext secrets in config; secrets via environment variables

### Network Access

- ProtAI API: HTTP on localhost or internal network (no public exposure in v1)
- PostgreSQL: internal to Compose network or VPC
- No outbound network from ProtAI in v1 (mock adapters only)
- Real connectors would require egress policy + destination trust map

### Infrastructure Dependencies

- Docker Compose (API + PostgreSQL 17.2)
- uv (Python dependency management)
- Alembic (database migrations)
- `firewall_test` database for integration tests

### Testing

- `scripts/check.sh` (11 steps) — full release gate
- `uv run pytest` — unit + integration + security tests (PostgreSQL required for
  integration tests)
- Evaluation quick subset — 15 dev cases, exit 2 on failures
- Abuse/load tests — deterministic, bounded

### Monitoring

- `GET /health/live` and `GET /health/ready`
- `audit_events` table (read-only SQL for investigation)
- `SECURITY_ALERT_RAISED` events (deterministic rules)
- No dashboard, no alert routing, no PagerDuty integration in v1

### Rollback

- No policy hot-reload; editing config requires restart
- To roll back: restore previous config files, restart, confirm readiness
- Verify chain integrity after restart (runbook RB-1)

### Operational Ownership

- **Platform operator:** Deployment, health, secrets, database, rollback
- **Security administrator:** Policies, DLP, host-auth keys, approver rules
- **Security operations analyst:** Alert triage, audit investigation, runbooks
- **Authorized approver:** Approval decisions (token delivered out-of-band)
- **Agent developer:** Host application, integration with `/v1` API

### Pilot Success Criteria

1. `scripts/check.sh` exits 0
2. Valid directory read executes and is audited
3. Unauthorized tool is denied with no adapter call
4. Approval flow works end-to-end (token → decision → consumption → execution)
5. Audit chain verifies after pilot activity
6. Rate limits enforced under test load

---

## 5. Post-v1 Recommendations

The blueprint §23 defines three maturity levels beyond v1:

### Research/Demo Release

- Optional local model integration
- Versioned evaluation fixtures
- Local UI/API demo with clear mock/real-mode labeling
- No claims beyond measured evidence

### Controlled Integration Release (before connecting real tools)

Required before any real connector:
1. Separate threat-model review
2. Connector permission design
3. Secret handling plan
4. Egress policy
5. Runtime deployment plan
6. Incident/rollback runbook
7. Regression benchmark
8. Host-application identity integration review
9. Every real connector disabled by default; enabled only with explicit config

### Company Deployment

Requires:
- Designated operator
- Security review
- Privacy/retention review
- Availability/backup design
- Dependency/supply-chain review
- Monitoring and incident response
- Documented responsibility boundary with the enterprise security team

### Recommended Implementation Sequence

1. **Validate pilot** (one agent, one tool, Pattern B)
2. **Build approval delivery** (token transport, UI, notification)
3. **Build audit query API** (read-only, paginated, redacted)
4. **Build real connectors** (one at a time, each with separate threat-model review)
5. **Add distributed rate limiter** (shared store for multi-worker)
6. **Add external audit checkpoint** (for tamper-proofing)
7. **Add approval revocation + resumption**
8. **Add UI** (security overview, tool registry, policy management, approvals,
   audit search, alerts, administration)

**v1 boundary reminder:** UI, real connectors, complete approval delivery/UI, and
production deployment hardening are outside v1. Do not silently expand v1.
