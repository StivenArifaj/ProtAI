# ProtAI Product Interaction Model

**Status:** Architecture and requirements document — v1 boundary respected.
**Scope:** Describes how humans and systems interact with ProtAI v1. Distinguishes
implemented functionality from recommended future work. No UI is implemented, no API
routes are invented, and no capabilities are claimed that do not exist.

## Interaction Classification

Every interaction in this document is classified as one of:

| Class | Description |
|---|---|
| **M2M API / gateway** | Machine-to-machine interaction over the signed `/v1` API or the enforced gateway |
| **Configuration / CLI / deployment** | Operator action via environment variables, config files, Docker Compose, Alembic, or `scripts/check.sh` |
| **Human approval workflow** | A human reviews and decides on an approval request; v1 has no UI/delivery transport |
| **Security monitoring / investigation** | Reading audit evidence, alerts, and logs; following runbooks |
| **Optional graphical interface** | Future UI concept; not implemented in v1 |

## Actor 1: Business End User

### Purpose

The employee who interacts with an existing company AI application (the "host
application"). That application integrates with ProtAI as a trusted host. The end user
does **not** interact with ProtAI directly.

### Required Interactions

| Interaction | Class | Implemented in v1? | Notes |
|---|---|---|---|
| Use the company AI application (chat, workflow, etc.) | M2M API / gateway (indirect) | Yes — via host | The host application calls ProtAI on the user's behalf; the user never sees ProtAI |
| See a tool-approval prompt | Human approval workflow | **No** | Approval delivery/UI does not exist in v1. The host must deliver the approval token out-of-band |
| Receive a denied-tool explanation | M2M API / gateway (indirect) | Yes — via host | The host application receives a typed denial from ProtAI and can present it to the user |

### System Interfaces

None directly. The end user's only interface is the existing company AI application,
which is the ProtAI host.

### Permissions

None in ProtAI. The host application owns end-user authentication and authorization.
ProtAI authenticates the **host**, not the end user.

### Security Constraints

- ProtAI has no end-user login, token refresh, or permission system (documented
  limitation #8).
- The end user cannot bypass ProtAI: the host must route all tool calls through the
  signed `/v1/requests` endpoint.
- The end user cannot submit a client-supplied `ALLOW`, decision, risk score, or
  approval outcome (blueprint §18.2).

### Implementation Status

**No direct interface.** The business end user interacts with the host application,
which integrates with ProtAI through the machine-to-machine API. Approval delivery,
rejection communication, and resumption are not implemented in v1 (see Actor 4).

---

## Actor 2: AI Agent / Application Developer

### Purpose

The person or system integrating agent tool calls with ProtAI's enforcement gateway.
They build the host application that calls ProtAI on behalf of end users.

### Required Interactions

| Interaction | Class | Implemented in v1? | Notes |
|---|---|---|---|
| Sign and send `POST /v1/requests` | M2M API / gateway | **Yes** | Sole execution surface. Requires host HMAC headers + signed principal assertion |
| Call `POST /v1/tool-calls/evaluate` (preview) | M2M API / gateway | **Yes** | Non-executing policy preview; never creates an execution grant |
| Call `POST /v1/approvals/{id}/decision` | M2M API / gateway | **Yes** | Records a token-bound human decision; never executes the action |
| Receive `APPROVAL_REQUIRED` (HTTP 202) with token | M2M API / gateway | **Yes** | Token returned once in the 202 response; host must deliver it out-of-band |
| Handle denial responses (403/429/503) | M2M API / gateway | **Yes** | Stable error envelope with code/message/request_id |
| Configure host-auth keys and principal assertion | Configuration / CLI / deployment | **Yes** | `HOST_AUTH_KEYS_JSON` env var; principal assertion in signed request body |
| Implement approval token delivery | Human approval workflow | **No** | No UI, transport, or notification channel in v1 |

### System Interfaces

- `POST /v1/requests` — sole execution surface (blueprint §18.1)
- `POST /v1/tool-calls/evaluate` — preview only (blueprint §18.1)
- `POST /v1/approvals/{approval_id}/decision` — one-time decision (blueprint §18.1)
- `GET /health/live`, `GET /health/ready` — health endpoints (unauthenticated)
- Host HMAC headers: `X-Gateway-Key-Id`, `X-Gateway-Timestamp`, `X-Gateway-Nonce`,
  `X-Gateway-Signature` (blueprint §9.2)

### Permissions

- The developer/host is authenticated via HMAC host auth (not end-user auth).
- The principal assertion (inside the signed body) binds `iss`/`aud`/`tenant`/`sub`/
  `roles` to the host key record.
- The developer cannot submit client-supplied authority (decision, risk, approval,
  call ID, resource target, destination, deadline, request ID).

### Security Constraints

- All `/v1/*` routes require valid host HMAC + one-time nonce before any processing
  (fail-closed middleware, blueprint §9.2).
- The gateway is the only execution path; policy is the sole `ALLOW` producer.
- The demo runtime supports only `mock_email.read` + `text.summarize` (two-call
  bounded plan); general planning does not exist.

### Implementation Status

**Implemented.** The signed `/v1` API is the complete host integration surface. The
developer must build their own approval delivery, error handling, and host application
logic. No client SDK is provided.

---

## Actor 3: Security Administrator

### Purpose

The person responsible for tool registrations, security policies, identity configuration,
and operational configuration.

### Required Interactions

| Interaction | Class | Implemented in v1? | Notes |
|---|---|---|---|
| Edit `config/policies.yaml` | Configuration / CLI / deployment | **Yes** | Tool/action registrations, side-effect classes, egress enablement; validated at startup |
| Edit `config/risk_thresholds.yaml` | Configuration / CLI / deployment | **Yes** | Risk scoring thresholds (40/80, experimental) |
| Edit `config/policy_self_checks.yaml` | Configuration / CLI / deployment | **Yes** | 21 startup/readiness self-check fixtures |
| Edit `config/input_defense.yaml` | Configuration / CLI / deployment | **Yes** | Detection dispositions, heuristics, session config |
| Edit `config/output_dlp.yaml` | Configuration / CLI / deployment | **Yes** | DLP patterns, limits, destination trust map |
| Set `HOST_AUTH_KEYS_JSON` | Configuration / CLI / deployment | **Yes** | Host-auth key records (secret, host_id, audience, allowed_tenants) |
| Set `APP_ENV`, `DATABASE_URL`, rate limits, TTLs | Configuration / CLI / deployment | **Yes** | Via environment variables (.env or Compose) |
| Run `scripts/check.sh` | Configuration / CLI / deployment | **Yes** | Full release gate (11 steps) |
| Run Alembic migrations | Configuration / CLI / deployment | **Yes** | `alembic upgrade head` / downgrade |
| Review alert events | Security monitoring / investigation | **Yes** (read-only) | SQL queries on `audit_events` where `event_type = 'SECURITY_ALERT_RAISED'` |
| Edit alert rules | Configuration / CLI / deployment | **Yes** | Alert config loaded in code (no file path setting yet — see limitations) |
| Create/modify approver rules | Configuration / CLI / deployment | **Yes** | `role:`/`principal:` grammar in policy entries |

### System Interfaces

- `config/*.yaml` — policy, risk, self-checks, input defense, output DLP
- Environment variables — `APP_ENV`, `DATABASE_URL`, `HOST_AUTH_KEYS_JSON`, rate
  limits, TTLs, etc. (see `.env.example`)
- `scripts/check.sh` — release gate
- Alembic — database migrations
- SQL on `audit_events` table — read-only audit inspection

### Permissions

- Security administrator is an operational role, not a ProtAI system role. They have
  filesystem access to config files and environment variables.
- ProtAI has no admin route, no RBAC UI, and no privileged API in v1.

### Security Constraints

- Startup refuses invalid/missing policy, invalid input-DLP config, non-covering output
  DLP destination trust map, sample passwords outside dev/test, and dev resolver outside
  dev/test.
- Policy hot-reload does not exist; editing config requires a restart.
- The administrator cannot create an `ALLOW` through config — policy only produces
  `ALLOW` through the deterministic engine; config can only narrow or deny.

### Implementation Status

**Implemented (config-driven).** All security configuration is through YAML files and
environment variables, validated at startup. No admin API or UI exists.

---

## Actor 4: Authorized Approver

### Purpose

The person who may approve a sensitive operation when policy requires human approval
(an engine `ASK_USER` decision).

### Required Interactions

| Interaction | Class | Implemented in v1? | Notes |
|---|---|---|---|
| Receive approval token | Human approval workflow | **No** | Token returned once in HTTP 202 response to host; no delivery/UI/notification in v1 |
| Review approval facts (tool, action, digest, resources, policy version) | Human approval workflow | **No** | No approval UI exists; approver sees whatever the host presents |
| Submit approve/deny decision | M2M API / gateway | **Yes** | `POST /v1/approvals/{id}/decision` with token in signed body |
| Have decision consumed atomically | M2M API / gateway | **Yes** | Row-locked one-time consumption; replay/expired/mutated never execute |

### System Interfaces

- `POST /v1/approvals/{approval_id}/decision` — records decision (token in signed body)
- The approval grant (id, token, expiry, rule) is returned in the `APPROVAL_REQUIRED`
  202 response from `POST /v1/requests`

### Permissions

- Only a verified principal satisfying the `required_approver_rule` can decide (blueprint
  §20.2 invariant #24).
- The approver must be in the same tenant as the requester.
- Self-approval requires an explicit `self_approval_allowed` policy flag.
- The token is consumed on decision (one-time); stored only as SHA-256 digest.

### Security Constraints

- An approved action can never override a `BLOCK`/hard denial (invariant #5).
- A missing, expired, replayed, or mutated approval never executes (invariants #6, #7, #8).
- Approval is a gate, not an `ALLOW` producer: the engine decision remains `ASK_USER`;
  approval never becomes `ALLOW` (blueprint decision).
- There is **no explicit revocation operation** in v1; pending/approved approvals expire
  lazily on the next decide/consume (default TTL 900s, configurable 60-86400s).

### Implementation Status

**Partial.** The decision route exists and is fully enforced. Approval **delivery**,
**UI**, **notification**, **approver directory**, and **revocation** are not implemented
in v1 (documented limitation #3).

---

## Actor 5: Security Operations Analyst

### Purpose

The person responsible for reviewing alerts, investigating audit evidence, and following
incident-response runbooks.

### Required Interactions

| Interaction | Class | Implemented in v1? | Notes |
|---|---|---|---|
| Review alert events | Security monitoring / investigation | **Yes** (read-only) | SQL on `audit_events` where `event_type = 'SECURITY_ALERT_RAISED'` |
| Investigate denied requests | Security monitoring / investigation | **Yes** (read-only) | SQL on `audit_events` by `request_id` |
| Verify audit-chain integrity | Security monitoring / investigation | **Yes** (read-only) | `verify_chain()` from `ai_security.audit.verifier` |
| Follow incident runbooks | Security monitoring / investigation | **Yes** | `docs/RUNBOOKS.md` (RB-1 through RB-8) |
| View alert dashboard | Optional graphical interface | **No** | No alert query API or UI in v1 |
| Search audit events | Optional graphical interface | **No** | No audit query API in v1 |

### System Interfaces

- `ai_security.audit.verifier.verify_chain()` — read-only chain verification
- SQL SELECT on `audit_events` table — read-only inspection (derived metadata columns:
  `event_type`, `request_id`, `trace_id`, `call_id`, `occurred_at`, `component`)
- `docs/RUNBOOKS.md` — eight runbooks (audit verification, alert triage, denied-request
  investigation, approval abuse, DLP findings, provider/database outage, rollback, key
  rotation/incident response)

### Permissions

- Read-only database access to `audit_events`. No write path (the repository is the sole
  writer of `audit_events`).
- No ProtAI system role for analysts; this is an operational role with database access.

### Security Constraints

- The verifier reads one consistent snapshot and never writes.
- Audit payloads never contain raw user text, tool output, secrets, or exception messages
  (redacted by design — `docs/AUDIT_RETENTION_AND_DATA_HANDLING.md`).
- Alert triage is read-only; analysts cannot block, allow, revoke, or contain from the
  audit trail.

### Implementation Status

**Partial.** Audit events are fully emitted and verifiable. Alert events are emitted by
deterministic rules. However, there is **no audit query API, no alert dashboard, and no
UI** in v1. Analysts must query the database directly or use the verifier library.

---

## Actor 6: Platform Operator

### Purpose

The person responsible for deployment, health monitoring, secrets, database operations,
and recovery.

### Required Interactions

| Interaction | Class | Implemented in v1? | Notes |
|---|---|---|---|
| Deploy API + PostgreSQL (Docker Compose) | Configuration / CLI / deployment | **Yes** | `docker compose up -d db` + `docker compose up api` |
| Check health (`/health/live`, `/health/ready`) | M2M API / gateway | **Yes** | Unauthenticated, returns booleans only |
| Run release gate (`scripts/check.sh`) | Configuration / CLI / deployment | **Yes** | 11 steps, exits non-zero on failure |
| Manage secrets (DB password, host-auth keys) | Configuration / CLI / deployment | **Yes** | Via environment variables; sample values refused outside dev/test |
| Run database migrations | Configuration / CLI / deployment | **Yes** | Alembic upgrade/downgrade; single head |
| Respond to database outage | Security monitoring / investigation | **Yes** (runbook RB-6) | Gateway fails closed; nonce-store failure → 503 |
| Rotate host-auth keys | Security monitoring / investigation | **Yes** (runbook RB-8) | Add new key, restart, remove old key |
| View deployment health dashboard | Optional graphical interface | **No** | No UI in v1 |
| Manage database backups/retention | Configuration / CLI / deployment | **No** | No automated retention or backup (documented limitation #19) |

### System Interfaces

- `docker-compose.yml` — API + PostgreSQL deployment
- `.env` — environment configuration
- `scripts/check.sh` — release gate (11 steps)
- Alembic — database migrations
- `GET /health/live`, `GET /health/ready` — health endpoints

### Permissions

- Operational role with filesystem, Docker, and database access. No ProtAI system role.

### Security Constraints

- The image runs as non-root (uid 10001) with digest-pinned base images.
- No seccomp/AppArmor profile, read-only root filesystem, or image vulnerability
  scanning (documented limitation #16).
- Compose credentials are disposable development values (documented limitation #15).

### Implementation Status

**Implemented (operational).** Deployment, health checks, migrations, secrets, and the
release gate are all implemented. Automated backup, retention, and a health dashboard
are not implemented in v1.

---

## Complete ALLOW/BLOCK/ASK Lifecycle

### What Actually Happens

1. **Client request:** The host application sends `POST /v1/requests` with a signed
   principal assertion and text. Host HMAC + nonce are verified first (middleware).
2. **Input inspection:** Bounded request text is inspected; `REJECT`/`QUARANTINE`
   dispositions stop before intent (403).
3. **Intent extraction:** A sealed manifest is issued server-side; provider failure
   yields `503 model_unavailable` with no tool events.
4. **Gateway evaluation:** The `ToolGateway` evaluates the tool call: argument
   validation, intent constraint validation, egress DLP, resource authorization,
   risk scoring, deadline, and policy. The engine produces `ALLOW`/`BLOCK`/`ASK_USER`.
5. **Decision audited:** `POLICY_EVALUATED` is appended before any execution.
6. **Execution or approval:**
   - `ALLOW`: Tool executes through the gateway; result is DLP-inspected before release.
   - `BLOCK`: Denied; no adapter call.
   - `ASK_USER`: An approval request is created in-process. `POST /v1/requests` returns
     HTTP 202 `APPROVAL_REQUIRED` with the approval ID and one-time token. **Nothing is
     executed.** The host must deliver the token to the approver out-of-band.
7. **Approval decision:** The approver calls `POST /v1/approvals/{id}/decision` with
   the token in the signed body. Decision + audit event commit atomically.
8. **Consumption (if approved):** The gateway atomically consumes the approved record
   (digest-bound, one-time, row-locked) and executes the action.
9. **Result release:** The complete buffered output is DLP-inspected before release;
   `PASS` releases, `REDACT` releases a span-preserving transformation, `BLOCK`/`REVIEW`
   /failure suppress the whole response.

### What Is Missing in v1

| Lifecycle Stage | Missing in v1 | Documented As |
|---|---|---|
| Approval delivery | No UI, transport, or notification channel | Limitation #3 |
| Authenticated approval UI | No approval UI exists | Limitation #3 |
| Rejection communication | Host must present denial to user | Not implemented |
| Expiration sweeper | Lazy expiry only; no background sweeper | Limitation #19 |
| Revocation | No explicit revocation operation | Limitation #3 |
| Safe resumption | No client approval field; approved action cannot be resumed through `/v1/requests` | Limitation #3 |

### ASK Is Never Permission

An engine `ASK_USER` decision **never** authorizes execution. The gateway executes only
on an engine `ALLOW` or a valid one-time approval of an engine `ASK_USER`. Approval is a
gate, not an `ALLOW` producer (blueprint decision). Policy remains the sole `ALLOW`
producer; the gateway is the only execution path.

---

## UI Design Decision

**No UI is implemented in v1.** The following functions were evaluated:

| Function | Classification | v1 Status |
|---|---|---|
| Host-to-gateway integration | M2M API / gateway | Implemented (`POST /v1/*`) |
| Security configuration | Configuration / CLI / deployment | Implemented (config files + env vars) |
| Human approval decision | Human approval workflow | Partial (decision route only; no delivery/UI) |
| Alert review | Security monitoring / investigation | Partial (SQL on audit_events; no UI) |
| Audit investigation | Security monitoring / investigation | Partial (verifier + SQL; no query API) |
| Deployment/health | Configuration / CLI / deployment | Implemented (Compose + health endpoints) |
| End-user interaction | — | None (host application owns this) |

All human-facing functions in v1 are supported by configuration files, CLI workflows,
logs, or direct database queries. A graphical interface is recommended for post-v1
(see `docs/PRODUCT_INTERACTION_MODEL.md` future work and the blueprint §23 maturity
path). No frontend is implemented, no routes are invented, and no capabilities are
claimed that do not exist.
