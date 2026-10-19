# AI Agent Security & Safety Platform — Master Engineering Blueprint

**Document status:** Implementation contract v1.2 (review amendments incorporated)  
**Project type:** Local-first, AI-first security gateway for AI applications and tool-using agents  
**Primary development environment:** macOS + Docker  
**Budget constraint:** $0 mandatory spend; open-source/local components first; optional cloud model adapters only by explicit opt-in  
**Audience:** Coding agents and engineers implementing, testing, reviewing, and extending the repository

**Authoritative document:** This file is the single authoritative implementation contract. The historical v1.0 draft is archived under `archive/` and marked superseded; it MUST NOT be used for implementation. Do not create further full copies of this blueprint.

---

## 0. Purpose and binding rules

This document is the authoritative implementation plan for the repository. Implement the system in phases and satisfy each phase's Definition of Done before starting the next. Do not silently change the security model, invent undocumented behavior, replace a dependency with a paid service, or mark an unimplemented feature as complete.

The design is AI-first, not a replacement for a company's entire cybersecurity stack. It focuses on risks created by language-model inputs, untrusted context, model-generated plans, tool calls, and AI-mediated data movement. Existing corporate identity, endpoint security, network security, and cloud controls should be integrated through adapters rather than reimplemented.

### 0.1 Mandatory engineering language

- **MUST / MUST NOT**: release-blocking requirement.
- **SHOULD / SHOULD NOT**: expected default; deviation requires a recorded design decision and test evidence.
- **MAY**: optional extension.
- A component is not considered implemented because a file exists or a method returns a plausible value. It must have tests that demonstrate its contract.
- The diagram, comments, and model responses are not sources of authorization. The versioned policy configuration and server-side principal are.
- No security metric may be invented or presented as measured until the evaluator has actually computed it from a versioned dataset and recorded the run configuration.

### 0.2 Engineering verdict on the initial proposal

Keep the two central ideas: (1) inspect user input and external content for manipulation, and (2) enforce a separate tool firewall even if the model is manipulated. Extend them with identity/context binding, output/egress protection, audit, evaluation, and safe execution.

The following initial assumptions are explicitly **not** accepted as security guarantees:

1. Regex sanitization cannot reliably detect every prompt injection. Use it as one signal, not as the security boundary.
2. Wrapping text in XML tags does not force a model to obey the boundary. Keep structured provenance labels and deterministic action controls; treat delimiters as defense-in-depth only.
3. An LLM-generated intent manifest does not grant permissions. It records the user's apparent goal and constraints; the policy engine authorizes each concrete action separately.
4. Semantic/vector similarity MUST NOT be the sole basis for allowing a tool call. It can flag a mismatch or increase risk, but cannot override a hard policy denial.
5. A risk score MUST NOT override denied permissions, invalid arguments, a failed identity check, or an unapproved sensitive action.
6. A final-response DLP scan cannot undo an email, HTTP request, database write, or other side effect already performed. Egress checks must happen before data crosses an external or lower-trust boundary.
7. Hash chaining makes logs tamper-evident under stated assumptions; it does not make a local log cryptographically impossible to rewrite if an attacker can rewrite the whole chain and its keys.
8. An AI SOC worker must not get autonomous authority to revoke access, kill processes, or change policy in the initial release. Begin with read-only analysis and deterministic response rules.
9. Free hosted-model quotas, model names, terms, and retention rules can change. The platform must not require a hosted LLM to run the core test suite or enforce tool policies.

---

## 1. Product definition

### 1.1 Mission

Provide a model-agnostic security gateway for AI applications that detects suspicious inputs, preserves the distinction between instructions and untrusted data, constrains model-generated actions, authorizes each tool invocation outside the model, inspects sensitive-data egress, and creates an auditable trail of decisions.

### 1.2 Core security properties

The platform must make these properties testable:

1. **No tool bypass:** every tool side effect exposed through the agent runtime passes through the firewall gateway.
2. **Fail closed on uncertain authorization:** if policy evaluation, schema validation, principal resolution, or required approval fails, a sensitive action does not execute.
3. **Model is not authority:** model output can propose actions; only server-side code and policy authorize them.
4. **Least privilege:** a tool receives only the scoped arguments and credentials it needs for the current action.
5. **Explicit trust labels:** user instructions, application policy, model output, retrieved text, and tool results remain distinguishable in internal representations and prompts.
6. **Bounded side effects:** tools have per-action limits, timeouts, and explicit side-effect classes.
7. **Data egress control:** sensitive content is checked before sending to tools or destinations with lower trust or external reach.
8. **Auditable outcomes:** each request and decision is traceable through correlated events without routinely storing raw secrets or complete private content.
9. **Reproducible evaluation:** test data, splits, configurations, model/provider versions, and output metrics are versioned.
10. **Honest degradation:** detectors and cloud LLMs are optional; outages do not silently disable mandatory authorization.

### 1.3 In scope

- Direct and indirect prompt-injection indicators, jailbreak indicators, malformed inputs, abuse/resource limits, and untrusted-content handling.
- Typed intent records and proposed action records.
- Deterministic policy evaluation and parameter-level action validation.
- Risk scoring as a secondary decision signal, never an authorization override.
- Human approval for selected actions, bound to the exact action and arguments.
- A central mediated tool registry/gateway.
- Synthetic/mock tools for testing; safe read-only demo tools after core enforcement works.
- Output DLP/sensitive-data checks and outbound-destination controls.
- Structured, tamper-evident audit events and security alerts.
- Local-first LLM adapter and optional cloud-provider adapters behind a stable interface.
- Evaluation harness, attack/benign fixtures, metrics, regression tests, and a simple FastAPI integration boundary.
- Docker-based local development and a documented path to future integrations.

### 1.4 Out of scope for v1

- Replacing Active Directory, SSO, company IAM, VPNs, EDR, network firewalls, or a full enterprise SOC.
- Guaranteeing detection of every prompt injection or claiming perfect protection.
- Training a new foundation model from scratch.
- Autonomous, unrestricted shell access or general-purpose command execution.
- Connecting to real employee mailboxes, production databases, or company file stores before the mock environment, policy tests, and approval flow are complete.
- Automatically deploying changed policies because an AI recommends it.
- Making cloud-hosted models mandatory.

### 1.5 Initial product surface

The v1 system is a **gateway/library plus optional API service**. The gateway owns tool authorization and tool invocation; the API exposes that same contract for integration. A separate demonstration agent may call the gateway, but it MUST NOT possess a direct route to execute the same tools outside it.

---

## 2. Threat model and trust boundaries

Write `docs/THREAT_MODEL.md` before implementing detectors. At minimum, include attacker goals, attack surfaces, assets, trust assumptions, mitigations, residual risks, and tests for each row below.

| Threat | Example | Primary defenses | Required test evidence |
|---|---|---|---|
| Direct prompt injection | User asks the model to ignore policy or reveal hidden instructions | Input signals, bounded system context, action policy, output checks | Direct-injection fixtures plus tool-denial tests |
| Indirect prompt injection | A web page/email/document contains instructions to exfiltrate data | Provenance labels, context isolation, detector signals, firewall enforcement | Malicious retrieved-content tests end-to-end |
| Multi-turn manipulation | Benign-looking messages gradually set up a later unsafe action | Session-linked events, conversation/context review, tool authorization per action | Multi-turn scenario tests; no reliance on detector memory alone |
| Tool/action mismatch | User asks for a summary but the model proposes forwarding the source | Intent/action validator, forbidden-action rules, destination checks | Exact arguments and side-effect tests |
| Privilege escalation | Model requests a file outside the authenticated user's scope | Verified principal, resource-scoped policy, connector ACL | Cross-user / cross-scope denial tests |
| Data exfiltration | Sensitive content goes to a public URL or external recipient | Data classification, sink/destination policy, DLP before egress | Canary secret must not reach mock external sink |
| Path/URL confusion | `../`, symlinks, encoded traversal, deceptive hostnames | Canonicalization, allowlisted resource IDs, safe URL parser | Normalization and traversal tests |
| Replay/approval abuse | An old approval is reused after arguments change | One-time approval token, action digest, expiry, principal and policy binding | Replay, mutation, and expiry tests |
| Detector/provider outage | Classifier or hosted LLM times out | Explicit failure mode; authorization never depends on detector availability | Timeout/exception tests; no bypass |
| Audit manipulation | An event is modified or deleted | Append-only writer contract, hash chain, protected checkpoint/export | Tamper-detection test and documented limits |
| Model/provider supply chain | A provider changes a model ID or model output format | Provider adapter, pinned config, schema validation, no model authority | Invalid output and provider error tests |
| Resource exhaustion | Huge prompts, deeply nested structures, repeated calls | Input limits, deadlines, quotas, bounded retries | Boundary and load tests |
| Tool adapter compromise | A tool adapter tries to perform an unapproved side effect | Narrow adapter APIs, minimal credentials, sandbox/egress restrictions | Adapter contract test and isolated mock runtime |
| Host-to-gateway impersonation or replay | An untrusted caller forges a principal assertion or replays a captured gateway request | Per-host HMAC authentication, short timestamp window, unique one-time nonce, request-body signature, private transport | Forged signature, body mutation, expired timestamp, and replay tests |
| Audit append race | Concurrent requests compute `prev_hash` from the same prior event | Database-serialized append transaction, monotonically increasing per-chain sequence | Multi-worker concurrent append test and chain verification |
| AI SOC prompt injection | Attacker-controlled text embedded in audit events manipulates the log summarizer | Treat all event fields influenced by requests/tools as untrusted data; analyzer is read-only and alert-only | Injected log strings cannot trigger tools, policy changes, or containment actions |

### 2.1 Security assets

- Authenticated principal and authorization context.
- User request and intent constraints.
- Policy documents and their versions.
- Secrets, private documents, personal data, and tool credentials.
- Tool side effects and their destinations.
- Approval records and session state.
- Audit integrity and the incident trail.
- Evaluation data and benchmark results.

### 2.2 Trust classes

Use an enum, not free-form strings, for trust provenance. Minimum values:

- `SYSTEM_POLICY`: application-owned, versioned instructions/policy.
- `AUTHENTICATED_USER`: user request associated with a server-verified principal.
- `MODEL_GENERATED`: model output, proposed plan, or tool-call proposal; never treated as authorization.
- `EXTERNAL_UNTRUSTED`: web pages, emails, files, documents, search results, and other content not controlled by application policy.
- `TOOL_RESULT`: data returned by a tool; treat as untrusted unless the adapter labels a field with a validated source.
- `SECURITY_METADATA`: server-generated detections, policy verdicts, and audit metadata.

A source can be authenticated without all its content being trusted as instructions. For example, an authenticated user's email body remains external content when it contains quoted messages or third-party text.

---

## 3. End-to-end architecture and request lifecycle

### 3.1 Logical flow

```text
Application / User
  -> API Boundary + Verified Principal Context
  -> Intake Bounds / Content Parsing / Provenance Labelling
  -> Input Threat Signals (heuristics + optional local classifier)
  -> Intent Extraction (typed proposal; never grants authority)
  -> Agent Runtime / Planner (optional; produces a proposed action)
  -> Tool Registry / Firewall Gateway (mandatory for every tool call)
       -> principal and session binding
       -> registered tool + strict argument schema
       -> hard policy rules and resource scope
       -> intent/action constraint validation
       -> egress/data classification where relevant
       -> deterministic risk calculation
       -> allow | block | require approval
       -> controlled tool adapter execution
  -> Tool Result -> label as untrusted context -> next model step if any
  -> Output / Egress DLP before release or external side effect
  -> Structured Audit Events + Metrics + Alert Rules
```

The input detector may run before an agent sees any text, but it is not the ultimate safety barrier. The firewall is the mandatory enforcement boundary for actions. Every multi-step tool call is evaluated independently, including calls proposed after a tool result has re-entered model context.

### 3.2 Critical order-of-operations rule

The **development order** is not identical to the **runtime order**. Even though input defense is first in the runtime pipeline, implement core schemas, policy contracts, and the no-bypass tool gateway early. A project that can detect prompt injection but has no reliable action enforcement is not yet safe to demonstrate as an agent security system.

### 3.3 Per-request lifecycle

1. Generate a server-side `request_id` and `trace_id`.
2. Resolve the principal through an authentication adapter. Never trust `user_id`, `role`, or permissions provided only in model-generated arguments or a client-supplied JSON field.
3. Enforce request size, content-type, parsing, deadline, and rate/resource bounds.
4. Preserve the original payload for processing but avoid writing raw private content to normal logs. Normalize only for detection; do not silently delete or rewrite content in a way that changes its meaning.
5. Label each content segment with source and trust class.
6. Run heuristic input checks; if configured, run the local detector. Produce a structured finding with reasons, not merely a boolean.
7. Apply a deterministic intake policy: allow, quarantine/review, or reject based on configured threat classes and confidence. Ambiguous detection is not permission to run a risky action.
8. Generate a typed intent proposal. Use deterministic extraction only for supported simple forms; otherwise a configurable local model may return a schema-constrained proposal. Treat confidence as a diagnostic field only.
9. Start the agent runtime. The runtime may propose an action but must call the controlled tool interface to execute it.
10. Validate the proposed call using a registered tool schema and normalized arguments.
11. Check mandatory authorization rules first. A hard denial cannot be overridden by a risk score or model confidence.
12. Check action/intent constraints. A semantic similarity signal may inform risk or ask for clarification; it cannot authorize an action by itself.
13. Evaluate data classification, target/destination, action side-effect level, and other configured risk signals.
14. Select `ALLOW`, `BLOCK`, or `ASK_USER`. Record the decision before execution.
15. For `ASK_USER`, create an approval request bound to the exact principal, tool, action, canonical arguments digest, resource, policy version, expiry, and one-time nonce. Do not execute until approval is verified.
16. If allowed, call the registered adapter only through the gateway. Apply timeout, output size, per-tool quotas, destination restrictions, and connector-level access checks.
17. Treat tool output as untrusted input when it returns to the model. Label its provenance and re-run the relevant context checks.
18. Before data leaves a trusted boundary, inspect the outbound payload and destination. Before displaying model output to the user, run output checks and apply the configured release policy.
19. Record completion, failure, DLP findings, and the final released/suppressed response metadata.
20. Return a safe response that does not reveal hidden policies, credentials, stack traces, or other users' data.

---

## 4. Repository layout

Keep modules small and enforce clear import boundaries. The coding agent may add files needed for a correctly tested implementation, but it must explain any change to this layout before making broad structural changes.

```text
ai-agent-security-platform/
├── pyproject.toml
├── uv.lock
├── README.md
├── .env.example
├── .gitignore
├── docker-compose.yml
├── Dockerfile
├── Makefile
├── config/
│   ├── policies.yaml
│   ├── policy_self_checks.yaml
│   ├── risk_thresholds.yaml
│   ├── input_defense.yaml
│   └── dlp_rules.yaml
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   ├── SECURITY_INVARIANTS.md
│   ├── DATA_HANDLING.md
│   ├── EVALUATION_PROTOCOL.md
│   ├── IMPLEMENTATION_STATE.md
│   ├── DECISIONS.md                 # Index linking to individual ADRs
│   ├── KNOWN_LIMITATIONS.md
│   ├── POLICY_DECISION_MATRIX.md
│   ├── adr/                         # Individual architecture decision records
│   └── RUNBOOK.md
├── migrations/
│   ├── env.py
│   └── versions/
├── alembic.ini
├── src/ai_security/
│   ├── __init__.py
│   ├── settings.py
│   ├── api/
│   │   ├── app.py
│   │   ├── dependencies.py
│   │   ├── routes_health.py
│   │   ├── routes_requests.py
│   │   ├── routes_tools.py
│   │   └── routes_approvals.py
│   ├── identity/
│   │   ├── models.py
│   │   ├── resolver.py
│   │   ├── host_auth.py
│   │   └── adapters.py
│   ├── security/
│   │   ├── canonical_json.py
│   │   └── constant_time.py
│   ├── input_defense/
│   │   ├── normalize.py
│   │   ├── heuristics.py
│   │   ├── detector.py
│   │   ├── context_labels.py
│   │   └── service.py
│   ├── intent/
│   │   ├── models.py
│   │   ├── extractor.py
│   │   └── constraints.py
│   ├── agent/
│   │   ├── runtime.py
│   │   ├── model_provider.py
│   │   └── providers/
│   │       ├── ollama.py
│   │       └── optional_cloud.py
│   ├── firewall/
│   │   ├── gateway.py
│   │   ├── action_validator.py
│   │   ├── policy_engine.py
│   │   ├── risk_engine.py
│   │   ├── decision.py
│   │   └── approval.py
│   ├── tools/
│   │   ├── registry.py
│   │   ├── base.py
│   │   ├── mock_email.py
│   │   ├── mock_files.py
│   │   └── mock_external_sink.py
│   ├── data_security/
│   │   ├── classification.py
│   │   ├── dlp.py
│   │   └── egress.py
│   ├── audit/
│   │   ├── models.py
│   │   ├── writer.py
│   │   ├── hash_chain.py
│   │   └── verify.py
│   ├── persistence/
│   │   ├── database.py
│   │   ├── models.py
│   │   ├── repositories.py
│   │   └── audit_repository.py
│   └── soc/
│       ├── rules.py
│       └── analyzer.py
├── evaluation/
│   ├── README.md
│   ├── dataset_manifest.yaml
│   ├── fixtures/
│   │   ├── benign.jsonl
│   │   ├── direct_injection.jsonl
│   │   ├── indirect_injection.jsonl
│   │   ├── tool_mismatch.jsonl
│   │   ├── data_exfiltration.jsonl
│   │   └── malformed_inputs.jsonl
│   ├── splits/
│   └── run_evaluation.py
├── scripts/
│   ├── dev.sh
│   ├── check.sh
│   ├── inspect_local_model.sh
│   ├── verify_audit.py
│   └── generate_sbom.sh
└── tests/
    ├── unit/
    ├── integration/
    ├── security/
    ├── evaluation/
    └── fixtures/
```

`core/` in earlier sketches becomes the more explicit `firewall/`, `intent/`, and `identity/` packages. This is deliberate: intent extraction, principal resolution, and authorization are separate concerns and must not be coupled into one ambiguous module.

### 4.1 Import rules

- `firewall/` may depend on typed models, policies, risk, tool registry interfaces, approval repository, and audit interface.
- Tool adapters must not call the agent runtime or bypass the gateway to request authorization from an LLM.
- `policy_engine.py` must not make network calls or call an LLM.
- `risk_engine.py` must be deterministic in v1 and must not make network calls.
- Input/output detection may use optional model-provider interfaces, but cannot become the policy authority.
- API routers orchestrate services; they must not duplicate policy logic.
- Evaluation code must not be imported into runtime request processing.
- Avoid circular imports. Shared data contracts belong in the package where their domain is defined, not in one giant `utils.py`.

---

## 5. Technology choices and zero-cost operating model

### 5.1 Required stack

- **Python:** use Python 3.12 for the first implementation to provide a stable baseline across current libraries and Docker images. Pin the chosen base image and dependency lock.
- **FastAPI + Uvicorn:** HTTP integration layer.
- **Pydantic v2:** validated typed input/output contracts; reject unknown fields for security-sensitive schemas.
- **PyYAML safe loading:** policy/config parsing; never evaluate YAML tags or load arbitrary Python objects.
- **pytest + HTTPX:** unit and API integration tests.
- **Ruff:** lint and format checks. Add static type checks for security-sensitive modules.
- **Docker Compose:** reproducible local API/database environment.
- **Persistence decision (ADR-005):** use SQLAlchemy 2.x async ORM/Core with `asyncpg` as the PostgreSQL async driver. Keep transaction boundaries explicit and repositories thin; do not mix raw driver calls across domain modules.
- **Migrations decision (ADR-006):** use Alembic for all schema changes. `Base.metadata.create_all()` is allowed only in isolated unit-test fixtures, never as the deployed schema-management mechanism. Phase 0b must provide a migration baseline and a documented migration command.
- **PostgreSQL in Docker:** persistent multi-request policy, approval, and audit metadata storage; no managed cloud database is required.
- **Ollama or the already-installed local model service:** optional local inference adapter. The model identity is configuration, not a hard-coded guess.
- **Git:** version all code, configuration, dataset manifests, architecture decisions, and evaluation reports.

Only add libraries with a concrete need. Do not add a vector database in Sprint 1: semantic retrieval is not necessary for deterministic authorization. Do not add Redis, Kafka, a hosted observability product, or an embedding service merely because they are common in enterprise stacks.

### 5.2 Optional services

Cloud model APIs may be used only through provider adapters and only after an explicit configuration choice. They are not needed to run unit tests, policy tests, tool-denial tests, or the core evaluation suite.

A “free API” is not a guaranteed unlimited service. Providers set model-specific and account-specific quotas, can change available models, may return 429/503 errors, and can have data-use conditions that differ by tier. The application must:

- keep `ALLOW_EXTERNAL_MODEL_CALLS=false` by default;
- fail startup or reject cloud-provider configuration when an API key is missing or the provider is not enabled, rather than silently sending data elsewhere;
- support timeouts, bounded retries with exponential backoff, cancellation, and provider error reporting;
- never use a second provider as an automatic fallback for confidential input without explicit consent and a documented data-handling rule;
- record provider/model identifiers and latency, not raw secrets or full private prompt content;
- have a tested local/mock path when providers are rate-limited or unavailable.

Before enabling any hosted model, the operator must review that provider's current quota, model availability, retention, and data-use terms. Free-tier limits should be read from the provider's current account dashboard/docs; do not hard-code old figures in this repository.

### 5.3 Identify the existing local model rather than guessing

Run `ollama list` if the local server is Ollama. Then use `ollama show <exact-model-name>` and inspect its version, parameter size, quantization, and capabilities. If the model is served by another application, document that application's endpoint and API compatibility before adding an adapter. Do not assume the 5 GB model is Qwen, has JSON-schema support, or is fast enough for every task.

The core product MUST work with a fake deterministic model provider in tests. The local model is an optional integration for intent proposals and experiments; it is not required to authorize actions.

### 5.4 Suggested local environment

Create `.env.example` containing placeholders only. Never commit `.env`, provider keys, access tokens, database passwords, or real sensitive example data. Minimum settings should include:

```dotenv
APP_ENV=development
LOG_LEVEL=INFO
DATABASE_URL=postgresql+asyncpg://firewall:firewall_dev_only@db:5432/firewall
PRINCIPAL_RESOLVER=dev
HOST_AUTH_KEYS_JSON={"local-dev":{"secret_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","host_id":"local-dev-host","audience":"ai-agent-security-gateway","allowed_tenants":["demo"]}}
ALLOW_EXTERNAL_MODEL_CALLS=false
MODEL_PROVIDER=mock
LOCAL_MODEL_BASE_URL=http://host.docker.internal:11434
LOCAL_MODEL_NAME=SET_TO_EXACT_INSTALLED_MODEL
REQUEST_MAX_BYTES=65536
REQUEST_TIMEOUT_SECONDS=30
AUDIT_RAW_CONTENT_MODE=never
HOST_AUTH_TIMESTAMP_TOLERANCE_SECONDS=60
HOST_AUTH_NONCE_TTL_SECONDS=300
SESSION_SIGNAL_TTL_SECONDS=86400
SESSION_MAX_AGE_SECONDS=604800
```

These are development defaults only. The compose credentials are disposable local values and MUST NOT be represented as production-safe credentials. Add a check that refuses the development secret in non-development environments.

HMAC-SHA256 host authentication is mandatory for every `/v1/*` HTTP route in every environment; v1 has no HTTP auth-bypass mode. `HOST_AUTH_KEYS_JSON` maps key IDs to records with exactly these fields: `secret_b64` (strict Base64 encoding of at least 32 cryptographically random secret bytes), `host_id`, `audience`, and `allowed_tenants` (an explicit list; use an empty list only if the key is configured for a single-tenant host that is constrained elsewhere). The sample `.env.example` uses a deliberately public all-zero secret and a demo-only tenant so a local mock setup is syntactically valid; startup MUST refuse that exact sample secret when `APP_ENV` is not `development` or `test`. For any controlled integration, generate a new secret with `python -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"`, replace the sample key, and store it outside version control. Do not use a model-provider API key as a gateway authentication key. The host signs the full request body, including the verified principal assertion. That assertion contains `iss` matching the configured `host_id`, `aud` matching the configured audience, `sub`, optional `tenant_id`, roles/groups used only as inputs to local policy mapping, `authenticated_at`, and optional IANA `timezone`. The `key_id` limits allowed tenants and audience. Effective permissions are derived by local policy; arbitrary request permissions are never authoritative. Never print keys or derived signatures to logs.

On macOS, a container generally reaches a model service running on the host through `host.docker.internal`; verify this on the current Docker setup. If the model is itself inside Compose, use the service name instead. Never bind a development model endpoint to a public network interface unnecessarily.

---

## 6. Shared data contracts and schema rules

Implement typed models before business logic. Use strict Pydantic models with `extra="forbid"`, field bounds, enums, and explicit optionality. Do not use unconstrained `Dict[str, Any]` as the only validation for tool arguments; each registered tool must own an argument schema.

### 6.1 Minimum domain models

`identity/models.py`

- `Principal`: server-resolved `subject_id`, `roles`, `tenant_id` if the host integration supports tenancy, optional IANA `timezone` from the signed host assertion or trusted user-profile adapter, authentication method/issuer metadata, and a stable permissions/context reference. Effective capabilities are derived by local policy from verified identity attributes; raw client-supplied permissions are never authoritative.
- The principal MUST be created by `identity/resolver.py` from a verified auth context or a conspicuously development-only test adapter. A body field `user_id` is not a verified principal.
- Do not treat a role name sent by the model or client as authoritative.

`input_defense` models

- `ContentSegment`: `segment_id`, `source_type`, `trust_class`, `content_digest`, optional bounded content reference, and source metadata.
- `ThreatFinding`: `finding_id`, `category`, `severity`, bounded numeric score if present, detector ID/version, evidence snippet only when safe, and rule IDs.
- `InputInspectionResult`: `status`, findings, normalized-content digest, detector versions, and the disposition recommended by policy.
- Scores from different detectors are not presumed calibrated to the same probability scale.

`intent/models.py`

- `IntentManifest`: server-created `manifest_id`, `request_id`, principal subject reference, creation/expiry timestamps, extractor version, list of `IntentConstraint`, and manifest status.
- `IntentConstraint`: allowed high-level action, tool/action identifier where known, resource scope, permitted destination/scope, and parameter constraints required by the user's request.
- Keep user goal text separately from enforceable constraints. No manifest field can grant permissions that the policy engine denies.
- Do not store a client-provided arbitrary `allowed_tools` list as trusted state.

`IntentManifest` MUST NOT require copying a full raw prompt into every manifest. Store only what is necessary; use a digest and a protected content reference when needed. For a non-specific request, constraints should be conservative or require clarification rather than inventing access scope.

`firewall` models

- `ProposedToolCall`: server-side `call_id`, `request_id`, principal reference, registered `tool_id`, `action_id`, arguments parsed into that tool's Pydantic schema, target resource IDs, destination metadata if relevant, side-effect class using the canonical `SideEffectClass` enum defined below, and deadline.
- Do not accept `risk_score`, `decision`, `permissions`, `principal role`, or an approval flag from the model as authoritative fields.
- `FirewallDecision`: enum `ALLOW`, `BLOCK`, `ASK_USER`.
- `DecisionRecord`: decision, stable reason codes, policy version, risk calculation version, applicable constraints, approval reference, and a correlation ID.
- `ApprovalRequest`: public `approval_id`, stored digest of one-time approval token, principal, canonical action digest, canonical target/destination fields, expiry, policy version, `required_approver_rule`, status, token-consumed timestamp, approver identity, and creation metadata. `required_approver_rule` is a machine-evaluable predicate over verified principal attributes (roles, permissions, or specific principal IDs) that determines who may approve; it is evaluated only against principals produced by the authenticated context (§9). By default the requester cannot approve their own action unless policy explicitly allows self-approval, and if no eligible approver can satisfy the rule the action is not approvable and the decision is `BLOCK`, never a permanently pending request. Full approver semantics and acceptance criteria are defined in §13.2.

`tools/base.py` (tool registry domain)

- `SideEffectClass` (canonical enum, defined exactly once here; used by the tool registry (§12.2), the decision matrix (§10.3), the risk engine (§11.3), policy configuration (§10.4), mock tool registrations (§14.1), and test fixtures): `READ_ONLY`, `LOCAL_MUTATION`, `EXTERNAL_MUTATION`, `DESTRUCTIVE`.
  - `READ_ONLY`: no state change; still subject to resource-scope, intent, and DLP rules.
  - `LOCAL_MUTATION`: changes state inside the trusted boundary (for example, the gateway's own datastore or a synthetic mailbox).
  - `EXTERNAL_MUTATION`: crosses a trust boundary or performs external egress (email, webhook, external API call).
  - `DESTRUCTIVE`: irreversible deletion or destruction; not registered in v1.
  - Unknown, missing, or invalid side-effect classes MUST fail closed: registration fails at startup and policy evaluation returns `BLOCK`. Do not implement string aliases, and never coerce an unknown value into an allowed class.

`data_security/classification.py`

- `DataClass` (canonical enum, defined exactly once here; used by the decision matrix (§10.3), egress policy (§15.3), policy configuration (§10.4), and examples): `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`.
  - Trusted classification source: resource metadata or an explicitly configured classification policy. An LLM self-assessment, a user-supplied label, or a label found inside untrusted document content is never the classification authority.
  - Unclassified or invalid data MUST NOT silently default to `PUBLIC`. When classification is required but unavailable, or when classifications conflict, the sensitive operation is denied unless an explicitly configured safe resolution rule (with documented precedence) applies.
  - Required tests: unknown, missing, invalid, and conflicting classification values each fail closed or follow only the documented precedence rule; none may default to `PUBLIC` or to any other permissive class.

`audit/models.py`

- `AuditEvent`: event ID, `chain_id`, monotonically increasing `sequence_number`, UTC timestamp, schema version, trace/request/session IDs, event type, actor reference, source component, tool/action where relevant, decision and reason codes, policy/detector versions, risk components, outcome, previous-event hash, and current event hash.
- Raw prompt text, full tool arguments, credentials, access tokens, or complete private documents MUST NOT be logged by default. Log digests, safe metadata, and redacted summaries instead.

### 6.2 Canonicalization and validation

- Validate Unicode/text limits before costly detector/model work. Retain an original digest; normalize a copy for detection.
- Canonical JSON for action digests must sort keys, use a documented Unicode representation, reject non-finite numbers, and encode with a fixed UTF-8 policy. Define and test it once in a shared utility.
- Paths: prefer registered resource IDs over free-form paths. If a file adapter accepts paths, resolve them under a configured base directory, reject traversal, and account for symlinks. Never trust a prefix string check alone.
- URLs/domains: parse with a standard URL parser; canonicalize the hostname; reject malformed URLs, user-info credentials, unapproved schemes, deceptive hostnames, and redirects that leave the allowed domain set. Revalidate redirect destinations at each hop.
- Email addresses: parse/normalize carefully and compare destination domains against policy. Do not assume a display name is an address. External sending is disabled in the first MVP.
- Reject unexpected fields and ambiguous action structures instead of silently ignoring them.

---

## 7. Input Threat Defense Engine

### 7.1 Purpose and limits

This subsystem estimates whether input or external content contains suspicious instruction patterns and maintains explicit trust/provenance. It does not prove that a prompt is safe. The firewall and tool adapters remain mandatory even when the detector returns “clean.”

### 7.2 Required pipeline

1. **Bounded intake:** enforce maximum bytes, nesting depth for structured payloads, content-type allowlist, and timeout.
2. **Safe normalization copy:** decode according to the declared format; flag invalid encodings, unexpected control characters, zero-width/format characters, homoglyph indicators, and excessive encoding/obfuscation. Do not overwrite original content.
3. **Deterministic heuristics:** maintain versioned, testable pattern rules for known suspicious behavior, such as instruction override, attempts to reveal hidden prompts/secrets, or instructions to perform unrelated external side effects.
4. **Context/provenance labeling:** distinguish actual user instructions from quoted, retrieved, or tool-returned material. Include source and trust metadata in the agent runtime's structured context.
5. **Optional local classifier:** wrap a classifier behind a provider interface. It returns label/scores, model/version, latency, and errors. The classifier is not required for the core system to start.
6. **Threat policy:** map findings to `PASS`, `FLAG`, `QUARANTINE`, or `REJECT` according to versioned configuration. Preserve reasons. The detector may not execute tools or grant permissions.
7. **Audit metadata:** emit the finding, detector versions, and content digest. Avoid copying full sensitive payloads into events.

### 7.3 Avoid the “regex sanitizer” trap

- Regex is useful for known indicators and malformed content; it does not understand all semantics and will produce both false positives and false negatives.
- Do not automatically delete suspicious phrases from text and then claim the result is sanitized. Deletion can distort meaning, hide evidence, or create new ambiguities.
- Prefer detection, source labeling, controlled context assembly, and explicit disposition. If the product offers a redacted view, retain an integrity-protected original reference and make the transformation explicit.
- XML-style `<untrusted_content>` boundaries MAY be used as one formatting aid. Escape content safely, avoid string-based attempts to strip only a closing tag, and do not treat the tag as a guarantee. Prefer structured messages with source labels when the model API supports them.

### 7.4 Multi-turn signals

Track only session metadata needed to detect suspicious sequences; session tracking is a detection signal and never an authorization input.

**Session identity and binding (v1):**

1. The gateway creates an opaque, high-entropy internal session ID using a cryptographically secure random generator (for example, at least 128 bits from the platform CSPRNG). A host- or client-supplied conversation ID is never the authoritative session identifier.
2. After request authentication, the internal session ID is bound server-side to the verified `tenant_id` and `subject_id` from the authenticated context. The binding is stored with the session record and re-checked on every session-state read and write.
3. A client-supplied conversation ID or session reference is not itself proof of identity or ownership. If the host supplies an external conversation reference, the gateway maps it to its own internal session identifier only after authentication, and only for the bound tenant/subject.
4. Session rotation creates a new internal identifier with its own binding. Rotation, guessed identifiers, borrowed identifiers, and cross-tenant or cross-user references MUST NOT allow access to another session's security signals; a lookup that fails the tenant/subject binding is treated as not found and cannot create, extend, or read state.
5. In v1, store bounded counters and timestamps in PostgreSQL `session_security_state`, keyed by the internal session identifier and the bound tenant/subject; do not store raw prompts or full model context as session memory.
6. Apply a 24-hour inactivity TTL (`SESSION_SIGNAL_TTL_SECONDS=86400`) and a seven-day absolute maximum lifetime (`SESSION_MAX_AGE_SECONDS=604800`), then delete or expire the record. Cleanup must also happen lazily when a state record is read so expiry does not depend solely on a scheduled job.

Useful signals include repeated policy override attempts, unusual escalation in requested privileges, and repeated blocked tool proposals. A “memory” of past threats must not automatically label the user malicious or silently create new permissions. Session tracking supplements per-action enforcement; it never replaces it.

**Required tests:** cross-user session access is denied; cross-tenant session access is denied; guessed or borrowed session IDs cannot read, extend, or create another session's state; session rotation cannot inherit or transfer another session's signals; TTL expiry and lazy cleanup match the configured values.

### 7.5 Detection outputs and errors

Return typed findings with stable reason codes such as `DIRECT_OVERRIDE_PATTERN`, `SECRET_EXTRACTION_REQUEST`, `OBFUSCATED_CONTENT`, `UNTRUSTED_INSTRUCTION`, `OVERSIZE_INPUT`, and `DETECTOR_UNAVAILABLE`. Version the codes. Use `DETECTOR_UNAVAILABLE` as a failure state, not as a clean result.

Policy decides whether detector unavailability blocks a request. For read-only, low-risk analysis it may permit a conservative degraded path if configured; for actions with external side effects, the authorization gateway MUST continue to apply all hard controls and MUST NOT assume the input is safe just because the classifier is down.

### 7.6 Tests

- Benign user messages containing strings such as “ignore previous instructions” in an educational, quoted, or defensive context must not automatically be treated as proof of malicious intent.
- Include direct injection, indirect injection in documents, multilingual and obfuscated variants, zero-width characters, invalid encodings, oversized payloads, and benign hard negatives.
- Ensure original content remains unchanged by detector-only operations.
- Ensure all detector exceptions/timeouts produce an explicit result.
- Ensure external content returns to the agent with an untrusted provenance label.

---

## 8. Intent extraction and manifest constraints

### 8.1 Role

Intent extraction converts the user's request into a structured description of the goal and constraints that are relevant to future actions. It is not an authorization service and cannot decide which company resources the principal may access.

### 8.2 Implementation requirements

- Implement an `IntentExtractor` interface with at least `MockIntentExtractor` for tests and `LocalModelIntentExtractor` for optional runtime use.
- Optional cloud model providers must implement the same interface and require explicit opt-in.
- Require strict structured output (provider-native JSON schema if supported; otherwise parse and validate bounded JSON). Retry malformed output at most a small configured number of times; never treat parse failure as permission.
- Use deterministic handling for simple known demo scenarios only if it is clearly marked as a test/mock implementation, not as real general-purpose natural-language understanding.
- Capture uncertainty, missing scope, and ambiguity. Ask a clarification question or constrain the manifest; do not guess file scope, recipients, user authority, or an external destination.
- Bind the manifest to the server request, principal reference, policy version, and expiry. Prevent the client or model from submitting a forged manifest as if the server had issued it.

### 8.3 Intent constraints should be concrete

For an example request, “summarize my unread emails from today,” a useful manifest might encode:

- supported action: `email.search` with a fixed query scope (`unread`, received since start of current day in the user's configured timezone);
- supported action: `text.summarize` on only the returned email content;
- prohibited-by-intent actions: forwarding, sending, deletion, changing mailbox state, or accessing unrelated files;
- no external destination is permitted because none was requested.

These are request constraints, not grants of mailbox access. The authenticated principal and policy engine still decide which mailbox can be searched.

For relative dates such as “today” or “this week,” use an IANA timezone supplied in the verified host-signed principal context or loaded from the trusted host's user-profile adapter. Validate it with Python `zoneinfo`. Never infer timezone from prompt text, IP address, browser headers, or model output. If no trusted timezone is available, use an explicitly configured tenant timezone; if none exists, ask for clarification or use UTC only where product behavior explicitly says so. Resolve the time interval once on the server and store its exact UTC start/end instants in the manifest. Tests must include daylight-saving transitions.

### 8.4 Confidence handling

`confidence_score` may be retained for diagnostic or clarification decisions. Never use “high confidence” to override policy. Confidence scores from different LLMs are not necessarily calibrated or comparable. In tests, use structured scenarios with expected constraints and record extraction errors separately from authorization errors.

---

## 9. Identity and authorization context without rebuilding enterprise IAM

The system should not implement an entire corporate identity platform. It must, however, consume a verified identity context from the host application.

### 9.1 Interface

Define a small `PrincipalResolver` interface. In development, use a clearly named `DevPrincipalResolver` that is enabled only under `APP_ENV=development` or `test`. Production integration MUST authenticate the host application and verify a host-signed principal assertion before policy evaluation. Do not accept a plain `role` or `user_id` field from a model output or an unsigned client field.

### 9.2 V1 host-to-gateway authentication contract (ADR-001)

Use a per-host shared secret with HMAC-SHA256 for v1. This authenticates the trusted host application to the gateway; it is not a replacement for end-user login. The host application authenticates the user using its own system, then inserts a principal assertion into the request body and signs the exact body bytes. The gateway trusts that assertion only after validating the host signature and checking the key ID's configured host/audience scope.

For all authenticated `/v1/*` routes, require these headers:

- `X-Gateway-Key-Id`: identifier selecting one configured host secret; it is not secret itself.
- `X-Gateway-Timestamp`: Unix seconds as an ASCII integer; reject if absolute clock skew exceeds `HOST_AUTH_TIMESTAMP_TOLERANCE_SECONDS` (default 60 seconds).
- `X-Gateway-Nonce`: cryptographically random value of at least 128 bits; v1 clients SHOULD use 256 bits.
- `X-Gateway-Signature`: lowercase hex HMAC-SHA256 digest.

The signature message is exactly the UTF-8 encoding of the following newline-separated fields, with no trailing newline:

```text
v1
{key_id}
{HTTP_METHOD_UPPERCASE}
{PATH}
{timestamp_ascii}
{nonce_ascii}
{sha256_hex_of_exact_raw_body}
```

`PATH` is the exact ASCII raw path sent by the host, excluding the query string; signed v1 routes MUST reject all query strings, non-ASCII path bytes, duplicate-slash paths, dot-segment paths, and percent-encoded path forms. HTTP methods are uppercased by the signing helper, and the accepted route path is matched against the gateway's canonical route path. Validate that `key_id`, timestamp, nonce, and path contain no newline or control characters before constructing the signing message. Enforce request-body size limits before buffering bytes for signature verification. The raw request body used to calculate the digest MUST be the exact received byte sequence, before JSON parsing or re-serialization. The expected HMAC is `HMAC-SHA256(secret_bytes, signing_message_bytes)`. Put constant-time comparisons behind `security/constant_time.py`, implemented with `hmac.compare_digest`; use it for request signatures and approval nonce/action digests. Reject malformed lengths before comparing. Do not log signatures, request bodies, or secrets.

After signature validation, atomically insert `(key_id, nonce, expires_at)` into a `host_request_nonces` table with a unique constraint on `(key_id, nonce)`. A duplicate is a replay and MUST be rejected. Nonces remain valid for at least the configured timestamp acceptance window plus clock-skew margin; expired rows can be deleted after that window. A database failure during replay protection means reject the request. The signed body includes the host-asserted principal context (subject, tenant/workspace if applicable, roles/groups needed for local policy mapping, issuer, audience, and authentication timestamp); the configured key ID constrains which host and audience can make those assertions. The gateway derives effective capabilities from its local policy; do not accept arbitrary permissions from the request as final authorization.

Require HTTPS for non-loopback deployments and keep the service on a private interface/network. Rotate per-host secrets manually through deployment configuration for v1; document rotation and overlapping key IDs. Never provide a general-purpose public “shared secret” endpoint.

### 9.3 Development resolver guard

`DevPrincipalResolver` MUST be constructible only when `APP_ENV` is exactly `development` or `test`; it returns only one fixed synthetic principal and ignores user/role/tenant/permission fields supplied by callers. It is a principal test adapter, NOT an HTTP authentication mode: the HMAC signature and replay check must still pass before the resolver is invoked. If `APP_ENV` is `staging`, `production`, or any unknown value and `PRINCIPAL_RESOLVER=dev`, startup MUST fail. The settings validator and app factory must both enforce this rule. A production startup test must prove the invariant; there must be no query/header/body override that re-enables the development resolver at runtime.

### 9.4 Required invariants

- Principal resolution happens before policy evaluation.
- Every approval, action, and audit event is bound to a principal or an explicit system actor.
- Tenant/workspace scope, if supported, is part of resource authorization—not just UI filtering.
- A missing, expired, malformed, or unverifiable identity yields an unauthenticated/denied result for protected operations.
- The API must not expose development identity bypasses in a non-development environment.

---

## 10. Deterministic Policy Engine

### 10.1 Purpose

The policy engine is the authoritative, deterministic permission evaluator. It must be fast, testable, side-effect-free, and independent of every LLM provider.

### 10.2 Rule evaluation order

Use a documented, fail-closed order:

1. Confirm the principal has been resolved by the trusted adapter.
2. Confirm the tool/action exists in the registered tool catalog.
3. Parse arguments using that tool/action's strict schema; reject unknown or missing required fields.
4. Apply hard-deny rules. Any matching hard deny returns `BLOCK` and cannot be overridden by risk score or approval unless the policy explicitly defines an authorized exception mechanism (do not add exceptions in v1).
5. Check principal/role/resource scope and action permission.
6. Check intent constraints and approved destination/resource bounds.
7. Run sensitive-data/egress policy as required for the action.
8. Calculate risk for residual signals.
9. Select allow, block, or approval according to the policy decision matrix.
10. Record the decision and policy version before any side effect begins.

If a mandatory check throws an exception or returns an unknown state, block or return a safe service error without executing. Do not interpret errors as `True`.

### 10.3 Mandatory policy decision matrix

The following matrix is the v1 baseline and MUST be mirrored by `docs/POLICY_DECISION_MATRIX.md` and the validated `config/risk_thresholds.yaml`. Policy rules may be stricter but MUST NOT weaken a hard denial. `Risk` is the deterministic 0–100 residual risk score calculated only after mandatory checks pass.

| Preconditions / side-effect class | Data class and destination | Risk 0–39 | Risk 40–79 | Risk 80–100 | V1 rule |
|---|---|---|---|---|---|
| Any hard-denied action, invalid schema, missing/invalid principal, unavailable mandatory policy, failed required DLP/egress check, or expired/replayed approval | Any | **BLOCK** | **BLOCK** | **BLOCK** | Hard constraints dominate every score and approval. |
| `READ_ONLY` | Data the principal is already authorized to read; no egress | **ALLOW** if all policy checks pass | **ASK_USER** only if policy marks clarification/approval eligible; otherwise **BLOCK** | **BLOCK** | Detector confidence alone never grants access. |
| `LOCAL_MUTATION` | `PUBLIC` or `INTERNAL`, destination is approved | **ALLOW** if explicitly permitted | **ASK_USER** if approval is configured; otherwise **BLOCK** | **BLOCK** | Write is allowed only by explicit tool/action policy. |
| `LOCAL_MUTATION` | `CONFIDENTIAL` | **ASK_USER** if the action is approval-eligible; otherwise **BLOCK** | **ASK_USER** if eligible; otherwise **BLOCK** | **BLOCK** | No implicit permission from read access. |
| `LOCAL_MUTATION` | `RESTRICTED` | **BLOCK** in v1 | **BLOCK** in v1 | **BLOCK** in v1 | Restricted-data writes are not registered in the initial release. |
| `EXTERNAL_MUTATION` | `PUBLIC`, exact destination is allowlisted, method/payload schema approved | **ALLOW** only if external egress is explicitly enabled | **ASK_USER** if eligible; otherwise **BLOCK** | **BLOCK** | External network and sending tools are disabled by default. |
| `EXTERNAL_MUTATION` | `INTERNAL` | **ASK_USER** only for an explicitly enabled, approved destination; otherwise **BLOCK** | **ASK_USER** if eligible; otherwise **BLOCK** | **BLOCK** | Must pass destination and payload checks before execution. |
| `EXTERNAL_MUTATION` | `CONFIDENTIAL` or `RESTRICTED` | **BLOCK** in v1 | **BLOCK** in v1 | **BLOCK** in v1 | No exception through score or human approval in the initial release. |
| `DESTRUCTIVE` | Any | **BLOCK** in v1 | **BLOCK** in v1 | **BLOCK** in v1 | Destructive tools are not registered in the initial release. |

Decision precedence is mandatory: (1) hard deny / invalid state, (2) policy permissions and resource scope, (3) required DLP/egress and approval rules, (4) risk thresholds for otherwise eligible actions, (5) allow only if every required gate passed. A score of 0 cannot make a forbidden action legal. An approval cannot override a hard deny. `ASK_USER` is valid only when the policy explicitly says that action is approvable; otherwise unresolved risk becomes `BLOCK`. The policy self-check suite MUST test representative rows of this matrix at startup and in CI.

Side-effect classes in this matrix are the canonical `SideEffectClass` enum defined in §6.1 and declared by tool registrations (§12.2); data classes are the canonical `DataClass` enum defined in §6.1. Unknown, missing, or invalid enum values MUST fail closed (`BLOCK`); do not implement string aliases, and never coerce an unknown value into an allowed class.

### 10.4 Configuration format

Use declarative YAML loaded with a safe parser and validated into Pydantic policy models. Support:

- schema version and policy version;
- named roles or capability sets;
- exact tool/action identifiers;
- allowed resource scopes and destinations;
- forbidden actions/paths/domains;
- action side-effect category (canonical `SideEffectClass` from §6.1);
- required approvals, including `required_approver_rule` semantics (see §13.2);
- explicit data-classification (canonical `DataClass` from §6.1) and egress rules;
- risk weights/thresholds;
- test fixtures or policy self-checks where appropriate.

Prefer specific resource identifiers or bounded patterns. Do not implement an unrestricted mini-language, dynamic Python expressions, shell expressions, or custom code execution in policy YAML. If wildcard patterns are supported, document their exact matching semantics and test boundary cases.

### 10.5 Example starter policy

The initial policy may allow these demo actions only:

- `mock_email.search` — read-only against the synthetic current user's mailbox;
- `mock_email.read` — read a message returned by an authorized search and within that mailbox;
- `text.summarize` — process only provided text; no external side effect;
- `mock_files.read` — read a synthetic file under the user's demo workspace;
- `mock_external_sink.write` — disabled by default and only enabled in a dedicated test scenario to prove egress blocking.

The initial policy MUST deny arbitrary shell execution, unrestricted network requests, real external email sending, file deletion, arbitrary database writes, and cross-user resource access.

### 10.6 Policy versioning and reload

Load policy at startup, validate it fully, and expose the loaded version/hash in health metadata and audit events. In addition to schema validation, load `config/policy_self_checks.yaml` and run deterministic, side-effect-free fixture evaluations against the actual loaded policy before the app becomes ready. Each fixture names a synthetic principal, tool/action, resource/data class, arguments, and expected decision/reason-code family. Any mismatch MUST fail readiness/startup; never “fix” the policy automatically to match a fixture. Run the same checks in CI and after every policy reload. If runtime policy reload is later implemented, reload atomically: validate the entire new file and pass self-checks first; if invalid, continue using the prior validated version or stop protected execution according to explicit configuration. Never partially apply a malformed policy. Record who/what changed a policy through the host's controlled administration flow; the AI SOC cannot mutate policy directly in v1.

### 10.7 Policy tests

Create table-driven tests covering every policy rule. Include allowed action, forbidden action, disallowed resource, invalid tool, missing argument, extra argument, cross-user access, path traversal, unapproved destination, policy parse error, and unexpected policy engine exception. `config/policy_self_checks.yaml` must include at minimum: one allowed mock read; one forbidden external egress; one cross-user resource denial; one unknown tool denial; one invalid-argument denial; one restricted-data egress block; and one hard-deny case with a low risk score to prove the score cannot override it. Enforce the invariant: **no policy failure or unknown state can result in an allowed side effect.**

---

## 11. Action validation, semantic matching, and risk engine

### 11.1 Action validator

The validator checks the concrete tool call against both the request's bounded intent constraints and the registered action schema. It must examine more than tool names. At minimum:

- exact tool/action identity;
- normalized arguments and unexpected fields;
- target resources and their scope;
- destination/recipient/domain when relevant;
- side-effect category and user-requested objective;
- action count or scope limits from the manifest;
- whether each prerequisite action succeeded and whether returned resource IDs belong to this request/principal.

Example: “summarize this email” does not authorize `email.forward`, even if the same email was legitimately read. A request to draft an email does not authorize sending it. A request to find a document does not authorize uploading it to an external URL.

### 11.2 Semantic matching

Semantic embeddings or model-based similarity may later detect that an action proposal appears unrelated to the request. Use it only as a signal:

- a high similarity score cannot grant a permission;
- a low or uncertain score may block, add risk, or require clarification depending on policy;
- define the input/output schema and model/version for reproducibility;
- evaluate false positives on benign paraphrases and multilingual requests;
- do not add a vector database until a measured use case justifies the operational cost.

### 11.3 Risk engine

Build v1 as deterministic scoring from versioned, auditable factors. Example factors include external destination, sensitive-resource classification, action side-effect class (`LOCAL_MUTATION`, `EXTERNAL_MUTATION`, `DESTRUCTIVE`; canonical `SideEffectClass` from §6.1), breadth of requested data, intent mismatch, repeated blocked actions, unknown resource, or incomplete security context. Each factor must have a code, bounded value, rationale, version, and test.

Do not start with “ML risk scoring” unless a labelled dataset and calibration/evaluation plan exist. A numeric score without calibration is just a heuristic. Store the individual contributing factors alongside the aggregate score so a reviewer can explain the decision.

### 11.4 Hard constraints versus score thresholds

The decision engine MUST apply hard policy denial before risk scoring. Risk thresholds apply only to actions that are otherwise eligible. Use a configuration such as:

```yaml
schema_version: 1
version: "dev-1"
thresholds:
  ask_user_at_or_above: 40
  block_at_or_above: 80
```

These values are **initial experimental defaults**, not empirically validated security thresholds. They must be calibrated against the project’s validation split and accompanied by false-positive/false-negative analysis. No threshold is allowed to override a hard denial, invalid argument schema, missing principal, failed egress control, or outstanding approval.

If a required risk component is unavailable, return an explicit error/unknown signal and apply the action-specific failure policy. Never substitute a fabricated score of zero.

---

## 12. Firewall gateway and tool invocation enforcement

### 12.1 The gateway is the execution chokepoint

Implement a single public internal interface, conceptually:

```python
async def invoke_tool(
    *,
    principal: Principal,
    request_context: RequestContext,
    manifest: IntentManifest,
    proposal: ProposedToolCall,
) -> ToolExecutionResult:
    ...
```

The final signature may vary to match the typed models. Its behavior may not vary: every adapter invocation goes through this gateway. The agent runtime must receive only a `ToolExecutor` interface that delegates to the gateway, not raw tool objects with direct execution methods.

### 12.2 Registry

Register tools by stable IDs and explicit action names. Each registration declares:

- argument schema;
- result schema and maximum output size;
- side-effect category using the canonical `SideEffectClass` enum from §6.1 (`READ_ONLY`, `LOCAL_MUTATION`, `EXTERNAL_MUTATION`, `DESTRUCTIVE`); registration with an unknown, missing, or invalid class fails at startup;
- resources/destinations it can access;
- timeout and concurrency limits;
- whether user approval is required and, if so, the `required_approver_rule` (semantics in §13.2);
- data sensitivity / egress behavior (expressed with the canonical `DataClass` enum from §6.1 where applicable);
- adapter version.

Unknown tool IDs must fail closed. Do not dynamically import modules based on LLM-generated tool names.

### 12.3 Execution flow

The gateway must:

1. validate principal, request, session, and manifest bindings;
2. find the exact tool registration;
3. parse/validate the arguments with its schema;
4. canonicalize resource/destination identifiers;
5. evaluate policy and intent constraints;
6. run mandatory egress checks where applicable;
7. compute deterministic risk factors;
8. block or create an approval request if needed;
9. persist a decision/audit event;
10. execute the adapter with explicit timeout and bounded result size only after `ALLOW`;
11. record execution outcome and sanitized result metadata;
12. return the typed result to the caller.

The tool adapter must also perform its own resource check using least-privilege access. The gateway is not a substitute for connector authorization.

### 12.4 No-bypass test

Provide tests proving that:

- the agent runtime cannot directly call adapters;
- every registered adapter invocation originated from the gateway;
- invalid policy/config prevents startup or prevents protected execution;
- exceptions during policy/validation/audit prerequisites do not silently continue to a side effect;
- a blocked external-sink action leaves the sink unchanged;
- a tool name or arguments modified after approval fail the action-digest check.

---

## 13. Human-in-the-loop approval

Approval is a narrow authorization workflow, not a general “click yes” bypass.

### 13.1 Actions that may require approval

Initially: sensitive external egress in dedicated tests, irreversible/destructive mutations when later introduced, and other policy-designated high-impact operations. Real external sending and arbitrary shell execution remain disabled in v1 even if an approval feature exists.

### 13.2 Approval binding

An approval record must bind to:

- verified requesting principal;
- exact tool/action;
- canonical arguments digest;
- exact target resource and destination;
- data classification / egress summary;
- policy version;
- expiry time;
- public opaque `approval_id` plus a separate cryptographically random one-time `approval_token` (at least 256 bits before encoding); store only a SHA-256 digest of the token, never the plaintext token;
- approver identity and approval timestamp, once decided.

**Approver eligibility (v1):**

1. An approver MUST be a verified principal produced by the authenticated authorization context (§9). An identity or role claimed in an AI response, a request body, a display name, or any unsigned field is never sufficient.
2. The configured `required_approver_rule` determines which roles, permissions, or specific principals may approve the operation; it is evaluated only against verified principal attributes.
3. By default the requester cannot approve their own action. Self-approval is permitted only when policy explicitly allows it for that action.
4. If no eligible approver can satisfy the configured rule, the operation is not approvable and the decision is `BLOCK`; do not leave an unsatisfiable approval request pending indefinitely.
5. Approval is bound to the exact canonical action, target resource, parameters, data classification, requester principal, policy version, and expiry, as listed above; any material change to the requested action, arguments, or target invalidates the approval and requires a new authorization decision.
6. The approval interface must display canonicalized targets — the resolved recipient address, canonical URL or hostname after policy checks, or canonical resource identifier — never attacker-controlled display text alone (§13.3).
7. The one-time token digest, constant-time comparison, atomic consumption, expiry checks, and replay protections defined in this section remain mandatory.
8. Record the verified approver identity and the final approval decision in the audit trail (`APPROVAL_DECIDED`, §16.1); never log the plaintext `approval_token` or other approval secrets.

Return the plaintext `approval_token` only once to the authenticated host application for delivery to an authorized approver; never put it in audit logs, URLs, telemetry, or model context. The approval decision request body carries the token over the authenticated host-to-gateway channel. Hash the received token with the specified SHA-256 procedure and compare it with the stored token digest using `hmac.compare_digest`; mark the token as consumed in the same transaction that records the approve/deny decision. Approval cannot be reused for a changed argument, different recipient, different file, changed model-generated plan, new policy version requiring re-evaluation, expired request, or different principal. Use `hmac.compare_digest` for canonical action-digest comparison as well; reject malformed lengths before comparing. Do not compare security tokens or digests with ordinary string equality.

**Required atomic consumption procedure for execution:** (1) re-resolve the authenticated principal and re-canonicalize the proposed tool/action/arguments/target; (2) begin a database transaction; (3) lock the approval row with `SELECT ... FOR UPDATE` or use one conditional update equivalent to `UPDATE approvals SET status='consumed', consumed_at=:now WHERE approval_id=:id AND status='approved' AND expires_at > :now AND principal_id=:principal AND policy_version=:current_policy RETURNING approval_id`; (4) compare the current canonical action digest with the approved digest in application code using `hmac.compare_digest`, and confirm the principal, resource/destination, expiry, and policy version match; the `approval_token` was consumed when the human's approve/deny decision was recorded and is not reused during execution; (5) require exactly one affected/returned row; (6) write the approval-consumed audit event in the same transaction; (7) commit before invoking the tool. If no row is returned, the approval is denied/replayed/expired and no tool runs. Consume the approved state before the external side effect to prevent concurrent double execution; if the tool subsequently fails, require a new approval rather than automatically restoring a consumed approval. Do not hold the transaction open during tool execution.

**Approval acceptance criteria (tested):** an unauthorized approver (wrong role, wrong principal, or self-approval without an explicit policy allowance) cannot approve; an unsatisfiable `required_approver_rule` results in `BLOCK` rather than a pending request; expired approvals cannot be consumed; a modified target, recipient, resource, arguments, or data classification fails the digest binding and no tool executes; a replayed approval decision or a repeated execution attempt fails the atomic consumption transition; the audit trail records the verified approver and decision without approval secrets.

### 13.3 API and UI contract

An approval prompt should clearly describe the action, canonical target, destination, data class, and relevant risk reasons. Build target identity from server-canonicalized fields: normalized email address (not a display name), canonical hostname/URL after policy checks (not a raw URL label), and stable resource ID plus a safe descriptive label (not attacker-controlled display text). If canonicalization fails, do not present an approvable request; block it. User-supplied display names or text may be shown only as quoted, untrusted metadata and must never replace the canonical target. Do not expose unnecessary raw secrets. Denial, expiry, missing approver identity, and service error all result in no execution. The caller cannot claim approval merely by setting `approved=true` in a tool argument.

---

## 14. Tools and execution isolation

### 14.1 MVP adapters

Begin with synthetic/mock tools only:

1. `mock_email.search` and `mock_email.read`: use a fixture dataset assigned to test users.
2. `mock_files.search` and `mock_files.read`: use a fixed synthetic workspace with resource IDs instead of arbitrary host paths.
3. `text.summarize`: deterministic fake implementation in unit tests; optional LLM summarizer in integration tests.
4. `mock_external_sink.write`: records attempted outbound content to a test sink and is used to prove that policy/DLP blocks egress.

Registry side-effect classes use the canonical `SideEffectClass` enum from §6.1: `mock_email.search`, `mock_email.read`, `mock_files.search`, `mock_files.read`, and `text.summarize` are `READ_ONLY`; `mock_external_sink.write` is `EXTERNAL_MUTATION`. No v1 mock tool is `LOCAL_MUTATION` or `DESTRUCTIVE`.

Do not connect to live inboxes, a real company database, or personal documents in the first implementation.

### 14.2 Shell execution

Do not implement an unrestricted `system_tool.py` or arbitrary shell execution in v1. Shell tools dramatically increase risk and create platform-specific sandboxing obligations. If added in a later phase, require all of the following before merging:

- a separate isolated container or OS sandbox;
- no host filesystem mounts other than a dedicated temporary directory;
- no inherited host credentials or Docker socket;
- network disabled by default;
- fixed command registry and argument schemas; no `shell=True` with model-provided strings;
- CPU/memory/process/time/output limits;
- non-root runtime, read-only base filesystem where practical, and disposable workspace;
- independent security review and sandbox escape tests.

A prompt to “run this command” is never sufficient authorization to execute arbitrary commands.

### 14.3 File access

The first file tool must operate on a sandbox root populated with test files. Use resource IDs or resolved paths constrained beneath that root. Test traversal encodings, symlinks, case sensitivity, unicode normalization, and race conditions. Do not expose the host user's home directory to the tool container.

### 14.4 Network and external actions

External HTTP or email adapters are disabled by default. Before adding them, create an explicit egress model: scheme, canonical hostname, resolved destination/redirect policy where applicable, allowed methods, payload data class, timeouts, maximum bytes, and audit behavior. Do not treat a domain suffix string check as sufficient SSRF defense. Avoid accessing link-local, loopback, private, or metadata-service ranges unless a deliberate local test adapter requires them and is isolated.

---

## 15. Output security and Data Loss Prevention

### 15.1 Inspect both user-facing output and tool-bound egress

The output defender has two distinct responsibilities:

1. **Response release:** inspect the final response before returning it to the user, integration, or downstream system.
2. **Outbound data flow:** inspect data before it is sent through an email, webhook, external API, file export, or other lower-trust sink.

**Streaming policy for v1: token streaming is disabled.** The runtime must collect the complete bounded response in memory or a bounded temporary buffer, run DLP/output policy, then release the response only if permitted. If the response exceeds the configured maximum, cancel/suppress it and return a safe error. Do not emit partial tokens before inspection. A future streaming mode would require a documented chunk protocol with buffering sufficient to detect cross-chunk secrets and with the ability to withhold the entire response; do not implement it in v1.

A response-only scanner does not prevent data from being exfiltrated through a tool call. Egress DLP must be integrated into the firewall decision before the adapter performs the side effect.

### 15.2 Detection strategy

Start with deterministic patterns and explicit data labels:

- API-key/token-like patterns and known synthetic canary secrets;
- credentials/password-like assignments;
- email addresses and selected personal identifiers where appropriate;
- configured confidential document/resource IDs;
- data-classification labels inherited from authorized sources;
- oversized unexpected output and possible hidden payload encodings.

Do not claim that regex or entropy scanning can detect all secrets, all PII, or semantic leakage. Add optional classifiers only after a test set and false-positive analysis exist. Avoid storing detections with full matching secret values; log a redacted category and location/field reference instead.

### 15.3 Destination-aware policy

Data classification must be checked against the destination. A user having permission to read a confidential file does not automatically have permission to send that file to a public endpoint. The egress policy evaluates destination trust, allowed data class, operation, and current principal authority. Data classes are the canonical `DataClass` enum defined in §6.1; classification comes from resource metadata or configured policy, never from model or user self-assessment, and unclassified data fails closed rather than defaulting to `PUBLIC`.

### 15.4 DLP outcomes

Use explicit results such as `PASS`, `REDACT`, `BLOCK`, and `REVIEW`. For tool-bound payloads, `BLOCK`/`REVIEW` happens before side effects. Redaction must be an explicit, testable transformation that preserves a digest/reference to the original; it must not silently alter data in a way that changes an action's meaning. Output inspection failures must have a configured disposition; sensitive egress fails closed.

### 15.5 Tests

Seed fake test data with synthetic canaries such as `CANARY_SECRET_...`—never use real credentials. Assert the canary cannot be written to an unauthorized external sink and is not printed unredacted in logs. Test benign similar strings to measure false positives. Include multilingual PII test cases only when there is a defined detector and test policy for them.

---

## 16. Audit, telemetry, and privacy

### 16.1 Events

Emit structured events for at least:

- `REQUEST_RECEIVED`
- `PRINCIPAL_RESOLVED` / `PRINCIPAL_REJECTED`
- `INPUT_INSPECTED`
- `INTENT_CREATED` / `INTENT_FAILED`
- `TOOL_CALL_PROPOSED`
- `POLICY_EVALUATED`
- `APPROVAL_REQUESTED` / `APPROVAL_DECIDED` / `APPROVAL_EXPIRED`
- `TOOL_EXECUTION_STARTED` / `TOOL_EXECUTION_COMPLETED` / `TOOL_EXECUTION_FAILED`
- `EGRESS_INSPECTED`
- `OUTPUT_INSPECTED`
- `RESPONSE_RELEASED` / `RESPONSE_SUPPRESSED`
- `SECURITY_ALERT_RAISED`

Use stable event names and schema versions. Include `trace_id`, `request_id`, `event_id`, UTC timestamp, component and version identifiers, policy version, decision reason codes, duration, and safe resource references as applicable.

### 16.2 Hash chain, canonical bytes, and concurrency (ADR-002)

**V1 decision:** use PostgreSQL-serialized append with a transaction-scoped advisory lock, not an in-process mutex. This works across multiple FastAPI workers connected to the same database. Every event in v1 belongs to one `chain_id` per deployed database. The audit repository MUST use the same lock protocol for every append to that chain; no other module may insert directly into the audit-event table. A future high-volume version may shard into independent chains, but that is not part of v1.

Within one database transaction running at PostgreSQL `READ COMMITTED` isolation, the append routine MUST acquire the lock before reading any prior-chain state. It MUST:

1. acquire a PostgreSQL transaction-level advisory lock using a documented fixed signed 64-bit lock key (or fixed two-int key) for the v1 chain;
2. read the latest committed `sequence_number` and `event_hash` for that chain (or the documented genesis record if empty);
3. assign the next integer sequence number while holding the lock;
4. build the canonical event payload excluding `prev_hash`, `event_hash`, and any storage-only fields;
5. serialize that payload as UTF-8 canonical JSON: object keys sorted lexicographically; no insignificant whitespace; Unicode emitted as UTF-8 rather than ASCII escapes; normalize audit metadata strings to Unicode NFC during canonical serialization only; do not mutate original request/tool input, which is not stored raw by default and is represented by a digest where needed; integers/booleans/null only for hashed numeric/primitive fields unless a field schema explicitly defines a canonical decimal string; reject NaN/Infinity and other non-JSON values; no trailing newline;
6. calculate the hash using the exact byte formula below;
7. insert the event with sequence number, previous hash, the exact `canonical_event_bytes` stored in a `BYTEA` column, and calculated hash; indexed/queryable metadata columns may be stored alongside it but the verifier MUST hash the exact stored bytes, not a reconstructed ORM/JSONB serialization; commit while the lock is still transaction-scoped.

Define `canonical_event_bytes` as the UTF-8 bytes of the canonical JSON payload described above. Define `chain_id_bytes` as the UTF-8 bytes of the configured chain ID. Use a 32-byte all-zero genesis previous-hash value for the first event. Hash input is exactly:

```python
hash_input = (
    b"AIAS-AUDIT-V1\x00"
    + len(chain_id_bytes).to_bytes(4, "big")
    + chain_id_bytes
    + sequence_number.to_bytes(8, "big")
    + previous_hash_bytes  # exactly 32 raw bytes, not 64 ASCII hex bytes
    + len(canonical_event_bytes).to_bytes(8, "big")
    + canonical_event_bytes
)
event_hash = hashlib.sha256(hash_input).digest()
```

Persist hashes as lowercase 64-character hex strings for readability, but decode the previous hash to raw 32-byte form before hashing. `sequence_number` begins at 1 and is contiguous within each chain. Event order is the database append serialization/sequence order, **not wall-clock timestamp order**; UTC timestamps are event metadata and may be equal or slightly out of order due to clock behavior. The unique constraint on `(chain_id, sequence_number)` is a final integrity guard. If the lock, prior-hash read, insert, or commit fails, the event append has failed; apply §16.4 and do not perform a protected side effect that requires an audit record.

Add tests with concurrent tasks from multiple workers/processes to prove that sequences are contiguous, each `prev_hash` references the preceding sequence's hash, and the verifier accepts the final chain. Add fixed test vectors for the canonical JSON bytes and hash input; changes to serialization require an audit schema/version decision, not an unreviewed helper refactor.

A plain local hash chain is **tamper-evident, not absolutely tamper-proof**. An attacker able to rewrite the entire chain can recompute hashes. Stronger guarantees require a separately protected signing key, signed periodic checkpoints, and/or exporting checkpoints to an append-only or independently administered store. Those are future hardening options and must be described honestly.

### 16.3 Privacy and retention

- Do not log raw prompts, full model context, private documents, complete tool arguments, secrets, or full DLP match values by default.
- Prefer digests, lengths, safe categories, resource IDs, decision codes, and redacted excerpts only when needed for investigation.
- Make any diagnostic payload capture opt-in, local-development-only by default, redacted, and subject to a documented retention period.
- Never send raw logs or private content to a cloud model automatically.
- Ensure exception messages and provider errors do not include API keys or complete request bodies.

### 16.4 Operational failures

Define explicitly how the gateway behaves if audit persistence is unavailable before an external side effect. For sensitive or irreversible actions, if the required decision/audit write cannot be completed, do not execute. For low-risk read-only demo actions, any weaker behavior must be an explicit configuration decision and covered by tests; the default should remain to fail closed for security-critical records.

---

## 17. Security analytics / AI SOC — later phase only

The longer-term concept may include an AI-assisted analyst that summarizes audit trails and detects multi-step suspicious behavior. It is not part of the initial authorization path.

### 17.1 First version: deterministic alerts

Implement simple, auditable rules first, such as repeated blocked calls, unusually broad resource access, a burst of read attempts across synthetic files, repeated external-destination attempts, or several approval failures. Thresholds are configurable and tested.

### 17.2 Optional AI-assisted analysis

The SOC analyzer is itself an AI component and therefore an attack surface. Audit fields such as user text excerpts, tool names, URLs, filenames, destination labels, and exception strings may be influenced by an attacker. Pass the analyzer a structured event envelope where all request/tool-originated fields are explicitly labeled `EXTERNAL_UNTRUSTED`; do not concatenate them into system instructions. Limit and redact fields before model submission, and never send raw audit payloads to a cloud model automatically.

After audit format and evaluation are stable, an optional local model may summarize event clusters and propose hypotheses. Its results must be labeled as untrusted analysis, not verified facts. It may open or annotate an alert and recommend an investigation, but MUST NOT invoke tools, consume approvals, change policies, alter audit records, revoke sessions, terminate workloads, or trigger a circuit breaker in v1. Only deterministic, separately tested alert rules may create alert records. Add an adversarial fixture where an audit field says to ignore instructions, reveal secrets, or execute a response; it must remain plain untrusted data and produce no action beyond a bounded alert/hypothesis.

### 17.3 Future circuit breakers

Any future automated containment must be driven by deterministic, pre-approved rules with narrowly scoped actions, audit events, rollback procedures, and human override. Do not give an LLM direct credentials to revoke sessions, kill containers, or rewrite policies. Test false alarms and recovery before activating any automatic response.

---

## 18. FastAPI integration contract

Use the API as an adapter over services; the business/security logic remains in domain modules and is invoked identically by in-process tests.

### 18.1 Initial endpoints

- `GET /health/live`: process is alive; no secrets or internal stack details.
- `GET /health/ready`: critical config, database, and mandatory dependencies are ready. It must not reveal credentials.
- `POST /v1/requests`: accepts a bounded request from an authenticated host application, establishes request context, runs input inspection and intent extraction, and returns either a safe result, a clarification/review state, or a reference to agent execution. It must not silently execute arbitrary tools.
- `POST /v1/tool-calls/evaluate`: evaluates a typed tool proposal and returns a `DecisionRecord`; execution remains behind the controlled server-side executor.
- `POST /v1/tool-calls/execute`: internal/development integration endpoint only if a separate evaluation/execution split is required. It must re-evaluate or use a short-lived server-issued decision token bound to exact arguments, principal, policy version, and expiry. Never trust a client-provided `ALLOW` result.
- `POST /v1/approvals/{approval_id}/decision`: records a verified approval decision; requires the configured approver identity, one-time `approval_token` in the signed request body, constant-time token validation, and valid transactional state transition.

Do not expose public unfiltered audit-log access in v1. If an admin/audit endpoint is added, require an authenticated administrative context and enforce field redaction and pagination limits.

### 18.2 API safeguards

- All `/v1/*` routes MUST enforce the HMAC host-auth contract in §9.2 before principal resolution, policy evaluation, or approval processing, including when `PRINCIPAL_RESOLVER=dev`. Health endpoints may be unauthenticated but reveal only liveness/readiness booleans and non-sensitive build/config status.
- FastAPI's `/docs`, `/redoc`, and `/openapi.json` MUST be disabled when `APP_ENV` is not exactly `development` or `test` (`docs_url=None`, `redoc_url=None`, `openapi_url=None`). If a later deployment requires documentation, expose it only through an authenticated administrative route.
- Token streaming is forbidden in v1; buffer and inspect the complete response as defined in §15.1.
- Validate request bodies with Pydantic; reject extra fields for sensitive routes.
- Add request size limits, deadlines, bounded concurrency, and safe error responses.
- Use explicit HTTP statuses for invalid input, denial, approval-required state, dependency outage, and internal failure. Do not leak stack traces in client responses.
- CORS must be disabled or narrowly configured for local development; no wildcard CORS with credentials.
- Add rate limiting per verified principal/session for request creation, tool proposals, invalid-call bursts, and approval attempts. The initial local implementation may use a simple in-process limiter; document that it is not multi-worker/distributed-safe. Move to a shared limiter only when deployment needs it.
- API routes must not accept a user-supplied principal, decision, risk score, or approval outcome as authority.

---

## 19. Dataset and evaluation protocol

### 19.1 Never invent the “1,000 samples” claim

The first release should create a reproducible seed dataset and grow it systematically. A target of 1,000 cases can be useful, but the count itself does not establish security. Each case must have an ID, source/provenance, license or origin note, task, attack category, expected outcome, label, and split. Do not copy public datasets into the repository without checking their license and usage requirements.

Use original synthetic fixtures for deterministic unit and policy tests. Public prompt-injection/agent benchmarks may be integrated as optional evaluation adapters after checking license, version, model assumptions, and reproducibility. Candidate references include InjecAgent and AgentDojo; benchmark results depend on the model, tools, agent scaffold, and configuration and should not be compared without matching methodology.

### 19.2 Separate evaluation tasks

Do not collapse these distinct problems into one accuracy number:

1. **Input detection:** did the detector flag the malicious input or untrusted content?
2. **Intent extraction:** did the system capture the requested goal and constraints?
3. **Authorization correctness:** did the policy/gateway allow valid actions and block unauthorized actions?
4. **End-to-end attack success:** did any prohibited side effect occur in the full agent scenario?
5. **DLP/egress:** did a protected canary/sensitive record reach an unauthorized sink?
6. **Operational performance:** latency, errors, throughput under a defined test environment.

A detector may miss an injection while the firewall still correctly blocks its attempted action. Report these as separate facts. Likewise, an injection detector may flag an attack while a policy bug still allows the tool call.

### 19.3 Metrics and definitions

For any binary task, declare the positive class explicitly. For attack detection, a useful convention is positive = malicious/unauthorized. Compute:

- `TP`: malicious cases correctly flagged/blocked according to the task's specific definition.
- `FN`: malicious cases incorrectly treated as benign/allowed.
- `FP`: benign cases incorrectly flagged/blocked.
- `TN`: benign cases correctly treated as benign/allowed.
- `precision = TP / (TP + FP)` when denominator is non-zero.
- `recall = TP / (TP + FN)` when denominator is non-zero.
- `F1 = 2 * precision * recall / (precision + recall)` when defined.
- `accuracy = (TP + TN) / total`.
- `false_negative_rate = FN / (TP + FN)`, therefore it equals `1 - recall` for the same positive class, same sample set, same decision threshold, and same missing-value convention.
- `false_positive_rate = FP / (FP + TN)`.

Report undefined denominators as `N/A`, never as a misleading zero. Report class counts and a confusion matrix. Include per-category metrics because high aggregate accuracy can hide a severe failure category.

For tool authorization, also report **unauthorized side-effect count** and **unauthorized side-effect rate**. An event is an end-to-end attack success only if the prohibited effect actually occurred under a documented definition—not merely because the detector missed a phrase.

### 19.4 Dataset design

Build categories such as:

- benign direct instructions, paraphrases, and legitimate quoted discussion;
- direct injection/jailbreak attempts;
- indirect injection embedded in synthetic email/document/web results;
- intent mismatch and unauthorized tool substitutions;
- cross-user/cross-resource access attempts;
- destination manipulation and data exfiltration;
- path traversal and malformed identifiers;
- invalid schemas, extra fields, malformed JSON, oversize content, unicode/encoding variations;
- multi-turn attack scenarios;
- ambiguous user requests requiring clarification;
- provider timeout, detector outage, and audit failure cases;
- hard negatives that look suspicious but are legitimate.

### 19.5 Splits and reproducibility

- Keep development, validation, and final holdout sets distinct.
- Deduplicate paraphrases and templates across splits to reduce leakage.
- Do not tune thresholds on the final holdout and then report it as an unbiased test.
- Fix random seeds where randomness is present; record them in the run metadata.
- Record git commit, Python/dependency lock hash, dataset version, policy hash, detector/model/provider version, thresholds, hardware, and timestamp for each run.
- Keep a small quick regression subset for every commit and a larger evaluation for scheduled/manual runs.

### 19.6 Required evaluation artifacts

Each run must create a machine-readable JSON report and a human-readable Markdown summary, including:

- counts and dataset version;
- confusion matrices per task/category;
- metric definitions and values;
- latency p50/p95/p99 and sample count;
- detector/provider failures and retry counts;
- unauthorized side effects observed;
- configuration/version metadata;
- known limitations and any skipped tests.

Do not embed desired or fabricated results into the README. Report only actual run output.

---

## 20. Test strategy and security gates

### 20.1 Test layers

- **Unit tests:** schema validation, canonicalization, heuristics, policy decisions, action validator, risk-factor arithmetic, approval digest/state transitions, DLP patterns, audit hashes.
- **Integration tests:** API + policy + mock tools + database + audit sequence.
- **Security tests:** prompt injection scenarios, indirect content, forbidden side effects, path traversal, parameter mutation after approval, replay, cross-user access, provider failures.
- **Evaluation tests:** metric calculations against small hand-calculated cases; fixed regression suite; full dataset runner.
- **Reliability tests:** database unavailable, detector/model timeouts, invalid configuration, audit writer failure, duplicate concurrent approval submissions, timeouts, oversized output.

### 20.2 Mandatory invariants in tests

1. Unknown tool/action -> no execution.
2. Missing/invalid principal -> no protected action.
3. Policy evaluation error -> no execution.
4. Invalid arguments or unexpected fields -> no execution.
5. Hard deny -> no execution regardless of risk score or model confidence.
6. Missing approval -> no execution.
7. Changed approved arguments -> no execution.
8. Reused/expired approval -> no execution.
9. Egress/DLP block -> sink is unchanged.
10. Detector false negative -> firewall still enforces permissions.
11. Detector/provider outage -> no automatic fail-open for a protected action.
12. Every adapter call has a correlated gateway decision event.
13. Audit-chain tampering is detected by the verifier.
14. Secrets and full private payloads do not appear in default logs or API error messages.
15. Tool output fed to the model is labeled untrusted.
16. Local/mock operation works with no internet access and no API keys.
17. Invalid HMAC signature, signed-body mutation, stale timestamp, unknown key ID, replayed nonce, or database failure during nonce registration -> no protected processing.
18. `DevPrincipalResolver` cannot start outside `APP_ENV=development|test`; it never bypasses HMAC; `/docs`, `/redoc`, and `/openapi.json` are absent outside those environments.
19. Concurrent audit appends produce one contiguous sequence with correct previous-hash links; fixed canonicalization vectors remain stable.
20. Concurrent approval consumption allows at most one consumer; altered target, nonce, or digest -> no tool execution.
21. No response bytes are released before full DLP inspection in v1; oversized or DLP-blocked outputs are fully suppressed.
22. AI SOC analysis of prompt-injected audit fields cannot call tools, change policies, edit logs, or trigger containment.
23. Session security state is bound to the verified tenant/subject; guessed, borrowed, rotated, cross-user, or cross-tenant session references cannot read, extend, or create another session's signals.
24. Only a verified principal satisfying `required_approver_rule` can approve; self-approval requires explicit policy; an unsatisfiable rule results in `BLOCK`, never a pending request.
25. Unknown, missing, or invalid `SideEffectClass` or `DataClass` values fail closed: tool registration is rejected or the decision is `BLOCK`; no aliases or coercions exist.

### 20.3 CI/local check command

`bash scripts/check.sh` should run, in order:

1. lockfile/dependency consistency check;
2. Gitleaks scans with a documented, version-pinned CLI: `gitleaks dir --redact --exit-code 1 .` for working files and `gitleaks git --redact --exit-code 1 .` for repository history; fail if the scanner is missing or either command returns non-zero, and never print unredacted findings;
3. Ruff formatting/lint;
4. static type checks for designated modules;
5. constant-time-compare helper tests and static review for signature/approval digest comparisons;
6. unit tests;
7. integration/security tests using the configured test database/mock adapters;
8. audit-chain verifier tests, including concurrent appends;
9. policy self-check fixture evaluation;
10. a small deterministic evaluation regression suite;
11. invariant greps or static checks for obvious prohibited patterns.

The script must exit non-zero on any failure and print a clear summary. Coding agents MUST run it before declaring a task complete.

---

## 21. Development roadmap — phase gates

Build vertical, testable slices. Do not attempt the entire SOC, every classifier, and every tool at once.

### Phase 0a — Repository foundation

**Deliverables:** repository layout and package scaffold; `pyproject.toml`/`uv.lock`; `.gitignore`; `.env.example`; Dockerfile and Compose config (API + PostgreSQL); settings validation; minimal FastAPI app with `/health/live` and `/health/ready`; baseline pytest/HTTPX test setup; `scripts/check.sh` with the initial checks (lockfile consistency, Ruff, type checks, unit tests, invariant greps); README setup; and the documentation scaffold: `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/SECURITY_INVARIANTS.md`, `docs/IMPLEMENTATION_STATE.md`, `docs/DECISIONS.md` (ADR index), `docs/KNOWN_LIMITATIONS.md`, `docs/POLICY_DECISION_MATRIX.md`, and `docs/adr/`.

Create and record at least these decisions before Phase 1: ADR-001 host-to-gateway HMAC authentication and development-resolver guard; ADR-002 Postgres-serialized audit hash-chain append and exact canonical byte format; ADR-003 v1 streaming disabled/buffer-then-release; ADR-004 AI SOC analyzer treated as an injection target and alert-only; ADR-005 SQLAlchemy async persistence; ADR-006 Alembic migrations; ADR-007 policy matrix and startup self-checks. `docs/DECISIONS.md` is only the index/summary linking to one file per ADR under `docs/adr/`; do not duplicate full ADRs in the index.

**Rules:** no real tools and no cloud model calls; no host-auth, nonce, migration, or development-resolver-guard implementation yet (that is Phase 0b). Compose must start the API and database; tests run from a clean checkout using documented commands. `/docs`, `/redoc`, and `/openapi.json` must be absent outside dev/test.

**Commands and expected results:**

- `docker compose up -d db` — the PostgreSQL container starts and reports healthy.
- `uv sync --frozen` — dependencies install from the committed lockfile with no resolution drift.
- `uv run pytest` — baseline tests pass; `bash scripts/check.sh` exits 0 on the clean scaffold and non-zero on an injected failure.
- `docker compose up api` — `GET /health/live` returns 200; `GET /health/ready` reports configured readiness; neither leaks secrets or stack details; `/docs` is absent when `APP_ENV` is not `development`/`test`.

**Definition of Done:** fresh clone setup succeeds on macOS with Docker using only documented commands; configuration errors are clear and fail startup; no secrets committed; `scripts/check.sh` exits non-zero on any failure; the health and OpenAPI checks above pass. Phase 0a is scaffold- and documentation-complete only; it must not claim any security control that Phase 0b implements.

### Phase 0b — Security foundation

**Deliverables:** host-to-gateway HMAC-SHA256 authentication per §9.2 (headers, canonical signing message, constant-time verification, request-size bounds); timestamp tolerance and nonce validation with atomic replay rejection (`host_request_nonces`, unique `(key_id, nonce)`); SQLAlchemy 2.x async database layer with `asyncpg`; Alembic baseline migration and documented migration command; `DevPrincipalResolver` startup guard rejecting non-dev/test environments; `config/policy_self_checks.yaml` and startup/CI policy self-check scaffolding wired into readiness; Gitleaks secret scanning in `scripts/check.sh` (`dir` and `git` scans, redacted, fail if the scanner is missing or reports findings); tests for authentication failures and startup security invariants.

**Rules:** no real tools and no cloud model calls. All `/v1/*` routes MUST enforce the HMAC contract before principal resolution, including when `PRINCIPAL_RESOLVER=dev`. A database failure during replay protection means reject. Audit-repository append scaffolding must follow ADR-002's lock protocol; the full hash chain is completed in Phase 7.

**Commands and expected results:**

- `uv run alembic upgrade head` — applies the baseline migration to an empty database; running it again reports the database is already at head (idempotent per revision state).
- `uv run pytest tests/integration -k "host_auth or nonce or principal"` — valid signed requests succeed; a forged signature, signed-body mutation, stale timestamp, unknown key ID, or replayed nonce each returns the documented denial status with no protected processing.
- `APP_ENV=production PRINCIPAL_RESOLVER=dev uv run uvicorn ai_security.api.app:app` — refuses to start with a clear error.
- `bash scripts/check.sh` — includes both Gitleaks scans; fails non-zero if Gitleaks is unavailable or reports a secret.

**Definition of Done:** host-auth signing/verification and replay rejection tests pass; migrations apply to an empty database and re-apply idempotently according to Alembic's revision state; `DevPrincipalResolver` cannot start outside `APP_ENV=development|test`; policy self-check scaffolding runs at startup and in CI and fails on a deliberately mismatching fixture; `/docs`, `/redoc`, and `/openapi.json` remain absent outside dev/test; Gitleaks runs in `check.sh`; no secrets committed; `check.sh` exits non-zero on any failure. Phase 0b is not complete merely because the application starts: the security-invariant tests above must actually pass and their commands recorded.

### Phase 1 — Typed contracts and deterministic policy engine

**Deliverables:** strict Pydantic models, safe YAML loader, validated policy model, principal test adapter, decision reason codes, action/resource canonicalization.

**Definition of Done:** table-driven policy tests cover allowed, forbidden, malformed, cross-scope, unknown, and error cases. No LLM is involved in authorization.

### Phase 2 — Tool registry and enforced gateway

**Deliverables:** registry, base tool protocol, mock email/files/external sink adapters, `invoke_tool` gateway, timeouts/result bounds, audit interface.

**Definition of Done:** no-bypass tests prove the mock side-effect sink changes only after a valid gateway `ALLOW`; unknown or denied actions have no side effect.

### Phase 3 — Input threat defense and context provenance

**Deliverables:** intake limits, normalization copy, versioned heuristics, typed detector findings, trust labels, prompt/context assembly utilities, detector failure behavior.

**Definition of Done:** direct/indirect attack and benign hard-negative tests pass; untrusted source labels survive to the agent context; no claim of complete injection detection.

### Phase 4 — Intent extraction and action validation

**Deliverables:** mock extractor, local-model adapter interface, bounded `IntentManifest`, request binding/expiry, action-constraint validator, ambiguous request behavior.

**Definition of Done:** malformed LLM output and extractor outages do not grant permissions; tool arguments are compared with concrete intent limits; all execution still routes through the gateway.

### Phase 5 — Risk engine and approval workflow

**Deliverables:** deterministic, versioned risk factors; threshold configuration; approval request storage; one-time approval flow bound to canonical action digest.

**Definition of Done:** risk calculations are unit tested; hard denies cannot be overridden; approval mutation/replay/expiry tests prove no unauthorized execution.

### Phase 6 — Output DLP and egress policy

**Deliverables:** test canaries, configurable sensitive patterns, data-classification model, destination-aware egress checks, release outcomes.

**Definition of Done:** canary data never reaches an unauthorized mock sink; DLP logs remain redacted; false-positive cases are documented.

### Phase 7 — Audit persistence and verification

**Deliverables:** structured event schema, database persistence, transaction-serialized hash chain with fixed canonical-byte tests, concurrent writer test, verifier, retention/data-handling document, safe operational logs.

**Definition of Done:** full request-to-tool event sequence is correlatable; mutation/reordering is detected; privacy tests show that raw secrets are not in default logs.

### Phase 8 — FastAPI integration and local model

**Deliverables:** request/tool/approval routes, local model provider adapter, startup config checks, safe errors, deadlines and basic rate limiting, integration docs.

**Definition of Done:** local/mock path works offline; no route trusts client-supplied decisions; optional model provider failures do not bypass policy.

### Phase 9 — Evaluation harness and benchmark adapters

**Deliverables:** dataset manifest and provenance, split tooling, metric unit tests, evaluation CLI, JSON + Markdown reports, regression suite.

**Definition of Done:** one command reproduces results from a versioned fixture set and emits accurate confusion matrices/latency. All reported metrics are derived by code and match hand-calculated unit tests.

### Phase 10 — Security hardening and AI-assisted monitoring

**Deliverables:** threat-model review, abuse/load tests, alert rules, optional local read-only audit summarizer with adversarial-log tests, runbooks and known limitations, CycloneDX SBOM generated from the locked dependency set and archived with the release/evaluation artifacts.

**Definition of Done:** the AI monitor has no tool-execution or policy-edit privileges; deterministic alerts have tested actions; all release gates pass.

### Work order note

Input defense is first in the runtime data flow, but the first implementation milestone should be schemas + policy + an unbypassable mock tool gateway. Then implement the input detector early, before integrating any powerful agent tools. This prevents a false sense of safety and establishes measurable security invariants from day one.

---

## 22. Coding-agent operating protocol

A coding agent must work in small verifiable tasks, not rewrite the repository wholesale.

### 22.1 Start-of-task checklist

Before editing code, the agent MUST:

1. Read this blueprint, `docs/SECURITY_INVARIANTS.md`, and the relevant module docs/tests.
2. Inspect the current repository state, existing files, git diff, and dependency lock.
3. State the specific files it expects to change and the acceptance criteria.
4. Identify any ambiguity that materially changes security behavior. Ask rather than guess; if the blueprint already specifies behavior, follow it.
5. Avoid unrelated refactors and preserve currently passing behavior unless the task explicitly changes it.

### 22.2 Implementation rules

- One small deliverable per task: schema + tests, policy rule + tests, one route + tests, one adapter + tests.
- Do not add a dependency without explaining why it is needed, its license, and its runtime impact.
- Do not hard-code a cloud model ID, rate limit, key, absolute local path, or developer-specific configuration.
- Do not place policy evaluation in a prompt, tool description, or model-generated JSON field.
- Do not let the agent call real tool adapters directly.
- Do not swallow exceptions or treat missing data as clean/allowed.
- Do not weaken a test merely to make it pass. Add the minimal regression test for every bug discovered.
- Never use real secrets or private documents in fixtures.
- If a planned feature is deferred, update the status and explain the trigger for implementing it later.

### 22.3 End-of-task checklist

Before reporting completion, the agent MUST:

1. Run the focused tests for the changed module.
2. Run `bash scripts/check.sh` or report precisely why the required environment is unavailable.
3. Inspect `git diff` for unrequested edits, secrets, raw payload logs, broad exception handling, and bypass paths.
4. Report files changed, implementation summary, actual commands/results, remaining risks, and any skipped tests.
5. Update documentation/config examples if contracts changed.
6. Never claim tests pass unless the commands were actually executed and returned success.

### 22.4 Mandatory project memory/state files for long coding sessions

Maintain:

- `docs/IMPLEMENTATION_STATE.md`: current phase, last verified commit/state, known blockers, next concrete task.
- `docs/DECISIONS.md`: a concise index/summary linking to individual decision files under `docs/adr/`; do not store a second full copy of ADR content here.
- `docs/adr/ADR-NNN-*.md`: one decision per file, including context, decision, alternatives considered, security consequences, tests/verification, and status.
- `docs/KNOWN_LIMITATIONS.md`: what the system cannot currently detect/prevent and which phase addresses each item.

Update these only with confirmed facts, not assumptions. When a decision changes, create a superseding ADR and update the index; do not silently rewrite the historical rationale.

---

## 23. Definition of “done” and release maturity

Do not label the system “production-grade,” “enterprise-ready,” “fully secure,” or “perfect protection” merely because the roadmap is implemented. Use precise maturity language.

### Prototype release

- Local mock tools only.
- Deterministic authorization gateway and input detector.
- Repeatable tests and documented limitations.
- No real data or external side effects.

### Research/demo release

- Optional local model integration.
- Versioned evaluation fixtures and benchmark reports.
- Local UI/API demo with clear mock/real-mode labeling.
- No claims about general injection prevention beyond measured evidence.

### Controlled integration release

Before connecting any real tools, require a separate threat-model review, connector permission design, secret handling plan, egress policy, runtime deployment plan, incident/rollback runbook, regression benchmark, and review of host-application identity integration. Every real connector must be separately disabled by default and enabled only with explicit config.

### Company deployment

A real company deployment additionally requires a designated operator, security review, privacy/retention review, availability/backup design, dependency/supply-chain review, monitoring and incident response, and a documented responsibility boundary with the existing enterprise security team. This personal project does not automatically satisfy those needs.

---

## 24. First task to hand to a coding agent

Use the following prompt as the first implementation task (Phase 0a) after creating this file. Phase 0b is a separate follow-up task with its own acceptance criteria; do not ask the agent to start it in the same pass. Do not ask the agent to build the whole platform in one pass.

```text
1. Read the supplied master blueprint in full (currently `AI_Agent_Security_Platform_Master_Blueprint_v1.2.md`), especially §§0–6, §§9–13, §§15–22.

Task: implement Phase 0a only. Inspect the current repository before editing. Read `AI_Agent_Security_Platform_Master_Blueprint_v1.2.md` in full (or its renamed copy in the repository), then create the repository scaffold and package layout, pyproject.toml and uv.lock, Dockerfile, docker-compose.yml with API + PostgreSQL, settings validation, a minimal FastAPI app with /health/live and /health/ready, baseline pytest/HTTPX tests, scripts/check.sh with the initial checks, .env.example, .gitignore, README setup, and the documentation scaffold (docs/ARCHITECTURE.md, docs/THREAT_MODEL.md, docs/SECURITY_INVARIANTS.md, docs/IMPLEMENTATION_STATE.md, docs/DECISIONS.md as an ADR index, docs/KNOWN_LIMITATIONS.md, docs/POLICY_DECISION_MATRIX.md, docs/adr/ with ADRs 001–007 recorded).

Constraints:
- Do not implement real tools, cloud model calls, arbitrary shell execution, or bypassable authorization shortcuts.
- Do not implement host authentication, nonce replay protection, database migrations, or the DevPrincipalResolver startup guard yet; those are Phase 0b and must be a separate task after Phase 0a review.
- Keep external model calls disabled by default.
- Do not introduce optional infrastructure not required by Phase 0a.
- Do not include real credentials.
- Make the project work locally on macOS using Docker Compose.
- Pin dependencies and document reproducible commands.
- Disable /docs, /redoc, and /openapi.json outside APP_ENV=development|test.
- Tests and check script must fail non-zero on failure.
- Do not start Phase 0b or Phase 1 until Phase 0a is reviewed and passes its Definition of Done.

Before coding, report the intended file changes and how each Phase 0a acceptance criterion will be verified. After coding, run the checks and report the actual output. Update docs/IMPLEMENTATION_STATE.md and docs/DECISIONS.md with only verified facts. Do not begin Phase 0b until Phase 0a is reviewed and passes its Definition of Done.
```

---

## 25. Reference material

These references inform the threat model and evaluation approach; they do not replace repository-specific testing or policy decisions.

- OWASP GenAI / LLM Top 10, including prompt injection, insecure output handling, sensitive information disclosure, and excessive agency: https://owasp.org/www-project-top-10-for-large-language-model-applications/ and https://genai.owasp.org/llm-top-10/
- NIST AI Risk Management Framework resources and Generative AI Profile: https://airc.nist.gov/ and https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- InjecAgent, a benchmark for indirect prompt injection in tool-integrated agents: https://aclanthology.org/2024.findings-acl.624/ and https://github.com/uiuc-kang-lab/InjecAgent
- AgentDojo, a dynamic environment for evaluating prompt-injection attacks and defenses in LLM agents: https://github.com/ethz-spylab/agentdojo
- Gemini API rate limits and pricing (quotas and terms vary by model/project and can change): https://ai.google.dev/gemini-api/docs/rate-limits and https://ai.google.dev/gemini-api/docs/pricing
- GroqCloud rate limits (exact limits depend on account/model and should be checked in the current dashboard/docs): https://console.groq.com/docs/rate-limits
- PostgreSQL explicit/advisory locking: https://www.postgresql.org/docs/17/explicit-locking.html
- SQLAlchemy asyncio: https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html
- Alembic migration tool: https://alembic.sqlalchemy.org/en/latest/
- Gitleaks secret scanning CLI: https://github.com/gitleaks/gitleaks

---

## Final non-negotiable principle

The v1 transport contract is HMAC-authenticated host-to-gateway requests; the persistence contract is SQLAlchemy async + asyncpg + Alembic; the audit chain is appended under a PostgreSQL transaction-scoped advisory lock with defined canonical bytes; v1 response streaming is disabled; approval consumption is atomic and one-time; and the AI SOC analyzer is read-only/alert-only with all attacker-influenced fields treated as untrusted. These are design decisions, not open questions for the coding agent to guess.

**The input defense reduces the chance of model manipulation. The independent firewall limits what a manipulated model can do. Tool isolation limits the damage if another control fails. Egress protection prevents sensitive data from leaving through allowed-looking actions. Audit and evaluation provide evidence rather than assurances.**

Every one of these is a separate control with its own tests. No model score, prompt, XML tag, detector label, or aggregate “risk score” can replace deterministic authorization at the point where a real side effect occurs.
