> **SUPERSEDED — historical record only.** This v1.0 draft is archived for history and MUST NOT be used for implementation. The single authoritative implementation contract is `AI_Agent_Security_Platform_Master_Blueprint_v1.2.md` at the repository root. Do not implement from this file.

# AI Agent Security & Safety Platform — Master Engineering Blueprint

**Document status:** Implementation contract v1.0 (superseded by v1.2)  
**Project type:** Local-first, AI-first security gateway for AI applications and tool-using agents  
**Primary development environment:** macOS + Docker  
**Budget constraint:** $0 mandatory spend; open-source/local components first; optional cloud model adapters only by explicit opt-in  
**Audience:** Coding agents and engineers implementing, testing, reviewing, and extending the repository

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
│   ├── risk_thresholds.yaml
│   ├── input_defense.yaml
│   └── dlp_rules.yaml
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   ├── SECURITY_INVARIANTS.md
│   ├── DATA_HANDLING.md
│   ├── EVALUATION_PROTOCOL.md
│   ├── ADR/
│   └── RUNBOOK.md
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
│   │   └── adapters.py
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
│   │   └── repositories.py
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
│   └── verify_audit.py
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
DATABASE_URL=postgresql+psycopg://firewall:firewall_dev_only@db:5432/firewall
ALLOW_EXTERNAL_MODEL_CALLS=false
MODEL_PROVIDER=mock
LOCAL_MODEL_BASE_URL=http://host.docker.internal:11434
LOCAL_MODEL_NAME=SET_TO_EXACT_INSTALLED_MODEL
REQUEST_MAX_BYTES=65536
REQUEST_TIMEOUT_SECONDS=30
AUDIT_RAW_CONTENT_MODE=never
```

These are development defaults only. The compose credentials are disposable local values and MUST NOT be represented as production-safe credentials. Add a check that refuses the development secret in non-development environments.

On macOS, a container generally reaches a model service running on the host through `host.docker.internal`; verify this on the current Docker setup. If the model is itself inside Compose, use the service name instead. Never bind a development model endpoint to a public network interface unnecessarily.

---

## 6. Shared data contracts and schema rules

Implement typed models before business logic. Use strict Pydantic models with `extra="forbid"`, field bounds, enums, and explicit optionality. Do not use unconstrained `Dict[str, Any]` as the only validation for tool arguments; each registered tool must own an argument schema.

### 6.1 Minimum domain models

`identity/models.py`

- `Principal`: server-resolved `subject_id`, `roles`, `tenant_id` if the host integration supports tenancy, authentication method/issuer metadata, and a stable permissions/context reference.
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

- `ProposedToolCall`: server-side `call_id`, `request_id`, principal reference, registered `tool_id`, `action_id`, arguments parsed into that tool's Pydantic schema, target resource IDs, destination metadata if relevant, side-effect class, and deadline.
- Do not accept `risk_score`, `decision`, `permissions`, `principal role`, or an approval flag from the model as authoritative fields.
- `FirewallDecision`: enum `ALLOW`, `BLOCK`, `ASK_USER`.
- `DecisionRecord`: decision, stable reason codes, policy version, risk calculation version, applicable constraints, approval reference, and a correlation ID.
- `ApprovalRequest`: one-time opaque identifier, principal, canonical action digest, expiry, policy version, required approver rule, status, and creation metadata.

`audit/models.py`

- `AuditEvent`: event ID, UTC timestamp, schema version, trace/request/session IDs, event type, actor reference, source component, tool/action where relevant, decision and reason codes, policy/detector versions, risk components, outcome, previous-event hash, and current event hash.
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

Track only session metadata needed to detect suspicious sequences, with explicit retention limits. Useful signals include repeated policy override attempts, unusual escalation in requested privileges, and repeated blocked tool proposals. A “memory” of past threats must not automatically label the user malicious or silently create new permissions. Session tracking supplements per-action enforcement; it never replaces it.

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

### 8.4 Confidence handling

`confidence_score` may be retained for diagnostic or clarification decisions. Never use “high confidence” to override policy. Confidence scores from different LLMs are not necessarily calibrated or comparable. In tests, use structured scenarios with expected constraints and record extraction errors separately from authorization errors.

---

## 9. Identity and authorization context without rebuilding enterprise IAM

The system should not implement an entire corporate identity platform. It must, however, consume a verified identity context from the host application.

### 9.1 Interface

Define a small `PrincipalResolver` interface. In development, use a clearly named `DevPrincipalResolver` that is enabled only under `APP_ENV=development` or `test`. Production integration should validate the host application's authenticated context through a documented adapter. Do not accept a plain `role` or `user_id` field from a model output.

### 9.2 Required invariants

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

### 10.3 Configuration format

Use declarative YAML loaded with a safe parser and validated into Pydantic policy models. Support:

- schema version and policy version;
- named roles or capability sets;
- exact tool/action identifiers;
- allowed resource scopes and destinations;
- forbidden actions/paths/domains;
- action side-effect category;
- required approvals;
- explicit data-classification and egress rules;
- risk weights/thresholds;
- test fixtures or policy self-checks where appropriate.

Prefer specific resource identifiers or bounded patterns. Do not implement an unrestricted mini-language, dynamic Python expressions, shell expressions, or custom code execution in policy YAML. If wildcard patterns are supported, document their exact matching semantics and test boundary cases.

### 10.4 Example starter policy

The initial policy may allow these demo actions only:

- `mock_email.search` — read-only against the synthetic current user's mailbox;
- `mock_email.read` — read a message returned by an authorized search and within that mailbox;
- `text.summarize` — process only provided text; no external side effect;
- `mock_files.read` — read a synthetic file under the user's demo workspace;
- `mock_external_sink.write` — disabled by default and only enabled in a dedicated test scenario to prove egress blocking.

The initial policy MUST deny arbitrary shell execution, unrestricted network requests, real external email sending, file deletion, arbitrary database writes, and cross-user resource access.

### 10.5 Policy versioning and reload

Load policy at startup, validate it fully, and expose the loaded version/hash in health metadata and audit events. If runtime policy reload is later implemented, reload atomically: validate the entire new file first; if invalid, continue using the prior validated version or stop protected execution according to explicit configuration. Never partially apply a malformed policy. Record who/what changed a policy through the host's controlled administration flow; the AI SOC cannot mutate policy directly in v1.

### 10.6 Policy tests

Create table-driven tests covering every policy rule. Include allowed action, forbidden action, disallowed resource, invalid tool, missing argument, extra argument, cross-user access, path traversal, unapproved destination, policy parse error, and unexpected policy engine exception. Enforce the invariant: **no policy failure or unknown state can result in an allowed side effect.**

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

Build v1 as deterministic scoring from versioned, auditable factors. Example factors include external destination, sensitive-resource classification, write/delete/send action, breadth of requested data, intent mismatch, repeated blocked actions, unknown resource, or incomplete security context. Each factor must have a code, bounded value, rationale, version, and test.

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
- side-effect category (`READ_ONLY`, `LOCAL_MUTATION`, `EXTERNAL_MUTATION`, `DESTRUCTIVE`);
- resources/destinations it can access;
- timeout and concurrency limits;
- whether user approval is required;
- data sensitivity / egress behavior;
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
- one-time nonce or opaque identifier;
- approver identity and approval timestamp, once decided.

Approval cannot be reused for a changed argument, different recipient, different file, changed model-generated plan, new policy version requiring re-evaluation, expired request, or different principal. Consume approval once, using a transactional state transition to prevent concurrent replay.

### 13.3 API and UI contract

An approval prompt should clearly describe the action, target, destination, data class, and relevant risk reasons. Do not expose unnecessary raw secrets. Denial, expiry, missing approver identity, and service error all result in no execution. The caller cannot claim approval merely by setting `approved=true` in a tool argument.

---

## 14. Tools and execution isolation

### 14.1 MVP adapters

Begin with synthetic/mock tools only:

1. `mock_email.search` and `mock_email.read`: use a fixture dataset assigned to test users.
2. `mock_files.search` and `mock_files.read`: use a fixed synthetic workspace with resource IDs instead of arbitrary host paths.
3. `text.summarize`: deterministic fake implementation in unit tests; optional LLM summarizer in integration tests.
4. `mock_external_sink.write`: records attempted outbound content to a test sink and is used to prove that policy/DLP blocks egress.

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

Data classification must be checked against the destination. A user having permission to read a confidential file does not automatically have permission to send that file to a public endpoint. The egress policy evaluates destination trust, allowed data class, operation, and current principal authority.

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

### 16.2 Hash chain

For each audit event, serialize the approved canonical event fields in a deterministic form. Define:

`event_hash = SHA256(previous_event_hash || canonical_event_bytes)`

The first event uses a documented genesis value. Store the previous hash and current hash in every record and provide `verify_audit.py` to detect modified, missing, reordered, or malformed events within the retained chain.

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

After audit format and evaluation are stable, an optional local model may summarize event clusters and propose hypotheses. Its results must be labeled as analysis, not verified facts. It can open an alert or suggest an investigation but cannot execute a high-impact response or edit policies automatically in v1.

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
- `POST /v1/approvals/{approval_id}/decision`: records a verified approval decision; requires the configured approver identity and valid state.

Do not expose public unfiltered audit-log access in v1. If an admin/audit endpoint is added, require an authenticated administrative context and enforce field redaction and pagination limits.

### 18.2 API safeguards

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

### 20.3 CI/local check command

`bash scripts/check.sh` should run, in order:

1. lockfile/dependency consistency check;
2. Ruff formatting/lint;
3. static type checks for designated modules;
4. unit tests;
5. integration/security tests using the configured test database/mock adapters;
6. audit-chain verifier tests;
7. a small deterministic evaluation regression suite;
8. invariant greps or static checks for obvious prohibited patterns.

The script must exit non-zero on any failure and print a clear summary. Coding agents MUST run it before declaring a task complete.

---

## 21. Development roadmap — phase gates

Build vertical, testable slices. Do not attempt the entire SOC, every classifier, and every tool at once.

### Phase 0 — Repository foundation and architecture decisions

**Deliverables:** repository layout, pyproject/lockfile, Dockerfile and Compose config, settings validation, README setup, architecture/threat model docs, `.gitignore`, `scripts/check.sh`, API health endpoints.

**Rules:** no real tools and no cloud model calls. Compose must start the API and database; tests run from a clean checkout using documented commands.

**Definition of Done:** fresh clone setup succeeds on macOS with Docker; config errors are clear; no secrets committed; lint/test command exits non-zero on failure.

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

**Deliverables:** structured event schema, database persistence, hash chain, verifier, retention/data-handling document, safe operational logs.

**Definition of Done:** full request-to-tool event sequence is correlatable; mutation/reordering is detected; privacy tests show that raw secrets are not in default logs.

### Phase 8 — FastAPI integration and local model

**Deliverables:** request/tool/approval routes, local model provider adapter, startup config checks, safe errors, deadlines and basic rate limiting, integration docs.

**Definition of Done:** local/mock path works offline; no route trusts client-supplied decisions; optional model provider failures do not bypass policy.

### Phase 9 — Evaluation harness and benchmark adapters

**Deliverables:** dataset manifest and provenance, split tooling, metric unit tests, evaluation CLI, JSON + Markdown reports, regression suite.

**Definition of Done:** one command reproduces results from a versioned fixture set and emits accurate confusion matrices/latency. All reported metrics are derived by code and match hand-calculated unit tests.

### Phase 10 — Security hardening and AI-assisted monitoring

**Deliverables:** threat-model review, abuse/load tests, alert rules, optional local read-only audit summarizer, runbooks and known limitations.

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
- `docs/DECISIONS.md`: short architecture decision records including alternatives rejected and consequences.
- `docs/KNOWN_LIMITATIONS.md`: what the system cannot currently detect/prevent and which phase addresses each item.

Update these only with confirmed facts, not assumptions.

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

Use the following prompt as the first implementation task after creating this file. Do not ask the agent to build the whole platform in one pass.

```text
Read AI_Agent_Security_Platform_Master_Blueprint.md in full, especially §§0–6, §§10–12, §§20–22.

Task: implement Phase 0 only. Inspect the current repository before editing. Create the minimal repository scaffold, pyproject.toml with pinned/locked dependencies, Dockerfile, docker-compose.yml with API + PostgreSQL, settings validation, FastAPI app with /health/live and /health/ready, .env.example, .gitignore, README setup, docs/SECURITY_INVARIANTS.md, scripts/check.sh, and basic tests.

Constraints:
- Do not implement real tools, cloud model calls, arbitrary shell execution, or bypassable authorization shortcuts.
- Keep external model calls disabled by default.
- Do not introduce optional infrastructure not required by Phase 0.
- Do not include real credentials.
- Make the project work locally on macOS using Docker Compose.
- Pin dependencies and document reproducible commands.
- Tests and check script must fail non-zero on failure.

Before coding, report the intended file changes and how each Phase 0 acceptance criterion will be verified. After coding, run the checks and report the actual output. Update docs/IMPLEMENTATION_STATE.md and docs/DECISIONS.md with only verified facts. Do not begin Phase 1 until Phase 0 is reviewed and passes its Definition of Done.
```

---

## 25. Reference material

These references inform the threat model and evaluation approach; they do not replace repository-specific testing or policy decisions.

- OWASP GenAI / LLM Top 10, including prompt injection, insecure output handling, sensitive information disclosure, and excessive agency: https://owasp.org/www-project-top-10-for-large-language-model-applications/ and https://genai.owasp.org/llm-top-10/
- NIST AI Risk Management Framework resources and Generative AI Profile: https://airc.nist.gov/ and https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- InjecAgent, a benchmark for indirect prompt injection in tool-integrated agents: https://aclanthology.org/2024.findings-acl.624/ and https://github.com/uiuc-kang-lab/InjecAgent
- AgentDojo, a dynamic environment for evaluating prompt-injection attacks and defenses in LLM agents: https://github.com/weidutech/agentdojo
- Gemini API rate limits and pricing (quotas and terms vary by model/project and can change): https://ai.google.dev/gemini-api/docs/rate-limits and https://ai.google.dev/gemini-api/docs/pricing
- GroqCloud rate limits (exact limits depend on account/model and should be checked in the current dashboard/docs): https://console.groq.com/docs/rate-limits

---

## Final non-negotiable principle

**The input defense reduces the chance of model manipulation. The independent firewall limits what a manipulated model can do. Tool isolation limits the damage if another control fails. Egress protection prevents sensitive data from leaving through allowed-looking actions. Audit and evaluation provide evidence rather than assurances.**

Every one of these is a separate control with its own tests. No model score, prompt, XML tag, detector label, or aggregate “risk score” can replace deterministic authorization at the point where a real side effect occurs.
