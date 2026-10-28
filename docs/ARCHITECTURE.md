# Architecture

Status: **implemented through Phase 8.** This document describes the intended v1
architecture from blueprint v1.2 (sections 3-4) and marks what actually exists today.
Host authentication, host-signed principal assertions, the deterministic policy engine, the
mock-tool gateway, advisory input threat detection with trust labels and session signals,
server-issued intent manifests with concrete action constraints, `risk-v2`, durable
one-time human approvals, mandatory output DLP with destination-aware egress and
complete-response release/suppression, the full structured audit lifecycle with an
exact-stored-bytes verifier, and signed `/v1` request/preview/approval-decision routes
exist and are tested; a general agent planner, real connectors, cloud models, approval
delivery/UI, and an external audit anchor do not. The detector is advisory, the intent
layer can only narrow execution, and the local model is optional and never an
authorization input. Only components marked Implemented below may be cited as controls.

## Logical flow (target v1)

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

The input detector is not the safety barrier; the firewall gateway is the mandatory
enforcement boundary for actions. Every multi-step tool call is evaluated independently,
including calls proposed after a tool result re-enters model context.

## Order of operations (development order != runtime order)

Even though input defense runs first at runtime, the implementation order is schemas +
policy + an unbypassable mock tool gateway first, then the input detector, then stronger
agent tools. A system that can detect prompt injection but has no reliable action
enforcement is not an agent security system (blueprint section 3.2).

## Per-request lifecycle (target v1, blueprint section 3.3)

1. Server-side `request_id`/`trace_id`; never trust client identifiers.
2. Principal resolution through an authentication adapter (HMAC host auth + verified
   assertion before any `/v1/*` processing).
3. Request size/content-type/deadline/rate bounds.
4. Preserve payload; avoid raw private content in normal logs; normalize for detection
   only.
5. Provenance/trust labelling of each content segment.
6. Heuristic input checks; optional local detector; structured findings.
7. Deterministic intake policy: allow, quarantine/review, or reject.
8. Typed intent proposal (deterministic extraction or schema-constrained model output;
   confidence is diagnostic only).
9. Agent runtime proposes actions; execution only through the controlled tool interface.
10. Registered tool schema + normalized arguments validation.
11. Mandatory authorization rules first: hard deny cannot be overridden by score or
    model confidence.
12. Intent/action constraint checks (semantic similarity never authorizes).
13. Data classification and destination-aware egress inspection (Phase 6 runs DLP after
    intent/argument validation and before risk/policy; findings may only raise the
    registry data class), side-effect level, risk signals.
14. Decision recorded before execution: `ALLOW`/`BLOCK`/`ASK_USER`.
15. `ASK_USER`: approval bound to principal, tool, canonical argument digest, resource,
    policy version, expiry, and one-time token; the gateway atomically consumes a
    matching approved record before execution and never for a `BLOCK` (Phase 5).
16. Execution only through the gateway with timeouts, output bounds, quotas,
    destination restrictions, connector ACLs.
17. Tool output re-labeled untrusted when returned to the model.
18. Complete buffered output DLP before release: `PASS`/`REDACT`/`BLOCK`/`REVIEW`;
    `BLOCK`/`REVIEW`/failure suppress the whole response (Phase 6; streaming disabled).
19. Mandatory structured audit lifecycle: request receipt, proposal, egress inspection,
    decision, approval consumption, execution start/outcome, output inspection, and
    response release/suppression; every mandatory pre-execution append gates execution and
    a post-execution failure withholds the result (Phase 7).
20. Safe response; no hidden policies, credentials, stack traces, or other users' data.

## Component map and current status

| Package / component | Blueprint role | Status (Phase 8) |
|---|---|---|
| `src/ai_security/api/` | HTTP adapter, health endpoints | **Implemented:** `create_app` factory, `/health/live`, `/health/ready`, host-auth middleware, registry + gateway wiring on `app.state`, and the Phase 8 signed routes `POST /v1/requests`, `POST /v1/tool-calls/evaluate`, `POST /v1/approvals/{approval_id}/decision` |
| `src/ai_security/settings.py` | Validated configuration | **Implemented:** fail-closed validation incl. host keys, replay window, request bound, policy/threshold/self-check paths, input-defense path, session windows, intent-manifest TTL, the bounded approval TTL (60-86,400 s; default 900), `OUTPUT_DLP_PATH`, Phase 8 request timeout/rate limits, and the optional local-model provider contract (`MODEL_PROVIDER`, origin/name/timeout; external cloud calls refused) |
| `identity/` (HMAC host auth, assertion, resolver) | Authenticate host, verify principal | **Implemented (0b/1/8):** exact signing message, full rejection surface, atomic nonce store, dev guard, test-only principal adapter, and the strict host-signed principal assertion (`iss`/`aud`/`tenant` binding, future-time rejection, no unsigned fallback) |
| `security/` (canonical JSON, constant-time, URLs) | Canonical bytes, comparisons, destinations | **Implemented (0b/1):** ADR-002 canonical JSON, constant-time helpers, destination canonicalization |
| `input_defense/` | Heuristics, detector, provenance | **Implemented (3/8, advisory):** strict versioned config, bounded intake, copy-only normalization, 10 versioned heuristic rules, typed findings with non-PASS failure semantics, trust-labelled context assembly, session-signal math, and a Phase 8 ingress gate: `REJECT`/`QUARANTINE` stop the request before intent; `FLAG`/`PASS` continue. Detection never authorizes |
| `intent/` | Intent manifest, constraints | **Implemented (4/8):** server-only issuer, mock demo extractor, strict local-model adapter plus the Ollama-compatible provider, sealed request/principal/policy-bound manifests, exact constraint matching, trusted-timezone relative dates, bounded per-process uses; provider failure yields no manifest |
| `agent/` (+ providers) | Runtime, mock/local models | **Implemented (8, narrow):** bounded `DemoRuntime` executes only the two-call `mock_email.read` + `text.summarize` plan through the gateway; general planning is not implemented |
| `firewall/` | Gateway, policy engine, risk engine, approvals | **Implemented (1-6/8):** decision/engine/risk (`risk-v2` with one bounded breadth factor), the single `invoke_tool` gateway with audit-first ordering, bindings, deadlines, bounds, manifest/constraint enforcement, one-time approval consumption for engine `ASK_USER`, egress DLP before risk/policy, and complete-response release/redaction/suppression; the Phase 8 approval-decision route uses the same service, and preview evaluation never executes |
| `tools/` (registry + mock adapters) | Tool capability layer | **Implemented (2):** validated registry + startup consistency (incl. external-destination inventory for the DLP trust map), digest-bound execution authorization, deterministic in-memory email/files/sink/text adapters |
| `data_security/` | Classification, DLP, egress | **Implemented (1/6, deterministic):** canonical `DataClass`; strict versioned output-DLP config; five deterministic detectors; span-preserving redaction; exact-canonical destination trust map with startup coverage; `PASS`/`REDACT`/`BLOCK`/`REVIEW` outcomes. No classifier/entropy/semantic detection |
| `audit/` | Hash-chained audit events | **Implemented (0b/2/5/7/8):** ADR-002 append protocol and hash chain, full §16.1 taxonomy with event-specific required fields, mandatory gateway/approval/intent lifecycle emission, first-class redacted DLP events, ingress receipt/principal/input producers, and a read-only verifier over exact stored bytes with typed content-free failures. No external anchor/query API (ADR-014) |
| `persistence/` | SQLAlchemy async repositories | **Implemented (0b/3/5/7):** engine/session, nonce + audit repositories (derived indexed metadata columns for correlation), `session_security_state` repository, and `approval_requests` repository (row-locked decisions/consumption, digest-only tokens, same-transaction audit) |
| `soc/` | Alert-only analytics | Not implemented (Phase 10) |
| `config/*.yaml` | Policies, thresholds, self-checks | **Implemented (1-3/6):** `policies.yaml`, `risk_thresholds.yaml`, 21-fixture `policy_self_checks.yaml`, exhaustive-disposition `input_defense.yaml`, and strict `output_dlp.yaml` (`1.0.1`: five patterns, limits, exact destination trust map) |
| `migrations/`, `alembic.ini` | Alembic schema management | **Implemented (0b/3/5/7):** baseline + `session_security_state` + `approval_requests` + audit-metadata migrations; upgrade/downgrade verified; `alembic check` clean |
| `evaluation/` | Dataset, metrics, reports | Not implemented (Phase 9) |
| `docs/adr/` | Decision records | **Implemented:** ADR-001..015 recorded |

## Import boundaries (enforced from Phase 1 onward; check.sh enforces prohibited patterns)

- `firewall/` may depend on typed models, policies, risk, tool-registry interfaces,
  approval repository, and audit interface.
- Tool adapters never call the agent runtime or request authorization from an LLM.
- `policy_engine.py` and `risk_engine.py` are deterministic and make no network calls.
- `data_security/dlp.py` is deterministic, configuration-driven, and makes no network,
  model, or database calls; it never logs matched content.
- Detectors never become the policy authority.
- API routers orchestrate; they do not duplicate policy logic.
- Evaluation code is never imported into runtime request processing.
- No circular imports; shared contracts live in their owning domain package.

## API boundary (Phase 8 implementation)

- `GET /health/live` -> `200 {"status":"alive"}`; no dependency checks, no internal
  details.
- `GET /health/ready` -> `200` when `checks.config`, `checks.database`, and
  `checks.policy_self_checks` are all true (plus `policy_version`/`policy_hash`), else
  `503 {"status":"not_ready",...}`; the database probe performs a real `SELECT 1` with a
  2 s timeout and never reveals credentials.
- `POST /v1/requests` is the sole execution surface. It verifies the signed principal
  assertion, records one receipt, gates on input defense, extracts an intent manifest,
  and executes only the bounded read-then-summarize demo plan through the gateway. It
  returns `COMPLETED`/`NO_ACTION`/`REQUIRES_CLARIFICATION`/`APPROVAL_REQUIRED` or a typed
  error. Approval tokens are returned once, in the 202 response.
- `POST /v1/tool-calls/evaluate` is a non-executing preview: same validation/egress/risk/
  policy facts, no manifest use, no approval consumption, no authorization, no execution.
- `POST /v1/approvals/{approval_id}/decision` records a token-bound, tenant/role-checked,
  row-locked one-time decision; it never executes the approved action.
- Every `/v1/*` request requires valid host HMAC headers and a one-time nonce
  (400/401/413/503 per the denial surface); application routes use the documented error
  envelope, while middleware denials keep `{"detail":"<stable_code>"}`.
- `/docs`, `/redoc`, `/openapi.json` are registered only when `APP_ENV` is exactly
  `development` or `test` (blueprint section 18.2).
- Configuration errors raise at startup with a clear message; the process does not boot
  partially configured.
