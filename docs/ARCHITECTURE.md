# Architecture

Status: **Phase 0a scaffold.** This document describes the intended v1 architecture from
blueprint v1.2 (sections 3-4) and marks what actually exists today. Only the API
skeleton with liveness/readiness endpoints is implemented; every security component
below is specified but not yet implemented. Do not cite this document as evidence that
a control exists.

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
13. Data classification, destination, side-effect level, risk signals.
14. Decision recorded before execution: `ALLOW`/`BLOCK`/`ASK_USER`.
15. `ASK_USER`: approval bound to principal, tool, canonical argument digest, resource,
    policy version, expiry, one-time nonce.
16. Execution only through the gateway with timeouts, output bounds, quotas,
    destination restrictions, connector ACLs.
17. Tool output re-labeled untrusted when returned to the model.
18. Output/egress DLP before release or external side effect.
19. Completion/failure/DLP metadata recorded.
20. Safe response; no hidden policies, credentials, stack traces, or other users' data.

## Component map and current status

| Package / component | Blueprint role | Status (Phase 0a) |
|---|---|---|
| `src/ai_security/api/` | HTTP adapter, health endpoints | **Implemented:** `create_app` factory, `/health/live`, `/health/ready`; `/v1/*` routes do not exist yet |
| `src/ai_security/settings.py` | Validated configuration | **Implemented:** APP_ENV/LOG_LEVEL/DATABASE_URL with fail-closed validation |
| `identity/` (HMAC host auth, resolver) | Authenticate host, verify principal | Not implemented (Phase 0b) |
| `security/` (canonical JSON, constant-time) | Canonical bytes, comparisons | Not implemented (Phase 0b+) |
| `input_defense/` | Heuristics, detector, provenance | Not implemented (Phase 3) |
| `intent/` | Intent manifest, constraints | Not implemented (Phase 4) |
| `agent/` (+ providers) | Runtime, mock/local models | Not implemented (Phase 4/8) |
| `firewall/` | Gateway, policy, risk, approvals | Not implemented (Phases 1-5) |
| `tools/` (mock adapters) | Mock email/files/sink | Not implemented (Phase 2) |
| `data_security/` | Classification, DLP, egress | Not implemented (Phase 6) |
| `audit/` | Hash-chained audit events | Not implemented (Phase 7) |
| `persistence/` | SQLAlchemy async repositories | Not implemented (Phase 0b) |
| `soc/` | Alert-only analytics | Not implemented (Phase 10) |
| `config/*.yaml` | Policies, thresholds, self-checks | Not created yet (Phases 0b-1) |
| `migrations/`, `alembic.ini` | Alembic schema management | Not implemented (Phase 0b) |
| `evaluation/` | Dataset, metrics, reports | Not implemented (Phase 9) |
| `docs/adr/` | Decision records | **Implemented:** ADR-001..007 recorded |

## Import boundaries (enforced from Phase 1 onward)

- `firewall/` may depend on typed models, policies, risk, tool-registry interfaces,
  approval repository, and audit interface.
- Tool adapters never call the agent runtime or request authorization from an LLM.
- `policy_engine.py` and `risk_engine.py` are deterministic and make no network calls.
- Detectors never become the policy authority.
- API routers orchestrate; they do not duplicate policy logic.
- Evaluation code is never imported into runtime request processing.
- No circular imports; shared contracts live in their owning domain package.

## API boundary (Phase 0a implementation)

- `GET /health/live` -> `200 {"status":"alive"}`; no dependency checks, no internal
  details.
- `GET /health/ready` -> `200 {"status":"ready","checks":{"config":true,"database":true}}`
  or `503 {"status":"not_ready",...}`; the readiness probe performs a real
  `SELECT 1` against `DATABASE_URL` with a 2 s timeout and never reveals credentials.
- `/docs`, `/redoc`, `/openapi.json` are registered only when `APP_ENV` is exactly
  `development` or `test` (blueprint section 18.2).
- Configuration errors raise at startup with a clear message; the process does not boot
  partially configured.
