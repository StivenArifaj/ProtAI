# Phase Roadmap

Source: blueprint v1.2 §21 (phase gates) and §23 (release maturity). Status labels per
[README.md](README.md). Phases 0a, 0b, 1, 2, 3, 4, and 5 are complete; Phase 6 is the next
eligible phase. Build vertical, testable slices — never the whole platform at once.

## Phase table

| Phase | Name | Status | Key deliverables | Definition of Done (summary) |
|---|---|---|---|---|
| 0a | Repository foundation | **COMPLETE — VERIFIED** (2026-10-19) | scaffold, pyproject/uv.lock, Dockerfile/Compose, settings validation, `/health/*`, tests, `check.sh`, docs scaffold, ADR-001..007 | fresh setup works with documented commands; config errors fail startup; no secrets; `check.sh` non-zero on failure; health/OpenAPI checks pass |
| 0b | Security foundation | **COMPLETE — VERIFIED** (2026-10-19) | HMAC host auth (§9.2) + replay rejection, request bounds, SQLAlchemy async, Alembic baseline, dev-resolver guard, ADR-007 self-checks, pinned Gitleaks, auth tests | auth/replay denial matrix passes (unit + integration + live container); migrations idempotent; resolver cannot start outside dev/test; self-checks fail on mismatching fixture; docs gating unchanged; Gitleaks clean; gate non-zero on failure |
| 1 | Typed contracts and deterministic policy engine | **COMPLETE — VERIFIED** (2026-10-19) | strict Pydantic contracts + canonical enums, safe YAML loader, validated policy model + bundle hashes, principal test adapter, reason codes, canonicalization, deterministic engine, ADR-008 | table-driven policy tests: allowed/forbidden/malformed/cross-scope/unknown/error; no LLM in authorization; ADR-007 fixtures pass against the real engine at startup/readiness; 406 tests green; gate 8/8 |
| 2 | Tool registry and enforced gateway | **COMPLETE — VERIFIED** (2026-10-19) | registry + startup consistency, mock email/files/sink/summarize adapters, `invoke_tool` gateway, execution authorization digest, `risk-v1` scoring, timeouts/result bounds, audit recorder over the chain, ADR-009 | no-bypass tests: sink changes only after a valid gateway `ALLOW`; denied/unknown/malformed/expired/audit-failed actions have no side effect; 520 tests green; gate 8/8 |
| 3 | Input threat defense and provenance | **COMPLETE — VERIFIED** (2026-10-19) | intake limits, normalization copy, versioned heuristics, typed findings, trust labels, context assembly, detector failure behavior, session signal store, ADR-010 | direct/indirect attack + benign hard-negative tests pass (64 targeted + 13 integration); labels survive assembly with external content forced `EXTERNAL_UNTRUSTED`; detector faults never PASS; session bindings/expiry/rotation proven against real PostgreSQL; 600 tests green; gate 8/8 |
| 4 | Intent extraction and action validation | **COMPLETE — VERIFIED** (2026-10-19) | server-only manifest issuer, mock extractor, strict local-model adapter interface, sealed request/principal/policy-bound manifest with expiry, exact constraint validator, trusted-timezone relative dates, gateway enforcement, ADR-011 | malformed model output/outage/ambiguity grants no permission (56 targeted tests); args compared to concrete intent limits; execution only via gateway; 661 tests green; gate 8/8 |
| 5 | Risk engine and approval workflow | **COMPLETE — VERIFIED** (2026-10-26) | `risk-v2` breadth factor, strict approver rules, PostgreSQL approval store, token-digest decisions, row-locked one-time consumption with same-transaction audit, gateway `ASK_USER` gating, ADR-012 | 30 risk tests + 24 rule tests + real-PostgreSQL lifecycle/expiry/mutation/replay/concurrency; hard denies ignore approvals; 734 tests green; gate 8/8 (V57–V62) |
| 6 | Output DLP and egress policy | NOT IMPLEMENTED | test canaries, configurable patterns, data classification, destination-aware egress, release outcomes | canary never reaches an unauthorized sink; DLP logs redacted; false-positive cases documented |
| 7 | Audit persistence and verification | NOT IMPLEMENTED | event schema, persistence, serialized hash chain with fixed byte vectors, concurrent writer test, verifier, retention doc, safe logs | request→tool event sequence correlatable; tampering detected; raw secrets absent from default logs |
| 8 | FastAPI integration and local model | NOT IMPLEMENTED | `/v1` routes, local model provider adapter, startup checks, safe errors, deadlines + basic rate limiting, integration docs | offline mock path works; no client-supplied decisions trusted; provider failure does not bypass policy |
| 9 | Evaluation harness and benchmark adapters | NOT IMPLEMENTED | dataset manifest/provenance, split tooling, metric unit tests, evaluation CLI, JSON + Markdown reports, regression suite | one command reproduces results from a versioned fixture set; metrics match hand-calculated tests |
| 10 | Security hardening and AI-assisted monitoring | NOT IMPLEMENTED | threat-model review, abuse/load tests, alert rules, alert-only audit summarizer with adversarial-log tests, runbooks, CycloneDX SBOM | AI monitor has no tool/policy powers; alerts tested; all release gates pass |

## Work-order rule (blueprint §21 note)

Input defense runs first at runtime but is built **after** typed schemas + policy + the
unbypassable mock tool gateway; the detector then lands before any powerful agent tools.

## Release maturity (blueprint §23) — language discipline

| Level | Requirements | Current status |
|---|---|---|
| Prototype release | local mock tools only; deterministic gateway + input detector; repeatable tests; documented limitations; no real data or side effects | Target of v1; **not yet achieved** (Phases 0a-5 deliver infrastructure, contracts, policy engine, enforced mock-tool gateway, advisory input detector, in-process intent validation, `risk-v2`, and durable in-process approvals; no `/v1` routes, DLP, manifest/approval transport, or real model path yet) |
| Research/demo | optional local model; versioned fixtures + benchmark reports; local UI/API demo with mock/real labeling; measured claims only | Future (Phases 8–9) |
| Controlled integration | separate threat-model review, connector permission design, secret/egress plans, runbooks, regression benchmark, host identity integration; real connectors disabled by default | Future; not planned in current phases |
| Company deployment | operator, security/privacy reviews, availability/backup, supply chain, monitoring/IR, responsibility boundary | Out of scope; this personal project does not satisfy it |

Never label the system "production-grade", "enterprise-ready", "fully secure", or
"perfect protection" (blueprint §23).
