# Threat Model

Status: **partially implemented through Phase 8.** This document transcribes the v1
threat model from blueprint v1.2 section 2 with an implementation-status column. Phases
0a-8 delivered host authentication/replay defense, host-signed principal assertions, the
deterministic policy engine, the mock-tool gateway, advisory input-threat detection with
trust labels and session signals, server-issued intent manifests with concrete action
constraints, `risk-v2`, durable one-time human approvals, deterministic output DLP with
destination-aware egress and complete-response release/suppression, the full audit
taxonomy/verifier, and signed `/v1` routes with an optional local-model provider. Real
connectors, general planning, approval delivery/UI, and an external audit anchor remain
future work. The input detector now gates the request path and intent extraction is
available through the mock or local provider, but the demo runtime and heuristic
detection leave rows 1-4 Partial. The repository must not be presented as providing
controls not marked here. Update the status column as each phase lands; every row
eventually needs the "required test evidence" listed in the blueprint.

## Threats

| # | Threat | Example | Primary defenses (target v1) | Required test evidence | Status (Phase 8) |
|---|---|---|---|---|---|
| 1 | Direct prompt injection | User asks the model to ignore policy or reveal hidden instructions | Input signals, bounded system context, action policy, output checks | Direct-injection fixtures plus tool-denial tests | **Implemented (Phase 3/8, heuristic scope):** versioned heuristics raise typed findings with quoted-context downgrade; `/v1/requests` gates `REJECT`/`QUARANTINE` before intent and records redacted `INPUT_INSPECTED` evidence; gateway policy remains mandatory. Detection is not a safety proof and model-prompt isolation is not implemented |
| 2 | Indirect prompt injection | A web page/email/document instructs exfiltration | Provenance labels, context isolation, detector signals, firewall enforcement | Malicious retrieved-content tests end-to-end | Partial (3/8): external email content is labelled `EXTERNAL_UNTRUSTED` even for authenticated requesters, and external-only heuristics flag assistant-directed instructions; `/v1/requests` gates quarantined input and actions remain gateway-enforced. End-to-end retrieved-content tests with a general agent remain future work |
| 3 | Multi-turn manipulation | Benign-looking messages set up a later unsafe action | Session-linked events, context review, per-action authorization | Multi-turn scenario tests | Partial (3/8): bound, bounded-counter session state with TTL/max-age and signal-free rotation exists behind a tenant/subject-checked repository (real-PostgreSQL tests); escalation logic and per-action session linkage remain future work (not an authorization or scoring input); intent manifests and approvals are per request |
| 4 | Tool/action mismatch | "Summarize" request becomes "forward the source" | Intent/action validator, forbidden-action rules, destination checks | Exact arguments and side-effect tests | **Implemented (Phase 4/8, demo runtime scope):** exact `(tool_id, action_id)` resolution, strict arguments/resources/destination, real policy engine, server-issued manifests compared against the derived action with exact resource/destination/parameter/use limits, and a bounded runtime that executes only the two-call read-then-summarize plan. General planning and real connectors remain unimplemented |
| 5 | Privilege escalation | Model requests a file outside the user's scope | Verified principal, resource-scoped policy, connector ACL | Cross-user/cross-scope denial tests | Partial (2): verified principal binding + mock ownership checks; real connector ACLs with Phase 10 |
| 6 | Data exfiltration | Sensitive content goes to a public URL/recipient | Data classification, sink/destination policy, DLP before egress | Canary must not reach mock sink | **Implemented (Phase 6, in-process/mock scope):** mandatory output-DLP on validated arguments before risk/policy/execution; canary/private-key/API-key/blocking-credential findings deny with `dlp_egress_blocked` and an unchanged sink; an exact canonical destination trust map (startup coverage required) bounds classified content; response canaries/oversize/`REVIEW` suppress the whole buffered result. **Narrower than the target:** deterministic pattern matching only (no classifier/entropy/semantic detection), and no real connectors exist. False positives/negatives documented. |
| 7 | Path/URL confusion | `../`, symlinks, encoded traversal, deceptive hostnames | Canonicalization, allowlisted resource IDs, safe URL parser | Normalization and traversal tests | Partial (1-2): canonical destination parser + resource-ID scope; Phase 6 adds exact-canonical destination trust (no wildcards). Real filesystem handling remains out of scope (no real connectors; sandbox Phase 10) |
| 8 | Replay/approval abuse | Old approval reused after argument change | One-time token, action digest, expiry, principal/policy binding | Replay, mutation, expiry tests | **Implemented (Phase 5/8, signed host scope):** 256-bit token returned once/stored only as SHA-256; approval binds request/principal/tenant/tool/action/canonical action digest/resources/destination/policy version+hash; decisions and `SELECT ... FOR UPDATE` consumption commit with audit events in one transaction; five-way concurrency yields one winner; pending/denied/expired/mutated/replayed approvals never execute, and a valid approval never overrides `BLOCK` (unit, security, real-PostgreSQL integration). Phase 8 adds the token-in-signed-body decision route and one-time approval creation through `/v1/requests`; revocation/resumption remain unimplemented |
| 9 | Detector/provider outage | Classifier or LLM times out | Explicit failure mode; authorization never depends on detector availability | Timeout/exception tests; no bypass | **Implemented (Phase 3/4/8, fail-closed scope):** intake/normalizer/heuristic/classifier faults yield explicit `DETECTOR_UNAVAILABLE` non-PASS findings; extractor timeout/outage/malformed output yields no manifest and `/v1/requests` returns `503 model_unavailable` without tool events; the Phase 8 local provider has typed timeout/connection/protocol failures. Policy/audit outages already fail closed |
| 10 | Audit manipulation | Event modified or deleted | Append-only writer, hash chain, protected checkpoint/export | Tamper-detection test and documented limits | **Implemented (Phase 7, local-chain scope):** the verifier recomputes ADR-002 hashes from exact stored bytes and detects payload/hash mutation, reordering, middle deletion, malformed/non-canonical JSON, and derived-metadata tampering (real-PostgreSQL tests). Mandatory lifecycle events gate execution/result release. **Narrower than the target:** no external checkpoint yet, so newest-event truncation and a consistent full-chain rewrite by a database owner are not detectable; documented in ADR-014 and `docs/AUDIT_RETENTION_AND_DATA_HANDLING.md` |
| 11 | Model/provider supply chain | Provider changes model ID or output format | Provider adapter, pinned config, schema validation, no model authority | Invalid output and provider error tests | **Implemented (Phase 8, local scope):** exact model name required; origin-only HTTPS-or-loopback base URL; fixed `/api/generate`; non-streaming `format=json`/`temperature=0`; no redirects, no environment proxy trust, bounded timeout/envelope/output; strict duplicate-key envelope parsing and schema validation; every provider failure yields no manifest and never authority. No cloud adapter or model signature/pinning beyond the configured name |
| 12 | Resource exhaustion | Huge prompts, deep nesting, repeated calls | Input limits, deadlines, quotas, bounded retries | Boundary and load tests | **Implemented (Phase 8, single-process scope):** 64 KiB request bound, 32 KiB request text, per-tool deadlines/timeouts/concurrency, per-input byte cap, iterative JSON-depth check, detector evaluation budget, intent output cap (64 KiB), bounded extractor attempts, local-model 1 MiB/64 KiB/1-60 s bounds, bounded manifest uses, and four per-principal rate-limit buckets. Limits are per process; no distributed quota store |
| 13 | Tool adapter compromise | Adapter performs an unapproved side effect | Narrow adapter APIs, minimal credentials, sandbox/egress restrictions | Adapter contract test and isolated mock runtime | Partial (2): narrow adapter protocol + digest verification + typed refusal; process isolation Phase 10 |
| 14 | Host-to-gateway impersonation/replay | Forged principal assertion or captured request replayed | Per-host HMAC, short timestamp window, unique nonce, body signature, private transport | Forged signature, body mutation, stale timestamp, replay tests | **Implemented (0b/8):** full HMAC denial matrix + live replay proof; every `/v1` route also requires a host-signed principal assertion bound to the key's `host_id`/`audience`/tenant scope, with all rejections audited and no unsigned fallback |
| 15 | Audit append race | Concurrent requests reuse the same `prev_hash` | DB-serialized append, monotonic per-chain sequence | Multi-worker concurrent append + chain verification | **Implemented (Phase 7):** advisory-lock append + unique `(chain_id, sequence_number)`; 5-writer append contiguity and an 8-writer verifier test; the verifier recomputes each hash from exact stored bytes |
| 16 | AI SOC prompt injection | Attacker text in audit events manipulates the summarizer | Event fields treated as untrusted; analyzer read-only and alert-only | Injected log strings cannot trigger tools/policy/containment | Not implemented (Phase 10) |

## Security assets

- Authenticated principal and authorization context
- User request and intent constraints
- Policy documents and versions
- Secrets, private documents, personal data, tool credentials
- Tool side effects and destinations
- Approval records and session state
- Audit integrity and incident trail
- Evaluation data and benchmark results

## Trust classes (enum, not free-form strings)

`SYSTEM_POLICY`, `AUTHENTICATED_USER`, `MODEL_GENERATED`, `EXTERNAL_UNTRUSTED`,
`TOOL_RESULT`, `SECURITY_METADATA` (blueprint section 2.2). A source can be
authenticated without its content being trusted as instructions (e.g., a quoted email
body inside an authenticated user request remains external content).

## Trust boundaries (target v1)

1. Host application -> gateway HTTP boundary: HMAC-authenticated `/v1/*` only, with a
   host-signed principal assertion in the exact signed body; health endpoints
   unauthenticated and non-sensitive. The host owns end-user authentication; there is
   no public/browser API.
2. Gateway -> model boundary: model output is `MODEL_GENERATED` and advisory, never
   authorization. Phase 8 sends only inspected request text to an optional local model;
   tool output is not yet fed back to a model.
3. Gateway -> tool adapters: adapters are narrow and only invoked through the firewall
   gateway after a recorded decision. The Phase 8 runtime receives only a `ToolExecutor`.
4. Gateway -> database boundary: policy/approval/audit persistence with serialized
   audit appends and same-transaction approval decision/consumption events (Phase 5);
   the full chain verifier is implemented (Phase 7) but has no external anchor.
5. Gateway -> external destinations: egress is disabled by default in the starter policy
   and enforced by exact-match destination allowlisting plus a Phase 6 exact-canonical
   destination trust map. DLP inspects validated tool-bound arguments before execution;
   a classification can only raise the registry data class. No real destination exists.
6. Gateway -> caller / host application: the complete buffered tool result is inspected
   before release. `PASS` releases, `REDACT` releases an explicit span-preserving
   transformation linked by digest, and `BLOCK`/`REVIEW`/inspection failure suppress the
   whole response. Phase 8 returns the buffered result or a `response_blocked` error;
   no token streaming exists in v1 (ADR-003).
