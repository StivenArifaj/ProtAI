# Threat Model

Status: **partially implemented through Phase 2.** This document transcribes the v1
threat model from blueprint v1.2 section 2 with an implementation-status column. Phases
0a-2 delivered host authentication/replay defense, the deterministic policy engine, and
the mock-tool gateway; input defense, intent binding, DLP, approvals, and the audit
verifier remain future work. The repository must not be presented as providing controls
not marked here. Update the status column as each phase lands; every row eventually needs
the "required test evidence" listed in the blueprint.

## Threats

| # | Threat | Example | Primary defenses (target v1) | Required test evidence | Status (Phase 2) |
|---|---|---|---|---|---|
| 1 | Direct prompt injection | User asks the model to ignore policy or reveal hidden instructions | Input signals, bounded system context, action policy, output checks | Direct-injection fixtures plus tool-denial tests | Not implemented (Phase 3+) |
| 2 | Indirect prompt injection | A web page/email/document instructs exfiltration | Provenance labels, context isolation, detector signals, firewall enforcement | Malicious retrieved-content tests end-to-end | Partial (2): actions remain gateway-enforced, but no provenance/detector; end-to-end Phase 3 |
| 3 | Multi-turn manipulation | Benign-looking messages set up a later unsafe action | Session-linked events, context review, per-action authorization | Multi-turn scenario tests | Not implemented (Phase 3/5) |
| 4 | Tool/action mismatch | "Summarize" request becomes "forward the source" | Intent/action validator, forbidden-action rules, destination checks | Exact arguments and side-effect tests | Partial (2): exact `(tool_id, action_id)` resolution, strict arguments/resources/destination, real policy engine; manifest/intent binding Phase 4 |
| 5 | Privilege escalation | Model requests a file outside the user's scope | Verified principal, resource-scoped policy, connector ACL | Cross-user/cross-scope denial tests | Partial (2): verified principal binding + mock ownership checks; real connector ACLs with Phase 10 |
| 6 | Data exfiltration | Sensitive content goes to a public URL/recipient | Data classification, sink/destination policy, DLP before egress | Canary must not reach mock sink | Partial (2): mock egress sink unchanged on every denial (tested); content-level DLP Phase 6 |
| 7 | Path/URL confusion | `../`, symlinks, encoded traversal, deceptive hostnames | Canonicalization, allowlisted resource IDs, safe URL parser | Normalization and traversal tests | Partial (1-2): canonical destination parser + resource-ID scope; real filesystem handling Phase 6 |
| 8 | Replay/approval abuse | Old approval reused after argument change | One-time token, action digest, expiry, principal/policy binding | Replay, mutation, expiry tests | Not implemented (Phase 5) |
| 9 | Detector/provider outage | Classifier or LLM times out | Explicit failure mode; authorization never depends on detector availability | Timeout/exception tests; no bypass | Not implemented (Phase 3/4); Phase 2 already fails closed on engine/audit outages |
| 10 | Audit manipulation | Event modified or deleted | Append-only writer, hash chain, protected checkpoint/export | Tamper-detection test and documented limits | Not implemented (Phase 7) |
| 11 | Model/provider supply chain | Provider changes model ID or output format | Provider adapter, pinned config, schema validation, no model authority | Invalid output and provider error tests | Not implemented (Phase 4) |
| 12 | Resource exhaustion | Huge prompts, deep nesting, repeated calls | Input limits, deadlines, quotas, bounded retries | Boundary and load tests | Partial (0b/2): 64 KiB request bound, per-tool deadlines/timeouts/concurrency; input-depth and rate limits Phase 3/8 |
| 13 | Tool adapter compromise | Adapter performs an unapproved side effect | Narrow adapter APIs, minimal credentials, sandbox/egress restrictions | Adapter contract test and isolated mock runtime | Partial (2): narrow adapter protocol + digest verification + typed refusal; process isolation Phase 10 |
| 14 | Host-to-gateway impersonation/replay | Forged principal assertion or captured request replayed | Per-host HMAC, short timestamp window, unique nonce, body signature, private transport | Forged signature, body mutation, stale timestamp, replay tests | Implemented (0b): full denial matrix + live replay proof |
| 15 | Audit append race | Concurrent requests reuse the same `prev_hash` | DB-serialized append, monotonic per-chain sequence | Multi-worker concurrent append + chain verification | Partial (0b/2): advisory-lock append + 5-writer contiguity + gateway emission; verifier Phase 7 |
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

1. Host application -> gateway HTTP boundary: HMAC-authenticated `POST /v1/*` only;
   health endpoints unauthenticated and non-sensitive.
2. Gateway -> model boundary: model output is `MODEL_GENERATED`, never authorization.
3. Gateway -> tool adapters: adapters are narrow and only invoked through the firewall
   gateway after a recorded decision.
4. Gateway -> database boundary: policy/approval/audit persistence with serialized
   audit appends (Phase 7).
5. Gateway -> external destinations: egress disabled by default; destination allowlists
   (Phase 6).
