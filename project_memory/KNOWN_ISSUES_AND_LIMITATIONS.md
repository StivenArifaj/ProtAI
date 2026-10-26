# Known Issues and Limitations

Severity: **High** (blocks security goals) / **Medium** / **Low**. Status labels follow
[README.md](README.md) ("RESOLVED (0b)"/"RESOLVED (1)"/"RESOLVED (2)"/"RESOLVED (3)"/
"RESOLVED (4, in-process)"/"RESOLVED (5, in-process)"/"RESOLVED (6, gateway scope)"/
"RESOLVED (7, local chain)" mark items closed in Phase 0b/1/2/3/4/5/6/7). "Section"
refers to the master blueprint v1.2. The canonical long-form list (with phase pointers)
is [../docs/KNOWN_LIMITATIONS.md](../docs/KNOWN_LIMITATIONS.md); this file adds
severity, status, and next actions. Keep both consistent.

## Security controls absent (High — do not claim otherwise)

| # | Issue | Severity | Status | Blueprint | Next action |
|---|---|---|---|---|---|
| 1 | Host authentication: **implemented** for the `/v1/*` path prefix (HMAC + timestamp + atomic nonce replay + size bounds, fail-closed); no `/v1/*` routes exist yet; principal resolution beyond dev/test fails closed | High | **PARTIAL (0b/1)** | §9, §21 | Later phase (principal metadata), Phase 8 (routes) |
| 2 | Execution is mock-only and in-process: registry, gateway, execution authorization, `risk-v2`, manifest enforcement, one-time approvals, output DLP, and mock adapters exist and are tested, but there are no real connectors and no sandbox | High | **PARTIAL (2-6)** | §§10–13, 15 | Phase 10 (isolation); real connectors are out of v1 scope |
| 3 | Input defense exists but is advisory and not consumed: deterministic heuristics, typed non-PASS failure semantics, trust labels, and session signals are implemented (Phase 3/ADR-010), but no `/v1` route or model path uses them; intent extraction and approvals are in-process; output DLP is consumed only at the gateway | High | **PARTIAL (3-6)** | §§3, 8, 15 | Phase 8 (routes/provider); input findings still have no consumer |
| 4 | Audit: append repository + ADR-002 lock protocol + fixed vectors; the complete §16.1 taxonomy, mandatory ordered gateway lifecycle with fail-closed gating, approval/intent producers, first-class redacted DLP events, derived correlation metadata, and a read-only exact-stored-bytes verifier exist and are tested. No external checkpoint/anchor, scheduled verification, retention automation, or query API | High | **RESOLVED (7, local chain)** — mutation/reordering/middle deletion/non-canonical payloads/metadata tampering are detected; newest-event truncation and a consistent full-chain rewrite are not detectable without an external anchor | §16 | Phase 10 or later (anchor/ops); document the residual limit |
| 5 | No AI SOC analytics | Medium | NOT IMPLEMENTED | §17 | Phase 10 |
| 6 | No request-level rate limiting or request deadlines; request-size bound exists (64 KiB, 413); per-tool deadlines exist | Medium | **PARTIAL (0b/2)** | §18.2 | Phase 8 |
| 7 | Persisted state: `host_request_nonces`, `audit_events` (+ Phase 7 derived metadata columns/indexes), `session_security_state`, and `approval_requests` apply via Alembic; no intent-use table (in-memory tracker); no automated pruning job (expired session and approval rows are transitioned lazily on access; nonce/audit rows persist) | High | **PARTIAL (0b/3/4/5/6/7)** | §§13, 20.2 | Later operational phase (retention job); shared intent-use store |

## Environment and tooling gaps

| # | Issue | Severity | Status | Next action |
|---|---|---|---|---|
| 8 | Repository not under git | Medium | **RESOLVED (0b)** — baseline `41e10da` + 7 Phase 0b commits on `main`; no remote | Configure a remote only if the operator wants one |
| 9 | Compose dev values; HMAC all-zero sample secret refusal | Low | **RESOLVED (0b)** — both the sample password and the all-zero HMAC sample secret are refused outside development/test | None |
| 10 | Container hardening minimal: non-root + digest pins only; no seccomp/read-only rootfs/image scanning | Medium | PARTIAL | Phase 10 hardening |
| 11 | No secret scanning in the gate | Medium | **RESOLVED (0b)** — Gitleaks 8.30.1 pinned in `check.sh` (dir+git, redacted); `.gitleaks.toml` allowlists one documented dev value; history scanned clean | None (local-only until CI exists) |
| 12 | No SBOM (CycloneDX is Phase 10) | Low | NOT IMPLEMENTED | Phase 10 |
| 13 | No schema/migrations | Medium | **RESOLVED (0b)** — Alembic baseline `d15b46c49950` (`host_request_nonces`, `audit_events`); idempotent; `alembic check` clean | Extend per phase |
| 14 | No CI configuration; `check.sh` (8 steps) is the only gate | Low | NOT IMPLEMENTED | Out of scope for 0a–0b (documented) |
| 15 | No markdown linter installed in this environment; memory-file link checks are ad hoc | Low | VERIFIED (not installed) | Install only if the operator wants it |
| 16 | ADR files omit explicit "alternatives considered" / "tests/verification" sections named in blueprint §22.4 | Low | VERIFIED (format nuance) | New ADRs can include them; do not rewrite ADR-001..007 silently |
| 21 | `HostPrincipalResolver` fails closed (raises) until the host-signed principal assertion path is implemented; signed requests reach no principal | Medium | BY DESIGN (0b/1) | Phase 8 (principal assertion) |
| 22 | Interim policy evaluator (`policy/interim_matrix.py`) was scaffolding, not the real engine | Medium | **RESOLVED (1)** — deleted; the deterministic engine + fixture suite replaced it | None (readiness drift detection retained) |
| 23 | `check.sh` fails on any Gitleaks version ≠ 8.30.1 (deliberate pin) | Low | BY DESIGN | Update pin deliberately if the scanner is upgraded |
| 25 | Engine consumes upstream-supplied facts; the gateway produces them (registry capability, validated/deduplicated resource IDs, canonical destination, `risk-v2` score). Intent manifests and approvals deliberately do **not** enter policy facts; they narrow/gate execution after policy | Medium | **RESOLVED (2/4/5)** — intent is a post-policy constraint; approval is a post-policy gate | None |
| 26 | No policy hot-reload: the process keeps its startup-loaded bundle; readiness detects file drift (503) but does not reload | Low | BY DESIGN (1) | Phase 2+ (not scheduled) |
| 27 | Destination allowlisting is exact-match only (no wildcards); non-ASCII paths/queries and IPv6 zone IDs are rejected | Low | BY DESIGN (1) | Revisit when wildcard matching semantics are documented |
| 28 | Risk thresholds 40/80 are experimental defaults, not empirically calibrated | Low | BY DESIGN (1) | Phase 9 (evaluation/calibration) |

| 29 | Approvals are storage-and-gateway only: `ASK_USER` can execute once with a valid consumed approval, but there is no `/v1/approvals` route, approval UI, token-delivery transport, approver directory, notification channel, revocation operation, or background expiry sweeper; the gateway does not create requests automatically | Medium | **RESOLVED (5, in-process)** | §13 | Phase 8 (route/transport/workflow); expiry is lazy on decide/consume |
| 30 | Manifest/intent binding exists **in-process only** with a mock extractor; no `/v1` route issues/transports a manifest and no signed serialization exists | Medium | **RESOLVED (4, in-process)** | §11.1–11.2 | Phase 8 (route/transport/provider) |
| 31 | Content-level DLP was absent through Phase 5 (data class was a registration-declared fact). Phase 6 adds deterministic argument/result inspection, canary/pattern detection, destination-aware egress, redaction, and suppression at the gateway; it is not a classifier and has no real connectors | High | **RESOLVED (6, gateway scope)** — canary/private-key/API-key/blocking-credential egress denied with an unchanged sink; response `BLOCK`/`REVIEW`/failure suppressed whole | §15 | Phase 9 (evaluation); expand detectors only with tests |
| 32 | Execution authorization is an in-process guardrail, not a sandbox: malicious in-process code could bypass private internals | High | BY DESIGN (2) | §14.2 | Phase 10 |
| 33 | Concurrency bounds and the in-memory sink are per process/event loop; no cross-worker coordination | Medium | BY DESIGN (2) | §18.2 | Later operational phase |
| 34 | `risk-v2` weights uncalibrated; factor set minimal (one breadth factor; no identity/session/history factors) | Low | BY DESIGN (2/5) | §11.3–11.4 | Phase 9 (calibration); expand factors only with an explicit version/ADR |
| 36 | Detector heuristics are modest: English-pattern based, homoglyphs are flagged but not normalized before matching, quoted/educational content can still raise FLAG, and PASS means "no configured finding matched", not "safe" | Medium | BY DESIGN (3) | §7.3 | Phase 9 evaluation; expand patterns/normalization deliberately with tests |
| 37 | Trust labels, input-detector findings, and session signals have no consumer yet (no routes/model); session state is not an authorization or scoring input. Intent manifests are consumed by the app gateway but no route/provider produces them; approvals are not wired to a host workflow. Output DLP is consumed at the gateway | Medium | BY DESIGN (3-6) | §§7.4, 8 | Phase 8 (routes/model/workflow); Phase 9 (evaluation of session signals as factors) |
| 38 | Abandoned session rows persist until touched (lazy expiry only); no scheduled pruning | Low | BY DESIGN (3) | §20.2 | Later operational phase (retention job) |
| 39 | Intent manifests are sentinel-sealed in-process objects, not signed tokens; no route may accept a client-carried manifest without a signing/transport contract | Medium | BY DESIGN (4) | §11.1 | Phase 8 |
| 40 | App uses the two-scenario mock intent extractor; general NLU and real local-model accuracy are unmeasured | Medium | BY DESIGN (4) | §8 | Phase 8 (provider), Phase 9 (evaluation) |
| 41 | Intent `max_uses` tracking is per process/in memory (10,000 manifest cap, fail-closed); multi-worker instances enforce independently | Medium | BY DESIGN (4) | §11.1 | Later operational phase |
| 42 | Manifest request binding uses a server-assigned `request_id` but no request-body digest; the Phase 8 route must generate unique ids and cannot let clients choose them | Low | BY DESIGN (4) | §11.1 | Phase 8 |
| 43 | Intent constraints are exact-match only (no wildcards/ranges/floats); coarse extractor proposals may require clarification | Low | BY DESIGN (4) | §11.1 | Revisit only with documented semantics/tests |
| 44 | Approval consumption burns the grant even if a later authorization/audit step fails before execution (deliberate anti-replay); a DLP-raised data class also invalidates a stale approval; the caller must request a new approval | Low | BY DESIGN (5/6) | §13 | Revisit only with a documented retry contract that cannot replay |
| 45 | Approval/resource ids are one flat distinct string set; two argument namespaces carrying the same textual id collapse to one target | Low | BY DESIGN (5) | §13 | Treat stable ids as globally meaningful; revisit if per-namespace ids are introduced |
| 46 | Output DLP is deterministic pattern matching, not a classifier: five configured detectors, no entropy scan, semantic model, multilingual PII, or detection of secrets without a configured shape; `PASS` means "no configured pattern matched", not "safe" | Medium | BY DESIGN (6) | §15 | Phase 9 evaluation; expand detectors deliberately with false-positive tests |
| 47 | Response `REVIEW` is operationally a whole-response block: no review queue, reviewer UI, release token, or post-review transport exists | Medium | BY DESIGN (6) | §15.4 | Phase 8 (review workflow/transport) |
| 48 | DLP inspects only validated tool-bound arguments and the complete buffered result: no model prompts/streams, adapter-internal fetched content, or local-write destinations | Medium | BY DESIGN (6) | §15 | Phase 8 (model path) and later real-connector work |
| 49 | Over-redaction is deliberate: credential redaction is line-scoped, can remove trailing comments/passphrases, and a redaction that violates a strict result schema or the size bound suppresses the entire response | Low | BY DESIGN (6) | §15.4 | Revisit only with a schema-aware redaction contract and tests |
| 50 | No per-resource classification metadata: the effective class is the registry declaration raised by deterministic inspection, never a real connector's per-file/per-record label | Medium | BY DESIGN (6) | §15.1 | Real-connector phase |
| 51 | Destination trust covers external mutations only, is exact-canonical (no wildcards), and has no per-tenant model; startup refuses missing/dead entries | Low | BY DESIGN (6) | §15.3 | Revisit with documented trust semantics |
| 52 | DLP evidence was an additive field on existing schema-v1 events through Phase 6; Phase 7 promotes it to first-class redacted `EGRESS_INSPECTED`/`OUTPUT_INSPECTED`/`RESPONSE_*` events and adds the verifier | Medium | **RESOLVED (7)** | §16.1 | None (retention/anchor remain separate) |
| 53 | No live `/v1` DLP surface or streaming path; enforcement is in-process at the single gateway result boundary | Medium | BY DESIGN (6) | §§15, 18 | Phase 8 (routes); streaming stays disabled (ADR-003) |
| 54 | No external audit checkpoint/anchor: newest-event truncation and a consistent full-chain rewrite by a database owner are undetectable | Medium | BY DESIGN (7, documented) | §16.2 | Later operational phase (external anchor); do not overclaim tamper-proof |
| 55 | The verifier is an in-process library: no scheduled job, route, or UI; it loads one chain into memory and assumes the v1 single-chain deployment; `max_failures` bounds output | Medium | BY DESIGN (7) | §16.2 | Later operational phase |
| 56 | Metadata backfill is deliberately best-effort: a corrupt historical payload stays unbackfilled (the migration does not abort) and is surfaced by the verifier; backfilled metadata is not authoritative | Low | BY DESIGN (7) | §16.1 | Repair/diagnose historical rows only with an explicit operator procedure |
| 57 | Intent `INTENT_CREATED`/`INTENT_FAILED` audit is best-effort; a failed intent audit write does not block manifest issuance (it can never grant authority, and the gateway independently fails closed on its own audit path) | Low | BY DESIGN (7) | §16.4 | None (intent is advisory/narrowing) |
| 58 | `PRINCIPAL_RESOLVED`/`PRINCIPAL_REJECTED`, `INPUT_INSPECTED`, and `SECURITY_ALERT_RAISED` are defined but producerless; taxonomy presence is not evidence that ingress/alerting exists | Medium | BY DESIGN (7) | §16.1 | Phase 8 (ingress) / Phase 10 (alerts) |

## Behavioral notes (expected behavior, not defects)

| # | Note | Next action |
|---|---|---|
| 17 | Readiness 503 is expected when PostgreSQL is down/unreachable; the API itself can still be alive (liveness 200). Readiness also reports `policy_self_checks` + `policy_version`/`policy_hash`, re-evaluated per probe (policy or fixture file drift → 503, deliberate) | None |
| 18 | Readiness runs `SELECT 1` through the persistence layer (`pool_pre_ping`, 2 s connect timeout); short-lived connection per check remains acceptable locally | None |
| 19 | Compose API host port is 8080 (host port 8000 is commonly occupied by unrelated local services); container port remains 8000 | None |
| 20 | `uv lock` resolves 38 packages while `uv sync` checks 36 (installed set) — both expected | None |
| 24 | Authenticated `/v1/*` requests answer 404 until routes land (auth passes first — verified live in 0b) | Phase 8 (routes) |
| 35 | An audit append failure after an executed mock side effect yields `AUDIT_FAILED` with no result returned; the in-memory sink is not rolled back (no compensating action in v1) | Documented; revisit with real connectors |

## How issues graduate

Close an item only by (a) implementing the control with tests, (b) recording evidence in
[TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md), and (c) updating [../docs/KNOWN_LIMITATIONS.md](../docs/KNOWN_LIMITATIONS.md),
[../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md), and this file in the same task.
