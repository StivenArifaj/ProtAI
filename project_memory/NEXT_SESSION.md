# Next Session Handoff

**Last updated: 2026-10-26.** Read [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) first if you have not.

## Where we are

Phases 0a (repository foundation), 0b (security foundation), 1 (typed contracts and
deterministic policy engine), 2 (tool registry and enforced gateway), 3 (advisory input
defense and context provenance), 4 (intent extraction and action validation), 5 (risk
engine and approval workflow), 6 (output DLP and egress policy), and 7 (audit persistence
and verification) are **COMPLETE — VERIFIED**. See
[phases/PHASE_7_COMPLETE.md](phases/PHASE_7_COMPLETE.md) and evidence V67–V71 in
[TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md). Exact commit hashes for every
Phase 7 deliverable are in the phase record. The repository is under git with a linear
history; the Compose `db` container and volume are preserved for tests (`api` stopped).
No remote is configured.

What exists now: host HMAC authentication + replay rejection on the `/v1/*` path prefix
(business routes do not exist yet), async persistence + migrations, dev-resolver guard +
test-only principal adapter, strict typed contracts, canonical destination handling, the
safe versioned policy loader, the deterministic §10.2 policy engine with 21 self-check
fixtures wired into startup/readiness, the typed tool registry + four mock adapters, the
digest-bound execution authorization, `risk-v2`, the single `invoke_tool` gateway with
audit-first ordering/bounds, strict advisory input detection with trust labels/session
signals, server-issued sealed intent manifests with exact constraints, durable one-time
human approvals bound to the canonical action digest, mandatory two-phase output DLP/egress
with destination trust and whole-response suppression, and a complete structured audit
lifecycle (request → proposal → inspection → decision → approval consumption → execution →
output inspection → response) with an exact-stored-bytes verifier and privacy tests.
**827 tests pass; the pre-commit gate is green (8/8, V70).** The post-commit gate is V71
and is recorded after the memory/status commits; do not claim it before it runs. Intent,
approvals, DLP, input
detection, and audit can only narrow, gate, raise sensitivity, or record; none is an
`ALLOW` producer. No route or real model provider consumes them yet.

## The next task: Phase 8 — FastAPI integration and local model (blueprint §§7, 8, 18, §21)

No blocking preconditions; Phase 7 passed its DoD, so proceed per the autonomy mandate.
Read first: blueprint §§7.1–7.6, 8.1–8.4, 9.2–9.4, 18.1–18.2, §21 Phase 8, ADR-001,
ADR-008 through ADR-014, `docs/SECURITY_INVARIANTS.md` (#2/#7/#10/#14/#22/#24),
`docs/KNOWN_LIMITATIONS.md`, `src/ai_security/api/{app,middleware,dependencies}.py`,
`src/ai_security/identity/{models,resolver,host_auth}.py`,
`src/ai_security/firewall/{gateway,models,approval}.py`, and the Phase 7 audit producers.

Expected deliverables (condensed from blueprint §§18/21):

1. **Authenticated business routes** (all under the existing `/v1/*` HMAC middleware):
   - `POST /v1/requests`: accepts a bounded request from the authenticated host, creates
     server-side `request_id`/`trace_id`, resolves the verified principal, runs bounded
     intake + advisory input inspection, issues an intent manifest, runs the bounded
     in-process agent/runtime path, and routes every proposed action through
     `ToolGateway`. Return a safe result, a clarification state, a rejection, or an
     approval-required state — never an arbitrary tool execution.
   - `POST /v1/tool-calls/evaluate`: validates a typed tool proposal and returns a
     `DecisionRecord` **without executing**. It is a preview, not an execution grant;
     do not expose client-supplied decisions or create approval authority here.
   - `POST /v1/approvals/{approval_id}/decision`: verifies the approver principal, the
     one-time `approval_token` in the signed body, and the configured approver rule;
     records the decision through the existing row-locked service. Never accept an
     approval outcome from an unsigned/client-only field.
   - `POST /v1/tool-calls/execute`: implement **only if** an evaluation/execution split
     is actually required. If added, it must re-evaluate through the gateway or use a
     short-lived server-issued binding to exact arguments/principal/policy version; it
     must never trust a client-provided `ALLOW`. It is acceptable to leave this route
     absent and document why `/v1/requests` is the single execution path.
2. **Real principal resolution at ingress.** Implement the host-signed principal
   assertion path required by §§9.2–9.4: the configured key constrains host/audience/
   tenant; reject missing, malformed, expired, unverified, or cross-tenant assertions;
   never accept a principal, role, or permission from an unsigned field. Audit
   `PRINCIPAL_RESOLVED` or `PRINCIPAL_REJECTED` with identifiers/status only. The dev
   resolver remains HMAC-gated and is not an HTTP bypass.
3. **Input and intent producers.** Wire `InputDefenseService.inspect` into
   `/v1/requests` and emit `INPUT_INSPECTED` with redacted findings/versions/content
   digest (no raw text). Map `REJECT`/`QUARANTINE` to safe refusal/review states and
   keep detection advisory: it can gate intake, never grant action authority. Issue the
   existing sealed manifest in-process; do not invent a client-carried manifest token.
4. **Audit ingestion without duplicate receipts.** The gateway already emits
   `REQUEST_RECEIVED`; ingress needs `PRINCIPAL_RESOLVED`/`_REJECTED`,
   `INPUT_INSPECTED`, and `INTENT_CREATED`/`_FAILED`. Choose and record one owner for
   `REQUEST_RECEIVED` (either ingress emits it and the gateway is told the receipt is
   already audited, or the gateway keeps ownership and ingress emits the later events).
   **One request must not produce two `REQUEST_RECEIVED` events.** Preserve the Phase 7
   fail-closed rules and correlation by `request_id`/`call_id`.
5. **Agent runtime + optional local model.** Add a bounded in-process runtime that can
   only propose gateway actions from the manifest (start with the documented mock demo
   scenarios). Wire an opt-in local-model provider adapter (Ollama-compatible HTTP is the
   natural local default) behind the existing `LocalModelIntentExtractor` interface:
   explicit `MODEL_PROVIDER` selection, exact model name required, bounded timeout/output,
   no cloud calls by default, no network in tests (inject a fake transport), and provider
   failure/timeout/malformed output must never bypass policy or become a grant. Keep the
   mock path fully offline.
6. **Deadlines, rate limits, and safe errors.** Enforce request deadlines
   (`REQUEST_TIMEOUT_SECONDS`) and basic in-process per-principal/session rate limits for
   request creation, tool proposals, invalid-call bursts, and approval attempts. Return
   explicit safe statuses/envelopes (400/401/403/404/409/413/422/429/503/504) with stable
   codes and a server request reference; never leak stack traces, raw payloads, tokens,
   approval material, or secrets. Document that the limiter is not multi-worker-safe.
7. **Startup config checks + integration docs.** Fail closed on an unusable provider
   selection (missing/placeholder model name, bad base URL, unsupported provider), invalid
   timeout/rate-limit configuration, or a route wiring mistake. Add
   `docs/API_INTEGRATION.md` with signing/headers, route contracts, status/error mapping,
   approval token handling, offline mock instructions, and honest limits. Record the
   ingress/route/provider/rate-limit contract in a new ADR (likely ADR-015). Update
   `IMPLEMENTATION_STATE`, `SECURITY_INVARIANTS`, `KNOWN_LIMITATIONS`, `ARCHITECTURE`,
   `THREAT_MODEL`, README, and this memory.

## Design decisions to make and record (do not silently invent)

- **Who owns `REQUEST_RECEIVED`** when ingress and gateway both handle one request
  (see item 4). Record the choice in ADR-015 and test the exact sequence.
- **How `/v1/requests` represents agent execution**: synchronous safe result for the
  mock demo, approval-required response with a one-time token, and clarification/rejection
  states. Keep it bounded and non-streaming (ADR-003).
- **Whether `/v1/tool-calls/execute` exists at all.** If absent, document that
  `/v1/requests` is the only execution surface and no client decision is trusted.
- **Approval transport**: if `/v1/requests` creates the approval automatically, return
  the one-time token only in the authenticated response (never logs/audit), or document
  an out-of-band delivery contract. Do not put tokens in URLs.
- **Principal assertion shape** from the host: strict fields, key→host/audience/tenant
  constraints, expiry/issued-at bounds, no unsigned fallback. Prefer a strict Pydantic
  model with `extra="forbid"` and an explicit verification function.
- **Local model scope**: intent extraction only in Phase 8 unless a deterministic agent
  planner is also justified; model output is never authorization. Keep `ALLOW_EXTERNAL_MODEL_CALLS=false`
  behavior unchanged.

## Honest scope boundaries to preserve

- The API is an adapter over existing services; business/security logic stays in domain
  modules and is invoked identically by in-process tests (§18). Routes must not duplicate
  policy/risk/DLP logic.
- No client-supplied principal, decision, risk score, approval outcome, or manifest may
  become authority. `/v1/tool-calls/evaluate` is a preview and must not create a reusable
  execution grant.
- HMAC enforcement remains identical under `PRINCIPAL_RESOLVER=dev`; no route bypasses
  it. Docs/OpenAPI gating stays as-is.
- Streaming stays disabled. The complete response must be inspected before release.
- Input findings/trust labels remain advisory: they may refuse/quarantine at intake, but
  cannot produce `ALLOW` or enter policy facts. Intent can only narrow. Approval is a gate
  for engine `ASK_USER` only. Audit is never an authorization input.
- The local model is optional and bounded; provider failure must leave policy and the
  gateway fully in control. No cloud calls by default.
- Keep `compare_digest` confined to `security/constant_time.py`; use it for approval
  tokens.
- No secrets, tokens, raw prompts, arguments, content, or exception messages in logs,
  audit, or error envelopes.

## Verification commands and expected results

| Command | Expected |
|---|---|
| `uv run --frozen pytest -q` | All tests pass (≥827; new route/principal/provider/rate-limit/error suites added; real-PostgreSQL tests still run) |
| `uv run --frozen mypy` / `ruff check .` / `ruff format --check .` | clean |
| `bash scripts/check.sh` | exit 0, all 8 steps (Gitleaks stays clean) |
| Alembic sequence | single head; `current` → `upgrade head` → `downgrade -1` → `upgrade head` → `check` clean if a migration is added (Phase 8 should not need one unless a new store is justified) |
| Route integration tests | signed `/v1/requests` works offline with the mock path; unsigned/forged/replayed requests denied by the existing middleware; client-supplied principal/decision fields have no effect |
| Principal tests | missing/expired/malformed/cross-tenant/mismatched-audience assertions deny and audit `PRINCIPAL_REJECTED`; valid assertion audits `PRINCIPAL_RESOLVED` |
| Input tests | direct/indirect attack fixtures produce `INPUT_INSPECTED` with redacted findings; no raw text in audit/logs; detector outage is an explicit non-PASS/refusal path |
| Agent/provider tests | mock path completes offline; provider timeout/malformed output yields a safe clarification/failure with no execution; no network in tests |
| Approval route tests | valid approver + token decides once; wrong principal/token/tenant/expired/replayed fail closed; no token in logs/audit |
| Rate-limit/deadline tests | over-limit → 429; over-deadline → 504/timeout envelope; denials have no side effect |
| Audit correlation | one `request_id` returns the complete implemented ingress→gateway sequence in chain order with no duplicate `REQUEST_RECEIVED` |
| Prior suites | policy/intent/approval/DLP/audit/no-bypass still green; sink unchanged on every denial |

## Security constraints that must hold throughout Phase 8

- Preserve ADR-008 (engine facts/sole `ALLOW`), ADR-009 (gateway chokepoint/audit-first),
  ADR-010 (advisory detection), ADR-011 (manifest boundary), ADR-012 (approval boundary),
  ADR-013 (DLP boundary), and ADR-014 (audit taxonomy/verifier).
- Every route that can lead to a tool call goes through `ToolGateway.invoke_tool`; no
  route calls an adapter directly.
- A failed/absent audit append cannot produce an unaudited execution or result release.
  Keep the Phase 7 fail-closed matrix green.
- The rate limiter must fail closed on malformed buckets and must not key on
  attacker-chosen identity fields.
- Error envelopes must not echo Pydantic input values, raw bodies, exception text, or
  secrets.

## Definition of Done (blueprint §21, Phase 8 condensed)

The local/mock path works fully offline; no route trusts client-supplied decisions,
principals, risk scores, or approval outcomes; optional model provider failure does not
bypass policy; routes are authenticated, bounded, rate-limited, deadline-aware, safely
erroring, audited, and documented; all prior suites and the 8-step gate stay green.

## Open decisions / notes for the operator

- None blocking. `check.sh` pins Gitleaks to exactly 8.30.1 by design; a mismatch fails
  the gate.
- Carried-forward limits (documented): no policy hot-reload; exact-match destination
  allowlisting; `risk-v2` uncalibrated; per-process concurrency/intent-use/rate-limit
  state; mock-only tools; no manifest transport; in-process guardrail (no sandbox) until
  Phase 10; no external audit anchor; no automated retention.
