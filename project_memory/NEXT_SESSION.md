# Next Session Handoff

**Last updated: 2026-10-26.** Read [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) first if you have not.

## Where we are

Phases 0a (repository foundation), 0b (security foundation), 1 (typed contracts and
deterministic policy engine), 2 (tool registry and enforced gateway), 3 (advisory input
defense and context provenance), 4 (intent extraction and action validation), 5 (risk
engine and approval workflow), and 6 (output DLP and egress policy) are **COMPLETE —
VERIFIED**. See [phases/PHASE_6_COMPLETE.md](phases/PHASE_6_COMPLETE.md) and evidence
V63–V66 in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md). Exact commit hashes
for every Phase 6 deliverable are in the phase record. The repository is under git with a
linear history; the Compose `db` container and volume are preserved for tests (`api`
stopped). No remote is configured.

What exists now: host HMAC authentication + replay rejection on the `/v1/*` path prefix
(business routes do not exist yet), async persistence + migrations, dev-resolver guard +
test-only principal adapter, strict typed contracts, canonical destination handling, the
safe versioned policy loader, the deterministic §10.2 policy engine with 21 self-check
fixtures wired into startup/readiness, the typed tool registry + four mock adapters, the
digest-bound execution authorization, `risk-v2`, the single `invoke_tool` gateway with
audit-first ordering/bounds, strict advisory input detection with trust labels/session
signals, server-issued sealed intent manifests with exact constraints, durable one-time
human approvals bound to the canonical action digest, and mandatory two-phase output
DLP/egress with destination trust and whole-response suppression. **766 tests pass; the
gate is green (8/8, V66).** Intent, approvals, and DLP can only narrow, gate, or deny;
none is an `ALLOW` producer. No route or real model provider consumes them yet.

## The next task: Phase 7 — Audit persistence and verification (blueprint §16, §21)

No blocking preconditions; Phase 6 passed its DoD, so proceed per the autonomy mandate.
Read first: blueprint §16 (all of 16.1–16.4), §21 Phase 7, ADR-002 (exact canonical bytes
and hash formula), ADR-008 through ADR-013, `docs/SECURITY_INVARIANTS.md` (#21/#22),
`docs/KNOWN_LIMITATIONS.md`, and the current `src/ai_security/audit/models.py`,
`src/ai_security/audit/writer.py`, `src/ai_security/persistence/audit_repository.py`,
`src/ai_security/persistence/models.py`, and gateway/approval event emission.

Expected deliverables (condensed from blueprint §16/§21):

1. **Full structured event taxonomy** — stable event names and schema version covering the
   §16.1 list: `REQUEST_RECEIVED`, `PRINCIPAL_RESOLVED`/`PRINCIPAL_REJECTED`,
   `INPUT_INSPECTED`, `INTENT_CREATED`/`INTENT_FAILED`, `TOOL_CALL_PROPOSED`,
   `POLICY_EVALUATED`, `APPROVAL_REQUESTED`/`APPROVAL_DECIDED`/`APPROVAL_EXPIRED`,
   `TOOL_EXECUTION_STARTED`/`TOOL_EXECUTION_COMPLETED`/`TOOL_EXECUTION_FAILED`,
   `EGRESS_INSPECTED`, `OUTPUT_INSPECTED`, `RESPONSE_RELEASED`/`RESPONSE_SUPPRESSED`,
   `SECURITY_ALERT_RAISED`. Keep the existing extra `APPROVAL_CONSUMED` (stable, tested).
   Each event carries `trace_id`, `request_id`, `event_id`, UTC timestamp, component and
   version, policy version, reason codes, duration, and safe resource references where
   applicable. Prefer bounded/reference fields only; never raw arguments/content.
2. **Database persistence suitable for correlation** — add queryable metadata columns to
   `audit_events` (at minimum `event_type`, `request_id`, `trace_id`, `occurred_at`,
   `component`) with indexes, populated by the single append repository from the exact
   payload. Keep `canonical_event_bytes` and the hash formula untouched; old rows may be
   nullable after a non-destructive migration. Prove that all events for one `request_id`
   can be read back in chain order.
3. **First-class DLP events** — promote the additive `dlp` evidence to
   `EGRESS_INSPECTED`, `OUTPUT_INSPECTED`, `RESPONSE_RELEASED`/`RESPONSE_SUPPRESSED`
   events while keeping the redacted `dlp` record where it aids correlation. Do not
   duplicate raw content; keep the Phase 6 detector/decision semantics unchanged.
4. **Exact-stored-bytes verifier** — a verifier that reads `canonical_event_bytes` and
   recomputes the ADR-002 hash from the exact stored bytes (never a reconstructed ORM/JSON
   serialization), checks `sequence_number` contiguity from 1, `previous_hash` linkage,
   stored `event_hash`, and chain id. Add fixed canonical-byte/vector tests plus mutation,
   deletion, insertion, and reordering-detection tests. Keep the concurrent-writer test
   (contiguity and linkage across multiple writers).
5. **Retention/data-handling document** — `docs/AUDIT_RETENTION_AND_DATA_HANDLING.md`
   covering stored fields, explicitly excluded data, default diagnostic capture (off),
   retention period/ownership, deletion/backup/export handling, and the honest
   tamper-evident-not-tamper-proof boundary. Add an ADR (likely ADR-014) for the taxonomy,
   correlation contract, metadata columns, verifier scope, and schema-evolution rule.
6. **Safe operational logs and privacy tests** — audit every logger path touched by
   gateway/approval/DLP/intent failures; add tests that capture default logs (DEBUG) and
   serialized audit payloads for canary, email, credential, private-key, and API-key
   inputs and assert the raw values are absent. Keep field paths bounded/control-free.

## Honest scope boundaries to preserve

- There are still no `/v1` business routes, API ingress, or model path. Producers for
  `REQUEST_RECEIVED`, `PRINCIPAL_RESOLVED`/`PRINCIPAL_REJECTED`, `INPUT_INSPECTED`, and
  `SECURITY_ALERT_RAISED` do not exist yet. Define them in the closed taxonomy, but do not
  fake emission from a component that did not perform the work. State this in the phase
  record; either (a) emit only from real in-process producers and document the remaining
  Phase 8 ingress events, or (b) add a minimal, real in-process request entry point that
  an HTTP route can later use. The DoD claim must match what is actually emitted.
- Correlation must be proven end-to-end for the implemented path: a `request_id` must
  return `TOOL_CALL_PROPOSED` → `EGRESS_INSPECTED` (public/mutation paths) →
  `POLICY_EVALUATED` → approval events (when `ASK_USER`) → `TOOL_EXECUTION_STARTED` →
  `TOOL_EXECUTION_COMPLETED`/`_FAILED` → `OUTPUT_INSPECTED` →
  `RESPONSE_RELEASED`/`SUPPRESSED`, in chain order. No gaps except events whose producer
  genuinely does not exist.
- `trace_id` is currently optional on `RequestContext`/`AuditEvent`. Decide and record:
  either require it for gateway events (derive a server-side value when absent) and persist
  it for approval correlation, or keep `request_id` as the documented correlation key for
  approval events. Do not claim a `trace_id` correlation that the data cannot support.
- Verifier limitation: a local hash chain is tamper-evident, not tamper-proof. An attacker
  able to rewrite the whole chain can recompute it; signing/checkpoints are future work.
  Do not overclaim.
- Event schema evolution: adding event types/optional fields is additive; any removal,
  rename, or type change requires a new schema version and ADR. Record the choice.
- Preserve ADR-008 (engine facts/sole `ALLOW`), ADR-009 (gateway chokepoint/audit-first),
  ADR-010 (advisory detection), ADR-011 (manifest boundary), ADR-012 (approval boundary),
  and ADR-013 (DLP boundary). Audit must never become an authorization input.

## Verification commands and expected results

| Command | Expected |
|---|---|
| `uv run --frozen pytest -q` | All tests pass (≥766; new taxonomy/verifier/privacy suites added; real-PostgreSQL tests still run) |
| `uv run --frozen mypy src` / `ruff check src tests` / `ruff format --check src tests` | clean |
| `bash scripts/check.sh` | exit 0, all 8 steps (Gitleaks stays clean) |
| Alembic sequence | single head; `current` → `upgrade head` → `downgrade -1` → `upgrade head` → `check` clean if a migration is added |
| Correlation test | one `request_id` returns the complete implemented event sequence in chain order |
| Verifier tests | intact chain passes; byte mutation, deletion, insertion, reordering, wrong prev-hash, and wrong sequence all fail with typed reasons |
| Privacy tests | raw canary/email/credential/private-key/API-key values absent from default logs and serialized audit payloads |
| Prior suites | policy/intent/approval/DLP/no-bypass still green; sink unchanged on every denial |

## Security constraints that must hold throughout Phase 7

- Invariants #6/#7/#8/#20/#24 stay green; keep `compare_digest` confined to
  `security/constant_time.py`; do not weaken the HMAC denial matrix.
- The audit repository remains the only writer of `audit_events`; the verifier is
  read-only; no direct inserts anywhere else.
- Audit-first behavior: if a required decision event cannot be persisted, no protected
  side effect; if a required outcome/response event cannot be persisted, withhold the
  result. Do not silently downgrade.
- No raw prompts, arguments, content, secrets, tokens, full DLP matches, or exception
  messages in logs/audit. Digests/lengths/categories/bounded field paths only.
- Mock/local only; no network calls by default; no real model dependency in tests.
- Update `docs/SECURITY_INVARIANTS.md`, `docs/KNOWN_LIMITATIONS.md`, both status files,
  `ARCHITECTURE_MAP.md`, `FILE_MAP.md`, `CHANGELOG.md`, ADR index, and this file in the
  same task.

## Definition of Done (blueprint §21, Phase 7 condensed)

The full request-to-tool event sequence is correlatable; mutation/reordering is detected
by a verifier that hashes the exact stored bytes; privacy tests show raw secrets are not
in default logs; retention/data-handling is documented; all prior suites and the 8-step
gate stay green.

## Open decisions / notes for the operator

- None blocking. `check.sh` pins Gitleaks to exactly 8.30.1 by design; a mismatch fails
  the gate.
- Carried-forward limits (documented): no policy hot-reload; exact-match destination
  allowlisting; `risk-v2` uncalibrated; per-process concurrency and intent-use tracking;
  mock-only tools and mock intent extractor; no manifest/approval routes or token
  transport; in-process guardrail (no sandbox) until Phase 10; no pruning job yet.
