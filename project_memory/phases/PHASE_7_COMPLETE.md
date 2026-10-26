# Phase 7 — Audit Persistence and Verification: COMPLETE — VERIFIED

**Completed:** 2026-10-26
**Blueprint:** v1.2 §§16.1–16.4, 20.2 #12/#13/#14/#19, §21 Phase 7
**ADR:** [../../docs/adr/ADR-014-audit-taxonomy-and-verification.md](../../docs/adr/ADR-014-audit-taxonomy-and-verification.md)
**Retention guidance:** [../../docs/AUDIT_RETENTION_AND_DATA_HANDLING.md](../../docs/AUDIT_RETENTION_AND_DATA_HANDLING.md)
**Evidence:** V67–V71 in [../TESTING_AND_VERIFICATION.md](../TESTING_AND_VERIFICATION.md)
**Commits:** `0b60ba0` (implementation/tests/migration), `d53b0ed` (ADR-014/docs),
this memory/completion commit, plus the final V71 status record commit.

## Definition of Done — verdict

| Criterion | Status | Evidence |
|---|---|---|
| Full request-to-tool event sequence is correlatable | PASS | The gateway durably emits `REQUEST_RECEIVED` → `TOOL_CALL_PROPOSED` → `EGRESS_INSPECTED` → `POLICY_EVALUATED` → (`APPROVAL_CONSUMED` when granted) → `TOOL_EXECUTION_STARTED` → `TOOL_EXECUTION_COMPLETED`/`_FAILED` → `OUTPUT_INSPECTED` → `RESPONSE_RELEASED`/`_SUPPRESSED`. Approval and intent producers emit their events. Unit + real-PostgreSQL tests assert exact order and shared `request_id`/`call_id`; indexed derived columns support correlation (ADR-014) |
| Mutation/reordering is detected | PASS | `tests/integration/test_audit_verifier.py` mutates payloads and hashes, reorders sequence numbers, deletes a middle event, rewrites metadata, and inserts invalid/non-canonical JSON; each yields a typed failure. Hashes are recomputed from exact stored bytes; linkage is checked separately. Newest-event truncation is honestly undetectable without an external anchor (tested/documented) |
| Privacy tests show raw secrets absent from default logs | PASS | `tests/security/test_audit_privacy.py` feeds canary, email, credential, private-key, and API-key shapes through egress denial, adapter failure, response suppression, and intent extraction at DEBUG; raw values are absent from serialized payloads and captured logs while stable codes/digests remain. Approval integration also asserts the one-time token and content never enter the chain |
| Taxonomy covers §16.1 without faking producers | PASS | Every §16.1 name (plus `APPROVAL_CONSUMED`) is a stable enum with event-specific required fields. Ingress/alerts names remain producerless until Phase 8/10; no placeholder events are emitted |
| Mandatory audit events gate execution and release | PASS | A parametrized gateway test fails each mandatory append position: pre-execution failure → `BLOCK`/`audit_unavailable` with no adapter call; post-execution failure → `AUDIT_FAILED` and the result is withheld. No lifecycle step can be skipped on a successful path |
| Schema evolution preserves prior payloads and hash formula | PASS | `schema_version=1` remains; fields became event-type-conditional rather than invented; historical bytes/hashes are never rewritten. The metadata migration is additive/backfill-only, and frozen ADR-002 vectors stay green |
| All prior suites and the 8-step gate stay green | PASS | V67–V71: **827 passed** (680 unit + 102 integration + 45 security), mypy 65 files, ruff clean (173 files), Gitleaks clean, Alembic single head |
| ADR-008 through ADR-013 boundaries untouched | PASS | Policy remains the sole `ALLOW` producer; the gateway remains the only execution path; intent/DLP only narrow/gate/raise; approval only makes an engine `ASK_USER` executable; audit is never an authorization input |

## Delivered

### Stable event taxonomy (`src/ai_security/audit/models.py`)

- All §16.1 event names are stable `AuditEventType` members, plus the already-stable
  `APPROVAL_CONSUMED` required by §§13.2–13.3.
- Required fields are **event-type-conditional** rather than filled with invented
  placeholders:
  - `principal_subject_id` is required except for `PRINCIPAL_REJECTED`;
  - `tool_id`/`action_id` are required only for tool-scoped events;
  - `decision`/`reason` are required only for decision events and must appear together;
  - `outcome` is required only for execution/response status events with event-specific
    allowed values;
  - `EGRESS_INSPECTED` requires an EGRESS `DlpAuditRecord`; `OUTPUT_INSPECTED` requires
    an OUTPUT record.
- `call_id` is validated and carried where a call exists (gateway/tool events); approval
  lifecycle events do not invent one.
- `to_payload()` omits `None`; unknown fields are refused (`extra="forbid"`).
- `PRINCIPAL_RESOLVED`/`PRINCIPAL_REJECTED`, `INPUT_INSPECTED`, and
  `SECURITY_ALERT_RAISED` remain producerless until Phase 8/10; Phase 7 does not fake
  them.

### Mandatory gateway lifecycle (`src/ai_security/firewall/gateway.py`)

- `REQUEST_RECEIVED` and `TOOL_CALL_PROPOSED` are mandatory before validation.
- `EGRESS_INSPECTED` is mandatory before resource/risk/policy evaluation.
- `TOOL_EXECUTION_STARTED` is mandatory before the adapter is invoked.
- `TOOL_EXECUTION_COMPLETED`/`TOOL_EXECUTION_FAILED` are mandatory before output
  inspection or return.
- `OUTPUT_INSPECTED` and `RESPONSE_RELEASED`/`RESPONSE_SUPPRESSED` are mandatory before
  releasing a result.
- Any mandatory pre-execution audit failure returns `BLOCK` / `audit_unavailable` /
  `DENIED`; post-execution failure returns `AUDIT_FAILED` and withholds the result.
- `TOOL_EXECUTION_COMPLETED` always carries `EXECUTED`; DLP suppression is represented
  separately by `RESPONSE_SUPPRESSED` + `RESPONSE_BLOCKED`.
- DLP evidence lives on first-class `EGRESS_INSPECTED`, `OUTPUT_INSPECTED`, and
  `RESPONSE_*` events (still redacted); `POLICY_EVALUATED`/execution events no longer
  duplicate it.

### Approval and intent producers

- Approval service emits `APPROVAL_REQUESTED`, `APPROVAL_DECIDED`,
  `APPROVAL_CONSUMED`, and `APPROVAL_EXPIRED`; consumption remains row-locked,
  one-time, and same-transaction with its event.
- `IntentManifestService` accepts an optional audit recorder and emits
  `INTENT_CREATED`/`INTENT_FAILED` with resolution status/stable error code only. Audit
  failure is best-effort there, changes neither resolution nor authority, and the gateway
  independently fails closed on its own audit path.

### Queryable correlation metadata

- `audit_events` gains nullable, indexed `event_type`, `request_id`, `trace_id`,
  `call_id`, `occurred_at`, and `component` columns.
- The single append repository derives them from the exact payload it is about to hash;
  malformed optional metadata refuses the append.
- Migration `f7a8b9c0d1e2` adds the columns/indexes and backfills historical rows from
  `convert_from(canonical_event_bytes, 'UTF8')::jsonb` without rewriting bytes or hashes.
  A per-row guarded PL/pgSQL loop keeps one corrupt historical payload from aborting the
  upgrade; such rows stay unbackfilled and the verifier reports them.
- Metadata is never authoritative: the verifier compares non-null columns with the
  parsed payload, and the hashed bytes remain the source of truth.

### Exact-stored-bytes verifier (`src/ai_security/audit/verifier.py`)

- `verify_chain(session, chain_id="v1", max_failures=100)` reads one chain in a single
  `SELECT` (consistent snapshot) ordered by sequence.
- Checks sequence start/contiguity, `previous_hash` linkage with the 32-zero-byte
  genesis, ADR-002 event hash recomputed from exact stored bytes, canonical JSON form,
  and derived metadata agreement.
- Typed failures: `SEQUENCE_DISCONTINUITY`, `MALFORMED_HASH`,
  `PREVIOUS_HASH_MISMATCH`, `EVENT_HASH_MISMATCH`, `INVALID_PAYLOAD`,
  `NON_CANONICAL_PAYLOAD`, `METADATA_MISMATCH`; bounded by `max_failures`, no raw
  content.
- Each row is rehashed from its own stored `previous_hash`; cross-row linkage is checked
  separately, so tampering row N yields its own failure plus a linkage failure at N+1.
- Read-only: never repairs or rewrites rows.

### Documentation and privacy

- `docs/adr/ADR-014-audit-taxonomy-and-verification.md` records taxonomy, conditional
  fields, metadata derivation, verifier scope, schema-evolution rule, and honest limits.
- `docs/AUDIT_RETENTION_AND_DATA_HANDLING.md` records stored/excluded fields, default
  diagnostic capture, retention/ownership, deletion/backup/export, integrity guarantees
  (tamper-evident, not tamper-proof), incident handling, and the missing external anchor.
- Updated `ARCHITECTURE.md`, `THREAT_MODEL.md`, `SECURITY_INVARIANTS.md`,
  `KNOWN_LIMITATIONS.md`, `DECISIONS.md`, `IMPLEMENTATION_STATE.md`, and `README.md`.
- Privacy tests assert raw canary/email/credential/private-key/API-key values and adapter
  exception messages are absent from audit payloads and DEBUG logs; intent records the
  status/error code, not request text or goal.

## Decisions and limitations (honest)

- `schema_version` stays `1` for the pre-release project. Additive event types and
  event-type-conditional fields are allowed; renaming/removing events, changing canonical
  JSON, or changing the hash input requires a new schema version and ADR.
- Audit availability is a hard gate: no unaudited execution or result release. This can
  deny/withhold during a database outage by design.
- A plain local hash chain is tamper-evident, not tamper-proof. Mutation, reordering, and
  middle deletion are detected; **truncation of the newest events** and a consistent
  full-chain rewrite by a database owner are not detectable without an externally stored
  head checkpoint. No anchor/checkpoint is deployed in Phase 7.
- No automated retention/purge, scheduled verification job, audit query API/UI, or
  per-event signature exists. The verifier loads one chain into memory and targets the
  v1 single-chain deployment.
- `PRINCIPAL_RESOLVED`/`PRINCIPAL_REJECTED`, `INPUT_INSPECTED`, and
  `SECURITY_ALERT_RAISED` are defined but producerless; Phase 8 ingress and Phase 10
  alerting must emit them when the work actually occurs.
- Intent audit is best-effort only; it cannot grant authority and does not replace the
  gateway's fail-closed audit gates.
- Metadata columns are a query convenience; editing them is detectable, but only the
  stored bytes are authoritative. Backups/exports must preserve the exact bytes and hash
  fields.

## Verification (V67–V71)

- V67: Alembic `current`/`downgrade -1`/`upgrade head`/`check` — starts/ends at
  `f7a8b9c0d1e2 (head)`, downgrade reaches `e5a1c2b3d4f6`; the guarded backfill was
  proven by a pre-existing corrupt fixture row; `alembic check` reports "No new upgrade
  operations detected".
- V68: full suite — **827 passed** (680 unit + 102 integration + 45 security); mypy clean
  (65 source files); ruff format/lint clean (173 files formatted).
- V69: targeted Phase 7 suites — **113 passed** (29 schema/taxonomy, 37 gateway lifecycle,
  16 intent audit, 17 verifier/tamper, 7 approval privacy/consumption, 4 audit/log
  privacy, plus e2e lifecycle).
- V70: pre-commit `bash scripts/check.sh` — PASS, exit 0, all 8 steps; 827 tests;
  Gitleaks 8.30.1 dir+git "no leaks found" (37 commits scanned); prohibited-pattern and
  constant-time-confinement checks clean.
- V71: post-commit `bash scripts/check.sh` after `0b60ba0`/`d53b0ed` and the memory
  commit — recorded in [../TESTING_AND_VERIFICATION.md](../TESTING_AND_VERIFICATION.md)
  and `docs/IMPLEMENTATION_STATE.md` (final status record).

## Next

Phase 8 — FastAPI integration and local model (blueprint §§7, 8, 18, §21 Phase 8):
authenticated `/v1/requests`, tool evaluate/execute, and approval-decision routes;
server-side request context and verified principal; ingress/input audit producers; agent
runtime + opt-in local-model provider; deadlines and basic per-principal rate limiting;
safe error envelopes and integration docs. See [../NEXT_SESSION.md](../NEXT_SESSION.md).
