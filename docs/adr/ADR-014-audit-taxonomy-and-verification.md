# ADR-014: Audit taxonomy, correlation metadata, and exact-bytes verification

- **Status:** Accepted
- **Date:** 2026-10-26
- **Phase:** 7 (audit persistence and verification)
- **Blueprint:** §§16.1-16.4, 20.2 #12/#13/#14/#19, 21 (Phase 7)
- **References:** ADR-002 (hash chain and canonical bytes), ADR-008 (policy engine),
  ADR-009 (gateway), ADR-010 (input defense), ADR-011 (intent manifests), ADR-012
  (approvals), ADR-013 (output DLP)

## Context

Through Phase 6, the audit chain stored the correct ADR-002 bytes but exposed only three
event types (`POLICY_EVALUATED`, execution outcome, approval lifecycle) plus an optional
nested `dlp` record. That is insufficient for the Phase 7 definition of done:

1. a complete request-to-tool sequence must be reconstructable and correlatable;
2. mutation/reordering of stored events must be detectable;
3. raw secrets and full private payloads must be absent from default logs and audit
   records.

The blueprint (§16.1) names a larger event taxonomy and requires queryability. At the
same time, ADR-002 fixes the hash formula over the exact stored `canonical_event_bytes`;
any change that rewrites historical bytes or the formula would invalidate every existing
chain. The design therefore separates **authoritative payload bytes** from **derived
queryable columns** and treats schema evolution as additive.

## Decision

### 1. Stable event taxonomy with conditional required fields

`AuditEventType` now contains every §16.1 name:

`REQUEST_RECEIVED`, `PRINCIPAL_RESOLVED`, `PRINCIPAL_REJECTED`, `INPUT_INSPECTED`,
`INTENT_CREATED`, `INTENT_FAILED`, `TOOL_CALL_PROPOSED`, `POLICY_EVALUATED`,
`APPROVAL_REQUESTED`, `APPROVAL_DECIDED`, `APPROVAL_EXPIRED`,
`TOOL_EXECUTION_STARTED`, `TOOL_EXECUTION_COMPLETED`, `TOOL_EXECUTION_FAILED`,
`EGRESS_INSPECTED`, `OUTPUT_INSPECTED`, `RESPONSE_RELEASED`, `RESPONSE_SUPPRESSED`,
`SECURITY_ALERT_RAISED`, plus `APPROVAL_CONSUMED` (required by §§13.2-13.3 and already
stable since Phase 5).

The schema stays at `schema_version=1` (pre-release, additive evolution). Rather than
inventing values for fields that do not apply, required fields are **event-type
conditional**:

- `principal_subject_id` is required for every event except `PRINCIPAL_REJECTED` (where
  the subject may be unknown);
- `tool_id`/`action_id` are required only for tool-scoped events;
- `decision`/`reason` are required only for decision events (and must be supplied
  together everywhere);
- `outcome` is required only for execution/response status events, with
  event-specific allowed values:
  - `TOOL_EXECUTION_COMPLETED` → `EXECUTED`;
  - `TOOL_EXECUTION_FAILED` → `ADAPTER_FAILED`/`TIMEOUT`/`RESULT_REJECTED`;
  - `RESPONSE_RELEASED` → `EXECUTED` plus an OUTPUT DLP record and result digest;
  - `RESPONSE_SUPPRESSED` → `RESPONSE_BLOCKED` plus an OUTPUT DLP record and result
    digest;
  - `TOOL_EXECUTION_STARTED` must not carry an outcome;
- `EGRESS_INSPECTED` requires an EGRESS `DlpAuditRecord`; `OUTPUT_INSPECTED` requires an
  OUTPUT record.

`to_payload()` still omits `None` values, so an event never contains invented
placeholders. Unknown fields are refused (`extra="forbid"`).

`PRINCIPAL_RESOLVED`/`PRINCIPAL_REJECTED`, `INPUT_INSPECTED`, and
`SECURITY_ALERT_RAISED` are defined but have **no producer yet**; they belong to the
Phase 8 HTTP ingress and Phase 10 alerting work. Phase 7 does not fake them.

### 2. Producers emit only events for work that actually occurred

The gateway lifecycle is mandatory and ordered:

```text
REQUEST_RECEIVED
TOOL_CALL_PROPOSED
EGRESS_INSPECTED            (when argument inspection runs)
POLICY_EVALUATED
APPROVAL_CONSUMED           (standalone, committed by the approval repository when granted)
TOOL_EXECUTION_STARTED
TOOL_EXECUTION_COMPLETED | TOOL_EXECUTION_FAILED
OUTPUT_INSPECTED            (when a result exists to inspect)
RESPONSE_RELEASED | RESPONSE_SUPPRESSED
```

Denials stop at the event that explains them (for example a binding denial ends after
`POLICY_EVALUATED`; an unknown tool ends after `TOOL_CALL_PROPOSED` and its decision).
The intent service emits `INTENT_CREATED` or `INTENT_FAILED` when a recorder is
configured; that instrumentation is best-effort and can never grant authority.

Each mandatory pre-execution event is a gate. If it cannot be durably appended, the
gateway returns `BLOCK`/`audit_unavailable`/`DENIED` and no adapter runs. If a mandatory
post-execution event cannot be appended, the side effect has already happened, so the
gateway returns `AUDIT_FAILED` and withholds the result. `TOOL_EXECUTION_COMPLETED`
always carries `EXECUTED`; a DLP suppression after execution is represented separately by
`RESPONSE_SUPPRESSED` with `RESPONSE_BLOCKED`, not by rewriting the execution event.

### 3. Queryable metadata is derived, never authoritative

The `audit_events` table gains nullable columns `event_type`, `request_id`, `trace_id`,
`call_id`, `occurred_at`, and `component`, with indexes for correlation. The single
append repository extracts them from the exact payload it is about to hash and stores
them alongside the bytes. The migration (`f7a8b9c0d1e2`) backfills historical rows from
`convert_from(canonical_event_bytes, 'UTF8')::jsonb` without rewriting bytes or hashes.

The verifier checks that non-null metadata columns agree with the parsed payload. Metadata
is therefore a performance/query convenience: changing it is detectable, and the hashed
bytes remain the only authoritative record. A correlation query is by `request_id`
(always present); `trace_id` is optional and propagated when available; `call_id` is
carried on gateway/tool events where a call exists (approval lifecycle events do not
invent one).

### 4. Verifier scope and honest limits

`verify_chain(session, chain_id=..., max_failures=...)` reads one chain in a **single
`SELECT`** (a consistent snapshot) ordered by sequence and checks:

1. sequence starts at 1 and is contiguous;
2. each `previous_hash` equals the preceding stored `event_hash`, with the 32-zero-byte
   genesis for sequence 1;
3. the ADR-002 event hash recomputed from the **exact stored `canonical_event_bytes`**
   equals the stored `event_hash`;
4. the stored bytes are the canonical JSON form of their parsed payload;
5. metadata columns agree with that payload.

Failures are typed (`SEQUENCE_DISCONTINUITY`, `MALFORMED_HASH`,
`PREVIOUS_HASH_MISMATCH`, `EVENT_HASH_MISMATCH`, `INVALID_PAYLOAD`,
`NON_CANONICAL_PAYLOAD`, `METADATA_MISMATCH`), bounded by `max_failures`, and never
contain payload content. Each row's event hash is recomputed from its own stored
`previous_hash`, so tampering row N yields its own failure plus a separate linkage failure
at N+1 rather than masking one with the other.

A plain local chain is **tamper-evident, not tamper-proof**. Removing or rewiring the
newest events (truncation) cannot be detected without an externally anchored checkpoint
(head hash + sequence). No external anchor is deployed in Phase 7; this limitation is
tested and documented rather than hidden.

### 5. First-class DLP events

DLP evidence moves from an optional marker on unrelated events to first-class
`EGRESS_INSPECTED`, `OUTPUT_INSPECTED`, `RESPONSE_RELEASED`, and `RESPONSE_SUPPRESSED`
events. The record remains redacted: stable finding code/category/count, bounded
control-character-free field paths, config version/hash, content digest/size,
truncation/error flags, destination trust facts, and (for release/redaction)
`released_digest`. It never contains matched text, raw arguments, result bodies, or
exception messages. `POLICY_EVALUATED` and execution events no longer duplicate the DLP
record.

### 6. Privacy and log hygiene

Audit payloads and default logs carry identifiers, decisions, provenance, digests, sizes,
and typed error class names only. Exception messages are never logged or audited. Intent
audit records the resolution status/error code, not the request text or goal. The privacy
suite feeds canary, email, credential, private-key, and API-key shapes through the
gateway, adapter-failure, result-suppression, and intent paths and asserts the raw values
are absent from serialized events and captured DEBUG logs.

### 7. Schema-evolution rule

Within `schema_version=1` and before the first production release:

- new event types may be added;
- a previously mandatory field may become event-type-conditional;
- optional fields may be added;
- existing payloads remain valid and the hash formula over stored bytes never changes.

Renaming/removing event types, changing the canonical JSON form, or changing the hash
input requires a new schema version and a new ADR. Historical rows are never rewritten.

## Consequences

- Every handled request now has a complete, correlated sequence (request receipt →
  proposal → inspection → decision → execution → inspection → response), queryable by
  `request_id` without parsing JSON.
- Audit unavailability is a hard stop before execution and result withholding after it;
  availability failures cannot silently produce an unaudited action or response.
- The append repository writes more columns, but the authoritative bytes and ADR-002
  formula are untouched; the migration is non-destructive.
- Verifier runs are O(chain length) and bounded in retained failures; very large chains
  will eventually need streaming/batching or an external anchor.
- Truncation remains undetectable locally; operators must add an external checkpoint
  before claiming full tamper evidence against a database owner.
- Producers that do not exist yet must not emit placeholder events; the taxonomy being
  defined is not a claim that every event is produced.
- Log privacy depends on continued discipline: only stable codes/class names may be
  logged, and new adapter errors must not interpolate exception text.

## Verification

- `tests/unit/test_audit_schema.py` — full taxonomy membership, conditional
  principal/tool/decision/outcome requirements, DLP phase binding, canonical payload
  shape, `call_id` validation, extra-field rejection.
- `tests/unit/test_gateway.py` — exact 8-event allowed-read sequence and correlation,
  egress-denial sequence, inspection-failure sequence, policy-error sequence, adapter
  failure/timeout/result-rejection events, and the parametrized matrix proving every
  mandatory lifecycle append failure either denies before execution or withholds the
  result.
- `tests/unit/test_intent_service.py` — `INTENT_CREATED`/`INTENT_FAILED` without text,
  stable error codes, and an audit outage that changes neither resolution nor authority.
- `tests/integration/test_audit_verifier.py` — untampered/empty chains, payload and hash
  mutation, reordering, deletion, truncation limitation, non-canonical/invalid JSON,
  malformed hashes, metadata tampering, concurrent writers, bounded failures, and
  chain isolation.
- `tests/integration/test_gateway_end_to_end.py` / `test_gateway_approval.py` — durable
  lifecycle order, hash linkage, metadata projection, approval-token/content privacy.
- `tests/security/test_audit_privacy.py` — raw canary/email/credential/private-key/API-key
  values absent from audit payloads and DEBUG logs on egress, adapter-failure,
  response-suppression, and intent paths.
- Fresh suite and 8/8 gate evidence in `project_memory/TESTING_AND_VERIFICATION.md`
  (V67+).

## References

- Blueprint v1.2 §§16.1-16.4, 20.2 #12-#14/#19, 21 (Phase 7).
- ADR-002 (exact canonical bytes, hash formula), ADR-009 (gateway lifecycle),
  ADR-013 (DLP semantics preserved).
- `src/ai_security/audit/{models,verifier}.py`,
  `src/ai_security/persistence/{models,audit_repository}.py`,
  `src/ai_security/firewall/{gateway,approval}.py`,
  `src/ai_security/intent/service.py`,
  `migrations/versions/f7a8b9c0d1e2_audit_event_metadata.py`,
  `docs/AUDIT_RETENTION_AND_DATA_HANDLING.md`.
