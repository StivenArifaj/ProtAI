# Audit retention and data handling

Status: **Phase 7 (audit persistence and verification), 2026-10-26.** This document
describes what the audit chain stores, what it deliberately does not store, how operators
should retain, export, back up, and delete it, and which integrity guarantees are and are
not provided. See ADR-002 (hash chain), ADR-014 (taxonomy, correlation, verifier), and
blueprint §16.3.

## 1. What is stored

Each event is one row in `audit_events`. The authoritative record is
`canonical_event_bytes` (the exact canonical JSON hashed by ADR-002). Queryable metadata
columns are derived from those bytes and are verifier-checked against them.

### 1.1 Envelope (every event)

| Field | Meaning |
|---|---|
| `schema_version` | Audit schema version (`1`) |
| `event_id` | Random 128-bit identifier (`32` lowercase hex chars) |
| `event_type` | Stable name from the §16.1 taxonomy (plus `APPROVAL_CONSUMED`) |
| `occurred_at` | UTC timestamp |
| `component`, `component_version` | Producer (`firewall.gateway`, `firewall.approval`, `intent.service`) and its version |
| `request_id` | Server-assigned correlation key (required) |
| `trace_id`, `session_id` | Optional correlation identifiers when available |
| `principal_subject_id` | Verified subject; omitted only for `PRINCIPAL_REJECTED` |
| `policy_version`, `policy_hash` | Policy provenance used for the decision |

### 1.2 Action, decision, and result facts (when applicable)

- `call_id`, `tool_id`, `action_id`;
- `decision` (`ALLOW`/`BLOCK`/`ASK_USER`) and stable `reason`;
- `side_effect_class`, effective `data_class`;
- `risk_score`, `risk_version`, bounded `risk_factor_codes`;
- canonical `destination` and stable `resource_ids`;
- `approval_id` and `approver_subject_id` (never the approval token or its digest);
- `duration_ms`, `result_digest` (SHA-256), `result_bytes`;
- `error_type` (exception **class name** only);
- `outcome` with event-specific allowed values;
- redacted DLP evidence on `EGRESS_INSPECTED`, `OUTPUT_INSPECTED`,
  `RESPONSE_RELEASED`, and `RESPONSE_SUPPRESSED`: phase, outcome, egress reason, effective
  class, stable finding code/category/count, bounded field paths, config version/hash,
  content digest/size, truncation/inspection flags, destination trust facts, and
  `released_digest` for redacted releases.

Storage-only columns: `id`, `chain_id`, `sequence_number`, `previous_hash`, `event_hash`,
`created_at`, plus the derived metadata columns `event_type`, `request_id`, `trace_id`,
`call_id`, `occurred_at`, and `component`. The derived columns are indexed for
correlation; the hashed bytes are authoritative.

## 2. What is deliberately excluded

The following are **never** written to audit payloads, the derived columns, or default
logs:

- raw prompts, request text, goals, message bodies, file contents, or tool results;
- tool arguments or their values (only identifiers/digests/sizes are recorded);
- matched DLP text, redaction markers, or the content that produced a finding;
- exception messages or stack traces (only the exception class name);
- approval tokens, token digests, or any bearer secret;
- host HMAC secrets, API keys, private keys, credentials, or database URLs;
- model/provider raw output (no model path exists yet);
- free-text notes, justifications, or reviewer comments.

`AUDIT_RAW_CONTENT_MODE=never` in `.env.example` documents the fixed operating rule; the
application does not read it as a switch, and **no configuration or runtime flag can
enable raw-content capture**. Adding one would require an ADR and a privacy review.

The intent service audits the resolution status and a stable error code, never the
request text or extracted goal. Approval rows store only canonical action facts and a
SHA-256 token digest; the one-time token is returned to the caller and never persisted or
audited.

## 3. Default diagnostic capture

- Application logging defaults to `INFO`; tests capture at `DEBUG` to prove no leakage.
- Log statements name a tool id, component, or exception **class**, never payload text,
  exception messages, secrets, or identifiers beyond request/tool correlation ids.
- No request/response body logging, no SQL echo of parameters, and no analytics/telemetry
  export exist.
- Readiness responses expose booleans and policy provenance only.

## 4. Retention and ownership

Recommended v1 operating policy (not yet automated):

- **Owner:** the deploying organization's security operations function owns the audit
  database and its backups. The application has append access only in normal operation;
  the verifier has read access.
- **Retention:** keep audit events at least as long as the organization's incident
  response and compliance obligations require (commonly 90 days hot, 1 year warm). The
  code does not enforce a retention period; deletion is an operator action.
- **Growth:** the nonce, session, approval, and audit tables grow until an operator
  prunes them. There is no scheduled retention/expiry sweeper in Phase 7.
- **Segregation:** audit data should live on storage with access controls appropriate to
  security telemetry. It contains identifiers, decisions, and metadata — not content —
  but identifiers and access patterns are still sensitive.

## 5. Deletion, backup, and export

- **Deletion is destructive to verifiability.** Deleting middle events produces
  `SEQUENCE_DISCONTINUITY` and `PREVIOUS_HASH_MISMATCH`. Deleting the newest events
  leaves a shorter chain that still verifies; without an external anchor it cannot be
  distinguished from a legitimate earlier end (see §6). If records must be removed,
  export and checkpoint the chain head first, document the deletion, and re-anchor.
- **Backups** must preserve `canonical_event_bytes`, all hash fields, `chain_id`, and
  `sequence_number` byte-for-byte. A restore that rewrites JSON or timestamps breaks
  verification. Backups should be encrypted and access-controlled like the live table.
- **Export** should select the stored columns (especially the exact bytes and hash
  fields), not a reconstructed ORM/JSON projection. Include the verifier result and the
  observed head hash/sequence with every export so the recipient can anchor it.
- **Archival** may move rows to another store, but keep them verifiable as a chain; a
  partial archive that splits a chain needs its own external checkpoint and documented
  boundary.
- **No automatic purge** is implemented. Any future purge must be an explicit,
  audited administrative action, not a side effect of application traffic.

## 6. Integrity guarantees and honest limits

Provided:

- every append is serialized per chain (transaction-scoped advisory lock + unique
  `(chain_id, sequence_number)`);
- each event hash covers `chain_id`, `sequence_number`, `previous_hash`, and the exact
  canonical bytes (ADR-002);
- `verify_chain` recomputes hashes from the **stored bytes** and checks sequence
  contiguity, previous-hash linkage, canonical form, and derived metadata agreement;
- mutation, reordering, and middle deletion are detected (tested).

**Not** provided:

- **Tamper-proofing.** A database owner can rewrite the entire chain consistently from
  genesis and produce a different valid chain. Hash chains without an external anchor are
  tamper-*evident* only relative to a trusted checkpoint.
- **Truncation detection.** Removing the newest event(s) cannot be detected locally;
  the remaining chain verifies. Deploy an external head checkpoint (separate store,
  transparency log, or signed daily digest) before claiming detection of newest-event
  deletion.
- **Confidentiality.** Hashes and metadata are not encrypted by the application; protect
  the database and backups with infrastructure controls.
- **Availability.** If the database is unavailable, the gateway fails closed: it does not
  execute or release results when a mandatory event cannot be appended.
- **Non-repudiation.** Events record a verified principal subject as asserted by the
  host/resolver; they are not digitally signed per event.

## 7. Verifier operation

```text
verify_chain(session, chain_id="v1", max_failures=100)
```

The verifier reads one consistent snapshot in a single `SELECT`, returns typed,
content-free failures with sequence numbers, and is side-effect free (it never repairs or
rewrites rows). Run it on a schedule and after restores, exports, or suspected incidents.
Record the returned `head_sequence`/`head_hash` in an external checkpoint to gain
truncation detection.

## 8. Incident handling

1. Stop writes to the affected chain if active tampering is suspected (fail-closed
   gateway behavior already withholds actions/results on audit failure).
2. Preserve the database and backups; do not "fix" rows.
3. Run the verifier and export its typed result plus the observed head.
4. Compare against external checkpoints/backups to bound what changed and when.
5. Treat absence of a mandatory event as a control failure, not as a logging gap.

## References

- Blueprint v1.2 §16.1-16.4, §20.2 #12-#14/#19, §21 Phase 7.
- ADR-002 (hash chain and exact canonical bytes), ADR-014 (taxonomy, metadata, verifier).
- `src/ai_security/audit/{models,verifier}.py`,
  `src/ai_security/persistence/audit_repository.py`,
  `src/ai_security/persistence/models.py`.
