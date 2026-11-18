# Incident-Response Runbooks (Phase 10)

These runbooks describe operational procedures for the ProtAI v1 platform. They are
read-only and alert-only: no runbook action invokes tools, changes policy, consumes
approvals, revokes sessions, or triggers containment.

## RB-1: Audit-Chain Verification

**Purpose:** Verify the integrity of the v1 audit hash chain.

**When to run:** On a regular schedule (e.g. daily), after any suspected tampering,
or as part of incident response.

**Procedure:**

1. Obtain a database session with read access to the `audit_events` table.
2. Run `verify_chain(session, chain_id="v1")` from `ai_security.audit.verifier`.
3. Examine the `AuditVerificationResult`:
   - `verified == True`: chain integrity confirmed for the observed snapshot.
   - `verified == False`: review each `AuditVerificationFailure` (code, sequence
     number, field). Codes include `SEQUENCE_DISCONTINUITY`,
     `PREVIOUS_HASH_MISMATCH`, `EVENT_HASH_MISMATCH`, `INVALID_PAYLOAD`,
     `NON_CANONICAL_PAYLOAD`, `METADATA_MISMATCH`.
4. If failures are found, preserve the database and escalate to security. Do not
   modify or delete audit rows.

**Limitations:** The verifier reads one consistent snapshot. Truncation of the
newest events is undetectable without an externally anchored checkpoint
(ADR-014). A database owner with sufficient privileges could rewrite the entire
chain consistently.

**Evidence:** Verifier failures are content-free (sequence numbers, field names,
failure codes only — no raw event content).

---

## RB-2: Alert Triage

**Purpose:** Triage `SECURITY_ALERT_RAISED` events emitted by deterministic alert
rules.

**When to run:** On alert emission, or during regular security monitoring.

**Procedure:**

1. Query the audit chain for `SECURITY_ALERT_RAISED` events (event_type filter).
2. For each alert, read the content-free evidence fields:
   - `risk_version`: rule ID
   - `risk_score`: observed count
   - `policy_version`: severity
   - `risk_factor_codes`: evidence tokens
3. Correlate with preceding `POLICY_EVALUATED`, `APPROVAL_DECIDED`, and
   `EGRESS_INSPECTED` events in the same window (by `request_id` and timestamp).
4. Determine the likely cause:
   - `repeated_blocked_calls`: possible probing or compromised agent
   - `repeated_approval_failures`: possible approver-boundary probing
   - `broad_resource_access`: possible privilege escalation
   - `burst_reads_across_resources`: possible bulk reading/scraping
   - `repeated_external_destination_attempts`: possible exfiltration
5. Record the triage decision. Alerts are hypotheses, not confirmed incidents.

**Authority:** Alert triage is read-only. Triage never blocks, allows, revokes, or
contains anything.

---

## RB-3: Denied-Request Investigation

**Purpose:** Investigate a specific denied tool call or rejected request.

**When to run:** On user report, alert correlation, or routine spot-check.

**Procedure:**

1. Identify the `request_id` from the alert, error response, or user report.
2. Query the audit chain for all events with that `request_id`.
3. Review the event sequence: `REQUEST_RECEIVED` → `PRINCIPAL_RESOLVED` /
   `PRINCIPAL_REJECTED` → `INPUT_INSPECTED` → `POLICY_EVALUATED` → ...
4. Identify the denial event (decision=`BLOCK` or disposition=`reject`) and read
   its `reason` code for the denial cause.
5. Confirm the denial was correct per policy. If incorrect, review the policy
   configuration (not the audit chain — audit is append-only).

**Authority:** Investigation is read-only. No changes to policy, audit, or
approvals are made during investigation.

---

## RB-4: Approval Abuse Investigation

**Purpose:** Investigate suspicious approval activity (repeated denials, expiries,
or unusual approver patterns).

**When to run:** On `repeated_approval_failures` alert or anomalous approval
patterns.

**Procedure:**

1. Query the audit chain for `APPROVAL_REQUESTED`, `APPROVAL_DECIDED`,
   `APPROVAL_CONSUMED`, and `APPROVAL_EXPIRED` events.
2. Filter by `request_id`, `principal_subject_id`, or `approver_subject_id` as
   relevant.
3. Review each decision's outcome (approved/denied) and reason code.
4. Check for: repeated denials by the same requester, expiries without decisions,
   consumption of approvals for unexpected actions.
5. Confirm all approvals were bound to the correct action digest, policy version,
   and principal.

**Authority:** Investigation is read-only. Approval revocation is not implemented
in v1; an abused approval simply expires (lazy expiry on next decide/consume).

---

## RB-5: DLP Findings Investigation

**Purpose:** Investigate data-leakage-prevention findings.

**When to run:** On `dlp_egress_blocked` or `dlp_inspection_failed` decision events,
or on DLP-related alerts.

**Procedure:**

1. Query the audit chain for events with `dlp` evidence attached
   (`EGRESS_INSPECTED`, `OUTPUT_INSPECTED`, `RESPONSE_RELEASED`,
   `RESPONSE_SUPPRESSED`).
2. Read the redacted DLP record: finding codes, categories, counts, field paths,
   max data class, outcome, destination.
3. Confirm no raw content was leaked (DLP audit records never contain matched
   text or raw arguments — see `docs/AUDIT_RETENTION_AND_DATA_HANDLING.md`).
4. If content may have been released before suppression, treat as a potential
   data incident and escalate.

**Authority:** DLP investigation is read-only. DLP findings never change policy or
approvals.

---

## RB-6: Provider / Database Outage

**Purpose:** Respond to provider or database outages that affect security controls.

**When to run:** On `503` responses, audit append failures, or database
connectivity errors.

**Procedure:**

1. Determine which dependency is down: PostgreSQL (audit/approval/nonce/session
   tables), or the optional local model provider (intent extraction only).
2. **Database outage:** The gateway fails closed — audit append failures on
   would-be `ALLOW` decisions yield `BLOCK`/`audit_unavailable` with no adapter
   call. Nonce-store failures yield `503` (never fail-open). No tool execution
   occurs while the database is unavailable.
3. **Provider outage:** Intent extraction yields no manifest; `/v1/requests`
   returns `503 model_unavailable` with no tool events. Policy enforcement is
   unaffected.
4. Restore the dependency. After database restoration, verify chain integrity
   (RB-1) before resuming normal operations.
5. Document the outage and any security-relevant observations.

**Authority:** Outage response is read-only/observational. No automated
containment or fail-open behavior exists.

---

## RB-7: Rollback

**Purpose:** Roll back a problematic configuration or deployment.

**When to run:** On configuration drift detected by readiness (503), or after a
failed deployment.

**Procedure:**

1. There is no policy hot-reload in v1. The process keeps its startup-loaded
   bundle; readiness detects file drift and returns 503.
2. To roll back: restore the previous policy/config files, restart the process,
   and confirm readiness returns 200.
3. Verify chain integrity (RB-1) after restart.
4. Confirm no unauthorized events occurred during the drift window (RB-3).

**Authority:** Rollback is an operational procedure performed by the platform
operator. No automated rollback exists.

---

## RB-8: Key Rotation / Incident Response

**Purpose:** Rotate host-auth keys or respond to a suspected key compromise.

**When to run:** On key compromise suspicion, scheduled rotation, or incident
response.

**Procedure:**

1. Generate a new host-auth key (32+ random bytes, strict Base64).
2. Add the new key to `HOST_AUTH_KEYS_JSON` with a new key ID.
3. Restart the process. Both old and new keys are accepted during the transition
   window (nonces are per-key).
4. After confirming all hosts use the new key, remove the old key from the
   configuration and restart again.
5. Replay rejection continues to work per-key: a nonce used with the old key
   cannot be reused with the new key (different key ID = different nonce store).

**Authority:** Key rotation is a configuration change performed by the platform
operator or security administrator. No automated rotation exists.

---

## General Principles

- **Read-only:** All runbook procedures read audit evidence and configuration.
  None write to the audit chain, modify policy, consume approvals, or trigger
  containment.
- **Content-free:** Audit evidence and alert events never contain raw user text,
  tool output, secrets, or exception messages.
- **Fail-closed:** Database or audit outages deny execution; they never fail open.
- **No containment:** v1 has no automated containment or circuit breaker. All
  response actions are manual and human-driven.
