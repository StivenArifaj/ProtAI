# ADR-012: Versioned risk v2 and durable, one-time human approvals

- **Status:** Accepted
- **Date:** 2026-10-26
- **Phase:** 5 (risk engine and approval workflow)
- **Blueprint:** §§11.3-11.4, 12.3, 13.1-13.3, 16.1, 20.2 #15/#20/#24, 21 (Phase 5)

## Context

Phase 2 introduced deterministic `risk-v1` scoring and returned `ASK_USER` as a typed
no-execution result. The platform still needed two Phase 5 capabilities:

1. a bounded, versioned risk extension that accounts for the breadth of a request
   without changing any existing `risk-v1` weight or threshold; and
2. a durable human-approval workflow that turns an engine `ASK_USER` into an
   execution opportunity without ever overriding a deterministic hard deny.

Approvals are security-sensitive in three ways. The token is a bearer secret that must
be stored only as a digest and accepted once. The decision must be bound to the exact
action, so changed arguments/resources/destination/policy cannot reuse it. The approver
must be a verified principal satisfying a startup-validated predicate; model output,
request text, or caller-supplied roles must never approve anything.

## Decision

### 1. `risk-v2` preserves `risk-v1` and adds one bounded factor

- `RISK_ENGINE_VERSION` becomes `risk-v2`. All prior weights are unchanged:
  side-effect base 0/10/15/100, external destination +10, data class 0/5/15/25, cap 100.
- A single resource-breadth factor is added from the number of distinct canonical
  target resources: 2-4 → +5, 5-8 → +10, 9+ → +15. `0`/`1` adds nothing, preserving
  every Phase 2 score for existing single-resource calls.
- Factor codes are stable (`breadth_2_to_4_resources`,
  `breadth_5_to_8_resources`, `breadth_9_or_more_resources`). Every factor carries a
  human-readable `rationale` in addition to its code and weight.
- `resource_count` is validated as an integer in `[0, 32]`; booleans, strings, floats,
  negatives, and out-of-range values raise `RiskScoringError`, which the gateway maps to
  `policy_evaluation_error` with no execution.
- Thresholds remain configuration, not code. Changing them still changes the combined
  policy hash, which invalidates previously bound approvals. Weight calibration remains
  Phase 9 work and is not claimed by this ADR.

### 2. Approver rules are a strict, non-scripting predicate

`required_approver_rule` uses the v1 grammar:

```text
rule        := alternative ("|" alternative)*
alternative := "role:" role-name | "principal:" subject-id
```

- Rules are at most 256 characters, reject control characters/empty alternatives/
  duplicate alternatives/unknown prefixes, and are parsed at registry startup so a
  malformed rule refuses startup.
- Evaluation uses only the server-resolved `Principal` (`subject_id`, `roles`) and the
  request tenant. No role, approver, or rule string is accepted from model output,
  request dialogs, or approval tokens.
- Self-approval is disabled by default. `ToolPolicy.self_approval_allowed` is valid only
  when `approval_eligible` is true, and a requester may approve their own request only
  when the policy explicitly enables it.
- A rule that lists only the requester as a specific principal, with self-approval
  disabled, is provably unsatisfiable; `ApprovalService.request` refuses to create it
  (`ApprovalNotApprovable`) rather than storing a permanently pending request. Role-only
  rules remain satisfiable because another role holder may exist.

### 3. Durable approval storage stores no raw action or secret

Migration `e5a1c2b3d4f6` adds `approval_requests` with:

- approval id (32 lowercase hex), tenant/requester, request/tool/action, canonical
  action digest, canonical resource ids, canonical destination;
- side-effect class, data class, risk score/version/factor codes, policy version/hash;
- approver rule, self-approval flag, status, created/expiry timestamps;
- SHA-256 token digest, decision/consumption timestamps, deciding subject/tenant;
- constraints on status, score range, and indexes for expiry and requester lookup.

No raw arguments, content, result data, or plaintext token is stored. The token is
256 bits from `secrets.token_urlsafe(32)`, returned only once in `ApprovalChallenge`, and
compared through the project constant-time helper (never direct `hmac.compare_digest`).

### 4. Decisions and consumption are transactional and one-time

`ApprovalRepository` owns the state machine (`pending` → `approved`/`denied` →
`consumed`, or `expired`), and every transition commits with its audit event in the same
PostgreSQL transaction using `AuditChainRepository.append_in_session`:

- `create` inserts the pending row and `APPROVAL_REQUESTED`;
- `decide` locks the row (`SELECT ... FOR UPDATE`), checks pending/expiry/token digest,
  evaluates the stored rule against the verified approver, applies tenant and
  self-approval checks, then records `APPROVAL_DECIDED` with allow/deny semantics;
- `consume` locks the row, verifies requester/tenant/request/tool/action/canonical digest/
  resource set/destination/policy version/hash, moves `approved` → `consumed`, and
  appends `APPROVAL_CONSUMED` in the same transaction.

Concurrent consumers serialize; exactly one observes `approved` and succeeds, others
receive `replay`. A pending or approved request past `expires_at` transitions to
`expired` on the next decide/consume and appends `APPROVAL_EXPIRED`; a pending request can
never be consumed. Default TTL is 900 s, bounded to 60-86,400 s; timestamps must be
timezone-aware.

### 5. The gateway treats approval as an execution gate, not policy authority

- Approval is consulted only for an engine `ASK_USER` and only when the caller presents
  an `approval_id`. `ALLOW` executes without approval; `BLOCK`/hard denials ignore any
  approval and never consume it.
- For an approval attempt, the gateway re-derives validated arguments/resources/
  canonical destination, recomputes the canonical action digest (which includes the
  policy combined hash), and atomically consumes a matching approved request before any
  execution. Derived resource ids are validated and deduplicated in first-occurrence
  order, so the digest, stored approval, breadth factor, and audit event all bind the
  same distinct target set. The approval record's decision metadata is attached to
  gateway audit events and the typed result.
- The engine decision remains `ASK_USER`; the human grant only makes that exact action
  executable once. Approval cannot create an `ALLOW`, cannot change policy facts, and
  cannot bypass a hard constraint.
- Failure mapping is fail-closed: pending/denied/expired/replayed/mismatched/not-found/
  malformed or unavailable storage → `BLOCK` with `approval_invalid`,
  `approval_denied`, or `approval_expired`; no adapter is invoked. If approval storage
  raises, the gateway logs the tool id (no secrets) and blocks.
- Audit events use `firewall.approval` for request/decision/consumption/expiry, and the
  gateway's decision/outcome events carry `approval_id`/`approver_subject_id`. Approval
  audit semantics use `ALLOW` for granted/consumed and `BLOCK` for denied/expired, while
  the gateway's own `ASK_USER` decision is preserved.

### 6. Wiring and non-goals

The app builds `ApprovalRepository` over the same audit chain as the gateway and exposes
`ApprovalService` on `app.state`; `APPROVAL_TTL_SECONDS` (default 900, 60-86,400) is
validated at startup. The gateway receives the service so production calls can present
an approval id.

Not in Phase 5:

- no `/v1/approvals` routes, UI, notification channel, or token delivery transport;
- no automatic request creation inside the gateway (Phase 8 request workflow must call
  `ApprovalService.request` with host-verified action facts);
- no real approver directory or revocation endpoint (deny/expiry/consume are the v1
  transitions);
- no background expiry sweeper (expiry is applied lazily on decide/consume);
- no risk-weight calibration (Phase 9) and no approval exception for hard denials.

## Consequences

- Existing single-resource scores are unchanged; multi-resource requests gain bounded
  risk and visible rationale without a new authority path.
- Approvals survive process restarts and are exactly-once under concurrency, but only
  when the database is available; storage outage fails closed.
- A consumed approval is burned even if a later audit or adapter failure prevents
  execution; operators must issue a new request. This is deliberate to avoid replay.
- The workflow is only as strong as the trusted host that requests decisions and the
  resolver's role facts; it is not a defense against malicious in-process code or a
  compromised database (Phase 10 boundary).
- If an adapter's registration facts change without a policy/threshold change, the
  combined policy hash may not change; operators should rotate policy version/hash when
  changing registrations. This is documented as a Phase 5 limitation.

## Verification

- `tests/unit/test_approver_rules.py` — grammar, eligibility, self-approval rules.
- `tests/unit/test_risk_engine.py` — all `risk-v1` weights, breadth boundaries, rationale,
  invalid counts, cap/version.
- `tests/unit/test_policy_models.py`, `tests/unit/test_tool_registry.py` — policy flag
  consistency and startup rule validation.
- `tests/integration/test_approval_flow.py` — real-PostgreSQL creation/decision/
  consumption, digest-only storage, one-time/replay, mutation, expiry, denial,
  self-approval/eligibility, concurrent exactly-one-winner, audit transaction linkage.
- `tests/integration/test_gateway_approval.py` — real-PostgreSQL gateway ASK_USER gating,
  approved execution metadata, pending/denied/mismatch/expiry/replay no-execution,
  engine `BLOCK` ignoring and not consuming approvals.
- `tests/security/test_gateway_no_bypass.py` — approval absent/granted/non-granted/error
  and hard-deny precedence, with sink counts unchanged on every denied path.
- `tests/unit/test_settings.py`, `tests/integration/test_gateway_wiring.py` — TTL bounds
  and app/gateway wiring.
- Fresh full suite and 8/8 gate evidence in `project_memory/TESTING_AND_VERIFICATION.md`
  (V57+).

## References

- Blueprint v1.2 §§11.3-11.4, 12.3, 13.1-13.3, 16.1, 20.2, 21 (Phase 5).
- ADR-002 (audit chain), ADR-008 (policy engine), ADR-009 (registry/gateway), ADR-011
  (intent manifests).
- `src/ai_security/firewall/{risk_engine,approval,gateway}.py`,
  `src/ai_security/identity/approver_rules.py`,
  `src/ai_security/persistence/{approval_repository,models}.py`,
  `migrations/versions/e5a1c2b3d4f6_approval_requests.py`.
