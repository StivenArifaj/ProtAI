# Phase 5 — Risk Engine and Approval Workflow: COMPLETE — VERIFIED

**Completed:** 2026-10-26
**Blueprint:** v1.2 §§11.3-11.4, 12.3, 13.1-13.3, 16.1, 20.2 #15/#20/#24, §21 Phase 5
**ADR:** [../../docs/adr/ADR-012-risk-v2-and-human-approvals.md](../../docs/adr/ADR-012-risk-v2-and-human-approvals.md)
**Evidence:** V57-V62 in [../TESTING_AND_VERIFICATION.md](../TESTING_AND_VERIFICATION.md)
**Commits:** `ad9e76a` (implementation/tests/migration), `0b2f1c9` (ADR-012/docs),
`8cce014` (memory/completion); final V62 status record commit follows.

## Definition of Done — verdict

| Criterion | Status | Evidence |
|---|---|---|
| Risk calculations are unit tested | PASS | `test_risk_engine.py` (30): every `risk-v1` weight preserved, breadth boundaries 0/1/2/4/5/8/9+, cap/version, stable rationale/codes, invalid counts (bool/str/float/negative/oversize), single-resource scores unchanged |
| Hard denies cannot be overridden | PASS | `test_gateway_no_bypass.py` and `test_gateway_approval.py`: a presented valid approval on `BLOCK`/hard deny is ignored, not consumed; zero adapter calls; sink unchanged |
| Mutation/replay/expiry prove no unauthorized execution | PASS | Canonical digest recomputation + resource/destination/policy version/hash verification; real-PostgreSQL mutation, replay, pending, denial, expiry; `test_gateway_approval.py` no-execution matrix |
| One-time/atomic under concurrency | PASS | `SELECT ... FOR UPDATE` decisions/consumption; five concurrent consumers yield one `consumed` + four `replay`; same-transaction audit events |
| Verified approver; no default self-approval | PASS | Strict `role:`/`principal:` grammar at startup; tenant equality; self-approval only with explicit policy; requester-only unsatisfiable rules refused before storage |
| No secrets/raw content stored or logged | PASS | 256-bit token returned once, only SHA-256 stored; approval rows carry canonical facts/provenance, never arguments/content; redacted payload tests |
| Execution only via gateway; policy remains sole `ALLOW` | PASS | Approval only makes an engine `ASK_USER` executable once; `ALLOW` needs none; `BLOCK` dominates; single `invoke_tool` chokepoint unchanged |
| Full quality gate | PASS | V57-V58: 734 tests, 8/8 gate steps, mypy 63 files, Gitleaks clean |
| ADR-008/009/010/011 contracts untouched | PASS | Policy, gateway, detector, and intent boundaries intact; all prior suites green |

## Delivered

### Risk v2 (`src/ai_security/firewall/risk_engine.py`)

- `RISK_ENGINE_VERSION = "risk-v2"`; every `risk-v1` factor/weight retained.
- One bounded breadth factor over distinct canonical resources: 2-4 → +5, 5-8 → +10,
  9+ → +15; 0/1 adds nothing; total capped at 100.
- Stable codes (`breadth_2_to_4_resources`, `breadth_5_to_8_resources`,
  `breadth_9_or_more_resources`) plus human-readable rationale on every factor.
- `resource_count` is a strict integer in `[0, 32]`; invalid values raise
  `RiskScoringError` → gateway `policy_evaluation_error` with no execution.
- Derived resource ids are validated and deduplicated in first-occurrence order before
  scoring, action digest, authorization, and audit, so duplicate argument values cannot
  inflate risk or violate the approval uniqueness contract.

### Approver rules (`src/ai_security/identity/approver_rules.py`)

- Strict v1 grammar `role:<role>` / `principal:<subject>` with `|` alternatives; max 256
  characters; no empty/duplicate alternatives, control characters, or unknown prefixes.
- Parsed at registry startup; malformed rules refuse startup.
- Evaluation uses only the verified `Principal` (`subject_id`, `roles`) and requires
  tenant equality. No rule/role/approver input comes from model output or request text.
- Self-approval is default-deny and requires `ToolPolicy.self_approval_allowed`, which is
  valid only with `approval_eligible`.
- A requester-only principal rule with self-approval disabled is refused before storage
  (`ApprovalNotApprovable`); role-only rules remain potentially satisfiable.

### Durable approval workflow

- Migration `e5a1c2b3d4f6` adds `approval_requests` with approval id, tenant/requester,
  request/tool/action, canonical action digest, resources, destination, side-effect/data
  class, risk provenance, policy version/hash, approver rule, self-approval flag, status,
  expiry, SHA-256 token digest, decision/consumption metadata, and status/score
  constraints plus expiry/requester indexes.
- `ApprovalService.request` returns a 256-bit token once (`secrets.token_urlsafe(32)`) and
  stores only its SHA-256 digest; IDs are 32 lowercase hex; TTL default 900 s, bounded
  60-86,400 s.
- `ApprovalRepository.decide` locks the row, checks pending/expiry/token, evaluates the
  stored rule against the verified approver, applies tenant/self-approval checks, and
  appends `APPROVAL_DECIDED` in the same transaction.
- `ApprovalRepository.consume` locks the row, verifies requester/tenant/request/tool/
  action/canonical digest/distinct resources/destination/policy version+hash, moves
  `approved` → `consumed` exactly once, and appends `APPROVAL_CONSUMED` in the same
  transaction.
- Pending or approved rows past expiry transition to `expired` on the next
  decide/consume and emit `APPROVAL_EXPIRED`; pending rows can never be consumed.
- Statuses: `pending|approved|denied|consumed|expired`; denied/expired/replayed rows never
  execute.

### Gateway and app changes

- `firewall/decision.py`: `approval_granted`, `approval_denied`, `approval_expired`,
  `approval_invalid`.
- `firewall/models.py`: typed result metadata `approval_id` / `approver_subject_id`.
- `firewall/gateway.py`: approval is consulted only for engine `ASK_USER` with a presented
  `approval_id`; re-derives arguments/resources/canonical destination; recomputes the
  canonical action digest (including combined policy hash); atomically consumes a matching
  approved record before execution. `ALLOW` needs no approval; `BLOCK`/hard denials ignore
  one and do not consume it. Failures map to `approval_invalid`, `approval_denied`, or
  `approval_expired` with no adapter call; storage errors log only the tool id and fail
  closed. Failure results now retain approval metadata.
- `api/app.py`: builds `ApprovalRepository` over the same audit chain and exposes
  `ApprovalService` on `app.state`; injects it into the gateway.
- `settings.py` / `.env.example`: `APPROVAL_TTL_SECONDS` default 900, bounded 60-86,400.
- `audit/models.py`: `firewall.approval` request/decision/consumption/expiry events;
  gateway decision/outcome events carry `approval_id`/`approver_subject_id`.
- `persistence/audit_repository.py`: `append_in_session` for same-transaction audit.

### Tests

- `tests/unit/test_risk_engine.py` — v1 parity, v2 breadth boundaries, rationale/codes,
  invalid counts, cap/version.
- `tests/unit/test_approver_rules.py` — grammar, alternatives, limits/control chars,
  duplicates, verified-principal evaluation, tenant/self-approval/unsatisfiable rules.
- `tests/unit/test_policy_models.py` / `test_tool_registry.py` — self-approval flag
  consistency and startup rule validation.
- `tests/integration/test_approval_flow.py` — real-PostgreSQL creation/decision/
  consumption, digest-only storage, one-time/replay, mutation, pending/approved expiry,
  denial, eligibility/self-approval, five-way concurrency, same-transaction audit.
- `tests/integration/test_gateway_approval.py` — real-PostgreSQL gateway ASK_USER gating,
  approved execution metadata, pending/denied/mismatch/expiry/replay no-execution, BLOCK
  ignoring/no-consumption.
- `tests/security/test_gateway_no_bypass.py` — approval absent/granted/non-granted/
  storage-error and hard-deny precedence; sink counts unchanged on every denied path.
- `tests/unit/test_gateway.py` — duplicate derived resource-id dedup regression.
- `tests/unit/test_settings.py` / `tests/integration/test_gateway_wiring.py` — TTL bounds
  and app/gateway/approval-service wiring.

Totals: **734 passed** (613 unit + 80 integration + 41 security).

## Decisions and limitations (honest)

- No `/v1/approvals` routes, approval UI, or token-delivery transport; the service is
  in-process for the Phase 8 host workflow.
- The gateway does not create approval requests automatically; Phase 8 must call
  `ApprovalService.request` with host-verified action facts.
- No approver directory, notification channel, revocation operation, or background
  expiry sweeper; expiry is lazy on decide/consume.
- Role rules trust the resolver's role membership; a compromised resolver or database is
  outside this phase's boundary (Phase 10).
- Consuming an approval burns it even if a later audit/adapter failure prevents
  execution (deliberate anti-replay behavior).
- An adapter registration change that does not change the policy/threshold files does not
  change the combined policy hash; rotate policy version/hash when registration facts
  change.
- Risk weights remain uncalibrated and factor coverage is still small (no identity/
  session/history factors); calibration is Phase 9. Thresholds remain 40/80.
- Approval/resource ids are a flat string set; two different argument namespaces with the
  same textual id collapse to one target. Stable ids are expected to be globally
  meaningful; this is a documented v1 simplification.

## Verification (V57-V62)

- V57: full suite — **734 passed** (613 unit + 80 integration + 41 security).
- V58: `bash scripts/check.sh` — exit 0, 8/8 steps; mypy 63 source files; Gitleaks
  8.30.1 dir+git clean across 27 commits.
- V59: targeted Phase 5 suites — **157 passed** (approval lifecycle/gateway/risk/rules/
  settings/no-bypass/wiring/migration).
- V60: Alembic `upgrade head` → `downgrade -1` → `upgrade head` → `check` — clean,
  single head `e5a1c2b3d4f6`.
- V61: dedup regression — 1 passed (duplicate derived resource ids collapse before
  risk/digest/audit).
- V62: post-commit gate — PASS, exit 0, all 8 steps; 734 tests, mypy 63 source files,
  Gitleaks 8.30.1 dir+git clean across 30 commits.

## Next

Phase 6 — output DLP and egress policy (blueprint §21): see
[../NEXT_SESSION.md](../NEXT_SESSION.md).
