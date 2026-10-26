# Phase 5 Plan — Risk engine and approval workflow

**Status: COMPLETE** (2026-10-26).

**Blueprint:** v1.2 §§11.3-11.4, 12.3, 13.1-13.3, 16.1, 20.2 #15/#20/#24, §21 Phase 5.

## Goal

Extend the deterministic, versioned risk model where Phase 5 assigns it, and add a
durable human-approval workflow whose one-time execution grant is atomically consumed
against the canonical action digest. Approval can only turn an engine `ASK_USER` into
an execution opportunity; it can never override a hard deny or an engine `BLOCK`.

## Deliverables

1. **Risk v2** — preserve every `risk-v1` factor/weight; add a bounded request-breadth
   factor (multiple target resources), stable factor codes/rationale, and keep scores
   capped at 100. Thresholds remain in `config/risk_thresholds.yaml`; changing the
   algorithm requires an explicit version and ADR-012.
2. **Approver rules** — strict v1 grammar (`role:<role>` / `principal:<subject>`,
   `|` alternatives) validated at registry startup; evaluated only against verified
   `Principal` attributes. Self-approval is refused unless the policy entry explicitly
   allows it; unsatisfiable requester-only rules block instead of creating a request.
3. **Approval storage** — PostgreSQL `approval_requests` table and repository; stores
   only the SHA-256 digest of a >=256-bit token, binds requester/tenant, request,
   tool/action, canonical action digest, resources, destination, data/side-effect class,
   policy version/hash, risk provenance, approver rule, status, expiry, and decision
   metadata. No raw arguments/content.
4. **Atomic decisions/consumption** — token decision and `SELECT ... FOR UPDATE`-based
   one-time consumption in PostgreSQL transactions; the project constant-time helper for
   token and action digests; decision, consumption, and their audit events occur in the
   same transaction; concurrent consumption yields exactly one winner.
5. **Gateway integration** — `ASK_USER` remains a no-execution result by default; with
   an `approval_id`, the gateway recomputes the current canonical digest and atomically
   consumes a matching approved record before execution. Replay, mutation, expiry,
   wrong principal/policy, and pending/denied approvals never execute; hard denies ignore
   approvals entirely.
6. **Tests** — risk arithmetic; rule parsing/eligibility; service storage/decision
   transitions; real-PostgreSQL concurrency/replay/expiry/mutation; gateway no-execution
   security; app wiring/settings; all existing suites green.
7. **Docs/memory/ADR-012.**

## Explicit non-goals

- No `/v1/approvals` routes, approval UI, or token delivery transport (Phase 8).
- No automatic approval request creation inside the gateway (Phase 8 request workflow
  calls `ApprovalService.request` with the host-verified action); the service is exposed
  on `app.state`.
- No real approver directory, notification channel, model/provider, content DLP, or
  audit verifier.
- No calibration of weights/thresholds (Phase 9); no approval exception path around
  hard constraints.

## Verification

| Check | Expected |
|---|---|
| Approver-rule/risk unit tests | pass |
| Approval unit + real-PostgreSQL integration | pass incl. one-consumer concurrency |
| Gateway approval/security tests | pass; denied paths leave sink unchanged |
| Full suite | all prior + new tests passed |
| `bash scripts/check.sh` | exit 0, all 8 steps, Gitleaks clean |

## Definition of Done mapping

- Versioned deterministic factors + threshold config → risk-v2 tests + ADR-012.
- Hard denies cannot be overridden → gateway test with a valid approval presented to a
  `BLOCK` action; sink unchanged.
- Mutation/replay/expiry cannot execute → service + gateway tests against real
  PostgreSQL, including concurrent consume attempts.
- Verified approver only / no self-approval → rule evaluator + decision tests.
- Audit records decision/approver without secrets → same-transaction event assertions.
- Full gate green → `scripts/check.sh` evidence recorded in V57+.

## Completion record (2026-10-26)

All deliverables are implemented and verified. Evidence: `TESTING_AND_VERIFICATION.md`
V57-V62, `phases/PHASE_5_COMPLETE.md`, ADR-012, and the code/tests cited there.

- `risk-v2` preserves every `risk-v1` weight and adds only the bounded breadth factor;
  derived resource ids are validated and deduplicated before scoring, digesting, and
  auditing so the approval contract and breadth count see one distinct target set.
- Approver rules, policy validation, approval storage/state machine, gateway gating,
  settings, and app wiring are implemented; no placeholder behavior remains.
- Real-PostgreSQL tests cover decision, expiry, mutation, replay, exactly-one-winner
  concurrency, same-transaction audit, and gateway no-execution paths.
- Full suite 733 passed (then +1 dedup regression test in the final fresh run),
  mypy clean, and `scripts/check.sh` 8/8 with Gitleaks clean.
- Non-goals remain non-goals (routes/UI/transport, automatic request creation, approver
  directory/notifications/revocation, background expiry sweeper, weight calibration).
