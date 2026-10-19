# Phase 4 Plan — Intent extraction and action validation

**Status: COMPLETE — VERIFIED** (2026-10-19). Kept as the executed plan; see
[PHASE_4_COMPLETE.md](PHASE_4_COMPLETE.md) and V51+ in
[../TESTING_AND_VERIFICATION.md](../TESTING_AND_VERIFICATION.md).

**Blueprint:** v1.2 §§8-9, 11.1, 12.3, 20.2 #3/#5, §21 Phase 4.

## Goal

Turn an authenticated user request into a bounded, server-issued intent manifest and
compare the gateway's validated action with it before execution. Extraction is untrusted
and can only deny/narrow; malformed output, outage, and ambiguity never grant permission.

## Deliverables

1. **Typed bounded manifest** — proposed action, concrete resources, canonical
   destination, exact parameter values, max uses, request/principal/policy binding,
   creation/expiry, goal digest. Server-only issuance; no raw goal text.
2. **Mock extractor** — deterministic demo scenarios; explicit rejected and
   clarification outcomes; no authority.
3. **Local-model adapter interface** — injected client, strict bounded JSON parsing,
   duplicate-key/unknown-field rejection, bounded retries, timeout/outage mapping; no
   provider pinned or required for tests.
4. **Constraint validator** — exact action/resource/destination/parameter matching,
   registered/policy-present action checks, adapter capability checks, bounded uses;
   ambiguity/unsafe destinations fail closed.
5. **Relative-date resolution** — trusted principal timezone only; `TODAY`/`THIS_WEEK`
   to exact UTC instants; DST-covered.
6. **Gateway integration** — app-built gateway requires a valid manifest; verify binding
   before policy work, compare derived action after validation, reserve uses only after
   policy `ALLOW`, deny without adapter call on every failure.
7. **Tests** — intent unit (models/extractors/validation/service), manifest no-grant
   security, app-wiring and real-PostgreSQL end-to-end; all prior suites green.
8. **Docs/memory/ADR-011.**

## Explicit non-goals

- No `/v1` route or signed manifest transport (Phase 8).
- No real model provider or general NLU (Phase 8); no network calls in tests.
- No cross-process use counter; no sandbox (Phase 10).
- No changes to the policy engine's facts or sole-`ALLOW` property.

## Verification

| Check | Expected |
|---|---|
| Targeted intent unit + security | 56 passed |
| App wiring + settings | 63 passed |
| Full suite | 661 passed (568 unit + 64 integration + 29 security) |
| `bash scripts/check.sh` | exit 0, all 8 steps, Gitleaks clean |
| Manual demo smoke | allow/allow/reject/clarify with expected manifests |

## Definition of Done mapping

- Malformed model output/outage grant no permission → extractor tests + allowlist denial.
- Ambiguous intent grants no permission → service tests + app integration clarification.
- Arguments/action compared with concrete limits → gateway constraint tests + security.
- Execution still only via gateway → adapter spy/no-bypass tests remain green.
- Gate green and ADR-008/009/010 contracts untouched → full suite/static checks.
