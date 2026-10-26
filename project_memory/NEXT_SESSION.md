# Next Session Handoff

**Last updated: 2026-10-26.** Read [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) first if you have not.

## Where we are

Phases 0a (repository foundation), 0b (security foundation), 1 (typed contracts and
deterministic policy engine), 2 (tool registry and enforced gateway), 3 (advisory input
defense and context provenance), 4 (intent extraction and action validation), and 5
(risk engine and approval workflow) are **COMPLETE — VERIFIED** — see
[phases/PHASE_5_COMPLETE.md](phases/PHASE_5_COMPLETE.md) and evidence V57–V62 in
[TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md). The repository is under git
with a linear history; the Compose `db` container and volume are preserved for tests
(`api` stopped). No remote is configured.

What exists now: host HMAC authentication + replay rejection on the `/v1/*` path prefix
(routes do not exist yet), async persistence + migrations, dev-resolver guard + test-only
principal adapter, strict typed contracts, canonical destination handling, the safe
versioned policy loader, the deterministic §10.2 policy engine with 21 self-check
fixtures wired into startup/readiness, the typed tool registry + four mock adapters, the
digest-bound execution authorization, `risk-v2`, the single `invoke_tool` gateway with
audit-first ordering/bounds, strict advisory input detection with trust labels/session
signals, server-issued sealed intent manifests with exact constraints, and — new in
Phase 5 — durable one-time human approvals bound to the canonical action digest.
**734 tests pass; the gate is green (8/8).** Intent and approvals can only narrow or gate
policy; neither is an `ALLOW` producer. No route or real model provider consumes them yet.

## The next task: Phase 6 — Output DLP and egress policy (blueprint §21)

No blocking preconditions; Phase 5 passed its DoD, so proceed per the autonomy mandate.
Read first: blueprint §§6, 12-13, and §21 (Phase 6); ADR-008 (engine facts), ADR-009
(gateway), ADR-012 (approval boundary); `docs/KNOWN_LIMITATIONS.md`; then audit the
current registration `DataClass` and mock adapters before designing content inspection.

Expected deliverables (condensed from blueprint §21):

1. **Test canaries** — deterministic canary values/fixtures usable by the mock sink and
   tests, with no real secrets.
2. **Configurable sensitive patterns** — strict, versioned configuration (likely
   `config/output_dlp.yaml`) with duplicate-key rejection, bounded patterns, and no
   silent fallback; invalid config refuses startup.
3. **Data-classification model** — content-level classification that can only *raise*
   sensitivity above the registration fact; deterministic, bounded, and typed.
4. **Destination-aware egress checks** — release/deny decisions that combine policy
   authorization, classification, destination, and (where applicable) an approval; the
   gateway remains the single execution path.
5. **Release outcomes** — typed results/audit events for released vs blocked/redacted
   output; no raw sensitive content in logs or default audit payloads.

Keep DLP authoritative only where the blueprint says so; do not let detection model
output, caller input, or an approval override a `BLOCK`/hard deny. If a new authority
path is introduced, record it in an ADR (likely ADR-013) with exact ordering and
fail-closed behavior.

## Verification commands and expected results

| Command | Expected |
|---|---|
| `uv run --frozen pytest -q` | All tests pass (≥734; new DLP/canary suites added; real-PostgreSQL tests still run) |
| `bash scripts/check.sh` | exit 0, all 8 steps (Gitleaks must stay clean) |
| Policy/intent/approval suites | still green; policy remains sole `ALLOW` producer; approval remains a gate |
| No-bypass suites | `tests/security` + gateway/integration still green |
| Alembic sequence | single head; upgrade → downgrade -1 → upgrade → check clean if a migration is added |
| DLP false-positive cases | documented and asserted, not just claimed |

## Security constraints that must hold throughout Phase 6

- Invariants #6/#7/#8/#20/#24 stay green; keep `compare_digest` confined to
  `security/constant_time.py`; do not weaken the HMAC denial matrix.
- Hard denies (`DESTRUCTIVE`, restricted/confidential egress, unknown tools) cannot be
  overridden by risk, approvals, or DLP outcomes.
- Canary data must never reach an unauthorized mock sink; denied paths must leave the
  sink byte-identical and empty where applicable.
- No raw sensitive content, secrets, or canary values in logs/audit; typed/bounded
  references and digests only.
- Mock/local only; no network calls by default; no real model dependency in tests.
- Update `docs/SECURITY_INVARIANTS.md`, both status files, `ARCHITECTURE_MAP.md`,
  `FILE_MAP.md`, `CHANGELOG.md`, and this file in the same task.

## Definition of Done (blueprint §21, Phase 6 condensed)

Canary data never reaches an unauthorized mock sink; DLP logs remain redacted; false
positive cases are documented; output release/deny outcomes are typed and audited; the
gateway remains the only execution path; all prior suites and the 8-step gate stay green.

## Open decisions / notes for the operator

- None blocking. `check.sh` pins Gitleaks to exactly 8.30.1 by design; a mismatch fails
  the gate.
- Carried-forward limits (documented): no policy hot-reload; exact-match destination
  allowlisting; `risk-v2` uncalibrated; per-process concurrency and intent-use tracking;
  mock-only tools and mock intent extractor; no manifest/approval routes or token
  transport; in-process guardrail (no sandbox) until Phase 10.
