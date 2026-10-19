# Phase 1 — Typed Contracts and Deterministic Policy Engine — COMPLETE (VERIFIED)

- **Status:** COMPLETE — technical DoD all PASS, verified 2026-10-19. Strict typed
  contracts, the safe versioned policy loader, the deterministic engine (replacing the
  0b interim matrix), canonical destination handling, the test-only principal adapter,
  and startup/readiness wiring are implemented and tested (406 tests). Commits
  `cffdd62` (contracts + canonicalization), `eaae462` (models/loader/engine + config +
  fixtures), `b91729b` (wiring + adapter + env example), on top of `c95f2a6`.
- **Blueprint:** §21 (Phase 1), §§6 (contracts), 10 (policy engine + matrix), 11.4
  (thresholds), 20.2 (#25); ADR-007; ADR-008 (new, this phase).

## Scope delivered

| Deliverable (blueprint §21) | Delivered as | Status |
|---|---|---|
| Strict typed contracts; canonical `SideEffectClass`/`DataClass`; fail-closed on unknown/invalid values | `tools/base.py`, `data_security/classification.py`, `firewall/decision.py` (canonical enums defined exactly once); `extra="forbid"`, strict int `risk_score`, anchored `TOOL_ID_PATTERN`, no aliases/coercions | VERIFIED |
| Safe YAML policy loader + validated policy model | `policy/loader.py` (`yaml.safe_load` + `yaml.compose` duplicate-key walk; `PolicyConfigError` fails closed); `policy/models.py` (`PoliciesDocument`, `ToolPolicy`, `RiskThresholdsDocument`, `Thresholds`, `PolicyBundle` with version + sha256 content hashes) | VERIFIED |
| Deterministic policy engine replacing `policy/interim_matrix.py` (ADR-007 contract kept) | `firewall/policy_engine.py` (§10.2 order over strict upstream facts; stable `DecisionReason` codes; `DecisionRecord` with policy version/hash); `interim_matrix.py` deleted; 17 fixtures (7 mandated names) pass against the engine | VERIFIED |
| Principal test adapter (test-scoped) | `identity/adapters.py` — constructible only under `APP_ENV=test`, unreachable via settings/factory; dev-resolver guard and HMAC middleware untouched | VERIFIED |
| Canonicalization utilities/tests | `security/urls.py` — https-only, IDNA host, percent-encoding normalization, no userinfo/fragment, zone-id/trailing-dot rejection; exact-match allowlisting (no wildcards in v1) | VERIFIED |
| Starter policy + thresholds | `config/policies.yaml` (v1 §10.5: four read actions; `mock_external_sink.write` registered with egress disabled; `version: dev-1`); `config/risk_thresholds.yaml` (40/80, validated, marked experimental) | VERIFIED |
| Startup + readiness wiring | invalid/missing policy file refuses startup; readiness reports `policy_self_checks` + `policy_version`/`policy_hash` and detects live drift (503); process keeps startup bundle (no hot reload) | VERIFIED |
| Table-driven tests | `tests/unit/test_policy_engine.py` (64) + models/loader/urls/self-checks/adapter suites; integration wiring/health updated | VERIFIED |

## Security properties actually enforced now (do not overstate)

- The engine is deterministic and fail-closed: invalid/unknown/missing state never yields
  `ALLOW`; hard deny dominates every score; `DESTRUCTIVE` is never executable in v1;
  `RESTRICTED` writes/egress and `CONFIDENTIAL` egress are blocked; `ASK_USER` requires
  explicit policy approval-eligibility; tools absent from the policy document are denied
  (`unknown_tool`). Decisions carry stable reason codes and policy provenance.
- No LLM, no network, no side effects in the engine path; prohibited-pattern greps remain
  clean in the gate.
- Policy files load safely (no `yaml.load`; duplicate keys rejected); invalid policy
  refuses startup; readiness detects drift; bundle hashes are exposed in health metadata.
- The test principal adapter cannot start outside `APP_ENV=test` and is not selectable
  through configuration; the HMAC denial matrix is unchanged and green.
- **Still absent (do not claim):** execution (no registry/gateway — decisions have no
  side effects), risk scoring engine, approvals, input defense, intent, DLP/egress
  enforcement at a sink, audit event emission, `/v1/*` routes, rate limiting, SOC.

## Conformance notes (documented, not hidden)

- `risk_score` and `destination` are validated caller-supplied facts until the Phase 5
  risk engine and the Phase 2 tool validator produce them; the engine cannot verify their
  origin and does not pretend to.
- Destination allowlisting is exact-match only; Unicode hosts are IDNA-encoded; non-ASCII
  paths/queries and IPv6 zone IDs are rejected.
- Thresholds (40/80) are experimental defaults, uncalibrated until Phase 9.
- No policy hot-reload: readiness detects file drift, the running process keeps its
  startup-loaded bundle.

## Verification evidence (fresh runs this session 2026-10-19; detail in ../TESTING_AND_VERIFICATION.md)

1. `uv run --frozen pytest -q` → **406 passed** (364 unit + 42 integration, incl. live
   PostgreSQL).
2. `uv run --frozen mypy src` → Success, 35 source files; ruff check/format clean (3
   files were reformatted first — the gate's format step caught them).
3. `bash scripts/check.sh` → exit 0, all 8 steps; Gitleaks 8.30.1 dir+git "no leaks
   found" (9 commits scanned).
4. Policy bundle smoke run → `version: dev-1`, `policies_sha256 35bcd687…`,
   `thresholds_sha256 3e1d34ae…`, `combined_hash 8a4ba203e3baaf86eabb2e299992166289cae938ec9ea9a7bccadf6e6e068e6a`;
   17 fixtures, 0 failures.
5. Wiring integration tests: startup refuses missing/invalid policy and fixture
   mismatch; live policy-version drift flips readiness to 503 while the startup bundle
   stays fixed; readiness payload carries `policy_version`/`policy_hash`.
6. Development findings fixed with regressions: unanchored tool-id pattern; lax int
   coercion of `risk_score`; loader restructured to avoid the gate-prohibited
   `yaml.load(`.

## Definition of Done (blueprint §21, Phase 1) — final status

| DoD item | Status |
|---|---|
| Table-driven policy tests cover allowed/forbidden/malformed/cross-scope/unknown/error | **PASS** — `test_policy_engine.py` (64 tests) + supporting suites |
| Strict contracts fail closed on unknown/invalid values | PASS — model/loader/url suites; no aliases or coercions |
| ADR-007 self-check fixtures pass against the real engine (startup + readiness) | PASS — 17 fixtures (7 mandated), startup + readiness + CI suite |
| No LLM involved in authorization | PASS — no provider imports; gate greps clean |
| Quality gate green (`check.sh`, Gitleaks clean) | PASS — 8/8 steps, exit 0 |

## Limitations added by this phase (honest list)

- No policy hot-reload (drift detection only); no wildcard destinations; thresholds
  experimental; `risk_score`/destination facts upstream-supplied; decisions are not yet
  persisted to the audit chain (Phase 7); nothing executes on a decision (Phase 2).

## Handoff

Next task: **Phase 2 — Tool registry and enforced gateway** (blueprint §§12, 14, 21).
Preconditions: none blocking — Phase 1 passed its DoD; proceed per the autonomy mandate.
The no-bypass DoD (sink changes only after a valid gateway `ALLOW`) becomes testable
there.
