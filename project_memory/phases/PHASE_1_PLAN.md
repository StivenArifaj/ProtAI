# Phase 1 — Typed contracts and deterministic policy engine

- **Status:** COMPLETE — VERIFIED (2026-10-19). Record: [PHASE_1_COMPLETE.md](PHASE_1_COMPLETE.md)
- **Blueprint:** sections 6 (shared contracts), 10 (policy engine + matrix), 11.4
  (thresholds), 20.2 (#25), 21 (Phase 1); ADR-007; ADR-008 (new, this phase)
- **Started:** 2026-10-19

## Objective

Make the v1 policy decision matrix real: strict typed contracts for policy evaluation,
validated `config/policies.yaml` + `config/risk_thresholds.yaml` loaded with a safe YAML
loader, and a deterministic engine (`firewall/policy_engine.py`) that replaces the Phase
0b interim transcription (`policy/interim_matrix.py`) while keeping the ADR-007 fixture
contract green. No LLM, no network, no side effects — decisions are data.

## Deliverables

- [x] Canonical enums defined once: `SideEffectClass` (`tools/base.py`), `DataClass`
      (`data_security/classification.py`), `FirewallDecision` + `DecisionReason` +
      `DecisionRecord` (`firewall/decision.py`).
- [x] Destination canonicalization utility (`security/urls.py`): https-only, no
      userinfo/fragment, lowercased IDNA host, default-port elision, normalized
      percent-encoding; exact-match allowlist semantics (no wildcards in v1).
- [x] Validated policy model (`policy/models.py`): `PoliciesDocument`, `ToolPolicy`,
      `RiskThresholdsDocument`, `Thresholds`, `PolicyBundle` (version + content hashes).
- [x] Safe YAML loader (`policy/loader.py`): `yaml.safe_load` only, duplicate-key
      rejection, strict validation, fail-closed `PolicyConfigError`.
- [x] Deterministic engine (`firewall/policy_engine.py`): `PolicyEvaluationRequest`
      (strict, frozen), documented evaluation order (§10.2), thresholds from config,
      stable `DecisionReason` codes, `DecisionRecord` (decision, reason, policy
      version/hash). Fail closed on every unknown/invalid state.
- [x] Starter policy exactly per blueprint §10.5 (`config/policies.yaml`) and
      thresholds per §11.4 (`config/risk_thresholds.yaml`).
- [x] Self-check fixtures v2 evaluated against the real engine (keep the 7 mandated
      fixtures; scenario-level `tool_policy` overrides for rows the starter policy must
      not enable by default — the "dedicated test scenario" of §10.5).
- [x] Principal test adapter (`identity/adapters.py`): constructible only under
      `APP_ENV=test`, unreachable through `build_principal_resolver`; dev-resolver guard
      untouched.
- [x] Startup refuses invalid policy configuration; readiness reports
      `policy_version`/`policy_hash` and detects live policy/fixture drift (ADR-007).
- [x] Table-driven tests: allowed, forbidden, malformed, cross-scope, unknown, error.

| Deliverable | Delivered as (files) | Status |
|---|---|---|
| Canonical enums | `src/ai_security/{tools/base,data_security/classification,firewall/decision}.py` | VERIFIED |
| Canonicalization | `src/ai_security/security/urls.py` | VERIFIED |
| Policy model + loader | `src/ai_security/policy/{models,loader}.py` | VERIFIED |
| Engine | `src/ai_security/firewall/policy_engine.py` | VERIFIED |
| Config | `config/policies.yaml`, `config/risk_thresholds.yaml` | VERIFIED |
| Self-checks v2 | `config/policy_self_checks.yaml`, `policy/self_checks.py` | VERIFIED |
| Test adapter | `src/ai_security/identity/adapters.py` | VERIFIED |
| Wiring | `settings.py`, `api/{app,dependencies,routes_health}.py` | VERIFIED |
| Tests | `tests/unit/test_{policy_models,policy_loader,policy_engine,urls,policy_self_checks,principal_test_adapter,settings}.py`, integration updates | VERIFIED (406 total) |

## Explicit non-goals (later phases)

- Tool registry, gateway, `ProposedToolCall` construction from a registry, real risk
  scoring engine (Phase 2/5), input detection (3), intent manifests (4), approvals
  (5), DLP/egress inspection facts beyond destination allowlisting (6), audit emission
  (7), `/v1/*` routes (8). The engine consumes validated facts supplied by earlier
  layers; it never performs I/O.
- No policy hot-reload (atomic reload per §10.6 is future work; readiness detects drift,
  the running process keeps its startup-loaded policy).
- No wildcard destination patterns (exact canonical match only, documented and tested).
- `HostPrincipalResolver` typed assertions stay deferred (it already fails closed).

## Decisions and deviations

| Decision / deviation | Rationale | Recorded in |
|---|---|---|
| Engine lives in `firewall/policy_engine.py`; policy document models/loader in `policy/` | Blueprint §4 layout names `firewall/policy_engine.py`; shared contracts live in their domain packages (§4.1) | ADR-008 |
| `SideEffectClass`/`DataClass` move to blueprint locations (`tools/base.py`, `data_security/classification.py`), defined exactly once | §6.1 canonical enum rule; Phase 2 extends these modules | ADR-008 |
| Request carries upstream-determined facts (`principal_resolved`, `arguments_valid`, `hard_deny`, `resource_authorized`, `risk_score`) and the action description; policy-derived flags (`tool membership`, `explicit permission`, `approval eligibility`, `egress enablement`, `destination allowlist`) come from the loaded policy | §10.2 evaluation order; registry/validator/risk-engine produce the facts in later phases; policy facts must never be caller-supplied | ADR-008 |
| Fixture scenario `tool_policy` override (strict same `ToolPolicy` model) for matrix rows the starter policy must not enable by default (e.g. egress enabled) | §10.5 sanctions a "dedicated egress-blocking test scenario"; ADR-007 fixtures must exercise the full matrix without weakening the starter policy | ADR-008 |
| Exact-match destination allowlist; https-only; no wildcards in v1 | §6.2 URL rules + §10.4 "prefer specific identifiers"; wildcards deferred until documented matching semantics exist | ADR-008 |
| Deny-by-default: tool absent from the policy document → `unknown_tool` BLOCK | §10.3 row 1 + §12.2; fail closed | ADR-008 |
| `DecisionRecord` minimal for Phase 1 (decision, reason, policy version/hash); constraint/approval/correlation fields arrive with their features | Avoid pretending fields exist that nothing produces | ADR-008 |
| Readiness payload gains `policy_version`/`policy_hash` (ADR-007 metadata) | ADR-007 requires exposing loaded policy version/hash in health metadata | ADR-008 |
| Hook order: principal → tool-known → arguments → hard-deny → resource scope (blueprint §10.2 steps 1–5) | Follow the documented order exactly; reason precedence tested | ADR-008 |

## Verification evidence

| ID | Command / check | Result |
|---|---|---|
| V30 | `uv run --frozen pytest -q` | PASS — 406 passed (364 unit + 42 integration) |
| V31 | `uv run --frozen mypy src` | PASS — 35 source files, strict, clean |
| V32 | `uv run --frozen ruff check src/ tests/` + `ruff format src tests` | PASS — clean (3 files reformatted first) |
| V33 | `bash scripts/check.sh` | PASS — exit 0, 8/8 steps; Gitleaks 8.30.1 clean (9 commits) |
| V34 | Policy bundle smoke (`load_policy_bundle` + `check_policy_self_checks`) | PASS — `dev-1`, `combined_hash 8a4ba203…`, 17 fixtures, 0 failures |
| V35 | Wiring integration tests | PASS — startup refusals; readiness drift → 503 with `policy_version`/`policy_hash` |

Full detail in [../TESTING_AND_VERIFICATION.md](../TESTING_AND_VERIFICATION.md) (V30–V35).

## Definition of Done checklist (blueprint §21, Phase 1)

| DoD item | Status |
|---|---|
| Table-driven policy tests cover allowed/forbidden/malformed/cross-scope/unknown/error | **PASS** — `test_policy_engine.py` (64) + supporting suites |
| Strict contracts fail closed on unknown/invalid values | **PASS** — no aliases/coercions; strict ints; anchored ids |
| ADR-007 self-check fixtures pass against the real engine (startup + readiness) | **PASS** — 17 fixtures (7 mandated names retained) |
| No LLM involved in authorization (engine imports no model provider; gate greps intact) | **PASS** |
| Quality gate green (`check.sh`, Gitleaks clean) | **PASS** — 8/8 steps |

## Known limitations added/closed by this phase

- Added (documented, not defects): no hot-reload; exact-match destinations only;
  facts are Phase 1 inputs until the gateway/registry/risk engine wire them.
- Closed: `KNOWN_ISSUES_AND_LIMITATIONS.md` #22 (interim evaluator) once the engine
  lands; `docs/SECURITY_INVARIANTS.md` #25 becomes fully testable.

## Handoff

Next task: Phase 2 — tool registry and enforced gateway (preconditions: Phase 1 gate
green). Update `IMPLEMENTATION_STATUS.md`, `NEXT_SESSION.md`, `CHANGELOG.md`, and the
`docs/` state files in the same task.
