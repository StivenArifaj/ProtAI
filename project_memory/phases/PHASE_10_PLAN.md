# Phase 10 Plan — Security Hardening & AI-Assisted Monitoring

**Source:** blueprint v1.2 §§17, 20.3, 21 Phase 10; ADR-004 (SOC alert-only); ADR-014 (audit taxonomy/verifier); ADR-016 (evaluation boundary).
**Status:** planning — implementation not started.
**Branch:** `main` at `c38d92f`, clean, synced with `origin/main`.

## Scope (v1 boundary preserved)

Phase 10 is **hardening and monitoring only**. It does NOT:
- add real connectors, cloud model calls, streaming, approved-action resumption,
  a distributed limiter, automated containment, circuit breakers, or any new authority path;
- build a UI or invent API routes;
- change existing authority behavior (policy remains the sole ALLOW producer; the gateway remains the only execution path);
- write into the production audit path from a read path unless the write is an explicit, documented append with normal fail-closed behavior.

Deliverables:
1. Threat-model review (`docs/THREAT_MODEL.md`) — add/refresh Phase 8/9/10 threats, record residual risks and explicit non-goals; update status column; reconcile with `docs/SECURITY_INVARIANTS.md` (#22).
2. Bounded offline abuse/load tests — request-size/depth/JSON caps, rate-limit buckets and charging, tool-call slot reservation, deadline behavior, detector/DLP/intent/provider failure paths, audit append pressure, concurrent request/approval behavior. Deterministic, non-flaky, bounded runtime.
3. Deterministic alert rules — versioned strict config, bounded windows/thresholds, stable rule IDs, tested true/false positives. `SECURITY_ALERT_RAISED` emitted only when a rule actually fires, through the existing audit recorder, content-free evidence. Alerts have no authority (no block/allow/revoke/containment).
4. Optional local read-only audit summarizer — opt-in setting, off by default; strict injected-client interface or deterministic local stub; `EXTERNAL_UNTRUSTED` envelope labels all request/tool-originated fields; bounded/redacted input; no raw audit payloads; no cloud calls; no authority; output labeled unverified hypothesis at most annotating an alert; adversarial-log tests mandatory.
5. Incident-response runbooks — audit-chain verification, alert triage, denied-request investigation, approval abuse, DLP findings, provider/database outages, rollback, key rotation/incident response.
6. CycloneDX SBOM generated from `uv.lock` — pinned tool/version, archived with release/evaluation artifacts, SHA256 + reproduction command documented.
7. Release-gate extension — `scripts/check.sh` gains deterministic, fast checks (alert-rule tests, SBOM presence/validation, invariant greps). All prior suites stay green.
8. Full verification, fix failures, review changes, commit, push, post-commit gate, record exact hashes/evidence.
9. Docs/memory/ADR-017 updates where the alert/summarizer trust contract is non-obvious.

## Non-goals (explicitly excluded from Phase 10)

- No UI implementation, no invented API routes, no claimed capabilities.
- No real company connectors or complete approval delivery/UI/notification.
- No automated containment or circuit breaker; invariant #22 remains "alert-only" per ADR-004.
- No distributed/shared rate limiter; per-process fixed window remains with documented caveat.
- No external audit checkpoint/anchor; truncation limits stay documented.
- No process isolation/sandboxing; mock-only adapters remain.
- No risk calibration; thresholds stay experimental.
- No invented test results; no claim that proposed features exist.

## Files expected to change (new)

| File | Purpose |
|---|---|
| `project_memory/phases/PHASE_10_PLAN.md` | This plan |
| `src/ai_security/soc/__init__.py` | SOC package: alert-only observability, no authority |
| `src/ai_security/soc/config.py` | Versioned alert-rule config (strict Pydantic, bounded thresholds) |
| `src/ai_security/soc/rules.py` | Deterministic alert rule evaluators over audit evidence |
| `src/ai_security/soc/emitter.py` | `SECURITY_ALERT_RAISED` emission through `AuditRecorder`, content-free |
| `src/ai_security/soc/summarizer.py` | Optional read-only audit summarizer: `EXTERNAL_UNTRUSTED` envelope, bounded/redacted input, opt-in |
| `src/ai_security/soc/audit_provider.py` | Read-only audit evidence provider (reads existing audit chain; never writes production audit path) |
| `tests/unit/test_soc_config.py` | Alert config validation tests |
| `tests/unit/test_soc_rules.py` | Alert rule firing / not-firing tests (true and false positives) |
| `tests/unit/test_soc_emitter.py` | Alert emission content-free tests |
| `tests/unit/test_soc_summarizer.py` | Summarizer boundary + adversarial-log tests |
| `tests/security/test_soc_no_authority.py` | Security test: summarizer/alerts cannot call tools, change policy, approve, revoke, contain |
| `tests/abuse/test_abuse_load.py` | Bounded offline abuse/load tests |
| `docs/SECURITY_ALERT_RULES.md` | Documented alert rules, thresholds, evidence |
| `docs/RUNBOOKS.md` | Incident-response runbooks |
| `docs/ALERT_SUMMARIZER_ADVERSARIAL.md` | Adversarial-log test protocol and results |
| `releases/sbom/cyclonedx-*.json` | Generated CycloneDX SBOM (archived) |
| `releases/sbom/SHA256SUMS` | SBOM hash + reproduction command |

## Files expected to change (modified)

| File | Change |
|---|---|
| `scripts/check.sh` | Add deterministic alert-rule test step + SBOM presence/validation step (steps 9-10) |
| `docs/SECURITY_INVARIANTS.md` | Invariant #22 stays "Not implemented (Phase 10; alert-only per ADR-004)" but note deterministic alerts are now testable; #22 authority boundary confirmed |
| `docs/THREAT_MODEL.md` | Add Phase 8/9/10 threats + alert/summarizer/SBOM rows; update status column |
| `docs/ARCHITECTURE.md` | Add soc/ alert-only observability row; mark alerting as Phase 10 implemented; summarizer optional/read-only |
| `docs/KNOWN_LIMITATIONS.md` | Add Phase 10 honest limits (no containment, no external anchor, per-process limiter, summarizer unverified analysis, mock-only connectors) |
| `docs/IMPLEMENTATION_STATE.md` | Phase 10 status, new test counts, SBOM path |
| `docs/DECISIONS.md` + `docs/adr/ADR-017*.md` | ADR-017: SOC alert/summarizer trust contract (read-only/alert-only; EXTERNAL_UNTRUSTED envelope; no authority) |
| `README.md` | Phase 10 status line + new docs references |
| `pyproject.toml` / `uv.lock` | No new runtime deps for SOC (uses existing packages); `--with cyclonedx-bom==7.6.0` for SBOM generation documented |

## Tests added (Phase 10)

| Suite | Count estimate | Focus |
|---|---|---|
| `tests/unit/test_soc_config.py` | ~20 | Config validation: rule IDs, bounded windows/thresholds, reject unbounded/invalid |
| `tests/unit/test_soc_rules.py` | ~40 | Rule fires only on documented pattern; no alert on benign/boundary; no authority side effect |
| `tests/unit/test_soc_emitter.py` | ~10 | Content-free `SECURITY_ALERT_RAISED` via audit recorder; emission only on actual firing |
| `tests/unit/test_soc_summarizer.py` | ~20 | Envelope labels, bounding/redaction, opt-in off-by-default, provider failure -> no hypothesis |
| `tests/security/test_soc_no_authority.py` | ~15 | Injected log text cannot trigger tools/approvals/policy edits/audit mutation/revocation/containment |
| `tests/abuse/test_abuse_load.py` | ~30 | Size/depth/JSON caps, rate-limit buckets/charging, slot reservation, deadline behavior, failure paths, audit append pressure, concurrent request/approval |

## Gate changes (`scripts/check.sh`)

- Step [9/10]: deterministic alert-rule tests (`uv run --frozen pytest tests/unit/test_soc_config.py tests/unit/test_soc_rules.py tests/unit/test_soc_emitter.py tests/unit/test_soc_summarizer.py tests/security/test_soc_no_authority.py -q`)
- Step [10/11]: SBOM presence + validation (`test -f releases/sbom/cyclonedx-*.json` + `cyclonedx-py validate` or equivalent)
- All existing 8 steps preserved; exit non-zero on any failure.

## Verification commands & expected results

| Command | Expected |
|---|---|
| `uv run --frozen pytest -q` | All tests pass (>=1013 + new suites); no failures |
| `uv run --frozen mypy` / `ruff check .` / `ruff format --check .` | Clean |
| `bash scripts/check.sh` | Exit 0, all steps pass, Gitleaks clean |
| Evaluation full | 106 cases / 6 tasks; 3 documented hard-negative failures; 0 unauthorized side effects; 0 DLP leaks |
| Evaluation quick | 15 dev cases; 0 failures; exit 0 |
| Alert-rule suite | Each rule fires only on its documented pattern; no alert on benign/threshold-boundary cases |
| Summarizer adversarial suite | Injected log instructions remain untrusted data; no tool/policy/audit/approval/containment action; provider failure yields no hypothesis |
| SBOM check | CycloneDX file validates; generated from locked set; archive/hash documented |

## Evidence to record after completion

- Exact post-commit gate hash
- Full test count (unit/integration/security/evaluation/new)
- SBOM path + SHA256 + reproduction command
- ADR-017 hash
- All docs updated and links validated
- Contradiction check vs blueprint/ADRs: none

## Sequence

1. Write PHASE_10_PLAN.md (this file)
2. Implement SOC package: config, rules, emitter, audit_provider, summarizer
3. Add SOC unit tests + security no-authority test + abuse/load tests
4. Update `scripts/check.sh` (steps 9-10)
5. Generate + archive CycloneDX SBOM from `uv.lock`
6. Write `docs/SECURITY_ALERT_RULES.md`, `docs/RUNBOOKS.md`, `docs/ALERT_SUMMARIZER_ADVERSARIAL.md`
7. Update `docs/SECURITY_INVARIANTS.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, `docs/KNOWN_LIMITATIONS.md`, `docs/IMPLEMENTATION_STATE.md`, README
8. Add ADR-017; update `docs/DECISIONS.md`
9. Run full verification; fix failures; review changes
10. Commit Phase 10; push; run post-commit gate; record exact hashes
11. Write `docs/PRODUCT_INTERACTION_MODEL.md` + company-integration/pilot architecture
12. Validate links/claims; update architecture/limitations/roadmap/memory; commit separately
13. Final report: implemented v1 vs company-integration-needed vs future human-interaction vs post-v1 recommendations
