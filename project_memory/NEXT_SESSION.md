# Next Session Handoff

**Last updated: 2026-10-29.** Read [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) first if you have not.

## Where we are

Phases 0a (repository foundation), 0b (security foundation), 1 (typed contracts and
deterministic policy engine), 2 (tool registry and enforced gateway), 3 (advisory input
defense and context provenance), 4 (intent extraction and action validation), 5 (risk
engine and approval workflow), 6 (output DLP and egress policy), 7 (audit persistence and
verification), 8 (HTTP ingress, bounded runtime, local model), and 9 (evaluation harness
and dataset) are **COMPLETE — VERIFIED**. See
[phases/PHASE_9_COMPLETE.md](phases/PHASE_9_COMPLETE.md) and evidence V76–V80 in
[TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md). Exact commit hashes are in
the phase record and [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). The
repository is under git with a linear history; `origin` =
`https://github.com/StivenArifaj/ProtAI.git`, branch `main`, pushed every stage. The
Compose `db` container and volume are preserved for tests (`api` stopped).

What exists now: host HMAC authentication + replay rejection on `/v1/*`, a host-signed
principal assertion, signed `POST /v1/requests` (sole execution surface),
`POST /v1/tool-calls/evaluate` (preview only), and
`POST /v1/approvals/{approval_id}/decision` (one-time decision, no resumption); a bounded
two-call `DemoRuntime`; per-process per-principal rate limits and request deadlines; the
deterministic policy engine + 21 self-check fixtures; the tool registry + mock adapters;
the single `invoke_tool` gateway with manifest/approval/DLP enforcement and the complete
audit lifecycle; advisory input detection gating the request path; sealed in-process
intent manifests (mock or optional strict local provider); deterministic output DLP at
the gateway; and a measurement-only evaluation harness with a strict 106-case synthetic
dataset and JSON/Markdown reports. **1013 tests pass; the pre-commit gate is green (8/8,
V79); the post-commit gate is V80.** Policy is the sole `ALLOW` producer; the gateway is
the only execution path; input defense, intent, and DLP narrow/gate/raise sensitivity
only; approval is a gate; audit is never an authorization input; evaluation is
measurement only.

## The next task: Phase 10 — Security hardening and AI-assisted monitoring (blueprint §§17, 20.3, 21)

No blocking preconditions; Phase 9 passed its DoD, so proceed per the autonomy mandate.
Read first: blueprint §§17.1–17.3, §16.1 (`SECURITY_ALERT_RAISED`), §20.3, §21 Phase 10,
§22 (release gates), §23 (maturity language); ADR-004 (SOC alert-only), ADR-014 (audit
taxonomy/verifier), ADR-016 (evaluation boundary); `docs/SECURITY_INVARIANTS.md` (#21/#25),
`docs/AUDIT_RETENTION_AND_DATA_HANDLING.md`, `docs/KNOWN_LIMITATIONS.md`,
`src/ai_security/audit/*`, `src/ai_security/api/*`, `config/*`, and `scripts/check.sh`.

Phase 10 is **hardening and monitoring only**. Do not add real connectors, cloud model
calls, streaming, approved-action resumption, a distributed limiter, automated
containment, or any new authority path. The AI monitor is read-only/alert-only and has no
tool-execution, policy-edit, approval, audit-write, session-revocation, or
circuit-breaker power. Deterministic rules alone may create alerts.

### Deliverables (condensed from blueprint §17/§21)

1. **Threat-model review.** Review `docs/THREAT_MODEL.md` against the implemented system;
   add/refresh threats for the Phase 8 ingress, Phase 9 evaluation harness, alerting/
   summarizer, SBOM/supply chain, and any abuse/load findings. Record residual risks and
   explicit non-goals. Update `docs/ARCHITECTURE.md` and `docs/SECURITY_INVARIANTS.md`
   only where the review changes a status.
2. **Abuse/load tests.** Deterministic tests for request-size/depth/JSON caps, rate-limit
   buckets and charging rules, tool-call slot reservation, deadline behavior, detector/
   DLP/intent/provider failure paths, audit append pressure, and concurrent request/
   approval behavior. Bound test runtime; do not add a production load generator or
   network dependency. Document measured limits and the per-process limiter caveat.
3. **Deterministic alert rules.** Versioned, strict config (e.g. repeated blocked calls,
   broad resource access, burst reads across synthetic resources, repeated
   external-destination attempts, repeated approval failures). Rules read existing audit
   evidence; they never authorize or block execution. Thresholds are configurable,
   bounded, tested, and documented. Emit `SECURITY_ALERT_RAISED` only from deterministic
   evaluators, with content-free evidence; never fabricate events. Alert evaluation must
   not write into the production audit path from a read path unless the write is an
   explicit, documented append with the normal fail-closed behavior.
4. **Optional local read-only audit summarizer.** Strict injected-client interface (or
   deterministic local stub) behind an opt-in setting; off by default. Structured
   envelope labels every request/tool-originated field `EXTERNAL_UNTRUSTED`; bounded and
   redacted input; no raw audit payloads; no cloud calls; no authority. Its output is
   labeled untrusted analysis/hypothesis and can at most annotate an alert. Adversarial
   fixtures must prove injected log text cannot trigger tools, approvals, policy edits,
   audit mutation, revocation, containment, or any action beyond a bounded alert/
   hypothesis. If a provider cannot be implemented safely offline, ship the interface +
   deterministic stub and document live-model evaluation as future work.
5. **Runbooks + known limitations.** Operational runbooks for audit-chain verification,
   alert triage, denied-request investigation, approval abuse, DLP findings, provider/
   database outages, rollback, and key rotation/incident response. Update
   `docs/KNOWN_LIMITATIONS.md` and memory with honest Phase 10 limits (no containment, no
   external anchor, per-process limiter, mock-only connectors, summarizer not verified
   analysis).
6. **CycloneDX SBOM.** Generate from the locked dependency set (`uv.lock`) with a pinned,
   documented tool/version; archive the SBOM with the release/evaluation artifacts and
   record its hash/provenance. Do not invent components; if generation cannot be
   reproduced offline, document the exact command and blocker rather than committing a
   fabricated file.
7. **Release-gate check.** Extend `scripts/check.sh` only with deterministic, fast checks
   (alert-rule tests, SBOM presence/validation, invariant greps). Keep all prior suites
   and the evaluation quick subset green. Update `docs/IMPLEMENTATION_STATE.md`,
   `SECURITY_INVARIANTS`, `THREAT_MODEL`, `ARCHITECTURE`, `KNOWN_LIMITATIONS`, README,
   ADR index, and memory; add ADR-017 if the alert/summarizer trust contract is
   non-obvious.

### Design decisions to make and record (do not silently invent)

- **Alert authority.** Alerts are evidence/notification only. No rule may block, allow,
  consume an approval, revoke a session, edit policy, or trigger containment. If a rule
  needs data not in the audit chain, add a read-only derived store; never make audit an
  authorization input.
- **Rule ownership and thresholds.** Versioned config with strict schema, bounded
  windows/thresholds, stable rule IDs, and tests for true/false positives. Avoid
  attacker-controlled raw text in rule matching/labels; use event types, codes, counts,
  and canonical destinations.
- **Event production.** `SECURITY_ALERT_RAISED` must be emitted only when a rule actually
  fires, through the existing audit recorder, with content-free fields. Decide and
  document whether evaluation runs against an in-memory recorder (no production writes).
- **Summarizer boundary.** Structured envelope, explicit untrusted labels, bounded/
  redacted fields, no tool/policy/audit access, output labeled unverified. Adversarial
  tests are mandatory even if the model is a stub.
- **Load-test scope.** In-process deterministic abuse tests, not a production benchmark;
  label results and avoid flaky timing assertions. Reuse the evaluation latency caveat.
- **SBOM provenance.** Pin tool/version, generate from `uv.lock`, archive under a
  documented path, record SHA256 and reproduction command; do not claim completeness
  beyond the locked Python dependency set (base images/system packages are separate).
- **Check-gate additions.** Keep `check.sh` fast and offline; do not require Docker,
  PostgreSQL, a network, or a model provider for new steps. Preserve failure-on-missing-
  tool behavior (as with Gitleaks).

## Honest scope boundaries to preserve

- Policy remains the sole `ALLOW` producer; the gateway remains the only execution path.
  Alerting/summarization/evaluation observe and report; they must not become authority.
- Input detection/intent/DLP stay advisory or narrowing; approvals stay a gate; audit is
  never an authorization input. Do not add an alert-only allow/deny path.
- No real connectors, cloud calls, streaming, approved-action resumption, distributed
  limiter, automated containment, or policy editing by a model.
- Do not weaken tests, skip security suites, lower existing coverage, or tune thresholds
  to make alerts/metrics look better. If a fixture exposes a defect, add a regression test
  and fix it or document it with severity.
- No real secrets/private data. Synthetic canaries only. Keep `compare_digest` confined to
  `security/constant_time.py`; keep logs/reports free of raw payloads/tokens/secrets.
- Preserve ADR-001 through ADR-016. Read the blueprint section before implementing; if a
  requirement is ambiguous, choose the narrower, testable interpretation and record it.

## Verification commands and expected results

| Command | Expected |
|---|---|
| `uv run --frozen pytest -q` | All tests pass (≥1013; new alert/summarizer/abuse/SBOM suites added; real-PostgreSQL tests still run) |
| `uv run --frozen mypy` / `ruff check .` / `ruff format --check .` | clean |
| `bash scripts/check.sh` | exit 0, all steps (Gitleaks stays clean; new deterministic checks pass) |
| Evaluation full command | 106 cases / 6 tasks; 3 documented hard-negative failures; 0 unauthorized side effects; 0 DLP leaks |
| Evaluation quick command | 15 dev cases; 0 failures; exit 0 |
| Alert-rule suite | Each rule fires only on its documented pattern; no alert on benign/threshold-boundary cases; no authority/containment side effect |
| Summarizer adversarial suite | Injected log instructions remain untrusted data; no tool/policy/audit/approval/containment action; bounded output; provider failure yields no hypothesis |
| SBOM check | CycloneDX file validates and is generated from the locked set; archive/hash documented |
| Prior suites | policy/intent/approval/DLP/audit/no-bypass/route/evaluation tests still green; no new allow path |

## Immediate first steps

1. Read blueprint §§17, 20.3, 21 Phase 10 and the ADRs/docs listed above.
2. Run `git status` and confirm Phase 9 is committed/pushed (V80 recorded).
3. Write a short Phase 10 plan in `project_memory/phases/PHASE_10_PLAN.md` (scope,
   non-goals, files, tests, gate changes) before coding.
4. Implement deterministic alert rules + tests first, then abuse tests, then the optional
   summarizer boundary + adversarial tests, then runbooks/SBOM/docs/memory.
5. Run the full gate, commit logical slices, push, then run the post-commit gate and record
   exact hashes/evidence.
