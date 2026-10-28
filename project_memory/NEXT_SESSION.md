# Next Session Handoff

**Last updated: 2026-10-28.** Read [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) first if you have not.

## Where we are

Phases 0a (repository foundation), 0b (security foundation), 1 (typed contracts and
deterministic policy engine), 2 (tool registry and enforced gateway), 3 (advisory input
defense and context provenance), 4 (intent extraction and action validation), 5 (risk
engine and approval workflow), 6 (output DLP and egress policy), 7 (audit persistence and
verification), and 8 (HTTP ingress, bounded runtime, local model) are
**COMPLETE — VERIFIED**. See [phases/PHASE_8_COMPLETE.md](phases/PHASE_8_COMPLETE.md)
and evidence V72–V75 in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md).
Exact commit hashes are in the phase record and
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). The repository is under git with
a linear history; `origin` = `https://github.com/StivenArifaj/ProtAI.git`, branch `main`,
pushed every stage. The Compose `db` container and volume are preserved for tests (`api`
stopped).

What exists now: host HMAC authentication + replay rejection on `/v1/*`, a host-signed
principal assertion, signed `POST /v1/requests` (sole execution surface),
`POST /v1/tool-calls/evaluate` (preview only), and
`POST /v1/approvals/{approval_id}/decision` (one-time decision, no resumption); a bounded
two-call `DemoRuntime`; per-process per-principal rate limits and request deadlines; the
deterministic policy engine + 21 self-check fixtures; the tool registry + mock adapters;
the single `invoke_tool` gateway with manifest/approval/DLP enforcement and the complete
audit lifecycle; advisory input detection gating the request path; sealed in-process
intent manifests (mock or optional strict local provider); and deterministic output DLP
at the gateway. **949 tests pass; the pre-commit gate is green (8/8, V74).** Policy is
the sole `ALLOW` producer; the gateway is the only execution path; input defense, intent,
and DLP narrow/gate/raise sensitivity only; approval is a gate; audit is never an
authorization input.

## The next task: Phase 9 — Evaluation harness and benchmark adapters (blueprint §§19, 21)

No blocking preconditions; Phase 8 passed its DoD, so proceed per the autonomy mandate.
Read first: blueprint §§19.1–19.6, §20.1, §21 Phase 9; ADR-008 through ADR-015;
`docs/SECURITY_INVARIANTS.md` (#10/#11/#14/#21); `docs/OUTPUT_DLP_FALSE_POSITIVES.md`;
`docs/KNOWN_LIMITATIONS.md`; `src/ai_security/input_defense/*`,
`src/ai_security/data_security/dlp.py`, `src/ai_security/firewall/risk_engine.py`,
`src/ai_security/policy/*`, and the Phase 8 route tests.

Phase 9 is **measurement only**. Do not add real connectors, cloud model calls, streaming,
approved-action resumption, a distributed limiter, or any new authority path. Do not
weaken or retune controls merely to improve a metric; report what the current code does.

### Deliverables (condensed from blueprint §19/§21)

1. **`evaluation/` package** with:
   - a strict dataset manifest and schema: every case has `case_id`, provenance/license
     note, task, attack category, expected outcome, label/positive class, and split
     (`dev`/`validation`/`holdout`); synthetic canaries only, never real secrets or
     private documents;
   - split tooling that keeps dev/validation/holdout distinct, deduplicates paraphrases/
     templates across splits, and refuses leakage or duplicate `case_id`s;
   - original synthetic fixtures from the repository only. Public benchmark adapters
     (e.g. InjecAgent/AgentDojo) are optional, must be disabled by default, and require
     a checked license/version/reproducibility note — do not vendor public datasets.
2. **Typed metric functions with hand-calculated unit tests:** TP/TN/FP/FN, precision,
   recall, F1, accuracy, false-positive rate, false-negative rate, and
   unauthorized-side-effect count/rate. Report undefined denominators as `N/A` (never
   `0`), class counts, confusion matrices, and per-category metrics; `FN rate == 1 -
   recall` only under the same positive class/sample set/threshold convention.
3. **Evaluation CLI** (one command) that runs the fixed fixture set through the real
   implementations:
   - input detection: `InputDefenseService.inspect` (report `PASS`/`FLAG` vs
     `REJECT`/`QUARANTINE` under a documented positive-class convention);
   - DLP/egress: argument/result inspection and release/redact/block outcomes, including
     benign near-misses and canary fixtures;
   - risk: record `risk-v2` scores/factors and report rank/ordering statistics; do not
     claim probability calibration without a labeled calibration set;
   - intent extraction: record extraction errors separately from authorization errors;
   - authorization/end-to-end: count unauthorized side effects actually observed (sink
     unchanged/executed adapter), not merely detector misses.
4. **JSON + Markdown reports** written by the CLI, containing counts/dataset version,
   per-task/per-category confusion matrices, metric definitions and values, latency
   p50/p95/p99 with sample counts, detector/provider failures and retries, unauthorized
   side effects, configuration metadata (git commit, lock hash, dataset version, policy/
   detector/risk/model versions, thresholds, Python version, hardware, timestamp, seed),
   known limitations, and skipped tests. Report only actual run output — never embed
   desired results in the README.
5. **Quick regression subset** (small, fast, deterministic) runnable in the normal suite
   or gate, plus the larger evaluation command for manual/scheduled runs. Add tests that
   prove the quick subset is representative of the runner contract (not a second
   implementation).
6. **Documentation:** a short `docs/EVALUATION.md` (how to run, dataset/split rules,
   metric definitions, current measured results with version metadata, limitations) and
   updates to `IMPLEMENTATION_STATE`, `SECURITY_INVARIANTS` only where measurement
   changes a status, `KNOWN_LIMITATIONS`, README, and memory. A new ADR is warranted if
   the label/positive-class, split, or report contract is non-obvious (likely ADR-016).

### Design decisions to make and record (do not silently invent)

- **Positive class per task.** For detection use positive = malicious/unauthorized and
  document exactly which dispositions count as "flagged". For DLP use positive =
  protected content that must not be released/egressed. Keep tasks separate — never one
  aggregate accuracy number.
- **Fixture ownership.** Cases are repository-owned synthetic fixtures with explicit
  provenance. Public benchmark adapters, if any, stay optional and separate from the
  deterministic suite.
- **Split policy.** Fix seeds, deduplicate templates/paraphrases across splits, and do
  not tune thresholds on the final holdout. Record the split version in every report.
- **Risk reporting.** `risk-v2` weights are uncalibrated. Report scores/ordering and
  threshold confusion matrices at the configured 40/80 only as operating points; do not
  call them probabilities or claim calibration without a labeled calibration set.
- **Latency scope.** Measure the defined local environment (in-process service calls,
  documented hardware/container) and label it as such; do not imply production latency.
- **What the harness may touch.** The CLI may construct services and call the gateway
  with mock adapters/test principals exactly as tests do. It must not add routes, bypass
  auth/policy/DLP, or persist evaluation data into the production audit chain unless a
  separate explicit evaluation database/chain is used and documented.

## Honest scope boundaries to preserve

- Policy remains the sole `ALLOW` producer; the gateway remains the only execution path.
  The evaluation harness observes existing behavior and must not become an authority.
- Input detection/intent/DLP stay advisory or narrowing; approvals stay a gate; audit is
  never an authorization input. Do not add an evaluation-only allow path.
- Do not weaken tests, skip security suites, or lower existing coverage to make metrics
  look better. If a fixture exposes a real defect, add a regression test and fix the
  defect (or document it as a known limitation with severity).
- No real secrets, private documents, cloud calls, streaming, real connectors, or
  approved-action resumption. Synthetic canaries only.
- Keep `compare_digest` confined to `security/constant_time.py`; keep error envelopes and
  logs free of raw payloads/tokens/secrets.
- Reports must be reproducible from the versioned fixture set; include the metadata
  required by §19.5/§19.6 and record any skipped tests honestly.

## Verification commands and expected results

| Command | Expected |
|---|---|
| `uv run --frozen pytest -q` | All tests pass (≥949; new evaluation/metric/split/report suites added; real-PostgreSQL tests still run) |
| `uv run --frozen mypy` / `ruff check .` / `ruff format --check .` | clean |
| `bash scripts/check.sh` | exit 0, all 8 steps (Gitleaks stays clean) |
| `uv run python -m ai_security.evaluation ...` (final CLI name decided in implementation) | one command reproduces JSON + Markdown from the versioned fixtures; exit non-zero on fixture/schema/metric errors |
| Metric unit tests | hand-calculated cases match; undefined denominators are `N/A`; per-category matrices sum correctly |
| Dataset tests | duplicate IDs, invalid splits, missing provenance, cross-split template leakage, and non-synthetic secrets are refused |
| Report tests | metadata fields present; no fabricated metrics; unauthorized-side-effect counts derived from observed sink/adapter state |
| Prior suites | policy/intent/approval/DLP/audit/no-bypass/route tests still green; no new allow path |
| Alembic | no migration expected; if one is genuinely required, single head and `current` → `upgrade head` → `downgrade -1` → `upgrade head` → `check` clean |

## Definition of Done (blueprint §21, Phase 9 condensed)

One command reproduces results from a versioned fixture set and emits accurate confusion
matrices/latency; all reported metrics are derived by code and match hand-calculated unit
tests; JSON + Markdown reports contain the §19.6 metadata and honest limitations; the
quick regression subset is wired in; prior suites and the 8-step gate stay green; docs and
memory record measured results, not claims.

## Open decisions / notes for the operator

- None blocking. `check.sh` pins Gitleaks to exactly 8.30.1 by design; a mismatch fails
  the gate.
- Carried-forward limits (documented): the `/v1` runtime is a fixed two-call demo;
  approved actions are not resumable; rate limits/intent uses are per process; the local
  model is optional and uncalibrated; input heuristics are English-pattern based; DLP is
  deterministic pattern matching, not a classifier; no policy hot-reload; exact-match
  destinations; in-process guardrail (no sandbox) until Phase 10; no external audit
  anchor or automated retention.
- Phase 9 results may legitimately be modest. Report measured precision/recall/FN rates,
  per-category failures, and known false positives/negatives; do not tune to a target.
