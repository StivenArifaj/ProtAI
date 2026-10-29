# Phase 9 — Evaluation Harness and Dataset: COMPLETE — VERIFIED

**Completed:** 2026-10-29
**Blueprint:** v1.2 §§19.1–19.6, §20.1, §21 Phase 9
**ADR:** [../../docs/adr/ADR-016-evaluation-harness-and-dataset-contract.md](../../docs/adr/ADR-016-evaluation-harness-and-dataset-contract.md)
**Documentation:** [../../docs/EVALUATION.md](../../docs/EVALUATION.md),
[../../evaluation/README.md](../../evaluation/README.md)
**Evidence:** V76–V80 in [../TESTING_AND_VERIFICATION.md](../TESTING_AND_VERIFICATION.md)
**Commits:** `b8d6ae3` (harness/dataset/tests), `4acdbe0` (docs/ADR-016), `6ac3089`
(memory/phase record), and the final V80 status-record commit (see
[../IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md)).

## Definition of Done — verdict

| Criterion | Status | Evidence |
|---|---|---|
| One command reproduces results from a versioned fixture set | PASS | `uv run python -m ai_security.evaluation --dataset evaluation/dataset_manifest.yaml --output-dir evaluation/reports` loads the strict manifest, verifies fixture hashes/counts and the split partition **before** running, executes all six tasks, and writes authoritative JSON + derived Markdown (V78). The 15-case dev quick command is the fast regression (V78) |
| Accurate confusion matrices and latency are emitted | PASS | Per-task and per-category TP/FN/FP/TN plus precision/recall/F1/accuracy/FPR/FNR where defined; `risk` reports exact score/factor/band conformance and ordering; `intent` reports a multiclass status matrix plus unexpected/missed manifests; `authorization` reports expected/actual outcomes and unauthorized side effects. Latency is nearest-rank in-process p50/p95/p99 with per-task sample counts and an explicit local label |
| All reported metrics are derived by code and match hand-calculated unit tests | PASS | `metrics.py` derives every value from counts; `tests/evaluation/test_metrics.py` asserts hand-calculated binary/multiclass values, zero-denominator `None` semantics, sparse union labels, and nearest-rank behavior; `test_report.py` asserts JSON→Markdown derivation; no desired value is hard-coded |
| Versioned fixture set, provenance, license, and split tooling exist | PASS | Dataset `2026.10.28-v1`, manifest SHA256 `d964b03ceeb5fbcfa94c85c0e9aee41deb7c7d4f5564e2ebbf0b2fab3e7061d1`, split-file SHA256 `20ae8603160e6f39c2c58576930520a2cd872638b83ef2c62f31ae7947f7108f`; 106 synthetic cases (20 input, 16 DLP egress, 14 DLP response, 18 risk, 18 intent, 20 authorization), 42 dev / 34 validation / 30 holdout, 15-case dev quick subset. Every case carries `case_id`, task, category, split, `template_id`, provenance, license (CC0-1.0), and `synthetic: true` |
| §19.6 artifacts are present | PASS | JSON + Markdown include counts/dataset version, per-task/per-category matrices, metric definitions/values, latency/sample counts, detector/provider failures and retries, unauthorized side effects, configuration/version/git/lock metadata, seed, skipped tests, limitations, and the exact reproduction command |
| The harness is measurement-only and adds no authority | PASS | No route, application wiring, or production audit write was added. Authorization cases run the real `ToolGateway`/registry/policy/`OutputDefenseService` with mock adapters wrapped to count calls, an `InMemoryAuditRecorder`, a sink store, and a fixed clock; no PostgreSQL/HTTP/auth/approval path. Policy remains the sole `ALLOW` producer and the gateway the only execution path |
| Split/leakage and dataset integrity are enforced before execution | PASS | Loader refuses path escapes, duplicate keys/IDs, exact duplicate content, cross-split `(task, template_id)` leakage, non-partition/disagreeing splits, unknown split names, hash/count drift, and an empty/oversized/non-dev/incomplete quick subset; each rule has a refusal test |
| All prior suites and the gate stay green; docs/memory/ADR updated | PASS | V76–V80: **1013 passed** (782 unit + 122 integration + 45 security + 64 evaluation); mypy 82 source files; ruff clean (212 files); Gitleaks 8.30.1 dir+git clean; no migration (`f7a8b9c0d1e2`); ADR-016, `docs/EVALUATION.md`, and memory records updated |
| ADR-008 through ADR-016 boundaries untouched | PASS | Policy sole `ALLOW`; gateway sole execution path; intent/DLP/input defense narrowing/gating/advisory only; approval a gate; audit never an authorization input; evaluation measurement only. No threshold was tuned to a metric |

## Delivered

### Installed harness (`src/ai_security/evaluation/`)

- `models.py` — strict task/case/fixture/split models for the six tasks with task-specific
  positive classes and required provenance/license/`synthetic`/`template_id` metadata.
- `dataset.py` — strict manifest/fixture/split loader; SHA256/count verification and
  refusal of path escapes, duplicate keys/IDs/content, cross-split `(task, template_id)`
  leakage, non-partition/disagreeing splits, unknown split names, and invalid quick
  subsets before any case runs.
- `metrics.py` — hand-testable binary and multiclass confusion counts/metrics, sparse but
  zero-filled union labels, `null` for undefined denominators, and nearest-rank
  p50/p95/p99 latency.
- `metadata.py` — direct `.git`/refs and `uv.lock` reads (no child process); missing
  values are `null`, never fabricated; Python/platform/environment metadata.
- `runners.py` — six task runners over shipped services:
  - input detection/gating via `InputDefenseService`;
  - DLP egress and response via `OutputDefenseService` with a sink store;
  - risk via the real `risk-v2` engine (exact score/factors/bands and ordering);
  - intent via `MockIntentExtractor` and deterministic transcript-backed local-provider
    outputs (multiclass status, unexpected/missed manifests, provider calls/retries);
  - authorization via the real gateway/registry/policy/DLP with mock adapters wrapped to
    count calls, an `InMemoryAuditRecorder`, a sink store, and fixed clock
    `2026-01-01T12:00:00Z`.
- `report.py` — JSON-authoritative §19.6 report assembly and derived Markdown; `N/A` for
  undefined values.
- `cli.py` + `__main__.py` — CLI-only entry point; exit `0` report written, `1`
  dataset/verification refusal before execution, `2` `--fail-on-failures` observed a
  failed expectation; `--quick` requires `--split dev`; report names must be a plain stem;
  the actual `sys.argv` invocation is recorded.

### Dataset (`evaluation/`)

- `dataset_manifest.yaml` — strict manifest with version `2026.10.28-v1`, seed
  `20261028`, creation date, provenance, CC0-1.0, fixture SHA256s/counts, and split
  counts.
- Six JSONL fixtures: 20 input-detection, 16 DLP-egress, 14 DLP-response, 18 risk, 18
  intent, and 20 authorization cases. Synthetic canaries include
  `CANARY_SECRET_EVAL_DO_NOT_RELEASE` and `alice.evaluation@example.test`; no real
  secret/private data. The credential fixture value is `abcdef` (shortened to avoid a
  Gitleaks `generic-api-key` false positive without an allowlist; DLP still matches it).
- `splits/splits.json` — explicit dev/validation/holdout partition and the 15-case
  dev-only quick subset covering all six tasks.
- `reports/evaluation_report.{json,md}` and `reports/quick_report.{json,md}` — generated
  reports (regenerated after the CLI command-metadata fix).
- `README.md` — provenance/license, update procedure, commands, interpretation,
  limitations, and baseline.

### Tests (`tests/evaluation/`, 64)

Hand-calculated metrics; dataset hash/count/partition/template-leakage/duplicate/path/
quick-subset refusal; metadata `null` behavior; JSON/Markdown report derivation; CLI exit
codes and module-style command recording; and a real 15-case quick-subset regression.
The quick subset also runs inside `check.sh` via pytest.

### Documentation

- `docs/EVALUATION.md`, ADR-016, `docs/IMPLEMENTATION_STATE.md` (Phase 9 decisions,
  verification rows 74–79, DoD, Phase 10 handoff), `docs/KNOWN_LIMITATIONS.md`,
  `docs/SECURITY_INVARIANTS.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`,
  `docs/DECISIONS.md`, and root `README.md`.
- Memory: entry point, roadmap, implementation status, changelog, decision log, known
  issues, testing/verification, architecture/file maps, security requirements, project
  context, this record, and `NEXT_SESSION.md`.

## Measured baseline (dataset `2026.10.28-v1`, 106 cases)

| Task | Result |
|---|---|
| Input detection | 14 TP / 3 TN / 3 FP / 0 FN (precision 0.824, recall 1.000, FPR 0.500); gating 13 TP / 5 TN / 1 FP / 1 FN (precision 0.929, recall 0.929, FPR 0.167) |
| DLP egress | 11 protected / 5 benign; 0 leak failures |
| DLP response | 10 protected (6 redacted, 4 suppressed) / 4 benign; 0 leak failures |
| Risk | 18/18 exact score+factors+band; 0 ordering violations; conformance only |
| Intent | 18/18 status matches; 0 unexpected/missed manifests; 11 provider calls; 1 retry |
| Authorization | 20/20 expected outcomes; 15 must-not-execute blocked; 5 expected executions; 0 unauthorized executions; 1 expected/observed sink write; 93 in-memory audit events |

The three failures are intentional hard-negative input false positives
(`in-dev-quote-01`, `in-dev-readthis-01`, `in-val-quote-01`); they were not tuned away.
All numbers are small-fixture, in-process measurements — not calibration, production
estimates, or public-benchmark comparisons.

## Decisions and limitations (honest)

- The dataset is small, synthetic, and self-authored; the 42/34/30 split is
  reproducibility discipline, not an independent third-party sample.
- No public benchmark adapter exists because no license, pinned version, and reproducible
  download hash was verified; no result is comparable to a public benchmark.
- Authorization evaluation is in-process and mock-only: it runs the real gateway/
  registry/policy/DLP but no PostgreSQL, HTTP ingress, host authentication, approvals, or
  real connectors. Shipped capabilities produce no `ASK_USER` row; approval behavior
  remains covered by the Phase 5 suites.
- Intent evaluation uses `MockIntentExtractor` and deterministic transcript-backed
  local-provider outputs; it measures adapter/gating conformance, not live local-model
  semantic accuracy.
- Risk evaluation measures exact score/factor/band conformance and ordering, not
  calibration; `risk-v2` weights and the 40/80 thresholds remain uncalibrated.
- DLP matrices are pattern-scoped (five deterministic detectors); 0 leaks on these
  fixtures is not exhaustive secret/PII coverage.
- Latency is local, in-process, single-machine wall-clock time; it excludes HTTP,
  database, network, real adapters, and concurrency and is not a production latency/
  throughput claim.
- The full 106-case run is manual/scheduled; only the 15-case quick subset runs in the
  gate. There is no coverage measurement. `metadata.git.commit` names the checked-out
  revision at run time, so a report committed afterwards names its parent unless
  regenerated.
- No detector/policy/DLP/risk/model threshold was changed and no real connector, cloud
  model call, streaming, approved-action resumption, distributed limiter, approval path,
  or new authority path was added.

## Verification (V76–V80)

- V76: full suite — **1013 passed** (782 unit + 122 integration + 45 security + 64
  evaluation).
- V77: `tests/evaluation` — **64 passed**.
- V78: full evaluation — 106 cases / 6 tasks, 3 documented failures, 0 unauthorized side
  effects, 0 DLP leaks, 0 detector errors; quick evaluation — 15 dev cases, 0 failures,
  exit 0.
- V79: pre-commit `bash scripts/check.sh` — PASS, exit 0, all 8 steps; 1013 tests;
  ruff/mypy clean (212 files / 82 source files); Gitleaks 8.30.1 dir+git no leaks;
  prohibited-pattern and constant-time-confinement checks clean.
- V80: post-commit `bash scripts/check.sh` after `b8d6ae3`, `4acdbe0`, and `6ac3089` —
  PASS, exit 0, all 8 steps; 1013 tests; ruff/mypy clean; Gitleaks dir+git "no leaks
  found" (54 commits scanned); prohibited-pattern and constant-time checks clean.
- Phase 9 adds no migration; Alembic head remains `f7a8b9c0d1e2`.

## Next

Phase 10 — security hardening and AI-assisted monitoring (blueprint §§17, 20.3, 21):
threat-model review, abuse/load tests, deterministic alert rules with tested actions, an
optional local read-only audit summarizer with adversarial-log tests, runbooks, and a
CycloneDX SBOM. See [../NEXT_SESSION.md](../NEXT_SESSION.md).
