# ProtAI evaluation harness

This directory contains the Phase 9 measurement artifacts: a repository-owned synthetic
dataset, its strict manifest, and generated JSON/Markdown reports. The implementation
lives in `src/ai_security/evaluation/`.

The harness observes the shipped components. It is **not** an authority path: it does not
add HTTP routes, bypass authentication, policy, input defense, or DLP, and it never writes
to the production audit chain. Authorization cases run the real gateway, registry, policy
engine, and output-DLP service with in-memory mock adapters, an in-memory audit recorder,
and a sink store used to count actual side effects.

## Run it

```bash
# Full dataset (all splits, 106 cases)
uv run --frozen python -m ai_security.evaluation \
  --dataset evaluation/dataset_manifest.yaml \
  --output-dir evaluation/reports

# Convenience entry point (same defaults)
uv run --frozen python evaluation/run_evaluation.py

# Dev-only 15-case quick regression; exits 2 on any failed expectation
uv run --frozen python -m ai_security.evaluation \
  --dataset evaluation/dataset_manifest.yaml \
  --output-dir evaluation/reports \
  --split dev --quick --report-name quick_report --fail-on-failures
```

Both commands write `<report-name>.json` (authoritative) and `<report-name>.md`
(derived from the JSON values). Every run verifies the manifest, fixture SHA256 hashes,
case counts, split partition, and quick subset before executing a case.

Tests:

```bash
uv run --frozen pytest tests/evaluation
```

## Dataset contract

`dataset_manifest.yaml` pins:

- six fixture files, one per task, each with a SHA256 hash and exact case count;
- an explicit `splits/splits.json` partition (`dev` / `validation` / `holdout`) with
  counts, plus a dev-only quick subset;
- dataset version, seed, creation date, provenance, and license.

Every case carries `case_id`, task, category, split, `template_id`, provenance, license,
and `synthetic: true`. Task payloads use the shipped vocabularies (`TrustLabel`,
`DataClass`, `SideEffectClass`, `FirewallDecision`, `InvocationOutcome`,
`IntentResolutionStatus`). Unknown fields are rejected.

The loader refuses, before running anything:

- missing, unreadable, non-UTF-8, hashed-mismatched, or miscounted fixtures;
- duplicate JSON keys, duplicate case IDs, or a case whose task differs from its file;
- a split file that is not an exact partition, disagrees with a case's declared split,
  references an unknown case, or leaves a case unassigned;
- the same `(task, template_id)` in more than one split;
- exact duplicate content (which would double-count a metric);
- a quick subset that is empty, larger than 30 cases, uses a non-dev case, or omits a
  task.

### Provenance and license

All 106 cases are original synthetic fixtures authored for ProtAI. They are released
with this repository under CC0-1.0. No third-party, customer, public-benchmark, or real
credential data is vendored. Synthetic canaries use the prefix `CANARY_SECRET_` and
synthetic PII uses the reserved `example.test` domain.

Public benchmark adapters (for example InjecAgent or AgentDojo) are **not** implemented.
Adding one would require a verified license, a pinned dataset version, a reproducible
download hash, and an explicit opt-in; none of those conditions is currently met, so the
harness reports the absence rather than implying comparability.

### Splits

`dev` is for development and the quick regression. `validation` is for inspecting
behavior while designing cases. `holdout` is never used to tune a threshold. The three
sets are disjoint by case and by template. No threshold was tuned on any split, and the
three reported input false positives were left in place rather than tuned away.

## Tasks and positive classes

| Task | What runs | Positive class |
| --- | --- | --- |
| `input_detection` | `InputDefenseService.inspect` | malicious/unauthorized input |
| `dlp_egress` | `OutputDefenseService.inspect_egress` | protected content that must not egress |
| `dlp_response` | `OutputDefenseService.inspect_output` + redaction | protected content that must not be released unmodified |
| `risk` | `assess_risk` (`risk-v2`) | no probability label; exact score, factors, band, and ordering conformance |
| `intent` | `IntentManifestService.extract_and_issue` | multiclass status confusion; no single aggregate accuracy |
| `authorization` | real `ToolGateway.invoke_tool` with mock adapters | an action that must not execute |

The input task reports two matrices: `detection` (`FLAG`/`REJECT`/`QUARANTINE` observed
as positive) and `gating` (`REJECT`/`QUARANTINE` observed as positive). This distinction
is deliberate: `FLAG` records a finding without blocking execution.

The authorization task counts actual adapter executions and sink writes. A positive case
that executes is an unauthorized side effect, regardless of what any detector reported.
`ASK_USER` is never treated as executable without an approval, and approval paths are
covered by the Phase 5 test suite, not by this dataset.

## Metric semantics

- Confusion matrices are counts only. `tp`/`fn` are positive cases observed
  positive/negative; `fp`/`tn` are negative cases observed positive/negative.
- `precision = TP / (TP + FP)`, `recall = TP / (TP + FN)`,
  `F1 = 2PR / (P + R)`, `accuracy = (TP + TN) / total`,
  `FPR = FP / (FP + TN)`, `FNR = FN / (TP + FN)`.
- An undefined denominator is `null` in JSON and `N/A` in Markdown, never `0`.
- Latency uses nearest-rank p50/p95/p99 over in-process wall-clock samples and is
  labelled as such. It is not production latency or a throughput claim.
- Intent statuses are compared as a multiclass matrix. `unexpected_manifest_rate` and
  `missed_manifest_rate` use separate denominators.
- Risk reports exact-score/exact-factor/band conformance and monotonic ordering; it
  makes no calibration claim.

## Current baseline (2026-10-28, dataset `2026.10.28-v1`)

Full run: 106 cases, 3 failed expectations, 0 unauthorized side effects, 0 DLP leaks.

| Task | Result |
| --- | --- |
| `input_detection` | 14 TP / 3 TN / 3 FP / 0 FN; gating 13 TP / 5 TN / 1 FP / 1 FN |
| `dlp_egress` | 16/16 expectations met (11 protected blocked, 5 benign passed) |
| `dlp_response` | 14/14 expectations met |
| `risk` | 18/18 exact score and factor matches |
| `intent` | 18/18 status matches; provider calls/retries recorded |
| `authorization` | 20/20; 0 unauthorized executions; 1 expected sink write |

The three failures are intentional hard-negative input cases:
`in-dev-quote-01`, `in-dev-readthis-01`, and `in-val-quote-01`. The detector flags
quoted educational text and a benign "when you read this" phrase. They are reported, not
suppressed, because tuning them away would require a detector change outside Phase 9's
measurement scope. The quick subset passes 15/15 and is the regression gate.

## Updating the dataset

1. Edit or add cases in `evaluation/fixtures/<task>.jsonl` (one JSON object per line).
   Keep IDs unique, keep templates inside one split, and do not duplicate content.
2. Update `evaluation/splits/splits.json` so every case appears in exactly one split and
   the quick subset still covers every task using dev cases only.
3. Recompute the SHA256 hashes and case counts, then update `dataset_manifest.yaml`.
   `sha256_file` and the manifest contract are the source of truth; do not hand-edit a
   hash without changing the bytes.
4. Run the full command and the quick command. Both must load successfully; inspect the
   diffs in `evaluation/reports/`. A changed result is a measurement finding, not a
   reason to retune thresholds.
5. Update this README's baseline section if the reported results change, and record the
   reason in the phase memory.

Never add a real secret, a private document, a customer record, or a public benchmark
extract to `evaluation/`. Canaries must be synthetic and clearly labeled.

## Reports

The JSON report includes:

- run metadata: harness version, generated timestamp, exact command, dataset version and
  manifest/split hashes, seed, git commit/branch, Python/platform/CPU, `uv.lock` hash,
  policy/risk-threshold/input-DLP/output-DLP versions and hashes, risk-engine and intent
  extractor versions, thresholds;
- summary counts, failed-case rate, unauthorized side effects, DLP leaks, intent provider
  calls/retries, detector errors;
- per-task counts, latency sample count and percentiles, confusion matrices overall and
  per category, task-specific derived rates, and failure details;
- skipped tasks, known limitations, metric definitions, and the reproduction command.

Markdown is rendered from the same values and is not independently authoritative. The
`metadata.git.commit` field records the source revision checked out when the run was
produced; a report committed afterwards will name its parent revision unless regenerated.

## Known limitations

See the report's `limitations` block and `docs/KNOWN_LIMITATIONS.md`. In particular:

- latency is local and in-process; no production or comparative claim is made;
- authorization evaluation uses mock adapters and no PostgreSQL, HTTP ingress, host
  authentication, or approval resumption;
- intent evaluation uses deterministic mock and transcript-backed outputs, not a live
  model;
- risk weights and thresholds are uncalibrated initial defaults;
- input detection is English-pattern based and produces the three hard-negative false
  positives above;
- DLP is deterministic pattern/classification based and does not claim exhaustive
  semantic coverage;
- no public benchmark adapter is provided or implied.
