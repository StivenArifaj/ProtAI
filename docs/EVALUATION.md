# Evaluation

As of **Phase 9 (evaluation harness, 2026-10-29, blueprint v1.2)**.

This document describes the measurement layer, not a security control. The harness runs
the shipped implementations against repository-owned synthetic fixtures and writes JSON
and Markdown reports. It adds no route, no authority, and no execution path; policy
remains the sole `ALLOW` producer and the gateway remains the only way a tool runs.
Authoritative artifacts live in `evaluation/reports/`; the dataset update procedure and
full result interpretation are in `evaluation/README.md`.

Related: [ADR-016](adr/ADR-016-evaluation-harness-and-dataset-contract.md),
[IMPLEMENTATION_STATE.md](IMPLEMENTATION_STATE.md),
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md), and blueprint §§19.1-19.6.

## What is measured

Six tasks are reported separately. There is no cross-task aggregate accuracy.

| Task | Implementation exercised | Positive class / label convention |
|---|---|---|
| `input_detection` | `InputDefenseService.inspect` | malicious or unauthorized input; `detection` counts `FLAG`/`REJECT`/`QUARANTINE` as observed positive, `gating` counts only `REJECT`/`QUARANTINE` |
| `dlp_egress` | `OutputDefenseService.inspect_egress` | protected content that must not egress to the declared destination; any non-`PASS` outcome is observed protected |
| `dlp_response` | `OutputDefenseService.inspect_output` + `redact_payload` | protected content that must not be released unmodified; any non-`PASS` outcome is observed protected, and released data is checked for forbidden substrings |
| `risk` | `assess_risk` (`risk-v2`) | no probability label; exact score, exact factor codes, band, and ordering conformance |
| `intent` | `IntentManifestService.extract_and_issue` | multiclass status confusion; active-manifest expectations and separate unexpected/missed-manifest rates |
| `authorization` | real `ToolGateway.invoke_tool`, registry, policy, DLP, and mock adapters | an action that must not execute; an executed positive case is an unauthorized side effect |

The authorization task counts actual adapter calls and sink writes through wrapped
adapters and a sink store. A detector miss that the gateway still blocks is not an
attack success. The intent task uses `MockIntentExtractor` and deterministic
transcript-backed local-provider responses; it measures conformance of the extractor and
gating, not live-model accuracy.

## Reproduce

```bash
# Full dataset: all 106 cases and all three splits
uv run --frozen python -m ai_security.evaluation \
  --dataset evaluation/dataset_manifest.yaml \
  --output-dir evaluation/reports

# Convenience wrapper with the same defaults
uv run --frozen python evaluation/run_evaluation.py

# Quick regression: 15 dev cases covering every task; exit 2 on a failed expectation
uv run --frozen python -m ai_security.evaluation \
  --dataset evaluation/dataset_manifest.yaml \
  --output-dir evaluation/reports \
  --split dev --quick --report-name quick_report --fail-on-failures

# Harness tests (metric arithmetic, dataset/split refusal, metadata, reports, CLI)
uv run --frozen pytest tests/evaluation
```

Exit codes: `0` report written; `1` dataset/manifest verification failed (nothing runs);
`2` `--fail-on-failures` saw at least one failed expectation. `--quick` is valid only
with `--split dev`.

## Dataset, provenance, and splits

`evaluation/dataset_manifest.yaml` is strict YAML and pins the dataset version, seed,
creation date, provenance, license, fixture SHA256 hashes, and exact case counts. Each
fixture is JSONL with one strict case object per line. Every case has `case_id`, task,
category, split, `template_id`, provenance, license, and `synthetic: true`; task
payloads use the shipped vocabularies and reject unknown fields.

The current dataset is `2026.10.28-v1`: **106 cases** — input 20, DLP egress 16, DLP
response 14, risk 18, intent 18, authorization 20. Splits are **42 dev / 34 validation /
30 holdout**; the quick subset is **15 dev cases** and covers all six tasks.

All cases are original synthetic fixtures, released with this repository under
CC0-1.0. Canaries use `CANARY_SECRET_`; synthetic PII uses `example.test`. No public
benchmark, customer record, real credential, or third-party extract is vendored.

The loader refuses, before execution: hash or count mismatches, duplicate JSON keys or
case IDs, exact duplicate content, cross-split `(task, template_id)` leakage, split files
that are not an exact partition or disagree with a case, unknown split names, a quick
subset that is empty/oversized/non-dev/incomplete, and path escapes. The holdout split is
never used to tune a threshold. Phase 9 changed no detector, policy, DLP, risk, or model
threshold.

## Metric semantics

For a declared positive class: `TP` positive observed positive, `FN` positive observed
negative, `FP` negative observed positive, `TN` negative observed negative.
`precision = TP/(TP+FP)`, `recall = TP/(TP+FN)`, `F1 = 2PR/(P+R)`,
`accuracy = (TP+TN)/total`, `FPR = FP/(FP+TN)`, `FNR = FN/(TP+FN)`. An undefined
denominator is `null` in JSON and `N/A` in Markdown, never `0`. FNR equals `1 - recall`
only for the same positive class, sample set, threshold, and missing-value convention.

Per-category matrices are reported alongside the overall matrix. Latency is in-process
wall-clock time per case, summarized with the nearest-rank p50/p95/p99 and sample count;
it is not production latency or a throughput claim.

## Measured baseline

Full run on 2026-10-28 (dataset `2026.10.28-v1`, source revision `17b9fb0`, Python
3.12.15, macOS arm64): **106 cases, 3 failed expectations, 0 unauthorized side effects,
0 DLP leak failures, 0 detector errors, 0 skipped tasks.** Full hashes, timestamps, and
hardware are in `evaluation/reports/evaluation_report.json`.

| Task | Result |
|---|---|
| `input_detection` | detection 14 TP / 3 TN / 3 FP / 0 FN (precision 0.824, recall 1.000, FPR 0.500); gating 13 TP / 5 TN / 1 FP / 1 FN (precision 0.929, recall 0.929, FPR 0.167) |
| `dlp_egress` | 11 protected blocked, 5 benign passed; protected matrix 11 TP / 5 TN / 0 FP / 0 FN |
| `dlp_response` | 10 protected handled (6 redacted releases, 4 suppressed), 4 benign passed; matrix 10 TP / 4 TN / 0 FP / 0 FN |
| `risk` | 18/18 exact score and factor codes; 18/18 band matches; 0 ordering violations |
| `intent` | 18/18 status matches; 0 unexpected and 0 missed manifests; 0 constraint/resource mismatches; 11 provider calls, 1 retry |
| `authorization` | 20/20 expected outcomes; 15 must-not-execute blocked, 5 expected executions, 0 unauthorized executions, 1 expected/observed sink write, 93 in-memory audit events, 0 forbidden-content leaks |

Latency (in-process, milliseconds, nearest rank):

| Task | n | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| `input_detection` | 20 | 0.072 | 0.154 | 0.228 |
| `dlp_egress` | 16 | 0.032 | 0.144 | 0.144 |
| `dlp_response` | 14 | 0.023 | 0.057 | 0.057 |
| `risk` | 18 | 0.006 | 0.019 | 0.019 |
| `intent` | 18 | 0.042 | 0.129 | 0.129 |
| `authorization` | 20 | 0.137 | 0.477 | 0.965 |

The three failed expectations are hard-negative input cases:
`in-dev-quote-01` (`FLAG`), `in-dev-readthis-01` (`QUARANTINE`), and
`in-val-quote-01` (`FLAG`). They are reported, not suppressed or tuned away. The
15-case quick subset passes 15/15 with 0 unauthorized side effects and 0 DLP leaks.

### Interpretation

- Detection and gating are deliberately different: the one malicious case that is
  flagged but not gated is a detector success and a gating miss, and the matrices say so.
- The hard-negative false positives are a real measured weakness of the English-pattern
  heuristics. They raise review noise; they do not authorize anything.
- The authorization matrix is green on this synthetic dataset, which shows the gateway
  contract holds for these cases. It is not evidence of real-world completeness: the
  dataset is small, synthetic, and written by the same project. The holdout split was
  not used for tuning, but it is not an independent third-party sample.
- Perfect DLP matrices reflect the five configured deterministic patterns over fixtures
  designed to exercise them. They are not a claim of exhaustive secret/PII detection.
- Risk conformance is exact for the current factor set. Weights and the 40/80 thresholds
  remain uncalibrated defaults; no calibration or probability claim is made.

## Report contract

Each run writes `<name>.json` (authoritative) and `<name>.md` (derived from the JSON
values). The JSON contains:

- report schema/type/harness version, exact command, generated timestamp, seed, dataset
  version, manifest and split hashes, selected splits/case counts;
- git commit/branch (read directly from `.git`, `null` when unavailable), Python,
  platform, machine, CPU count, memory, and the `uv.lock` SHA256 when present;
- policy/risk-threshold/input-defense/output-DLP versions and hashes, configured
  thresholds, risk-engine version, and intent-extractor versions;
- per-task counts, latency, confusion matrices overall and per category, task-specific
  derived rates, failure details, and multiclass counts where applicable;
- detector/provider failures and retries, unauthorized side effects, DLP leaks,
  skipped tests, known limitations, metric definitions, and the reproduction command.

No desired result is baked into the report or the README. Reports were produced by the
checked-in harness; regenerating them is the only way to change a value. A report
committed after the run names the revision checked out at run time, so its
`metadata.git.commit` is the parent revision.

## Limitations

- Latency is local, in-process, single-machine, and not production latency or throughput.
- All 106 cases are synthetic and small. There is no public benchmark adapter, no
  third-party holdout, and no claim of comparability with InjecAgent, AgentDojo, or any
  other benchmark.
- Authorization evaluation uses mock adapters, an in-memory audit recorder, a fixed
  clock, and no PostgreSQL, HTTP ingress, host authentication, approvals, or real
  connectors. Approval-required paths are covered by the Phase 5 test suite, not this
  dataset.
- Intent evaluation is deterministic transcript conformance, not live local-model
  accuracy; the model remains optional and uncalibrated.
- Risk weights and thresholds are uncalibrated. The report measures conformance and
  ordering, not calibration.
- Input detection is English-pattern based; DLP is deterministic pattern matching.
  The measured false positives/negatives bound behavior only on these fixtures.
- No coverage measurement and no continuous CI run; the 8-step local gate and
  `tests/evaluation` are the regression mechanism.

Update procedure, provenance rules, and the full task table are in
`evaluation/README.md`. Never add real secrets, private documents, customer records, or
public-benchmark extracts to `evaluation/`; update the manifest hashes and split file
together and re-run both commands.
