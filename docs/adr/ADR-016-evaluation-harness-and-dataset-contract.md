# ADR-016: Evaluation harness, positive-class labels, split discipline, and report contract

- **Status:** Accepted
- **Date:** 2026-10-29
- **Phase:** 9 (evaluation harness and benchmark adapters)
- **Blueprint:** §§19.1-19.6, 20.1, 21 (Phase 9)
- **References:** ADR-008 (policy authority), ADR-009 (gateway), ADR-010 (advisory input
  defense), ADR-011 (intent manifests), ADR-012 (approvals), ADR-013 (output DLP),
  ADR-014 (audit), ADR-015 (ingress and local model)

## Context

Through Phase 8 the security claims were tested by contract suites but not measured by a
reproducible evaluation artifact. Phase 9 must produce a versioned fixture set, separate
task measurements, and JSON/Markdown reports without adding authority or changing the
behavior it measures. Three contracts are easy to get silently wrong:

1. what counts as a positive case in each task, especially when detection is not
   authorization;
2. how fixtures stay split without template/content leakage or holdout tuning; and
3. which artifact is authoritative when the JSON and Markdown disagree, and how an
   undefined metric is serialized.

## Decision

### Measurement-only boundary

The harness lives in `src/ai_security/evaluation/`; the versioned dataset and generated
reports live in `evaluation/`. It observes the shipped components:

- input detection and DLP are called directly on their services;
- authorization runs the real `ToolGateway`, registry, policy engine, and
  `OutputDefenseService` with in-memory mock adapters, a counting adapter wrapper, an
  `InMemoryAuditRecorder`, and a sink store;
- intent runs the real `IntentManifestService` with the mock extractor and a
  deterministic transcript-backed provider.

The harness does **not** add HTTP routes, call the ingress, bypass authentication,
policy, input defense, or DLP, consume approvals, or write to the production audit
chain. It constructs the same in-process services the tests use. It is not an authority:
it cannot return `ALLOW`, execute an ungated tool, or turn a failed control into a pass.
Evaluation-only fixtures and in-memory adapters are not reachable from the application.

### Dataset contract

`evaluation/dataset_manifest.yaml` is strict YAML with `schema_version`,
`dataset_version`, seed, creation date, provenance, license, and a fixture entry per
task (`path`, `sha256`, `case_count`). The loader:

- resolves only relative member paths below the manifest directory and rejects escapes;
- reads UTF-8 JSONL, rejects blank lines and duplicate JSON object keys, and validates
  each case against a strict task model (`extra="forbid"`);
- requires `case_id`, task, category, split, `template_id`, provenance, license, and
  `synthetic: true` on every case;
- verifies each fixture's SHA256 and exact count against the manifest;
- verifies the split file's own dataset version, partition, counts, and hashes.

All cases are original synthetic fixtures released under CC0-1.0. Canaries use the
`CANARY_SECRET_` prefix; synthetic PII uses `example.test`. No real secret, private
document, customer record, third-party extract, or public benchmark is vendored.
Optional public-benchmark adapters are out of scope unless a license, pinned version,
reproducible download hash, and explicit opt-in are all verified; none is present, so the
harness reports the absence rather than implying comparability.

### Split contract

`evaluation/splits/splits.json` is the only split authority. The loader refuses:

- a split name outside `dev` / `validation` / `holdout`;
- a case missing from the split file, a split case that does not exist, or a case whose
  declared split disagrees with the file;
- a repeated case across splits, or split counts that disagree with the file/manifest;
- the same `(task, template_id)` in more than one split;
- exact duplicate content anywhere in the dataset (which would double-count a metric);
- a quick subset that is empty, larger than 30 cases, contains a non-dev case, or omits
  any of the six tasks.

The quick subset is a dev-only regression subset, not a second implementation. `dev` is
for development and the quick run; `validation` is for inspecting behavior; `holdout` is
never used to tune a threshold. Phase 9 changed no detector, policy, DLP, risk, or model
threshold, and the three measured hard-negative false positives were left in place.

### Positive class by task

Labels stay task-specific; there is no aggregate cross-task accuracy.

| Task | Positive class | Observed positive |
|---|---|---|
| `input_detection` / `detection` | malicious or unauthorized input | disposition `FLAG`, `REJECT`, or `QUARANTINE` |
| `input_detection` / `gating` | malicious input that must not proceed | disposition `REJECT` or `QUARANTINE` |
| `dlp_egress` | protected content that must not egress to the declared destination | any non-`PASS` inspection outcome |
| `dlp_response` | protected content that must not be released unmodified | any non-`PASS` outcome, with released data checked for forbidden substrings |
| `authorization` | an action that must not execute | no adapter call and no sink write |
| `risk` | no probability label | exact score/factor/band conformance and monotonic ordering |
| `intent` | multiclass status, not binary accuracy | exact expected status plus manifest/constraint/resource conformance |

`FLAG` is deliberately not gating: a detector finding can raise review noise while the
request proceeds. Reporting `detection` and `gating` separately prevents a flagged merge
from being counted as a blocked one. Authorization counts the prohibited effect that
actually occurred, not a detector miss. `ASK_USER` is never executable without an
approval; approval paths are covered by the Phase 5 suite rather than this dataset.

### Metric and report contract

Metrics are computed from counts. `precision`, `recall`, `F1`, `FPR`, and `FNR` are
`null` when their denominator is zero and render as `N/A` in Markdown, never `0`.
`FNR == 1 - recall` is asserted only for the same positive class, sample set, threshold,
and missing-value convention. Per-category matrices are reported with the overall matrix.
Latency is nearest-rank p50/p95/p99 over in-process wall-clock samples, with the sample
count, and is labelled local/in-process.

JSON is authoritative. Markdown is rendered from the JSON values and cannot add or alter
a metric. Each report includes the §19.6 artifact set: dataset counts/version, per-task
and per-category confusion matrices, metric definitions/values, latency and sample
counts, detector/provider failures and retries, unauthorized side effects, configuration
and version metadata (git commit/branch, lock hash, policy/detector/risk/model versions,
thresholds, Python/hardware, timestamp, seed), known limitations, skipped tests, and the
exact reproduction command. Git metadata is read directly from `.git/HEAD` and refs
without `subprocess`; a missing repository or lockfile yields `null`, never a fabricated
value. Report names must be a plain file stem, so a run cannot write outside the chosen
output directory.

The CLI verifies the dataset before running anything. Exit codes are `0` for a written
report, `1` for dataset/verification failure, and `2` when `--fail-on-failures` observes
a failed expectation. The 15-case quick subset is wired into the normal test suite so
the runner contract is exercised on every gate run.

## Alternatives considered

- **One aggregate accuracy number.** Rejected: blueprint §19.2 and the controls'
  different failure modes make aggregation misleading. Detection, gating, DLP release,
  risk conformance, intent status, and unauthorized side effects are separate facts.
- **Treat a detector miss as an attack success.** Rejected: the gateway may still block
  the action. Authorization success must be an observed prohibited effect.
- **Run the HTTP ingress and PostgreSQL in evaluation.** Rejected: it would measure
  transport/database availability and require host credentials, while the Phase 9
  question is control behavior. Mock adapters plus the real gateway isolate that. The
  limitation is stated in the report.
- **Vendor a public benchmark.** Rejected: no verified license, pinned version, and
  reproducible download hash; a partial adapter would invite invalid comparisons.
- **Retune the input detector until hard negatives pass.** Rejected: Phase 9 is
  measurement-only. The false positives are reported as findings; a detector change
  needs its own phase and regression coverage.
- **Serialize an undefined denominator as zero.** Rejected: it makes a missing sample
  look like a perfect failure rate and corrupts comparisons.
- **Expose evaluation as a service or route.** Rejected: it would create a second
  authority/execution surface. The CLI is the only entry point.

## Consequences

- Phase 9 adds a reproducible baseline of 106 synthetic cases, 42/34/30 across
  dev/validation/holdout, and a 15-case quick gate.
- The measured full run (2026-10-28, revision `17b9fb0`) has 3 failed expectations out of
  106, all hard-negative input false positives, 0 unauthorized side effects, 0 DLP leak
  failures, and 0 skipped tasks. The quick subset is green.
- Risk weights and thresholds remain uncalibrated; this ADR records a measurement
  contract, not a calibration result. Calibration needs a larger labeled set and is
  separate work.
- Reports are committed as evidence. Regenerating them changes the measured baseline
  only through changed code or fixtures, and any such change must be explained in the
  phase memory.
- Public benchmark adapters remain absent. Adding one later requires its own license/
  version/reproducibility review and must stay optional and separate from the
  deterministic fixture suite.
