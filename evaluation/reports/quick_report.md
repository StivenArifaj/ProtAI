# ProtAI evaluation report

- Generated: `2026-10-29T08:02:00.951510Z`
- Dataset: `2026.10.28-v1` (seed `20261028`)
- Cases: 15 selected / 106 total; splits: `dev`
- Quick subset: yes (partial)
- Git commit: `17b9fb0a7637150a1a8d6fcbabc6c2ecff393045` on branch `main`
- Policy: `dev-1` (`8a4ba203e3ba…`); thresholds: ASK_USER >= 40, BLOCK >= 80
- Python: 3.12.15 on macOS-26.7-arm64-arm-64bit (arm64)
- Dependency lock sha256: `afdbb9d254209515b4e582d4419a4098c2905c58a8243b21229fe859fd8767ae`
- Command: `python -m ai_security.evaluation --dataset evaluation/dataset_manifest.yaml --output-dir evaluation/reports --split dev --quick --report-name quick_report --fail-on-failures`

## Headline

| Metric | Value |
| --- | --- |
| `case_count` | 15 |
| `failed_cases` | 0 |
| `failed_case_rate` | 0.000 |
| `unauthorized_side_effects` | 0 |
| `unauthorized_side_effect_rate` | 0.000 |
| `dlp_leak_failures` | 0 |
| `intent_unexpected_manifests` | 0 |
| `intent_provider_calls` | 1 |
| `intent_provider_retries` | 0 |
| `input_detector_errors` | 0 |

## Tasks

| Task | Cases | p50 ms | p95 ms | p99 ms | Failed |
| --- | ---: | ---: | ---: | ---: | ---: |
| `input_detection` | 3 | 0.087 | 0.235 | 0.235 | 0 |
| `dlp_egress` | 2 | 0.056 | 0.136 | 0.136 | 0 |
| `dlp_response` | 2 | 0.019 | 0.044 | 0.044 | 0 |
| `risk` | 2 | 0.011 | 0.017 | 0.017 | 0 |
| `intent` | 3 | 0.094 | 0.123 | 0.123 | 0 |
| `authorization` | 3 | 0.438 | 0.914 | 0.914 | 0 |

## Confusion matrices

Positive classes are declared per block. `N/A` means the denominator is zero; it is never reported as zero.

### input_detection

**detection** — positive: malicious or unauthorized input

| Slice | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `overall` | 2 | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| `category/benign` | 0 | 1 | 0 | 0 | N/A | N/A | N/A | 1.000 | 0.000 | N/A |
| `category/direct_override` | 1 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | N/A | 0.000 |
| `category/obfuscated_or_malformed` | 1 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | N/A | 0.000 |

**gating** — positive: malicious input that must be gated (REJECT or QUARANTINE)

| Slice | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `overall` | 1 | 1 | 0 | 1 | 1.000 | 0.500 | 0.667 | 0.667 | 0.000 | 0.500 |
| `category/benign` | 0 | 1 | 0 | 0 | N/A | N/A | N/A | 1.000 | 0.000 | N/A |
| `category/direct_override` | 1 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | N/A | 0.000 |
| `category/obfuscated_or_malformed` | 0 | 0 | 0 | 1 | N/A | 0.000 | N/A | 0.000 | N/A | 1.000 |

### dlp_egress

**protected** — positive: protected content that must not egress to the declared destination

| Slice | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `overall` | 1 | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| `category/benign` | 0 | 1 | 0 | 0 | N/A | N/A | N/A | 1.000 | 0.000 | N/A |
| `category/secret_canary` | 1 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | N/A | 0.000 |

### dlp_response

**protected** — positive: protected content that must not be released unmodified

| Slice | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `overall` | 1 | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| `category/benign` | 0 | 1 | 0 | 0 | N/A | N/A | N/A | 1.000 | 0.000 | N/A |
| `category/pii_classification` | 1 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | N/A | 0.000 |

### risk

### intent

### authorization

**must_not_execute** — positive: an action that must not execute; an executed positive case is an unauthorized side effect

| Slice | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `overall` | 1 | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| `category/allow_read` | 0 | 1 | 0 | 0 | N/A | N/A | N/A | 1.000 | 0.000 | N/A |
| `category/dlp_response` | 0 | 1 | 0 | 0 | N/A | N/A | N/A | 1.000 | 0.000 | N/A |
| `category/resource_scope` | 1 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | N/A | 0.000 |

## Security-critical counts

### input_detection

| Count | Value |
| --- | ---: |
| `total` | 3 |
| `malicious` | 2 |
| `benign` | 1 |
| `malicious_gated` | 1 |
| `malicious_not_gated` | 1 |
| `benign_gated` | 0 |
| `detector_errors` | 0 |

| Derived | Value |
| --- | ---: |
| `malicious_gate_rate` | 0.500 |
| `benign_gate_rate` | 0.000 |

### risk

| Count | Value |
| --- | ---: |
| `total` | 2 |
| `exact_score` | 2 |
| `exact_factors` | 2 |
| `band_matches` | 2 |
| `ordering_violations` | 0 |

| Derived | Value |
| --- | ---: |
| `exact_score_rate` | 1.000 |
| `exact_factor_rate` | 1.000 |
| `band_match_rate` | 1.000 |
| `ordering_violation_count` | 0 |

### intent

| Count | Value |
| --- | ---: |
| `total` | 3 |
| `expected_active` | 2 |
| `expected_non_active` | 1 |
| `mock_cases` | 2 |
| `local_cases` | 1 |
| `status_matches` | 3 |
| `unexpected_manifests` | 0 |
| `missed_manifests` | 0 |
| `constraint_mismatches` | 0 |
| `resource_mismatches` | 0 |
| `provider_calls` | 1 |
| `provider_retries` | 0 |

| Derived | Value |
| --- | ---: |
| `status_match_rate` | 1.000 |
| `unexpected_manifest_rate` | 0.000 |
| `missed_manifest_rate` | 0.000 |
| `constraint_mismatch_rate` | 0.000 |
| `provider_retry_rate` | 0.000 |

### authorization

| Count | Value |
| --- | ---: |
| `total` | 3 |
| `blocked_expected` | 1 |
| `executed_expected` | 2 |
| `unauthorized_executions` | 0 |
| `missed_executions` | 0 |
| `outcome_mismatches` | 0 |
| `reason_mismatches` | 0 |
| `forbidden_content_leaks` | 0 |
| `sink_writes_expected` | 0 |
| `sink_writes_observed` | 0 |
| `audit_events_recorded` | 20 |

| Derived | Value |
| --- | ---: |
| `unauthorized_side_effect_count` | 0 |
| `unauthorized_side_effect_rate` | 0.000 |
| `missed_execution_rate` | 0.000 |
| `sink_write_mismatch` | 0 |

## Failures

No failed cases.

## Skipped tests

None.

## Limitations

- Latency is measured in-process on the machine in the metadata block; it is not production latency, throughput, or a capacity claim.
- All cases are original synthetic fixtures. No public benchmark dataset is vendored or implied, and no result is comparable to a benchmark run without matching the model, tools, agent scaffold, and configuration.
- The authorization task runs the real gateway/policy/registry/DLP over in-memory mock adapters. It does not exercise PostgreSQL durability, the HTTP ingress, host authentication, approvals, or real connectors.
- The intent task measures extractor and gating conformance against the deterministic mock extractor and transcript-backed local-provider outputs; it is not a live-model accuracy estimate.
- Risk weights and thresholds are uncalibrated initial defaults. The risk task reports score/factor/band conformance and ordering, never probability calibration.
- Shipped read-only and mock-sink capabilities produce no ASK_USER row in this dataset; approval-required paths remain covered by the Phase 5 approval test suite.
- No threshold was tuned on any split. Holdout results are only meaningful under that discipline and are reported as observed.

## Metric definitions

- **positive_class**: Declared per task/block. TP is an expected-positive case observed positive; FN is expected positive observed negative; FP is expected negative observed positive; TN is expected negative observed negative.
- **precision**: TP / (TP + FP); undefined (N/A) when TP + FP = 0.
- **recall**: TP / (TP + FN); undefined (N/A) when TP + FN = 0.
- **f1**: 2 * precision * recall / (precision + recall); undefined when either component is undefined, and 0.0 when both are defined and zero.
- **accuracy**: (TP + TN) / total; undefined (N/A) when the sample count is zero.
- **false_positive_rate**: FP / (FP + TN); undefined (N/A) when FP + TN = 0.
- **false_negative_rate**: FN / (TP + FN); undefined (N/A) when TP + FN = 0. For the authorization must-not-execute block this is the unauthorized side-effect rate.
- **latency**: Nearest-rank p50/p95/p99 over in-process wall-clock samples. It is not production latency and no throughput claim is made.
