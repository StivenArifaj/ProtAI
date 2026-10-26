# Phase 6 — Output DLP and Egress Policy: COMPLETE — VERIFIED

**Completed:** 2026-10-26
**Blueprint:** v1.2 §§6.1, 15.1-15.5, 16.1, 16.3, 20.2 #9/#14/#21, §21 Phase 6
**ADR:** [../../docs/adr/ADR-013-output-dlp-and-egress.md](../../docs/adr/ADR-013-output-dlp-and-egress.md)
**Evidence:** V63-V66 in [../TESTING_AND_VERIFICATION.md](../TESTING_AND_VERIFICATION.md)
**Commits:** `df70cd9` (implementation/tests/config), `e8919cb` (finding-cap fail-closed),
`e586c81` (complete credential-value redaction), `98cfdde` (ADR-013/docs),
`9e78933` (memory/completion), plus this final V66 status record commit.

## Definition of Done — verdict

| Criterion | Status | Evidence |
|---|---|---|
| Canary data never reaches an unauthorized mock sink | PASS | `test_gateway.py::test_synthetic_canary_never_reaches_an_enabled_sink` enables the sink, submits canary arguments, and asserts `dlp_egress_blocked`, zero adapter calls, and byte-identical sink state; detector-boundary and real-PostgreSQL e2e/no-bypass tests assert the same result |
| Release and deny outcomes are typed and audited | PASS | Closed `DlpOutcome` (`PASS`/`REDACT`/`BLOCK`/`REVIEW`), `dlp_egress_blocked`/`dlp_inspection_failed`, and `InvocationOutcome.response_blocked`; decision and outcome events carry the additive redacted `dlp` record; durable order/linkage tested |
| DLP logs/evidence remain redacted | PASS | Findings store code/category/count/bounded field paths only; tests serialize reports and audit payloads and require canary, email, and credential values to be absent; paths reject control characters and over-length values |
| False-positive cases are documented | PASS | [../../docs/OUTPUT_DLP_FALSE_POSITIVES.md](../../docs/OUTPUT_DLP_FALSE_POSITIVES.md) records tested benign cases, known false positives, intentional false negatives, fail-closed behavior, and tuning guidance; benign-lookalike regression tests exist |
| Gateway remains the only execution path | PASS | Mandatory constructor-injected `OutputDefenseService`; no adapter call on any egress denial or release suppression; the single `invoke_tool` chokepoint and digest-bound execution authorization are unchanged |
| All prior suites and the 8-step gate stay green | PASS | V63-V66: **766 passed** (640 unit + 85 integration + 41 security), mypy 64 source files, ruff clean, Gitleaks clean (36 commits) |
| ADR-008/009/010/011/012 contracts untouched | PASS | Policy remains the sole `ALLOW` producer; gateway/intent/approval boundaries intact; approval only gains effective-class binding; all prior suites green |

## Delivered

### Strict output-DLP configuration (`config/output_dlp.yaml`)

- Schema `1`, version `1.0.1`; frozen, `extra="forbid"` models; duplicate YAML keys and
  unknown fields rejected by the shared safe loader.
- Five deterministic detectors: synthetic canary (`RESTRICTED`/`BLOCK`), private-key
  header (`RESTRICTED`/`BLOCK`), `sk-` API key (`RESTRICTED`/`BLOCK`), credential
  assignment (`CONFIDENTIAL`/`BLOCK` egress, `REDACT` release), email (`CONFIDENTIAL`/
  `CLASSIFY` egress, `REDACT` release).
- Hard bounds: ≤64 patterns, ≤64 destination entries, pattern length ≤512, no control
  characters/empty matches/redaction-marker matches; `max_scan_bytes` 1 B-4 MiB,
  `max_findings` 1-128, `max_matches_per_pattern` 1-256; ≤4,096 scanned fields, depth 16,
  path length 256; ≤32 field paths/finding, ≤64 finding codes/audit record.
- Exact-canonical destination trust map; the shipped mock sink is `PUBLIC`-only.
  Startup refuses a missing/dead/unregistered entry, so the map must exactly cover every
  registered `EXTERNAL_MUTATION` destination.

### Output defense service (`src/ai_security/data_security/dlp.py`)

- `inspect_egress(data, declared_data_class, destination, require_destination)`: runs on
  validated `arguments.model_dump()`, classifies content, and compares it with the
  destination trust. `BLOCK`-scope findings deny regardless of destination; `CLASSIFY`
  findings use the destination's `max_data_class`.
- `inspect_output(data, declared_data_class)`: runs on the complete buffered result and
  returns `PASS`/`REDACT`/`BLOCK`/`REVIEW`.
- The effective class is `max(registry declaration, findings)` — a floor that can only
  rise. Detection never lowers a declaration and never produces `ALLOW`.
- Findings contain stable codes, canonical categories, counts, and bounded field paths;
  matched values are never included. Oversize content, excessive fields/depth, unsafe
  paths, and a saturated report that would skip configured patterns are inspection
  failures (`inspection_error=true`, `RESTRICTED`, no findings). Per-pattern truncation
  still records the evaluated finding.
- Redaction is span-preserving and idempotent, merges overlapping spans under the
  highest-severity category, starts credential redaction at the first value character
  (multi-word values cannot leave tails), and leaves the original content digest intact.
  A redaction that violates the result schema/size suppresses the whole response.
- `released()` records `released_digest` while retaining the original result digest.

### Gateway enforcement (`src/ai_security/firewall/gateway.py`)

- `ToolGateway.__init__` requires an `OutputDefenseService`; there is no no-op/`None`
  default.
- Egress inspection runs after principal/binding/intent/argument/target validation and
  before resource authorization, risk, policy, approval, and execution. A non-`PASS`
  report returns DENIED with `dlp_egress_blocked` (or `dlp_inspection_failed` for an
  inspection error), zero adapter calls, and the failed report audited.
- The effective class feeds risk, policy, approval binding/storage, and audit.
- Response release runs after the adapter returns and before any bytes are returned.
  `BLOCK`, `REVIEW`, and failed inspection return `result=None` with
  `InvocationOutcome.response_blocked`, preserving the engine decision/reason; `REDACT`
  returns the transformed result and records the released digest.
- Approval consumption now additionally binds `side_effect_class` and the effective
  `data_class`; a stale approval created before a DLP-raised classification cannot
  authorize the action. Egress denial precedes approval consultation and never consumes a
  grant.

### Audit and wiring

- `audit/models.py`: optional additive `dlp` record on existing schema-v1 events (phase,
  outcome, reason, effective class, redacted findings, config version/hash, content
  digest/size, truncation/error, destination trust, released digest). No new event types
  and no migration in Phase 6; first-class DLP events and the verifier are Phase 7.
- `api/app.py`: loads `OUTPUT_DLP_PATH`, exposes `output_dlp_config`/`output_defense`, and
  injects the service into the gateway; startup validates destination coverage.
- `settings.py` / `.env.example`: `OUTPUT_DLP_PATH` (default `config/output_dlp.yaml`).

### Fixes found during verification

- `e8919cb`: a saturated finding report that would leave configured patterns unevaluated
  now fails closed instead of silently skipping them; regression test added.
- `e586c81`: credential redaction is line-scoped and starts at the first non-space,
  non-quote value character, so a multi-word passphrase cannot leave a tail; config
  version bumped to `1.0.1` and a regression test added.

### Tests

- `tests/unit/test_output_dlp.py` (19) — repository config/coverage, exact trust-map
  matching, duplicate/unknown/bad-version/non-UTF-8/missing-file refusal, pattern
  validation, canonical destinations, canary redaction/evidence, destination-aware
  classing, floor behavior, benign lookalikes, missing/forbidden destinations, response
  redaction/block/review, oversize fail-closed, guarded helpers, overlapping spans,
  finding-cap fail-closed, multi-word credential redaction.
- `tests/unit/test_gateway.py` (+8, 29 total) — canary never reaches an enabled sink,
  destination trust denial, inspection failure before risk, response redaction with
  original digest, canary response suppression, oversize response suppression, `REVIEW`
  suppression, schema-breaking redaction suppression.
- `tests/integration/test_gateway_approval.py` (+2, 7 total) — stale data-class approval
  cannot authorize classified content; DLP denial precedes approval and does not consume
  it (real PostgreSQL).
- `tests/integration/test_gateway_wiring.py` (+3, 5 total) — startup refuses a missing
  sink trust entry, a dead trust entry, and a missing DLP file.
- Existing e2e, no-bypass, and intent suites updated to construct the mandatory service
  and assert redacted evidence/digests.

Totals: **766 passed** (640 unit + 85 integration + 41 security); 32 new tests.

## Decisions and limitations (honest)

- Detection is deterministic pattern matching only: no classifier, entropy scan, semantic
  analysis, multilingual PII, or per-resource classification metadata. `PASS` means "no
  configured pattern matched", not "safe".
- Response `REVIEW` is operationally a whole-response block: no review queue, reviewer
  UI, release token, or post-review transport exists.
- DLP inspects only validated tool-bound arguments and the complete buffered result. It
  does not inspect model prompts/streams (no model path exists), content fetched inside a
  future real adapter, or local-write destinations.
- Over-redaction is deliberate; a redaction that breaks a strict result schema or the
  result-size bound suppresses the entire response rather than releasing an invalid value.
- Destination trust covers external mutations only and is exact-canonical (no wildcards
  or per-tenant trust).
- DLP evidence is not yet a first-class audit taxonomy; `EGRESS_INSPECTED`,
  `OUTPUT_INSPECTED`, `RESPONSE_RELEASED`/`_SUPPRESSED`, the verifier, and retention
  policy are Phase 7.
- No live `/v1` DLP route or streaming path; enforcement is in-process at the single
  gateway boundary.
- Approval class binding means an approval may become unusable if content classification
  raises the class after it was created; requesting a new approval is the intended
  recovery.

## Verification (V63-V66)

- V63: Alembic `current`/`upgrade head`/`downgrade -1`/`upgrade head`/`check` — at
  `e5a1c2b3d4f6 (head)`, down to `c7f1a2b3d4e5`, back to head; "No new upgrade operations
  detected"; Phase 6 adds no schema object.
- V64: full suite — **766 passed** (640 unit + 85 integration + 41 security); mypy clean
  (64 source files); ruff format/lint clean (112 files formatted).
- V65: targeted Phase 6 suites — **93 passed** (19 DLP, 8 gateway DLP, 2 approval
  class-binding, 3 startup trust coverage, plus unchanged e2e/no-bypass/intent suites).
- V66: post-commit `bash scripts/check.sh` after docs `98cfdde` and memory `9e78933` —
  PASS, exit 0, all 8 steps; ruff format/lint clean (166 files); mypy clean (64 source
  files); **766 passed** (640 unit + 85 integration + 41 security); Gitleaks 8.30.1
  dir+git "no leaks found" (36 commits scanned); prohibited-pattern greps clean;
  `compare_digest` confined to `security/constant_time.py`.

## Next

Phase 7 — audit persistence and verification (blueprint §16 and §21): full structured
event taxonomy, correlation IDs, first-class DLP events, exact-byte chain verifier with
mutation/reordering detection, retention/data-handling document, and default-log privacy
tests. See [../NEXT_SESSION.md](../NEXT_SESSION.md).
