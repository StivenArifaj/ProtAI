# Testing and Verification

Rules: never claim a result that was not produced by a command actually run. Fresh
re-runs and historical records are kept in separate tables. Evidence IDs (V1–V29 for
0a/0b; V30–V35 for Phase 1; V36–V42 for Phase 2; V43–V50 for Phase 3; V51–V56 for
Phase 4; V57–V62 for Phase 5; V63–V66 for Phase 6; V67–V71 for Phase 7; V72–V75 for
Phase 8; V76+ for Phase 9) are referenced from
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and the phase records.

## How to verify (documented commands)

| Command | What it checks | Expected |
|---|---|---|
| `uv sync --frozen` | lockfile/install consistency | installs with no resolution drift |
| `uv run pytest` | unit/integration/security/evaluation tests | 1013 passed (DB-backed integration skips cleanly if PostgreSQL is unreachable) |
| `uv run python -m ai_security.evaluation --dataset evaluation/dataset_manifest.yaml --output-dir evaluation/reports` | full evaluation (blueprint §19) | 106 cases / 6 tasks; JSON + Markdown written; 3 documented hard-negative input failures |
| `uv run python -m ai_security.evaluation --dataset evaluation/dataset_manifest.yaml --output-dir evaluation/reports --split dev --quick --report-name quick_report --fail-on-failures` | 15-case dev-only quick regression | exit 0; 0 failed expectations; reports written |
| `bash scripts/check.sh` | full local gate (8 steps) | exit 0; prints "All checks passed." |
| `uv run alembic upgrade head` | migrations (needs §5.4 env; host `db`→`127.0.0.1`) | applies baseline through `f7a8b9c0d1e2`; second run reports already at head |
| `docker compose config -q` | Compose file syntax | exit 0 |
| `docker compose build api` | container build incl. `config/`, `migrations/`, `alembic.ini` | image builds |
| `docker compose run --rm api alembic upgrade head` | in-container migration | baseline applied |
| `docker compose up -d db api` | stack | `protai-db-1` + `protai-api-1` healthy |
| `curl http://127.0.0.1:8080/health/live` | liveness | 200 `{"status":"alive"}` |
| `curl http://127.0.0.1:8080/health/ready` | readiness | 200 ready incl. `policy_version`/`policy_hash` (503 not_ready without DB or with drifted self-checks) |
| unsigned/signed requests to `/v1/*` | host auth + ingress | unsigned → 400 `missing_headers`; valid signature without a `principal_assertion` → 403 `principal_rejected` (one audited `PRINCIPAL_REJECTED`); replay → 401 `replayed_nonce` |
| `uv run python -c "…load_policy_bundle…"` | policy bundle smoke | `version`, per-file hashes, `combined_hash`; 21 fixtures, 0 failures |
| `uv run pytest tests/security tests/unit/test_gateway.py -q` | no-bypass invariants | 87 passed (denied/unknown/audit-failed calls never reach the adapter; DLP denials, the Phase 7 fail-closed lifecycle, and the Phase 8 preview path included) |
| `docker compose down` | teardown (volume preserved) | stack removed |

Failure behavior: `check.sh` exits non-zero and prints `CHECK FAILED: <reason>`.

## Fresh evidence (2026-10-19, Phase 2 session)

| ID | Command / check | Result |
|---|---|---|
| V36 | `uv run --frozen pytest -q` | PASS — **520 passed** (461 unit + 47 integration + 12 security), incl. DB-backed gateway integration against Compose PostgreSQL |
| V37 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps: lockfile; ruff format; ruff lint; mypy clean; 520 tests; Gitleaks 8.30.1 dir+git "no leaks found" (13 commits scanned); prohibited-pattern greps clean; `compare_digest` confined |
| V38 | `uv run --frozen pytest tests/security tests/unit/test_gateway.py -q` | PASS — 31 passed (8 parametrized no-byte-denials + audit-down + no-decision-no-exec + outcome-audit-fail + direct-adapter fail-closed + 20 gateway unit tests) |
| V39 | `uv run --frozen pytest tests/integration/test_gateway_end_to_end.py tests/integration/test_gateway_wiring.py -q` | PASS — 5 passed (durable decision→outcome order + linkage + result digest + payload non-leakage; denied egress leaves sink unchanged; audit outage → `BLOCK`/`audit_unavailable`; startup refuses unregistered policy tool) |
| V40 | `uv run --frozen pytest tests/unit/test_policy_self_checks.py tests/integration/test_policy_self_checks_wiring.py -q` | PASS — 41 passed; fixture file now 21 fixtures incl. the 7 mandated names |
| V41 | `uv run --frozen mypy src` + `ruff check src/ tests/` + `ruff format --check src tests` | PASS — clean (45 source files, strict) |
| V42 | Post-commit re-run: `uv run --frozen pytest -q` + `bash scripts/check.sh` | PASS — 520 passed; gate exit 0, all 8 steps; Gitleaks "no leaks found" (18 commits scanned) |

Development-time findings fixed and regression-tested during Phase 2 (recorded for
honesty): `verify_execution_authorization` originally accepted any object passed as the
authorization — a security test now proves a non-authorization value raises
`ExecutionAuthorizationError`; the security spy adapter initially failed because
`MockEmailAdapter` requires `super().__init__()` (its store is an instance attribute);
the integration deny test initially asserted a non-existent `data_class` field on
`RiskAssessment` (the field lives in the audit payload, value `PUBLIC`).

## Fresh evidence (2026-10-19, Phase 4 session)

| ID | Command / check | Result |
|---|---|---|
| V51 | `uv run --frozen pytest -q tests/unit/test_intent_models.py tests/unit/test_intent_extractors.py tests/unit/test_intent_validation.py tests/unit/test_intent_service.py tests/security/test_intent_no_grant.py` | PASS — **56 passed** (50 intent unit: sealing/binding/expiry, strict extractor output/retry/outage, exact constraint + tracker + DST/math, service clarification/issuance/limits; 6 security no-grant tests) |
| V52 | `uv run --frozen pytest -q tests/integration/test_intent_wiring.py tests/unit/test_settings.py` | PASS — **63 passed** (4 app-wiring tests incl. end-to-end allow/limit/clarification/wrong-request against real PostgreSQL; 59 settings tests incl. TTL default/bounds) |
| V53 | `uv run --frozen mypy src` + `ruff check src tests` + `ruff format --check src tests` | PASS — strict mypy clean (60 source files); ruff clean; 151 files already formatted |
| V54 | `uv run --frozen pytest -q` + `bash scripts/check.sh` | PASS — **661 passed** (568 unit + 64 integration + 29 security); gate exit 0, all 8 steps; Gitleaks 8.30.1 dir+git "no leaks found" (23 commits scanned); prohibited patterns clean; `compare_digest` confined |
| V55 | Manual `IntentManifestService` smoke (demo summarize/read, forward, greeting) | PASS — ACTIVE with resolved UTC window; ACTIVE; REJECTED (no manifest); REQUIRES_CLARIFICATION (no manifest) |
| V56 | Post-commit re-run: `bash scripts/check.sh` after `2943593`/`74c502f`/`786cb08` | PASS — exit 0, all 8 steps; 661 tests; 151 files formatted; mypy 60 source files; Gitleaks 8.30.1 dir+git "no leaks found" (26 commits scanned) |

Development-time findings fixed and regression-tested during Phase 4 (recorded for
honesty): the integration test first used `app.state.intent_tracker`, but the app state key
is `intent_usage_tracker` (`AttributeError` caught and test corrected); repeated
`asyncio.run` calls in one test left SQLAlchemy pool connections bound to closed loops
(`RuntimeWarning: coroutine 'Connection._cancel' was never awaited`) — fixed by running all
gateway calls in one `async def scenario()` and awaiting `app.state.database.dispose()`;
the local-model timeout test initially passed `timeout_seconds=0.01`, below the
constructor's 0.1 s minimum (corrected to 0.1); the service module briefly carried an
unused `IntentManifest` import (removed for ruff/mypy).

## Fresh evidence (2026-10-26, Phase 5 session)

| ID | Command / check | Result |
|---|---|---|
| V57 | `uv run --frozen pytest -q` | PASS — **734 passed** (613 unit + 80 integration + 41 security), incl. real-PostgreSQL approval/audit/concurrency tests against Compose PostgreSQL |
| V58 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps; ruff format/lint clean; mypy clean (63 source files); 734 tests; Gitleaks 8.30.1 dir+git "no leaks found" (27 commits scanned); prohibited-pattern greps clean; `compare_digest` confined to `security/constant_time.py` |
| V59 | `uv run --frozen pytest tests/integration/test_approval_flow.py tests/integration/test_gateway_approval.py tests/integration/test_gateway_wiring.py tests/integration/test_migrations.py tests/unit/test_risk_engine.py tests/unit/test_approver_rules.py tests/unit/test_settings.py tests/security/test_gateway_no_bypass.py -q` | PASS — **157 passed** (11 approval lifecycle/expiry/mutation/replay/exactly-one-winner, 5 gateway approval gating/no-execution, 2 wiring, 1 migration, 30 risk, 24 approver rules, 60 settings, 24 no-bypass) |
| V60 | `alembic upgrade head` → `downgrade -1` → `upgrade head` → `check` (test DB) | PASS — `e5a1c2b3d4f6` applies, downgrades to `c7f1a2b3d4e5`, re-applies cleanly; "No new upgrade operations detected" |
| V61 | `uv run --frozen pytest tests/unit/test_gateway.py -k duplicate_derived_resource_ids -q` | PASS — 1 passed, 20 deselected (duplicate derived resource ids collapse before risk/digest/audit) |
| V62 | Post-commit re-run: `bash scripts/check.sh` after `ad9e76a`/`0b2f1c9`/`8cce014` | PASS — exit 0, all 8 steps; ruff format/lint clean; mypy clean (63 source files); 734 tests; Gitleaks 8.30.1 dir+git "no leaks found" (30 commits scanned); prohibited-pattern greps clean; `compare_digest` confined |

Development-time findings fixed and regression-tested during Phase 5 (recorded for
honesty): direct `hmac.compare_digest` calls initially appeared in `firewall/approval.py`
and `persistence/approval_repository.py`; both were replaced with
`security.constant_time.constant_time_hex32_equal` after the confinement test failed.
The gateway's `_failed_execution` result metadata initially dropped
`approval_id`/`approver_subject_id` (caught by the real-PostgreSQL execution-failure
test); both now propagate. Expiry originally applied only to approved rows on consume;
pending rows now also transition to `expired` (with an audit event) on decide/consume.
The gateway originally counted duplicate derived resource-id values toward the breadth
factor and passed them to approval storage (whose spec requires uniqueness); resource ids
are now deduplicated in first-occurrence order before risk/digest/audit, with a
regression test. Ruff format reformatted seven files after the approval suites landed.
The app-wiring test was extended to assert `app.state.approval_service` is the same
service injected into the gateway.

## Fresh evidence (2026-10-26, Phase 6 session)

| ID | Command / check | Result |
|---|---|---|
| V63 | Alembic `current` → `upgrade head` → `downgrade -1` → `upgrade head` → `check` (test DB, §5.4 env) | PASS — at `e5a1c2b3d4f6 (head)`; upgrade is a no-op; downgrade reaches `c7f1a2b3d4e5`; re-upgrade returns to head; "No new upgrade operations detected". Phase 6 adds no schema object |
| V64 | `uv run --frozen pytest -q`; then `uv run --frozen mypy src`, `ruff check src tests`, `ruff format --check src tests` | PASS — **766 passed** (640 unit + 85 integration + 41 security); mypy clean (64 source files); ruff format/lint clean (112 files formatted) |
| V65 | `uv run --frozen pytest tests/unit/test_output_dlp.py tests/unit/test_gateway.py tests/integration/test_gateway_approval.py tests/integration/test_gateway_wiring.py tests/integration/test_gateway_end_to_end.py tests/security/test_gateway_no_bypass.py tests/security/test_intent_no_grant.py -q` | PASS — **93 passed** (19 DLP config/detection/redaction/fail-closed, 29 gateway incl. 8 DLP cases, 7 real-PostgreSQL approval incl. 2 class-binding, 5 wiring incl. 3 trust-coverage, 3 e2e, 24 no-bypass, 6 intent) |
| V66 | Post-commit `bash scripts/check.sh` after docs `98cfdde` and memory `9e78933` | PASS — exit 0, all 8 steps; ruff format/lint clean (166 files formatted); mypy clean (64 source files); **766 passed** (640 unit + 85 integration + 41 security); Gitleaks 8.30.1 dir+git "no leaks found" (**36 commits scanned**); prohibited-pattern greps clean; `compare_digest` confined to `security/constant_time.py` |

Development-time findings fixed and regression-tested during Phase 6 (recorded for
honesty): the original finding-cap logic could stop scanning after `max_findings` and
skip a still-unevaluated blocking pattern; a saturated report now fails closed
(`e8919cb`). Credential redaction originally consumed only one whitespace-delimited token,
leaving the tail of a multi-word passphrase in the released result; redaction is now
line-scoped from the first value character, and the config version is `1.0.1`
(`e586c81`). Overlapping match spans originally risked leaving the tail of a longer match
unredacted; spans are now merged under the highest-severity category. Response release
changes result bytes, so end-to-end digest assertions compare `result_digest` with
`dlp.content_digest` and use `dlp.released_digest` for the released bytes. The mock email
adapter returns synthetic addresses, so response redaction intentionally changes sender
fields in those fixtures. The approval-class-binding test uses an email finding raised to
`INTERNAL` under a permissive test trust map because the shipped policy blocks
`CONFIDENTIAL`/`RESTRICTED` external egress before approval is consulted.

## Fresh evidence (2026-10-26, Phase 7 session)

| ID | Command / check | Result |
|---|---|---|
| V67 | Alembic `current` → `downgrade -1` → `upgrade head` → `check` (test DB, §5.4 env) | PASS — starts/ends at `f7a8b9c0d1e2 (head)`; downgrade reaches `e5a1c2b3d4f6`; re-upgrade returns to head; "No new upgrade operations detected". The guarded backfill was exercised with a pre-existing corrupt historical payload row: the migration completed and left that row unbackfilled for the verifier instead of aborting |
| V68 | `uv run --frozen pytest -q`; then `uv run --frozen mypy`, `ruff check .`, `ruff format --check .` | PASS — **827 passed** (680 unit + 102 integration + 45 security), incl. real-PostgreSQL verifier/tamper and approval/audit privacy tests; mypy clean (65 source files); ruff format/lint clean (173 files formatted) |
| V69 | `uv run --frozen pytest tests/unit/test_audit_schema.py tests/unit/test_gateway.py tests/unit/test_intent_service.py tests/integration/test_audit_verifier.py tests/integration/test_gateway_approval.py tests/integration/test_gateway_end_to_end.py tests/security/test_audit_privacy.py -q` | PASS — **113 passed** (29 audit schema/taxonomy, 37 gateway lifecycle incl. the 8-position fail-closed matrix, 16 intent audit, 17 verifier/tamper, 7 approval privacy/consumption, 4 audit/log privacy, plus lifecycle e2e cases) |
| V70 | `bash scripts/check.sh` (pre-commit) | PASS — exit 0, all 8 steps; ruff format/lint clean (173 files formatted); mypy clean (65 source files); **827 passed** (680 unit + 102 integration + 45 security); Gitleaks 8.30.1 dir+git "no leaks found" (37 commits scanned); prohibited-pattern greps clean; `compare_digest` confined to `security/constant_time.py` |
| V71 | Post-commit `bash scripts/check.sh` after `0b60ba0`, `d53b0ed`, and memory commit `5ae9ebe` | PASS — exit 0, all 8 steps; ruff format/lint clean; mypy clean; **827 passed** (680 unit + 102 integration + 45 security); Gitleaks 8.30.1 dir+git "no leaks found" (**40 commits scanned**); prohibited-pattern greps clean; `compare_digest` confined to `security/constant_time.py` |

Development-time findings and design points settled in Phase 7 (now regression-tested,
recorded for honesty): the migration initially would have aborted on a corrupt historical
payload; the final guarded per-row loop leaves such rows unbackfilled and the verifier
reports them. Each verifier row is rehashed from that row's own stored `previous_hash`,
with cross-row linkage checked separately, so tampering row N yields its own
`EVENT_HASH_MISMATCH` plus `PREVIOUS_HASH_MISMATCH` at N+1. The verifier reads one
consistent single-`SELECT` snapshot rather than paging, and failure output is bounded and
content-free. Audit metadata is derived from the exact payload before hashing; malformed
optional metadata refuses the append rather than storing a disagreeing column. DLP
evidence was moved off `POLICY_EVALUATED`/execution events onto first-class inspection and
response events. The newest-event truncation limit is tested and documented rather than
hidden.

## Fresh evidence (2026-10-29, Phase 9 session)

| ID | Command / check | Result |
|---|---|---|
| V76 | `uv run --frozen pytest -q` | PASS — **1013 passed** (782 unit + 122 integration + 45 security + 64 evaluation), including the real 15-case quick-subset regression; DB-backed suites ran against Compose PostgreSQL |
| V77 | `uv run --frozen pytest tests/evaluation -q` | PASS — **64 passed** (hand-calculated metric arithmetic, dataset hash/count/partition/template-leakage/duplicate refusal, metadata `null` behavior, JSON-to-Markdown derivation, CLI exit codes, module-style command recording, quick regression) |
| V78 | `uv run --frozen python -m ai_security.evaluation --dataset evaluation/dataset_manifest.yaml --output-dir evaluation/reports` and the `--split dev --quick --report-name quick_report --fail-on-failures` run | PASS — full run: 106 cases, 6 tasks, 3 expected hard-negative input failures, 0 unauthorized side effects (rate 0.000), 0 DLP leak failures, 0 detector errors; quick run: 15 dev cases, 0 failures, exit 0. Both wrote authoritative JSON + derived Markdown |
| V79 | `bash scripts/check.sh` (pre-commit) | PASS — exit 0, all 8 steps; **1013 passed**; ruff format/lint clean (212 files); mypy clean (82 source files); Gitleaks 8.30.1 dir+git "no leaks found"; prohibited-pattern and constant-time-confinement checks clean |
| V80 | Post-commit `bash scripts/check.sh` after Phase 9 commits `b8d6ae3`, `4acdbe0`, `6ac3089` | PASS — exit 0, all 8 steps; **1013 passed**; ruff format/lint clean (212 files); mypy clean (82 source files); Gitleaks 8.30.1 dir+git "no leaks found" (**54 commits scanned**); prohibited-pattern and constant-time-confinement checks clean |

Phase 9 adds **no migration** (head remains `f7a8b9c0d1e2`), **no route**, and no
application wiring. The harness is an installed package with a CLI-only entry point. The
full run's three failures are the intentional hard-negative input false positives
(`in-dev-quote-01`, `in-dev-readthis-01`, `in-val-quote-01`); they were not tuned away.
Measured baseline (dataset `2026.10.28-v1`, 106 cases; 42 dev / 34 validation / 30
holdout):

| Task | Measured result |
|---|---|
| Input detection | 14 TP / 3 TN / 3 FP / 0 FN (precision 0.824, recall 1.000, FPR 0.500); gating 13 TP / 5 TN / 1 FP / 1 FN (precision 0.929, recall 0.929, FPR 0.167) |
| DLP egress | 11 protected / 5 benign; 0 leak failures |
| DLP response | 10 protected (6 redacted, 4 suppressed) / 4 benign; 0 leak failures |
| Risk | 18/18 exact score+factors+band; 0 ordering violations; conformance only, not calibration |
| Intent | 18/18 status matches; 0 unexpected/missed manifests; 11 provider calls; 1 retry; mock/transcript conformance, not live-model accuracy |
| Authorization | 20/20 expected outcomes; 15 must-not-execute blocked; 5 expected executions; 0 unauthorized executions; 1 expected/observed sink write; 93 in-memory audit events |

Latency in the report is in-process per-case wall-clock time summarized with nearest-rank
p50/p95/p99 and sample counts; it is explicitly labelled local and is not a production
HTTP/database/concurrency measurement. Full details and limitations:
[../docs/EVALUATION.md](../docs/EVALUATION.md), [../evaluation/README.md](../evaluation/README.md),
and ADR-016.

Development-time findings settled in Phase 9: dataset fixtures are synthetic originals
(CC0-1.0) with explicit provenance/license/template/split metadata; the loader refuses
cross-split `(task, template_id)` leakage, exact duplicate content, hash/count drift, and
invalid quick subsets before execution; undefined denominators serialize as `null` in
JSON and `N/A` in Markdown, never zero; git metadata is read directly from `.git` without
a child process and is `null` when unavailable; the CLI records the actual `sys.argv`
invocation; and a synthetic credential value was shortened to `abcdef` to avoid a
Gitleaks `generic-api-key` false positive without adding an allowlist (DLP still matches
it, and the manifest hash was updated). The three hard-negative false positives are
reported, not tuned.

## Fresh evidence (2026-10-28, Phase 8 session)

| ID | Command / check | Result |
|---|---|---|
| V72 | `uv run --frozen pytest -q` | PASS — **949 passed** (782 unit + 122 integration + 45 security), including 28 signed `/v1` route tests, 9 API-support tests, 36 provider tests, and local-provider failure/success integration against real PostgreSQL |
| V73 | `uv run --frozen mypy`; `uv run --frozen ruff check .`; `uv run --frozen ruff format --check .`; `uv lock --check` | PASS — mypy clean (73 source files); ruff lint clean; 188 files already formatted; lockfile consistent (44 packages resolved) after moving `httpx2` to runtime dependencies |
| V74 | `bash scripts/check.sh` (pre-commit) | PASS — exit 0, all 8 steps; **949 passed**; ruff/mypy clean; Gitleaks 8.30.1 dir+git "no leaks found" (**48 commits scanned**); prohibited-pattern greps clean; `compare_digest` confined to `security/constant_time.py` |
| V75 | `uv run --frozen pytest tests/integration/test_api_requests.py tests/unit/test_api_support.py tests/unit/test_intent_providers.py tests/unit/test_principal_assertion.py tests/unit/test_principal_resolver.py tests/unit/test_settings.py -q` | PASS — **188 passed** (28 route contracts incl. local-provider failure/success, 9 API support, 36 provider strictness, 16 assertion binding, 14 resolver, 85 settings bounds/refusals) |

Phase 8 adds **no migration**; Alembic head remains `f7a8b9c0d1e2` (no schema object was
needed for routes, rate limits, or the local provider). Rate-limit and intent-use state
are in-memory and per process.

Development-time findings and design points settled in Phase 8 (now regression-tested,
recorded for honesty): a pytest/httpx import mismatch was resolved by replacing `httpx`
with the project's `httpx2` runtime dependency and refreshing the lockfile; the provider
initially ran under a dev-only dependency, so it was moved to runtime dependencies
(`uv lock --check` now guards it). `LOCAL_MODEL_TIMEOUT_SECONDS` was narrowed to 1–60 s
(whole seconds) because the extractor constructor rejects larger values. The request
deadline deliberately bounds only tool proposals (`received_at + REQUEST_TIMEOUT_SECONDS`),
not local-model extraction, which has its own per-attempt timeout; two attempts can
therefore precede the deadline. Raw request text, email content, and approval tokens were
asserted absent from audit payloads and DEBUG logs. Approved actions are not resumable
through `/v1/requests` in Phase 8 (documented limitation), and the decision route never
executes.

## Fresh evidence (2026-10-19, Phase 3 session)

| ID | Command / check | Result |
|---|---|---|
| V43 | `uv run --frozen pytest -q` | PASS — **600 passed** (517 unit + 60 integration + 23 security), incl. DB-backed session-state tests against Compose PostgreSQL |
| V44 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps; ruff format/lint clean (136 files); mypy clean (55 source files); 600 tests; Gitleaks 8.30.1 dir+git "no leaks found" (19 commits scanned); prohibited patterns clean; `compare_digest` confined |
| V45 | `uv run --frozen pytest -q tests/unit/test_input_normalization.py tests/unit/test_input_heuristics.py tests/unit/test_input_defense_config.py tests/unit/test_context_labels.py tests/unit/test_sessions.py tests/security/test_input_defense_failure.py` | PASS — 64 passed (normalization signals, attack/benign matrix, strict config, labels/rendering, expiry math, non-PASS failure semantics) |
| V46 | `uv run --frozen pytest -q tests/integration/test_input_defense_wiring.py tests/integration/test_session_security_state.py` | PASS — 13 passed (app wiring + invalid-config refusals; binding/guessed-ID/counters/TTL/max-age/rotation against real PostgreSQL) |
| V47 | `uv run --frozen mypy src` + `ruff check src tests` + `ruff format --check src tests` | PASS — clean (55 source files, strict); folded into V44 |
| V48 | `uv run --frozen alembic current` → `upgrade head` → `downgrade -1` → `upgrade head` → `check` (dev DB) | PASS — `c7f1a2b3d4e5` applies, downgrades, and re-applies; "No new upgrade operations detected" |
| V49 | Manual `InputDefenseService` smoke (benign / attack / quoted / external email / zero-width / Cyrillic homoglyph) | PASS — PASS / REJECT (direct) / FLAG (quoted) / QUARANTINE (untrusted) / REJECT (obfuscated+direct) / FLAG (homoglyph only); confirms documented honest limits |
| V50 | Post-commit re-run: `bash scripts/check.sh` after `faafe13`/`3bd5c69`/`1fe5588` | PASS — exit 0, all 8 steps; 600 tests; Gitleaks 8.30.1 dir+git "no leaks found" (22 commits scanned) |

Development-time findings fixed and regression-tested during Phase 3 (recorded for
honesty): the jailbreak rule initially missed the plural "jailbreaks" (pattern widened to
`jailbreak(?:ing|ed|s)?`); mypy rejected `InstrumentedAttribute[int]` where
`ColumnElement[int]` was declared for the bounded-counter helper (typed the parameter as
`InstrumentedAttribute[int]` and cast the zero-delta return); the max-age integration
test initially jumped six days without refreshing `last_seen_at`, which correctly expired
the session by the 24 h inactivity rule (test now simulates daily activity); the
normalization test initially counted scalar JSON depth incorrectly (implementation was
right; test corrected to 3).

## Fresh evidence (2026-10-19, Phase 1 session)

| ID | Command / check | Result |
|---|---|---|
| V30 | `uv run --frozen pytest -q` | PASS — **406 passed** (364 unit + 42 integration), incl. DB-backed integration against Compose PostgreSQL |
| V31 | `uv run --frozen mypy src` | PASS — no issues, 35 source files (strict) |
| V32 | `uv run --frozen ruff check src/ tests/` + `ruff format src tests` | PASS — clean; format applied to 3 files, then check clean |
| V33 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps: lockfile; ruff format; ruff lint; mypy; 406 tests; Gitleaks 8.30.1 dir+git "no leaks found" (9 commits scanned); prohibited-pattern greps clean; `compare_digest` confined |
| V34 | Policy bundle smoke (`load_policy_bundle` + `check_policy_self_checks`, live run) | PASS — `version: dev-1`; `policies_sha256 35bcd687…`; `thresholds_sha256 3e1d34ae…`; `combined_hash 8a4ba203e3baaf86eabb2e299992166289cae938ec9ea9a7bccadf6e6e068e6a`; 17 fixtures, 0 failures |
| V35 | Policy wiring integration tests (`test_policy_self_checks_wiring.py`, `test_health.py`) | PASS — invalid/missing policy file and mismatching fixture refuse startup; live policy/fixture drift flips readiness to 503; readiness payload carries `policy_version`/`policy_hash` |

Additional Phase 1 development-time findings (fixed and regression-tested, recorded for
honesty): the initially unanchored `TOOL_ID_PATTERN` accepted an invalid tool id (fixed
by anchoring); pydantic's lax int coercion accepted a string or bool `risk_score` (fixed
with `strict=True`); the loader's first duplicate-key approach would have added a
`yaml.load(` call the gate prohibits (restructured to a `yaml.compose` node walk +
`yaml.safe_load`); three files were not ruff-formatted (the gate's format step caught it).

## Fresh evidence (2026-10-19, Phase 0b session; Docker Desktop running)

| ID | Command / check | Result |
|---|---|---|
| V18 | `uv run --frozen pytest -q` | PASS — **231 passed** (~2.8 s), incl. DB-backed integration against Compose PostgreSQL |
| V19 | `uv run --frozen mypy` | PASS — no issues, 25 source files (strict, `src/`) |
| V20 | `uv run --frozen ruff check .` + `ruff format --check .` | PASS — clean after fixing import sorting in `migrations/` (cosmetic) |
| V21 | `uv run --frozen pytest tests/integration -k "host_auth or nonce or principal" -q` | PASS — 18 passed, 19 deselected |
| V22 | `uv run --frozen alembic upgrade head` ×2 | PASS — first run applies `d15b46c49950` to a fresh DB; second run already at head |
| V23 | `uv run --frozen alembic check` | PASS — "No new upgrade operations detected" |
| V24 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps: lockfile; ruff format; ruff lint; mypy; 231 tests; Gitleaks 8.30.1 dir+git "no leaks found"; prohibited-pattern greps clean; `compare_digest` confined to `security/constant_time.py` |
| V25 | `docker compose build api` + `docker compose run --rm api alembic upgrade head` | PASS — image contains `config/`, `migrations/`, `alembic.ini`; baseline applied in-container |
| V26 | Live compose stack HTTP checks | live 200; ready 200 `{"config":true,"database":true,"policy_self_checks":true}`; unsigned `POST /v1/echo` → 400 `{"detail":"missing_headers"}` |
| V27 | Signed request proof (Compose dev key; fresh timestamp + nonce; urllib) | first call → 404 Not Found (auth passed, nonce registered, body replayed; no `/v1` route exists — expected); replay of identical signed request → 401 `{"detail":"replayed_nonce"}` |
| V28 | Live startup refusals | `APP_ENV=production PRINCIPAL_RESOLVER=dev` → ValidationError "PRINCIPAL_RESOLVER=dev is refused outside development/test"; `POLICY_SELF_CHECKS_PATH=/nonexistent.yaml` → `PolicySelfCheckConfigError` — both refuse startup |
| V29 | `gitleaks git --redact --exit-code 1 .` | PASS — no leaks across full history (baseline + 7 Phase 0b commits) |

Notes: the one expected Gitleaks finding during development was the documented
disposable Compose dev host-auth key; the final `.gitleaks.toml` allowlists exactly that
value (verified: `gitleaks dir` and `gitleaks git` both clean). `check.sh` pins Gitleaks
to exactly 8.30.1.

## Historical evidence (Phase 0a, 2026-10-19; superseded freshness but unchanged code paths)

| ID | Check | Result |
|---|---|---|
| V1 | `uv --version`; `uv run python --version` | uv 0.13.1; Python 3.12.15 |
| V2 | `uv sync --frozen` | PASS — "Checked 36 packages" (see note below) |
| V3 | `bash scripts/check.sh` (0a, 6 steps) | PASS — exit 0; 25 tests |
| V4 | `docker compose config -q` | PASS — exit 0 |
| V5 | `docker info`; `docker compose version` | Docker 29.3.1 running; Compose v5.1.1 |
| V6 | `docker compose up -d db` | PASS — `protai-db-1` healthy |
| V7 | `docker compose up -d api` (0a image) | PASS — `protai-api-1` healthy |
| V8 | 0a dev-profile HTTP checks | live 200; ready 200 `{"config":true,"database":true}`; docs 200; leak scan 0 |
| V9 | `docker compose exec -T api id` | `uid=10001(app)` (non-root) |
| V10 | 0a production-profile run | docs/redoc/openapi 404; ready 503 (non-matching non-sample credential; fail-closed by design) |
| V11 | 0a in-container refusal (production + sample password) | exit 1, clear message |
| V12 | `docker compose down` (0a) | stack removed; `db_data` preserved |
| V13 | `git rev-parse --is-inside-work-tree` | fatal: not a git repository (exit 128 — since resolved) |
| V14 | Live uvicorn run without Docker (0a) | live 200; ready 503 (no DB); docs 200 |
| V15 | Startup refusal: `APP_ENV` missing | exit 1 (`app_env Field required`) |
| V16 | Startup refusal: wrong scheme | exit 1 with ADR-005 scheme error |
| V17 | Fresh-checkout approximation (0a) | `uv sync --frozen` then `check.sh` exit 0 |

Note: package counts differ by command — `uv lock` resolves **38 packages**; `uv sync
--frozen` reports **36 packages checked** (installed set). Both expected.

## Injected-failure proof (how `check.sh` was proven to fail)

A deliberately failing test was added and `check.sh` was run: the failure was caught at
the pytest step (`CHECK FAILED: test failures reported`, exit 1) and, in earlier
iterations, at the ruff format and lint steps. Removing the file restored exit 0. Note:
`assert False` trips ruff B011 — use `raise AssertionError(...)` in throwaway probes.
The Phase 0b gate additionally fails if Gitleaks is missing or version-mismatched
(deliberate pin, 8.30.1).

## Test inventory (1013 tests)

Unit (`tests/unit/`):

- `test_settings.py` (85) — 0a validation + masking + docs flag; 0b host-auth key
  schemas, duplicate rejection, sample-secret refusal, resolver guard, TTL/tolerance
  relation, `policy_self_checks_path`; 1 `policy_path`/`risk_thresholds_path` defaults,
  overrides, empty-path rejection; 3 input-defense path/session TTL defaults, TTL ≤
  max-age, positive windows; Phase 4 intent-manifest TTL default/bounds; Phase 5
  approval TTL default/bounds; Phase 8 request timeout/rate-limit/model-provider bounds,
  placeholder-name refusal, external-model refusal, and local-timeout mismatch refusal.
- `test_constant_time.py` (16) — equality helpers incl. unequal-length and hex paths.
- `test_canonical_json.py` (17) — canonical text/bytes stability and edge cases.
- `test_hash_chain.py` (17) — ADR-002 formula, genesis, fixed vectors, hex conversion.
- `test_host_auth_verifier.py` (46) — exact signing message vector, header handling,
  full rejection matrix, timestamp-window boundaries, constant-time paths.
- `test_principal_resolver.py` (14) — frozen `Principal` model, timezone validation,
  dev-resolver guard (incl. `model_construct` bypass attempt), host resolver over a
  verified signed assertion.
- `test_principal_assertion.py` (16) — strict assertion fields (`extra="forbid"`), key
  `host_id`/`audience` binding, tenant scope required/member/absent rules, future-time
  tolerance, typed rejection reasons.
- `test_principal_test_adapter.py` (8) — test-only constructor guard, factory exclusion.
- `test_api_support.py` (9) — Phase 8 error envelope/state enum, limiter fixed windows
  and atomic multi-slot reservation, strict request schema bodies.
- `test_urls.py` (36) — scheme/host/port/path/query canonicalization, IDNA hosts,
  percent-encoding, rejection cases (whitespace, controls, userinfo, fragment, zone id,
  trailing dot), exact-match equality.
- `test_policy_models.py` (40) — strict policy/threshold documents, anchored tool ids,
  strict enum/int rejection, bundle hashes, threshold ordering, self-approval flag
  consistency.
- `test_policy_loader.py` (20) — safe loading, duplicate keys, missing/non-UTF-8/malformed
  documents, `PolicyConfigError` behavior.
- `test_policy_engine.py` (71) — table-driven matrix (allowed/forbidden/malformed/
  cross-scope/unknown/error), evaluation-order precedence, thresholds, provenance,
  determinism, malformed requests.
- `test_policy_self_checks.py` (33) — repo fixture file passes completely; mandated rows
  present; runner detects decision/reason mismatches; malformed fixture shapes rejected;
  readiness report behavior.
- `test_action_digest.py` (14) — canonical action digest stability, field sensitivity,
  key-order invariance, hex shape.
- `test_tool_registry.py` (28) — registration validation matrix (DESTRUCTIVE refusal,
  schema strictness, resource/destination annotation checks, bounds, bool rejection),
  duplicate resolution, startup consistency failures (`ToolRegistryConfigError`),
  Phase 5 approver-rule syntax/policy consistency.
- `test_mock_adapters.py` (15) — mock email/files/sink/text behavior, ownership checks,
  unauthorized-call refusal (`UngatedExecutionError`), digest tamper rejection.
- `test_risk_engine.py` (30) — every `risk-v1` weight preserved under `risk-v2`, cap at
  100, external-destination requirement, breadth boundaries (0/1/2/4/5/8/9+), stable
  factor codes/rationale, invalid counts (bool/str/float/negative/oversize), version.
- `test_gateway.py` (42) — see the Phase 2 completion record for the base scenario list;
  Phase 5 adds duplicate-derived-resource-id dedup before risk/digest/audit; Phase 6 adds
  canary-never-sinks, destination-trust denial, egress inspection failure before risk,
  response redaction/digest, canary/oversize/`REVIEW` suppression, and schema-breaking
  redaction suppression; Phase 7 adds the mandatory ordered lifecycle and the 8-position
  pre/post audit fail-closed matrix, first-class redacted egress/output/response events,
  and the execution/completion/response split; Phase 8 adds preview evaluation with no
  execution and no approval/manifest consumption.
- `test_audit_schema.py` (32) — full §16.1 taxonomy membership; event-specific required
  fields (principal/tool/action/decision/reason/outcome); `call_id` validation; DLP record
  placement/redaction; payload omission of `None`; unknown-field refusal; approval and
  intent event payloads; Phase 8 ingress event shapes; producerless names never
  fabricated; schema/version constants.
- `test_output_dlp.py` (19) — repository config and exact destination coverage; strict
  loader (duplicate/unknown/bad version/non-UTF-8/missing); pattern and canonical
  destination validation; canary detection without matched text; destination-aware class
  decisions; registry floor; benign lookalikes; missing/forbidden destinations;
  span-safe/idempotent/digest-preserving redaction; block/review distinction; oversize
  fail-closed; guarded release helpers; overlapping-span merge; finding-cap fail-closed;
  multi-word credential redaction.
- `test_approver_rules.py` (24) — strict `role:`/`principal:` grammar (alternatives,
  limits, control characters, duplicates, unknown prefixes), verified-principal
  evaluation, tenant/self-approval/unsatisfiable-rule behavior.
- `test_input_normalization.py` (12) — copy-only normalization, zero-width/control/
  escape/Base64/NFKC/mixed-script signals, iterative JSON depth, invalid UTF-8.
- `test_input_heuristics.py` (20) — attack matrix, quoted/educational downgrade,
  external-only untrusted-instruction rules, benign hard negatives, determinism/offsets.
- `test_input_defense_config.py` (9) — repo config completeness, duplicate keys,
  missing/unknown codes, PASS mapping refusal, invalid content types, parameter stripping.
- `test_context_labels.py` (7) — trust labels, external email forced untrusted,
  deterministic rendering, duplicate/empty/blank refusals.
- `test_sessions.py` (5) — opaque IDs, TTL/max-age expiry math, counter/session constants.
- `test_intent_models.py` (14) — sentinel sealing/forgery, strict payloads/constraints,
  request/principal/tenant/policy binding, expiry/not-yet-valid, status consistency,
  resolved-time invariants.
- `test_intent_extractors.py` (13) — mock scenarios, strict local-model JSON, duplicate
  keys/unknown fields/oversize, retries, provider outage/timeout, unsafe destination.
- `test_intent_providers.py` (36) — Ollama-compatible client: origin-only URL validation
  (HTTPS/loopback policy), exact model name, fixed `/api/generate` request with
  `format=json`/`temperature=0`, redirect refusal, proxy trust disabled, 1 MiB envelope
  and 64 KiB output caps, content-type/UTF-8/duplicate-key rejection, timeout/connection
  failures mapped to typed `LocalModelProviderError`.
- `test_intent_validation.py` (10) — exact action/resource/destination/parameter matching,
  tracker uses/expiry/capacity/purge, DST TODAY, THIS_WEEK, timezone validation.
- `test_intent_service.py` (16) — issuance/bindings/digest/TTL, relative dates, missing
  timezone, ambiguity/rejection, unenforceable constraints, outage/malformed, limits;
  Phase 7 adds best-effort `INTENT_CREATED`/`INTENT_FAILED` audit behavior (failure never
  becomes a grant).

Security (`tests/security/`):

- `test_gateway_no_bypass.py` (24) — denied/unknown/malformed/expired/audit-failed calls
  never execute (spy adapter byte equality on the sink); no execution without a
  successfully recorded decision; result withheld on outcome-audit failure; direct
  adapter invocation without a gateway authorization fails closed; Phase 5 adds
  ASK_USER-without-approval, granted-execution metadata, non-granted outcome mapping,
  storage-failure, absent-service, and BLOCK-ignores-approval no-execution cases;
  Phase 6 supplies the mandatory output defense and keeps every denial sink-identical.
- `test_input_defense_failure.py` (11) — oversize/unsupported/invalid-encoding stop before
  heuristics; detector/normalizer/classifier faults yield `DETECTOR_UNAVAILABLE`
  (never PASS, no raw content in reports); trust label preserved; no invocation surface.
- `test_intent_no_grant.py` (6) — forged/missing/expired/wrong-principal/wrong-request
  manifests, other action/resource/parameter, unlisted destination, use limit, and
  legacy no-tracker fail-closed all deny without execution.
- `test_audit_privacy.py` (4) — canary, email, credential, private-key, and API-key shapes
  are fed through egress denial, adapter failure, response suppression, and intent
  extraction at DEBUG; raw values are absent from serialized audit payloads and captured
  logs while stable codes/digests remain; approval tokens/content never enter the chain.

Integration (`tests/integration/`):

- `test_api_requests.py` (28) — signed `/v1` contracts against real PostgreSQL:
  assertion rejection + single audited `PRINCIPAL_REJECTED`, input gating, no-side-effect
  denials, rate-limit charging/exhaustion, request states, in-process approval creation
  and one-time decisions, preview non-execution/non-consumption, local-provider
  failure/success, and audit correlation without duplicate receipts.
- `test_approval_flow.py` (11) — real-PostgreSQL approval creation/decision/consumption,
  digest-only token storage, one-time/replay, action mutation, pending/approved expiry,
  denial, tenant/eligibility/self-approval, exactly-one-winner concurrency, and
  same-transaction audit linkage.
- `test_gateway_approval.py` (7) — real-PostgreSQL gateway ASK_USER gating; approved
  execution with metadata; pending/denied/mismatch/expiry no-execution; BLOCK ignores and
  does not consume an approval; Phase 6 stale-class rejection and DLP-before-approval
  no-consumption.
- `test_health.py` (10) — liveness; readiness 200/503 incl. policy readiness override;
  `policy_version`/`policy_hash` assertions; docs gating all environments; non-leakage.
- `test_host_auth_middleware.py` (13) — end-to-end denial matrix through the app:
  valid sign → route + context; forged/mutated/stale/unknown-key → 401; replay → 401;
  failing registrar → 503; oversize content-length + chunked → 413; query string → 400;
  non-`/v1` paths unauthenticated.
- `test_nonce_repository.py` (5) — fresh/duplicate/expired re-registration/DB failure
  (incl. raw connection errors) paths.
- `test_input_defense_wiring.py` (4) — app wiring of the advisory service/config,
  invalid-config refusal, no execution surface.
- `test_session_security_state.py` (9) — tenant/subject binding, guessed-ID isolation,
  bounded counters, inactivity/absolute expiry, signal-free rotation (real PostgreSQL).
- `test_audit_verifier.py` (17) — real-PostgreSQL verifier: valid chain acceptance from
  exact stored bytes; payload/hash mutation; reordering; middle deletion; malformed and
  non-canonical JSON; malformed hash; metadata tampering; chain isolation; typed failure
  codes; bounded failures; newest-event truncation is confirmed undetectable without an
  external anchor.
- `test_audit_append.py` (5) — chain continuity, genesis, canonical bytes recompute,
  5-writer concurrency contiguity, unique-sequence guard.
- `test_migrations.py` (1) — upgrade idempotency on the test database (single Alembic
  head incl. the Phase 5 approval table).
- `test_policy_self_checks_wiring.py` (8) — startup refuses on missing policy/threshold
  file, invalid policy, and fixture mismatch; valid bundle passes startup + readiness
  with version/hash; live policy-version drift flips to 503 while the startup bundle
  stays fixed.
- `test_gateway_end_to_end.py` (3) — real-PostgreSQL chain: durable decision→outcome
  order and hash linkage, result digest = sha256 canonical result, no raw content in
  stored payloads, denied egress leaves the sink empty, audit outage → `BLOCK`/
  `audit_unavailable`; Phase 6 asserts the redacted `dlp` record and released-digest
  linkage.
- `test_gateway_wiring.py` (5) — `create_app` exposes a validated registry + gateway
  (`ChainAuditRecorder`) and the approval service actually injected into the gateway;
  startup refuses a policy tool with no registration; Phase 6 refuses a missing sink
  trust entry, a dead trust entry, and a missing DLP file.
- `test_intent_wiring.py` (4) — app exposes intent service/tracker and the gateway uses
  that tracker; TTL applied; end-to-end allow + use exhaustion; clarification and
  wrong-request manifest denial (real PostgreSQL).
- `conftest.py` + `db_helpers.py` — auto-create `firewall_test`, run Alembic, skip
  cleanly when PostgreSQL is unreachable; NullPool harness for asyncio.run tests.

Evaluation (`tests/evaluation/`, 64 tests):

- `test_metrics.py` — hand-calculated binary metrics (precision/recall/F1/accuracy/FPR/
  FNR), zero-denominator `None` semantics, sparse multiclass union labels, nearest-rank
  p50/p95/p99 and sample counts.
- `test_dataset.py` — repository manifest loads (106 cases, expected counts/splits),
  strict schema/version/provenance/license checks, SHA256/count drift refusal, path
  escape refusal, duplicate key/ID and exact duplicate content refusal, cross-split
  `(task, template_id)` leakage refusal, non-partition/disagreeing split refusal,
  unknown split names, and dev-only/≤30/all-task quick-subset rules.
- `test_metadata.py` — direct `.git`/refs and `uv.lock` reads, missing-file `null`
  behavior, Python/platform/environment metadata, no fabricated values.
- `test_report.py` — JSON-authoritative report shape (§19.6 counts, matrices, metric
  definitions/values, latency, failures/retries, unauthorized side effects, skipped
  tests, limitations, command), Markdown derivation, and `N/A` for undefined values.
- `test_cli.py` — exit codes (`0` report, `1` dataset/verification refusal before
  execution, `2` `--fail-on-failures`), report-name safety, module-style command
  recording, and the `--quick`/`--split dev` contract.
- `test_quick_regression.py` — runs the real 15-case dev quick subset through the CLI
  runner; asserts all six tasks, 0 failures, and report emission (no PostgreSQL).
- `conftest.py` — builds minimal hash-consistent temporary datasets for loader/report
  tests and supplies the shipped dataset path.

Evaluation runs need neither PostgreSQL nor Docker. The full 106-case run is manual/
scheduled; the quick subset runs inside pytest and therefore inside `check.sh`.

## Verification gaps (be honest about these)

- No coverage measurement; no CI system (`check.sh` is the gate).
- "Fresh clone" is now meaningful (git history exists) but a true `git clone` into a new
  directory has not been exercised; the 0a clean-copy approximation is the closest run.
- No markdown linter is installed in this environment; memory-file link checks are
  scripted ad hoc.
- Docker verification used the local Compose project; multi-host/registry pulls are not
  applicable to v1's local-only scope.
- Audit verification is in-process only: no scheduled job, route, or UI; the verifier
  loads one chain into memory and assumes the v1 single-chain deployment.
- No external checkpoint/anchor exists, so truncation of the newest events and a
  consistent full-chain rewrite by a database owner are not detectable. This is tested
  and documented, not claimed away.
- Metadata backfill is best-effort; corrupt historical payloads stay unbackfilled and are
  surfaced only when the verifier is run.
- The evaluation dataset is small, synthetic, and self-authored (106 cases), and its
  42/34/30 split is reproducibility discipline rather than an independent third-party
  sample; no field-performance or production estimate follows from it.
- No public benchmark adapter exists (license/pinned version/reproducible download hash
  were not verified), so no result is comparable to InjecAgent, AgentDojo, or any other
  public benchmark.
- Authorization evaluation runs the real gateway/registry/policy/DLP in-process with mock
  adapters and an in-memory audit recorder; it does not exercise PostgreSQL, HTTP
  ingress, host authentication, approvals, or real connectors. Approval behavior remains
  covered by the Phase 5 suites, and shipped capabilities produce no `ASK_USER` row.
- Intent evaluation uses `MockIntentExtractor` and deterministic transcript-backed
  local-provider outputs; it measures adapter/gating conformance, not live local-model
  semantic accuracy.
- Risk evaluation measures exact score/factor/band conformance and ordering; it is not
  calibration, and the `risk-v2` weights and 40/80 thresholds remain uncalibrated.
- DLP measurements are pattern-scoped (five deterministic detectors): 0 leaks on these
  fixtures is not exhaustive secret/PII coverage.
- Evaluation latency is local in-process wall-clock time; it excludes HTTP, database,
  network, real adapters, and concurrency. There is no production latency/throughput or
  SLO claim.
- The three hard-negative input false positives and the one gating miss are deliberate
  reported findings; no detector, policy, DLP, risk, or model threshold was changed in
  Phase 9.
- The full evaluation run is not a CI service and has no coverage measurement; only the
  15-case quick subset runs in the gate. `metadata.git.commit` names the checked-out
  revision at run time, so a report committed afterwards names its parent unless
  regenerated.
