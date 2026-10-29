# Changelog

Concise, dated history of project activity. Newest first.

## 2026-10-29

- **Phase 9 (evaluation harness and dataset) implemented and verified:** new installed
  `ai_security.evaluation` package (strict dataset loader, six task runners,
  confusion/latency metrics, direct-read provenance metadata, CLI, JSON-authoritative
  and Markdown-derived reports), a repository-owned synthetic dataset of **106 cases**
  across **42 dev / 34 validation / 30 holdout** with a **15-case dev-only quick subset**,
  and **64 evaluation tests** including hand-calculated metric arithmetic and a real
  quick-subset regression. The harness is measurement-only: it adds no route, authority,
  execution path, threshold change, or production audit write; authorization cases run
  the real gateway/registry/policy/DLP with mock adapters and an in-memory audit recorder.
  Measured baseline: 3 hard-negative input false positives, 0 unauthorized side effects,
  0 DLP leak failures, 0 detector errors; risk measured exact conformance/ordering only
  (no calibration); intent measured conformance, not live-model accuracy. Contract in
  ADR-016; documentation in [../docs/EVALUATION.md](../docs/EVALUATION.md) and
  [../evaluation/README.md](../evaluation/README.md). Evidence V76–V79 in
  [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) — **1013 tests** (782 unit +
  122 integration + 45 security + 64 evaluation), 8/8 gate, mypy 82 files, no new
  migration (`f7a8b9c0d1e2`). Phase record:
  [phases/PHASE_9_COMPLETE.md](phases/PHASE_9_COMPLETE.md).
- **Phase 9 honest limits:** the dataset is small, synthetic, and self-authored; no
  public benchmark adapter exists; authorization evaluation is in-process/mock-only and
  does not exercise PostgreSQL, HTTP/auth, approvals, or real connectors; intent is
  deterministic transcript conformance, not live-model semantic accuracy; risk weights
  and thresholds are still uncalibrated; latency is local/in-process; DLP coverage is
  pattern-scoped; and the three detector false positives remain reported rather than
  tuned away.

## 2026-10-28

- **Phase 8 (HTTP ingress, bounded runtime, local model) implemented and verified:** new
  host-signed `PrincipalAssertion` (strict `iss`/`aud`/tenant binding, future-time
  tolerance, no unsigned fallback), the three documented routes (`POST /v1/requests` as
  the sole execution surface, non-executing `POST /v1/tool-calls/evaluate`,
  token-in-signed-body `POST /v1/approvals/{approval_id}/decision`), ingress audit
  producers (`REQUEST_RECEIVED`, `PRINCIPAL_RESOLVED`/`PRINCIPAL_REJECTED`,
  `INPUT_INSPECTED`), a bounded `DemoRuntime` (exactly `mock_email.read` +
  `text.summarize`, atomic tool-call slot reservation, `NO_ACTION` otherwise), four
  per-principal fixed-window rate-limit buckets, `REQUEST_TIMEOUT_SECONDS`, stable error
  envelopes, and an optional strict Ollama-compatible local model provider behind
  `LocalModelIntentExtractor`. Provider failures yield no manifest and `503
  model_unavailable`; the mock path remains the default and runs offline. Contract in
  ADR-015; integration contract in
  [../docs/API_INTEGRATION.md](../docs/API_INTEGRATION.md). Evidence V72–V75 in
  [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) — **949 tests** (782 unit +
  122 integration + 45 security), 8/8 gate, mypy 73 files, no new migration
  (`f7a8b9c0d1e2`). Commits `5e20075` (ADR-015), `edda8ea` (assertion/resolver),
  `2bdf30f` (input evidence), `b561dd6` (preview support), `2fa66fe` (settings),
  `f0f9b6b` (format), `940600e` (routes), plus local-provider/docs commits. Phase record:
  [phases/PHASE_8_COMPLETE.md](phases/PHASE_8_COMPLETE.md).
- **Phase 8 honest limits:** the runtime is a fixed two-call demo, not a planner; an
  approval can be decided but the approved action is not resumable through HTTP; rate
  limits are per process/in memory; there is no approval UI/delivery/revocation/expiry
  sweeper, cloud model adapter, streaming, distributed limiter, model-prompt DLP,
  process sandbox, or external audit anchor. The local model is optional and never an
  authorization input.
- **Tooling:** `httpx2` moved from the dev group to runtime dependencies (the provider is
  imported by application code); lockfile refreshed and `uv lock --check` clean.

## 2026-10-26

- **Phase 7 (audit persistence and verification) implemented and verified:** the audit
  schema now covers every blueprint §16.1 event name (plus `APPROVAL_CONSUMED`) with
  event-specific required fields instead of invented placeholders. The gateway emits a
  mandatory ordered lifecycle (`REQUEST_RECEIVED` → `TOOL_CALL_PROPOSED` →
  `EGRESS_INSPECTED` → `POLICY_EVALUATED` → optional `APPROVAL_CONSUMED` →
  `TOOL_EXECUTION_STARTED` → `TOOL_EXECUTION_COMPLETED`/`_FAILED` → `OUTPUT_INSPECTED` →
  `RESPONSE_RELEASED`/`_SUPPRESSED`); a pre-execution append failure returns
  `BLOCK`/`audit_unavailable` with no adapter call, and a post-execution failure returns
  `AUDIT_FAILED` with the result withheld. Approval and intent services emit their events;
  DLP evidence moved to first-class redacted `EGRESS_INSPECTED`/`OUTPUT_INSPECTED`/
  `RESPONSE_*` records; `APPROVAL_CONSUMED` binds the effective side-effect/data class.
  New derived/indexed audit columns (`event_type`, `request_id`, `trace_id`, `call_id`,
  `occurred_at`, `component`) are extracted by the single append path from the exact
  payload, with additive migration `f7a8b9c0d1e2` and a guarded per-row backfill that
  never rewrites stored bytes or hashes. New `audit/verifier.py` reads one consistent
  snapshot, recomputes ADR-002 hashes from exact stored `canonical_event_bytes`, and
  checks sequence contiguity, previous-hash linkage, canonical JSON, and metadata
  agreement with typed content-free failures. New audit/log privacy tests prove canary,
  email, credential, private-key, and API-key values never enter serialized payloads or
  DEBUG logs. Contract in ADR-014; retention/data-handling guide in
  [../docs/AUDIT_RETENTION_AND_DATA_HANDLING.md](../docs/AUDIT_RETENTION_AND_DATA_HANDLING.md).
  Evidence V67–V71 in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) —
  **827 tests** (680 unit + 102 integration + 45 security), 8/8 gate, mypy 65 files,
  Alembic single head. Commits `0b60ba0` (implementation/tests/migration), `d53b0ed`
  (ADR-014/docs), plus memory/completion and V71 status records. Phase record:
  [phases/PHASE_7_COMPLETE.md](phases/PHASE_7_COMPLETE.md).
- **Phase 7 honest limits:** a local hash chain is tamper-evident, not tamper-proof;
  truncation of the newest events and a consistent full-chain rewrite by a database owner
  are not detectable without an external checkpoint (none is deployed). No automated
  retention/purge, scheduled verification, audit query API/UI, or per-event signature.
  `PRINCIPAL_RESOLVED`/`PRINCIPAL_REJECTED`, `INPUT_INSPECTED`, and
  `SECURITY_ALERT_RAISED` remain producerless until Phase 8/10 and are never faked.
- **Phase 6 (output DLP and egress policy) implemented and verified:** new
  `data_security/dlp.py` + strict `config/output_dlp.yaml` (`1.0.1`) provide five
  deterministic detectors (synthetic canary, private-key header, `sk-` API key,
  credential assignment, email), bounded scan/finding limits, span-preserving idempotent
  redaction, and an exact-canonical destination trust map that must cover every
  registered `EXTERNAL_MUTATION` destination at startup. `ToolGateway` now requires an
  `OutputDefenseService`: egress inspection runs on validated arguments after
  intent/argument checks and before resource/risk/policy/approval/execution; findings can
  only raise the registry data class (effective-class floor); `BLOCK`-scope findings deny
  regardless of destination and `CLASSIFY` findings compare with the destination's
  maximum class. Response release inspects the complete buffered result and returns
  `PASS`/`REDACT`/`BLOCK`/`REVIEW`; `BLOCK`/`REVIEW`/inspection failure suppress the whole
  result as `response_blocked`, while `REDACT` preserves the original digest and records
  `dlp.released_digest`. Audit gains an optional additive redacted `dlp` record on
  existing schema-v1 events (no new table/migration); approval consumption is additionally
  bound to the effective side-effect/data class. Two verification fixes: `e8919cb`
  (saturated finding report no longer skips an unevaluated blocking pattern; fails closed)
  and `e586c81` (credential redaction covers a complete multi-word value; config `1.0.1`).
  Contract recorded in ADR-013; false positives/negatives in
  [../docs/OUTPUT_DLP_FALSE_POSITIVES.md](../docs/OUTPUT_DLP_FALSE_POSITIVES.md). Evidence
  V63–V66 in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) — **766 tests**
  (640 unit + 85 integration + 41 security), 8/8 gate, mypy 64 files, Alembic unchanged.
  Commits `df70cd9` (implementation/tests/config), `e8919cb`, `e586c81`, plus docs/memory
  commits. Phase record: [phases/PHASE_6_COMPLETE.md](phases/PHASE_6_COMPLETE.md).
- **Phase 6 non-goals held:** no real connectors or per-resource classification; no
  classifier/entropy/semantic/multilingual detection; no review queue/transport
  (`REVIEW` blocks the whole response); no local-write destination trust; no model-prompt
  or adapter-internal inspection; no first-class DLP audit events/verifier or live `/v1`
  DLP route (Phase 7/8).
- **Phase 5 (risk engine and human approvals) implemented and verified:** `risk-v2`
  preserves every `risk-v1` weight and adds one bounded distinct-resource breadth factor
  (2–4/5–8/9+ → +5/+10/+15, cap 100) with strict `resource_count` validation and stable
  factor codes/rationale. New `firewall/approval.py` + `identity/approver_rules.py` +
  `persistence/approval_repository.py` + migration `e5a1c2b3d4f6` implement durable,
  tenant/action-bound approval requests with a strict `role:`/`principal:` rule grammar,
  a 256-bit token returned once and stored only as SHA-256, a 60–86,400 s TTL (default
  900), lazy expiry, verified-principal decisions with default-deny self-approval, and
  `SELECT ... FOR UPDATE` exactly-once consumption with same-transaction audit. The
  gateway now validates/deduplicates derived resource ids before risk/digest/audit and
  consults approval only for an engine `ASK_USER`; a valid consumed grant makes that
  exact action executable once, while `BLOCK`/hard denials ignore one. New reason codes
  `approval_granted`/`approval_denied`/`approval_expired`/`approval_invalid`; audit gains
  `APPROVAL_REQUESTED`/`APPROVAL_DECIDED`/`APPROVAL_CONSUMED`/`APPROVAL_EXPIRED`;
  `APPROVAL_TTL_SECONDS` added; app wiring exposes `approval_service` and injects it into
  the gateway. Contract recorded in ADR-012. Evidence V57–V62 in
  [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) — **734 tests** (613 unit +
  80 integration + 41 security), 8/8 gate, mypy 63 files, Alembic single head. Phase
  record: [phases/PHASE_5_COMPLETE.md](phases/PHASE_5_COMPLETE.md).
- **Phase 5 non-goals held:** no `/v1/approvals` routes/UI/token transport, no automatic
  request creation, no approver directory/notifications/revocation, no background expiry
  sweeper, and no weight calibration (Phase 9).

## 2026-10-19

- **Phase 4 (intent extraction and action validation) implemented and verified** (same
  day as 0a-3): new `intent/` package with a server-only manifest issuer, two-scenario
  mock extractor, strict local-model adapter interface (bounded/duplicate-key-safe JSON,
  bounded retries, outage/timeout mapping), sentinel-sealed request/principal/tenant/
  policy-bound manifests with short expiry and goal digest, exact action/resource/
  destination/parameter constraints with bounded uses, and trusted-timezone
  `TODAY`/`THIS_WEEK` resolution (DST-tested). Gateway gains manifest verification,
  exact constraint comparison, and post-policy use reservation; app wiring exposes
  `intent_usage_tracker`/`intent_manifest_service`, adds `INTENT_MANIFEST_TTL_SECONDS`,
  and constructs the gateway with the tracker. Contract recorded in ADR-011. Evidence
  V51+ in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) — **661 tests**
  (568 unit + 64 integration + 29 security), 8-step gate green. Commits `2943593`
  (implementation/tests), `74c502f` (ADR-011/docs), `786cb08` (memory/completion).
  Phase record: [phases/PHASE_4_COMPLETE.md](phases/PHASE_4_COMPLETE.md).
- **Phase 3 (input threat defense and provenance) implemented and verified** (same day as
  0a-3): shared strict YAML helper (`security/safe_yaml.py`, reused by the policy loader);
  advisory input-defense package (`input_defense/{models,config,normalize,heuristics,
  service,context_labels,sessions}.py`) with strict exhaustive-disposition config
  (`config/input_defense.yaml`, duplicate-key rejection, no PASS mapping), bounded intake,
  copy-only normalization (zero-width/control/escape/Base64/NFKC/mixed-script signals,
  iterative JSON depth), 10 versioned heuristic rules with quoted-context downgrade,
  typed non-PASS failure semantics (`DETECTOR_UNAVAILABLE`), structured trust-labelled
  context assembly, and session-signal math; tenant/subject-bound
  `session_security_state` repository + migration `c7f1a2b3d4e5` (bounded counters, 24 h
  inactivity/7 d absolute lazy expiry, signal-free rotation); settings
  (`INPUT_DEFENSE_PATH`, `SESSION_SIGNAL_TTL_SECONDS`, `SESSION_MAX_AGE_SECONDS`);
  `create_app` exposes `app.state.input_defense_config`/`input_defense_service`/
  `session_security`. Contract recorded in ADR-010. Evidence V43+ in
  [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) — **600 tests** (517 unit +
  60 integration + 23 security), 8-step gate green. Phase record:
  [phases/PHASE_3_COMPLETE.md](phases/PHASE_3_COMPLETE.md).
- **Phase 2 (tool registry and enforced gateway) implemented and verified** (same day as
  0a/0b/1): strict `ToolArguments`/`ToolResult` + sentinel-guarded, digest-bound
  `ExecutionAuthorization` (`tools/base.py`); immutable validated `ToolRegistration` +
  one-directional policy/capability consistency (`tools/registry.py`); deterministic mock
  adapters (`tools/mock_{email,files,external_sink,text}.py`); single `invoke_tool`
  chokepoint with bindings, strict validation, derived resources/destination, resource
  checks, deadlines, audit-first ordering, timeouts, per-process concurrency, and result
  bounds (`firewall/{models,gateway}.py`); `risk-v1` scoring engine
  (`firewall/risk_engine.py`); audit event subset + `ChainAuditRecorder`
  (`audit/{models,writer}.py`); reason codes `binding_mismatch`, `deadline_exceeded`,
  `policy_evaluation_error`, `audit_unavailable`; `create_app` wiring exposing
  `app.state.tool_registry`/`app.state.tool_gateway`; self-check fixtures extended to 21.
  Contract recorded in ADR-009. Evidence V36+ in
  [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) — **520 tests** (461 unit +
  47 integration + 12 security), 8-step gate green. Phase record:
  [phases/PHASE_2_COMPLETE.md](phases/PHASE_2_COMPLETE.md).
- **Phase 1 (typed contracts and deterministic policy engine) implemented and verified**
  (same day as 0a/0b): canonical enums defined exactly once (`tools/base.py`,
  `data_security/classification.py`, `firewall/decision.py`); strict contracts
  (`extra="forbid"`, strict int `risk_score`, anchored tool-id pattern, no aliases);
  destination canonicalization (`security/urls.py`); safe YAML loader with duplicate-key
  rejection (`policy/loader.py`); validated policy model + versioned bundle with content
  hashes (`policy/models.py`); deterministic §10.2 engine (`firewall/policy_engine.py`)
  replacing `policy/interim_matrix.py` (deleted); starter policy + experimental
  thresholds (`config/policies.yaml`, `config/risk_thresholds.yaml`); self-check fixtures
  v2 (17 fixtures, 7 mandated names retained, fixture-level `tool_policy` overrides);
  test-only principal adapter (`identity/adapters.py`); startup refusal + readiness
  `policy_version`/`policy_hash` + live drift detection. Contract recorded in ADR-008.
  Commits `cffdd62` (contracts + canonicalization), `eaae462` (models/loader/engine +
  config + fixtures), `b91729b` (wiring + adapter + env example) on top of `c95f2a6`.
  Evidence V30+ in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) — **406
  tests** (364 unit + 42 integration), 8-step gate green, bundle smoke check
  `combined_hash 8a4ba203…` with 17/17 fixtures passing. Phase record:
  [phases/PHASE_1_COMPLETE.md](phases/PHASE_1_COMPLETE.md).
- **Phase 0b (security foundation) implemented and verified end-to-end** (same day as
  0a): settings extensions; security primitives; identity package; async persistence +
  Alembic baseline; `/v1/*` host-auth ASGI middleware; policy self-check scaffolding;
  pinned Gitleaks + invariant steps in the gate; container runtime assets and Compose
  dev key. Commits `0aa11d9`, `9b3f153`, `42e8b71`, `4d18e27`, `28bede9`, `a5794cc`,
  `d180b89` on baseline `41e10da`. Evidence V18–V29 in
  [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) (231 tests; 8-step gate;
  live Docker auth/replay proof; startup refusals; `gitleaks git` clean). Phase record:
  [phases/PHASE_0B_COMPLETE.md](phases/PHASE_0B_COMPLETE.md).
- **Created the persistent project memory system** (`project_memory/`, this directory):
  13 core files + [phases/](phases/) records, per the memory-system task. Validation: all
  16 files present; 163 relative links checked, 0 broken; secret scan clean (no
  credential values; the sample password is referenced by location only); no files
  outside `project_memory/` created, deleted, or edited (35-file pre-existing inventory
  unchanged). No markdown linter is installed in this environment (checked; not installed).
- **Re-verified Phase 0a end-to-end in a fresh session:** `uv sync --frozen` clean;
  `bash scripts/check.sh` exit 0 (ruff, mypy, 25 tests, invariant greps);
  `docker compose config -q` exit 0; live Compose stack healthy with readiness 200
  against real PostgreSQL; non-root `uid=10001`; production gating 404s + fail-closed
  503; in-container startup refusal exit 1; stack torn down (volume preserved).
  Recorded as V1–V13 in [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md).
- **Phase 0a (repository foundation) implemented and verified** (prior session, same
  day): full scaffold (35 files before this memory directory), settings validation, `/health/live` +
  `/health/ready`, 25 tests, `scripts/check.sh` (6 steps), digest-pinned Dockerfile +
  Compose (API on host port 8080), and the documentation scaffold under
  [../docs/](../docs/) (ARCHITECTURE, THREAT_MODEL, SECURITY_INVARIANTS,
  POLICY_DECISION_MATRIX, DECISIONS, IMPLEMENTATION_STATE, KNOWN_LIMITATIONS, and
  `ADR-001..007`).
  Full record: [../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md); phase record:
  [phases/PHASE_0A_COMPLETE.md](phases/PHASE_0A_COMPLETE.md).
- **Blueprint corrections v1.1 → v1.2 completed** (prior session): documentation-only
  validation pass over the master blueprint (archived v1.0 superseded).

## Template for future entries

```text
## YYYY-MM-DD
- <what changed> (<phase>, files) — <evidence: command/result or record reference>.
- <decisions made> — <ADR link if contract-level>.
- <blockers opened/closed>.
```
