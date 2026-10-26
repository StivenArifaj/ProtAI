# Implementation State

Last updated: 2026-10-26 (Phase 6, blueprint v1.2).

Phases 0a (repository foundation), 0b (security foundation), 1 (typed contracts and
deterministic policy engine), 2 (tool registry and enforced gateway), 3 (advisory input
defense and context provenance), 4 (intent extraction and action validation), 5
(risk engine and approval workflow), and 6 (output DLP and egress policy) are **complete
and verified**; the Docker Compose path was verified in 0b. Phase 6 adds a mandatory
`OutputDefenseService` to the gateway: strict versioned output-DLP configuration,
deterministic canary/private-key/API-key/credential/email detection, egress inspection on
validated arguments before resource/risk/policy/execution, an exact-canonical destination
trust map with startup coverage of every registered external-mutation destination,
complete-response release/redaction/suppression, additive redacted `dlp` audit evidence,
and approval consumption bound to the effective side-effect/data class.
The codebase still does **not** implement `/v1` business routes, approval routes/UI/
token transport, real connectors, process isolation, rate limiting, a real model
provider, classifier/entropy/semantic DLP, or the full audit verifier. See
`docs/SECURITY_INVARIANTS.md` and `docs/KNOWN_LIMITATIONS.md`.

## What exists

| Area | Files | Notes |
|---|---|---|
| Project metadata | `pyproject.toml`, `uv.lock`, `.python-version` (3.12), `.gitignore`, `.env.example`, `README.md`, `Makefile`, `.gitleaks.toml` | Python `>=3.12,<3.13`; runtime deps: fastapi, uvicorn, pydantic, pydantic-settings, asyncpg, SQLAlchemy 2.x async, Alembic, PyYAML; dev deps: pytest, httpx2, ruff, mypy, types-PyYAML |
| Application | `src/ai_security/__init__.py`, `settings.py`, `api/{app,dependencies,routes_health,middleware}.py` | App factory + module-level `app`; validated settings (incl. policy/threshold/input-DLP paths, `INTENT_MANIFEST_TTL_SECONDS`, `APPROVAL_TTL_SECONDS`, and `OUTPUT_DLP_PATH`); `/health/live`, `/health/ready` (config, database, policy_self_checks + `policy_version`/`policy_hash`); host-auth ASGI middleware on `/v1/*`; Phase 4 intent service/tracker, Phase 5 approval service/repository, and Phase 6 `output_dlp_config`/`output_defense` exposed on `app.state` and wired into the gateway |
| Security primitives | `security/{constant_time,canonical_json,urls}.py`, `audit/hash_chain.py` | `hmac.compare_digest` wrappers (confined by the gate); canonical JSON bytes; ADR-002 hash formula + fixed vectors; destination canonicalization (IDNA, percent-encoding, https-only) |
| Identity | `identity/{models,signing,host_auth,resolver,adapters,approver_rules}.py` | `Principal` (strict, frozen); HMAC signing/verification (exact `v1` message, full rejection surface); `DevPrincipalResolver` guard + fail-closed `HostPrincipalResolver`; test-only `TestPrincipalResolver` (not selectable via settings/factory); Phase 5 strict `role:`/`principal:` approver-rule parser/evaluator |
| Persistence | `persistence/{database,models,nonce_repository,audit_repository,session_repository,approval_repository}.py` | Async engine/session; atomic nonce upsert (`ON CONFLICT ... WHERE ... RETURNING`); ADR-002 advisory-lock audit append plus `append_in_session`; tenant/subject-bound session signals with bounded counters, lazy expiry, and signal-free rotation; Phase 5 `approval_requests` repository with row-locked decide/consume and same-transaction audit |
| Migrations | `alembic.ini`, `migrations/env.py`, `migrations/versions/{d15b46c49950,c7f1a2b3d4e5,e5a1c2b3d4f6}_*.py` | Baseline: `host_request_nonces`, `audit_events`; Phase 3: `session_security_state`; Phase 5: `approval_requests` (status/score constraints + expiry/requester indexes); single Alembic head; upgrade/downgrade/upgrade verified; `alembic check` clean |
| Typed contracts | `tools/base.py` (`SideEffectClass`, `ToolArguments`/`ToolResult`, `ExecutionAuthorization`, `compute_action_digest`, adapters protocol), `data_security/classification.py` (`DataClass`), `firewall/decision.py` (`FirewallDecision`/`DecisionReason`/`DecisionRecord`) | Canonical enums defined exactly once (blueprint §4/§6.1); stable reason-code vocabulary (extended with `binding_mismatch`, `deadline_exceeded`, `policy_evaluation_error`, `audit_unavailable`, the Phase 4 `intent_*` codes, and the Phase 5 `approval_*` codes); sentinel-guarded authorization; strict schemas (`extra="forbid"`, `strict=True`) |
| Tool registry + mock adapters | `tools/registry.py`, `tools/mock_{email,files,external_sink,text}.py` | Immutable validated registrations; exact `(tool_id, action_id)` resolution; startup consistency vs policy (one-directional: policy→capability required; extra registrations stay policy-disabled); deterministic in-memory adapters with ownership checks and digest verification |
| Input defense + provenance | `input_defense/{models,config,normalize,heuristics,service,context_labels,sessions}.py`, `security/safe_yaml.py`, `config/input_defense.yaml` | Advisory only: strict config (every finding code mapped, no PASS mapping), byte/type/UTF-8 intake, copy-only normalization, versioned heuristics with quoted-context downgrade, typed `IntakeReport` with digests/offsets, six trust labels + deterministic JSON context, optional diagnostic classifier, typed `DETECTOR_UNAVAILABLE` failures |
| Intent extraction + manifests | `intent/{models,extractors,service,validator,time_window}.py` | Server-only issuer; mock demo extractor + strict local-model adapter interface (bounded JSON, duplicate-key rejection, retries, outage mapping); sealed request/principal/tenant/policy-bound manifest with short expiry and goal digest; exact action/resource/destination/parameter constraints and per-process bounded uses; trusted-timezone TODAY/THIS_WEEK resolution (DST-tested) |
| Gateway + risk engine | `firewall/{gateway,models,risk_engine,approval}.py` | Single `invoke_tool` chokepoint; binding/validation/resource/destination/deadline/engine checks; Phase 4 manifest verification + concrete constraint/use-limit checks; Phase 6 egress DLP after argument/intent validation and before resource/risk/policy/execution, with the effective (raised) data class feeding risk/policy/approval/audit; decision audited before execution; timeouts + per-process concurrency + result bounds; complete-response DLP release/redaction/suppression; typed outcomes; `risk-v2` scoring (all `risk-v1` weights + bounded breadth); Phase 5 one-time approval consumption for engine `ASK_USER`, with exact action/policy/class binding and no override of `BLOCK` |
| Output DLP + egress | `data_security/{classification,dlp}.py`, `config/output_dlp.yaml` | Mandatory gateway dependency (no no-op default): strict versioned config (`1.0.1`, duplicate/unknown-key rejection, bounded patterns/limits); five deterministic detectors (canary, private-key header, `sk-` API key, credential assignment, email); findings record code/category/count/field path only; `PASS`/`REDACT`/`BLOCK`/`REVIEW`; span-preserving idempotent redaction; exact-canonical destination trust map with startup coverage; oversize/inspection failure fails closed; no classifier/entropy/semantic/multilingual detection |
| Approval service | `firewall/approval.py`, `identity/approver_rules.py`, `persistence/approval_repository.py` | Strict request/decision/consumption API; token returned once and stored only as SHA-256; verified-principal rule evaluation with tenant and self-approval checks; 60-86,400 s TTL (default 900); lazy expiry; row-locked state machine and same-transaction audit events; Phase 6 consumption additionally requires the stored side-effect/data class to match current effective facts; no routes/token transport in Phase 5 |
| Audit emission | `audit/{models,writer}.py` | Phase-2 event subset (`POLICY_EVALUATED`, `TOOL_EXECUTION_COMPLETED`, `TOOL_EXECUTION_FAILED`) plus Phase 5 `APPROVAL_REQUESTED`/`APPROVAL_DECIDED`/`APPROVAL_CONSUMED`/`APPROVAL_EXPIRED`; Phase 6 adds an optional additive `dlp` record (phase/outcome/reason/effective class/redacted findings/config hash/digests/trust facts) under schema v1; `AuditRecorder` protocol + `ChainAuditRecorder` over the ADR-002 repository; payload-safe references only |
| Policy engine | `firewall/policy_engine.py`, `policy/{models,loader,self_checks}.py`, `config/{policies,risk_thresholds,policy_self_checks}.yaml` | Deterministic §10.2 evaluation order over validated facts; safe YAML (duplicate-key rejection); versioned bundle with content hashes; 21 fixtures (incl. 7 mandated names and the Phase 2 binding/deadline/inconsistent facts) evaluated at startup + readiness; replaces `policy/interim_matrix.py` (deleted) |
| Tests | `tests/conftest.py`, `tests/unit/*` (28 test files + helper), `tests/integration/*` (13 test files + helpers), `tests/security/*` (3 test files) | **766 tests** (640 unit, 85 integration, 41 security): prior suites plus Phase 6 strict DLP config/limits, canary/destination/floor/redaction/outcome/failure tests, gateway egress/response enforcement, approval class binding, and app/startup destination-coverage wiring |
| Quality gate | `scripts/check.sh` | 8 steps: lockfile, ruff format, ruff lint, mypy, pytest, pinned Gitleaks (dir+git), prohibited-pattern greps, constant-time confinement |
| Containers | `Dockerfile`, `docker-compose.yml` | Digest-pinned bases; non-root uid 10001; COPY `config/ migrations/ alembic.ini`; Compose `api` carries the disposable dev `HOST_AUTH_KEYS_JSON` |
| Docs | `docs/*` (10 files), `docs/adr/ADR-001..013` | Status columns honest; ADR-008 records the Phase 1 engine contract, ADR-009 the Phase 2 registry/gateway contract, ADR-010 the Phase 3 advisory-detection/session contract, ADR-011 the Phase 4 manifest/constraint contract, ADR-012 the Phase 5 `risk-v2`/approval contract, ADR-013 the Phase 6 output-DLP/egress contract; matrix doc reflects gateway-enforced facts; `OUTPUT_DLP_FALSE_POSITIVES.md` documents tested benign cases and known false positives/negatives |
| Git | baseline `41e10da`; 0b commits `0aa11d9`…`d180b89`; docs `c95f2a6`; Phase 1 commits `cffdd62`, `eaae462`, `b91729b`; Phase 2 commits `5725256`…`c7a0f8d`; Phase 3 commits `faafe13`…`30c0f41`; Phase 4 commits `2943593`, `74c502f`, `786cb08`, `c018955`; Phase 5 commits `ad9e76a`, `0b2f1c9`, `8cce014`; Phase 6 commits `df70cd9` (implementation/tests/config), `e8919cb` (finding-cap fail-closed), `e586c81` (complete credential-value redaction); docs/memory commits follow | Repository under git since 2026-10-19; linear history on `main`; no remote configured |
| Spec | `AI_Agent_Security_Platform_Master_Blueprint_v1.2.md`, `archive/..._v1.0_superseded.md` | v1.2 authoritative; v1.0 archived |

Deliberately deferred beyond Phase 6: full audit taxonomy + verifier (Phase 7), `/v1/*`
business and approval routes + token transport + agent runtime + real local-model
provider + rate limiting (Phase 8), evaluation (Phase 9), isolation/SOC/SBOM (Phase 10).
Intent extraction is available in-process only and uses the mock extractor in the app; no
route or real provider consumes it yet. Approvals are storage-and-gateway only: no route,
UI, notification channel, approver directory, revocation operation, or background expiry
sweeper. Detection and trust labels still have no route/model consumer; `evaluation/`
does not exist. Output DLP runs at the gateway (validated arguments and complete buffered
results) but has no `/v1` route, streaming path, classifier, or model-prompt inspection;
its evidence is embedded in existing audit events, not a Phase 7 taxonomy.

## Decisions taken during Phase 0b implementation (within blueprint constraints)

- **Pure-ASGI middleware, path-prefix based** (`/v1/*`): enforcement is fail-closed and
  independent of route existence; it runs before routing and identically under
  `PRINCIPAL_RESOLVER=dev`.
- **Exact denial surface** (recorded in tests): malformed target/headers → 400;
  forged/mutated/stale/unknown-key/replayed → 401; oversize → 413; nonce-store failure →
  503. Detail codes are stable strings (`missing_headers`, `replayed_nonce`, ...).
- **Size bound before signature work**: content-length check, then capped body read with
  replay via an ASGI receive wrapper; nothing is buffered beyond `REQUEST_MAX_BYTES`.
- **Atomic replay rejection in one statement** (`INSERT ... ON CONFLICT DO UPDATE ...
  WHERE expires_at < now() RETURNING`): row → fresh; no row → replay. Concurrency test
  proves at most one winner. Store failures (including raw `OSError`/connection errors)
  → 503, never fail-open.
- **Signed host-auth settings strictness**: `HOST_AUTH_KEYS_JSON` required; records
  `extra="forbid"`; secret must be strict base64 ≥32 bytes; the all-zero sample secret is
  refused outside `development`/`test`; duplicate key IDs rejected; nonce TTL must be
  ≥2× timestamp tolerance.
- **Dev-resolver guard in three places** (settings validator, resolver constructor,
  factory); tests include a `model_construct` bypass attempt to prove the constructor
  guard is independent.
- **Audit append scaffold follows ADR-002 exactly**: transaction-scoped advisory lock
  (`pg_advisory_xact_lock`), canonical bytes stored verbatim, unique
  `(chain_id, sequence_number)`, fixed hash vectors in unit tests; integration test
  appends 5 concurrently and asserts a contiguous sequence.
- **Policy self-checks wired to startup + readiness** (ADR-007): mismatching fixture or
  unreadable/invalid file refuses startup; readiness re-evaluates the file live so drift
  flips to 503. `POLICY_SELF_CHECKS_PATH` overridable; default `config/policy_self_checks.yaml`
  relative to CWD (repo root locally, `/app` in the image).
- **Gitleaks pinned to 8.30.1** in `check.sh` (dir + git scans, redacted; missing or
  version-mismatch = `CHECK FAILED`), with `.gitleaks.toml` extending the default ruleset
  and allowlisting exactly the one documented disposable Compose dev key.
- **Migration env reads Settings** (never `alembic.ini` for the URL); the documented
  commands are `make migrate` / `uv run --frozen alembic upgrade head` with the §5.4
  environment in place.
- **Test DB strategy**: integration fixtures auto-create `firewall_test` on the Compose
  PostgreSQL, run `alembic upgrade head`, and skip (with a clear reason) when the server
  is unreachable; tests never require `create_all` in integration paths (ADR-006).

## Decisions taken during Phase 1 implementation (within blueprint constraints; ADR-008)

- **Module layout**: engine in `firewall/policy_engine.py`; policy document models +
  loader in `policy/`; canonical enums defined exactly once (`tools/base.py`,
  `data_security/classification.py`, `firewall/decision.py`).
- **Fact separation**: `PolicyEvaluationRequest` carries upstream facts only
  (`principal_resolved`, `arguments_valid`, `hard_deny`, `resource_authorized`,
  `risk_score`, optional `destination`); policy-derived facts (membership, explicit
  permission, approval eligibility, egress enablement, allowlist) come only from the
  loaded bundle. The engine cannot authorize on caller-supplied policy flags.
- **Evaluation order = blueprint §10.2**: principal → tool membership (`unknown_tool`)
  → side-effect class match → arguments → hard deny → resource scope → destination
  (`invalid_destination` for malformed or misplaced) → matrix rows with configured
  thresholds. Every outcome has a stable `DecisionReason`; the vocabulary is an
  observable contract (renaming is a breaking change).
- **Fail closed everywhere**: `DESTRUCTIVE` never executable in v1 (registration may
  exist; the engine blocks); `RESTRICTED` writes/egress and `CONFIDENTIAL` egress
  blocked; `ASK_USER` only when policy marks the action approval-eligible, otherwise
  `BLOCK`; tool absent from the document → `unknown_tool` BLOCK (deny-by-default).
- **Strict primitives**: `risk_score` is a strict integer 0-100 (string/bool coercion
  rejected); `TOOL_ID_PATTERN` is anchored (`^…$`) because pydantic `pattern=` uses
  search semantics (an unanchored pattern accepted an invalid tool id containing a
  space, e.g. `"bad id"`).
- **Destination canonicalization (option chosen)**: Unicode hosts are supported and
  IDNA-encoded then lowercased (`BÜCHER.example` → `xn--bcher-kva.example`); paths and
  queries must be printable ASCII (percent-encoding normalized); whitespace/control
  characters anywhere, userinfo, fragments, IPv6 zone IDs, and trailing dots are
  rejected; port 443 elided; https-only. Allowlisting is exact-match (no wildcards).
- **Loader without the prohibited call**: duplicate keys are detected via a
  `yaml.compose` node walk (the gate prohibits `yaml.load(` in `src/`), then the
  document is parsed with `yaml.safe_load`; strict Pydantic validation; `PolicyConfigError`
  fails closed. Errors name the file, never dump the document.
- **Bundle provenance**: `PolicyBundle.version` + per-file `sha256` + `combined_hash`
  (`sha256("policies=<h>;thresholds=<h>")`); readiness exposes `policy_version` and
  `policy_hash` (the combined hash) on both 200 and 503 payloads (ADR-007 metadata).
- **Self-check fixtures v2**: each `case` is a full `PolicyEvaluationRequest`; an
  optional fixture-level `tool_policy` override (same strict `ToolPolicy` model) covers
  the §10.5 "dedicated test scenario" (e.g. enabling egress) without weakening the
  starter policy; all 7 mandated fixture names retained; expanded to 17 fixtures.
- **Wiring**: startup loads and self-checks the bundle (invalid policy refuses startup);
  readiness re-evaluates the files live so drift flips to 503; the running process keeps
  its startup-loaded bundle (no hot reload — documented limitation).
- **Test principal adapter**: `TestPrincipalResolver` constructible only under
  `APP_ENV=test`, not selectable via settings or `build_principal_resolver`; the
  dev-resolver guard and HMAC middleware are untouched (denial matrix unchanged).
- **Thresholds 40/80 marked experimental** in the config header; validated
  (`ask_user_at_or_above < block_at_or_above`); calibration defers to Phase 9.

## Decisions taken during Phase 2 implementation (within blueprint constraints; ADR-009)

- **Registry capability vs policy authorization (one-directional consistency)**: every
  tool declared in the policy must have a compatible registration or startup fails; a
  registration absent from the policy is registered but disabled (engine `unknown_tool`).
  This is what allows `mock_files.search` (blueprint section 14.1) while the starter
  policy (section 10.5) enables only `mock_files.read`. Class mismatch, `DESTRUCTIVE`,
  approval metadata inconsistency, enabled-egress-without-capability, and policy
  destinations outside the declared set all refuse startup.
- **Exact action identity, no naming convention**: the registry key is the exact
  `(tool_id, action_id)` pair; `action_id` is not required to equal the final dotted
  segment of `tool_id` (an earlier plan idea, deliberately dropped as unenforced
  convention).
- **Execution authorization is gateway-issued and digest-bound**: `ExecutionAuthorization`
  is sentinel-guarded (direct construction raises `UngatedExecutionError`); the digest is
  SHA-256 over canonical JSON of tool/action/validated arguments/resource IDs/destination/
  principal/request/policy hash. Adapters verify the digest immediately before the side
  effect; a non-authorization value raises `ExecutionAuthorizationError`. In-process
  guardrail, not a sandbox (Phase 10).
- **Gateway may only downgrade the engine**: the engine stays the sole `ALLOW` producer;
  audit-outage, deadline, and evaluation-error paths become BLOCK/DENIED typed outcomes.
  `ASK_USER` returns a no-execution result (no pending approval storage until Phase 5).
- **Audit ordering and failure semantics**: `POLICY_EVALUATED` is appended before any
  protected side effect; an append failure on a would-be `ALLOW` yields
  `BLOCK`/`audit_unavailable` and no adapter call. Post-execution append failure yields
  `AUDIT_FAILED` with no result returned. A denial whose audit append fails keeps the
  denial reason (no side effect to roll back). Audit payloads carry identifiers,
  provenance, risk factors, and result digests/sizes only.
- **`risk-v1` scoring is gateway-computed and versioned**: side-effect class, external
  destination (only for `EXTERNAL_MUTATION`; inconsistent facts raise), and registration
  data class; capped at 100; factor codes recorded in decision and audit payloads;
  zero-weight data-class factor omitted. Weights are initial experimental defaults
  (calibration Phase 9); no caller-supplied score is accepted.
- **Bounds are explicit registration facts**: timeout 1-60 s, per-process concurrency
  1-64 (`asyncio.Semaphore` held per running loop via `WeakKeyDictionary`), result size
  <=1 MiB measured over canonical JSON bytes; results are re-validated for schema identity
  and canonicalizability before being returned.
- **Two new observable reason codes**: `policy_evaluation_error` and `audit_unavailable`
  (gateway fail-closed overrides); `binding_mismatch` and `deadline_exceeded` are engine
  facts added in Phase 2 self-check fixtures (21 total).
- **Strictness tightening**: `ToolArguments`/`ToolResult` are `strict=True`; registration
  validation requires resource/destination argument annotations to be exactly `str`
  (a non-str annotation could smuggle mismatched resource IDs past derivation).

## Decisions taken during Phase 3 implementation (within blueprint constraints; ADR-010)

- **Advisory, not authoritative**: the detector returns evidence only; it never feeds
  `PolicyEvaluationRequest`, the engine, or the gateway, exposes no execution surface, and
  cannot widen permissions. This is what makes invariant #10 true by construction rather
  than by accidental coupling.
- **Disposition configuration is exhaustive and monotonic**: every `FindingCode` must be
  mapped; any mapping to PASS is rejected; duplicate YAML keys and unknown codes refuse
  startup. Detection failure (`DETECTOR_UNAVAILABLE`) is therefore never clean.
- **Intake order** is size → content type → UTF-8 decode → JSON structure → normalization
  → heuristics → optional classifier; each stage's violations become typed findings, and
  oversize/type/encoding failures never reach heuristics.
- **Copy-only normalization**: the original string/bytes are never mutated; zero-width,
  control, escape, Base64, NFKC, and mixed-script signals are returned separately. JSON
  depth uses an iterative walk (no recursion limit attack).
- **Heuristics are versioned, deterministic, and provenance-bearing**: ten named rules
  (`input-heuristics-v1`), offsets only (no raw content in findings), quoted/educational/
  defensive contexts downgrade to `QUOTED_INSTRUCTION_CONTEXT` (FLAG), and assistant-
  directed rules apply only to `EXTERNAL_UNTRUSTED`/`TOOL_RESULT`.
- **Trust labels are structural**: six canonical labels; email/external content is
  `EXTERNAL_UNTRUSTED` even for an authenticated requester; duplicate/empty segment sets
  are refused; rendering is sorted JSON carrying the label.
- **Session state is opt-in and bound**: `(tenant_id, subject_id)` is required for every
  operation; mismatch = not found; 24 h inactivity and 7 d absolute expiry with lazy
  deletion; `LEAST(...)` clamps counters at 1,000,000; rotation never inherits signals;
  no prompts or findings are stored; the state is not an authorization input in Phase 3.
- **Shared strict YAML**: duplicate-key detection lives in `security/safe_yaml.py` and is
  reused by the policy loader; parsing still uses `yaml.safe_load` (gate-compatible).
- **Optional classifier is not wired**: the protocol exists for Phase 4+ experimentation;
  faults/timeouts produce `DETECTOR_UNAVAILABLE`, preserving fail-closed behavior.

## Decisions taken during Phase 4 implementation (within blueprint constraints; ADR-011)

- **Extractor proposes, server issues**: only `IntentManifestService.extract_and_issue`
  can create manifests; extractor output is untrusted data. The mock extractor is
  deliberately limited to two documented demo requests and clarifies everything else.
- **Strict local-model boundary**: output is bounded to 65,536 bytes, duplicate JSON keys
  and unknown fields are rejected, the provider cannot set the extractor version or any
  binding, malformed output is retried at most twice by default, and timeouts/provider
  failures map to `IntentExtractorUnavailable`. Every failure path returns no manifest.
- **Concrete constraints only**: exact tool/action, resource ids, canonical destinations,
  and scalar parameter values plus `max_uses`; wildcards, prefixes, floats, duplicates,
  unknown/reserved parameters, inapplicable scopes, and destinations outside adapter
  capability are rejected before issuance. Limits are 16 constraints / 32 uses total.
- **Sealed manifest and full binding**: the frozen dataclass is sentinel-sealed; the
  verifier checks request, principal, tenant, policy version/hash, creation, and expiry.
  The goal is stored only as a SHA-256 digest; raw request text never enters the manifest.
- **Trusted-timezone relative dates**: `TODAY`/`THIS_WEEK` resolve once from the verified
  principal's IANA timezone; missing timezone asks for clarification; invalid timezone
  fails closed. UTC start/end instants are stored and DST transition tests cover 23-hour
  and 25-hour days.
- **Gateway ordering**: the app-built gateway requires a manifest and verifies it before
  registry/policy work; constraint matching happens after argument/resource/destination
  derivation; `max_uses` is reserved only after policy would `ALLOW` and before the
  decision audit. Policy remains the sole `ALLOW` producer and intent can only downgrade.
- **Legacy mode is explicit**: `ToolGateway(intent_tracker=None)` retains Phase 2
  in-process test behavior; the app always supplies a tracker, so production wiring
  cannot execute without a manifest. The tracker is per-process and fails closed at
  10,000 live manifests.
- **Transport limitation**: no route accepts a manifest. A future API must keep issuance
  and verification in-process or add a server-signed serialization; accepted as a
  documented Phase 4 limitation.

## Decisions taken during Phase 5 implementation (within blueprint constraints; ADR-012)

- **Versioned, conservative risk extension**: `risk-v2` keeps every `risk-v1` weight and
  adds one breadth factor over *distinct* canonical resources (2-4 → +5, 5-8 → +10,
  9+ → +15, cap 100). Factor codes are stable and every factor carries a rationale. The
  gateway validates and deduplicates derived resource ids before scoring, digesting, and
  auditing, so duplicate argument values neither inflate risk nor break the approval
  contract. `resource_count` is a strict integer in `[0, 32]`; invalid values map to
  `policy_evaluation_error` with no execution.
- **Approver rules are parsed, not scripted**: the only v1 forms are `role:<role>` and
  `principal:<subject>` with `|` alternatives, at most 256 characters, no duplicates,
  and no control characters. Registry startup validates every rule. Evaluation uses only
  the verified `Principal` and requires tenant equality; model output/request text cannot
  supply a role or approver. Self-approval is default-deny and requires an explicit
  policy flag that is itself valid only with `approval_eligible`. A requester-only rule
  with self-approval disabled is refused before storage (`ApprovalNotApprovable`).
- **Approval storage is digest-only**: `approval_requests` stores the SHA-256 digest of a
  256-bit token returned once, plus canonical action digest, resources, destination,
  requester/tenant, tool/action, risk/side-effect/data provenance, policy version/hash,
  approver rule, status, expiry, and decision metadata. Raw arguments, content, result
  data, and plaintext tokens are never stored. IDs are 32 lowercase hex; TTL defaults to
  900 s and is bounded to 60-86,400 s.
- **Transactional, one-time state machine**: `ApprovalRepository` uses
  `SELECT ... FOR UPDATE` for decisions and consumption and commits each transition with
  its audit event through `AuditChainRepository.append_in_session`. Exactly one of
  several concurrent consumers wins; the rest observe `replay`. Pending or approved rows
  past expiry transition to `expired` on the next decide/consume and emit
  `APPROVAL_EXPIRED`. A pending request can never be consumed.
- **Approval is an execution gate, not policy authority**: the gateway consults it only
  for an engine `ASK_USER` with a presented `approval_id`, re-verifies validated
  arguments/resources/canonical destination, recomputes the canonical action digest
  (including the combined policy hash), and consumes the matching record before any
  adapter call. `ALLOW` needs no approval and `BLOCK`/hard denials ignore one. The
  engine decision remains `ASK_USER`; failures map to `approval_invalid`,
  `approval_denied`, or `approval_expired` with no execution, and storage errors fail
  closed.
- **Audit and wiring**: approval request/decision/consumption/expiry events use
  `firewall.approval`; gateway decision/outcome events carry `approval_id` and
  `approver_subject_id` but no secrets. The app builds `ApprovalRepository` over the
  same audit chain and exposes `ApprovalService`; `APPROVAL_TTL_SECONDS` is validated at
  startup. Phase 5 adds no routes/UI/token transport, automatic request creation,
  approver directory, notifications, revocation operation, or background expiry sweeper
  (Phase 8), and no weight calibration (Phase 9).

## Decisions taken during Phase 6 implementation (within blueprint constraints; ADR-013)

- **Output defense is mandatory, not optional**: `ToolGateway` requires an
  `OutputDefenseService` built from a startup-validated `OutputDlpConfig`; there is no
  no-op/`None` default. The app loads `OUTPUT_DLP_PATH` (default
  `config/output_dlp.yaml`), exposes the config/service on `app.state`, and injects the
  service into the gateway. Missing, unreadable, non-UTF-8, unknown-key, bad-version,
  duplicated, or invalid-regex configuration refuses startup.
- **Two-phase ordered inspection**: egress runs on validated `arguments.model_dump()`
  after principal/binding/intent/argument and target validation but before resource
  authorization, risk, policy, approval, or execution; release runs on the complete
  bounded result after the adapter returns and before any bytes are returned. Read-only
  calls are inspected but may not carry a destination; a destination on a non-mutation
  action or a missing destination on an external mutation is an inspection failure.
- **Effective data class is a floor**: `max(registry data_class, DLP findings)` feeds
  risk, policy, approval binding/storage, and audit. DLP cannot lower a declaration or
  produce `ALLOW`; the policy engine remains the sole `ALLOW` producer. A `BLOCK`-scope
  finding denies regardless of destination; `CLASSIFY` findings are compared with the
  destination's exact `max_data_class`.
- **Destination trust is exact and must cover capability**: the configuration's
  destinations must exactly match all registered `EXTERNAL_MUTATION` destinations at
  startup — a missing entry or a dead (unregistered) entry refuses startup. Matching is
  canonical-string equality (no wildcards/prefixes). The shipped mock sink is
  `PUBLIC`-only, so classified content cannot reach it.
- **Typed outcomes and whole-response suppression**: egress yields `PASS`/`BLOCK` (and a
  fail-closed inspection-error report) mapped to `dlp_egress_blocked` or
  `dlp_inspection_failed`; release yields `PASS`/`REDACT`/`BLOCK`/`REVIEW`. `BLOCK`,
  `REVIEW`, and every inspection failure return no result with
  `InvocationOutcome.response_blocked`, preserving the engine decision/reason and adding
  the `dlp` fact. `REDACT` is span-preserving and idempotent, merges overlapping spans
  under the highest-severity category, starts credential redaction at the first value
  character (so multi-word passphrases cannot leave tails), and must still satisfy the
  registered schema/size bound; otherwise the whole response is suppressed. `REDACT`
  records the released digest while retaining the original result digest.
- **Strict detection bounds fail closed**: five deterministic detectors (canary,
  private-key header, `sk-` API key, credential assignment, email); findings carry
  code/category/count/bounded field paths only, never matched text. Content over
  `max_scan_bytes`, excessive fields/depth, unsafe paths, or a saturated finding report
  that would leave configured patterns unevaluated is an inspection failure, not a
  silent partial pass; per-pattern match truncation still records the evaluated finding.
- **Audit evidence is additive and redacted**: existing schema-v1 events gain an
  optional `dlp` record (phase/outcome/reason/effective class/findings/config
  version+hash/digests/sizes/truncation/error/destination trust). Paths are bounded and
  control-character-free; no matched values, raw arguments, or result bodies are stored.
  No table or migration is added; `EGRESS_INSPECTED`/`OUTPUT_INSPECTED`/`RESPONSE_*`
  event types and the verifier remain Phase 7.
- **Approvals bind the effective class**: approval rows now store and consume
  `side_effect_class` and effective `data_class`; a DLP-raised class cannot reuse an
  approval created for the lower class. Egress DLP denial happens before approval
  consultation and never consumes a grant.
- **Findings and non-goals**: deterministic pattern matching only (no classifier,
  entropy, semantic, multilingual, or per-resource metadata); response `REVIEW` is
  operationally a whole-response block until a review transport exists; no model-prompt
  or adapter-internal content inspection; no live `/v1` DLP route. False
  positives/negatives are documented in `docs/OUTPUT_DLP_FALSE_POSITIVES.md`.

## Phase 0a verification record (actual runs, 2026-10-19; historical)

Environment: macOS (darwin), uv 0.13.1, CPython 3.12.15, Docker 29.3.1 / Compose
v5.1.1 (Docker Desktop started for this verification).

| # | Command | Result |
|---|---|---|
| 1 | `uv sync --frozen` | PASS — installs from committed lockfile, 38 packages resolved, no drift |
| 2 | `uv run pytest` | PASS — 25 passed, 0 warnings |
| 3 | `bash scripts/check.sh` (clean) | PASS — exit 0, all six steps |
| 4 | `bash scripts/check.sh` (injected failing test) | PASS (expected failure) — exit 1 at pytest step: "CHECK FAILED: test failures reported"; the injected failure was also caught at the ruff format and lint steps in earlier iterations |
| 5 | `bash scripts/check.sh` (after removing injected test) | PASS — exit 0 |
| 6 | `docker compose config -q` | PASS — syntax valid |
| 7 | `docker compose up -d db` | PASS — `protai-db-1` reports **healthy** (`pg_isready` healthcheck) |
| 8 | `docker compose build api` | PASS — image builds from digest-pinned base images; dependencies from `uv.lock` only |
| 9 | `docker compose up -d api` | PASS — `protai-api-1` reports **healthy**; `depends_on: service_healthy` honored |
| 10 | Host checks against Compose (dev profile) | `/health/live` → 200 `{"status":"alive"}`; `/health/ready` → **200** `{"status":"ready","checks":{"config":true,"database":true}}` against the real PostgreSQL; `/docs` → 200; `/openapi.json` → 200; leak check found 0 occurrences of credentials/DNS/port |
| 11 | Non-root runtime check | `docker compose exec -T api id` → `uid=10001(app)` |
| 12 | Production profile inside the container (`docker compose run` with `APP_ENV=production`, non-sample password) | `/health/live` → 200; `/docs`, `/redoc`, `/openapi.json` → 404; `/health/ready` → 503 `{"status":"not_ready","checks":{"config":true,"database":false}}` — correct: the non-sample password does not match the dev database, and dev credentials are refused in production mode by design, so readiness honestly reports the database as not reachable |
| 13 | In-container startup refusal (production + sample password) | PASS — container exits 1 with `refusing the sample development database password outside development/test` |
| 14 | Live dev run without Docker (uvicorn 127.0.0.1:8011) | `/health/live` → 200; `/health/ready` → 503 (no database); `/docs` → 200 |
| 15 | Startup refusal: `APP_ENV` missing | PASS — exits 1 with `app_env Field required` |
| 16 | Startup refusal: wrong scheme (`postgresql+psycopg://`) | PASS — exits 1 with clear scheme error referencing ADR-005 |
| 17 | Fresh-checkout approximation (clean copy without `.venv`/caches, 34 files) | PASS — `uv sync --frozen` then `bash scripts/check.sh` exit 0 |

## Phase 0b verification record (actual runs, 2026-10-19)

Rows 18+ continue the numbered record. Detail codes and file references are in
`project_memory/TESTING_AND_VERIFICATION.md` (V18–V28).

| # | Command | Result |
|---|---|---|
| 18 | `uv run --frozen pytest -q` | PASS — **231 passed** (~2.8 s); includes DB-backed integration tests against the Compose PostgreSQL |
| 19 | `uv run --frozen mypy` | PASS — no issues, 25 source files (strict, `src/`) |
| 20 | `uv run --frozen ruff format --check .`; `ruff check .` | PASS — clean (import sorting fixed in `migrations/`) |
| 21 | `uv run --frozen pytest tests/integration -k "host_auth or nonce or principal" -q` | PASS — 18 passed, 19 deselected |
| 22 | `uv run --frozen alembic upgrade head` (run twice) | PASS — first run applies baseline to a fresh database; second run reports already at head (idempotent) |
| 23 | `uv run --frozen alembic check` | PASS — "No new upgrade operations detected" |
| 24 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps: lockfile; ruff format; ruff lint; mypy; 231 tests; Gitleaks 8.30.1 dir+git ("no leaks found"); prohibited-pattern greps clean; `compare_digest` confined to `security/constant_time.py` |
| 25 | `docker compose build api`; `docker compose run --rm api alembic upgrade head` | PASS — image builds incl. `config/`, `migrations/`, `alembic.ini`; baseline applies inside the container |
| 26 | Live Compose stack (`protai-api-1`) | `/health/live` → 200; `/health/ready` → 200 `{"config":true,"database":true,"policy_self_checks":true}`; unsigned `POST /v1/echo` → 400 `{"detail":"missing_headers"}` |
| 27 | Signed-request proof against the container (Compose dev key, fresh timestamp+nonce) | First request: 404 Not Found — auth passed, nonce registered, body replayed (no `/v1` route exists yet, expected); replay of the identical signed request → 401 `{"detail":"replayed_nonce"}` |
| 28 | Live startup refusals | `APP_ENV=production PRINCIPAL_RESOLVER=dev` → ValidationError "PRINCIPAL_RESOLVER=dev is refused outside development/test"; `POLICY_SELF_CHECKS_PATH=/nonexistent.yaml` → `PolicySelfCheckConfigError` — both refuse startup |
| 29 | `gitleaks git --redact --exit-code 1 .` | PASS — no leaks across the full history (baseline + 7 Phase 0b commits) |

The Compose API container was stopped after verification (`docker compose stop api`);
the database container and `db_data` volume are preserved for local runs and tests.

## Phase 1 verification record (actual runs, 2026-10-19)

Rows 30+ continue the numbered record. Full evidence: `project_memory/TESTING_AND_VERIFICATION.md` (V30+).

| # | Command | Result |
|---|---|---|
| 30 | `uv run --frozen pytest -q` | PASS — **406 passed** (364 unit + 42 integration; DB-backed integration against the Compose PostgreSQL) |
| 31 | `uv run --frozen mypy src` | PASS — no issues, 35 source files (strict) |
| 32 | `uv run --frozen ruff check src/ tests/`; `ruff format src tests` | PASS — clean (format applied to 3 files, then check clean) |
| 33 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps; Gitleaks 8.30.1 `git` scan: 9 commits, no leaks found |
| 34 | Policy bundle smoke check (`load_policy_bundle` + `check_policy_self_checks`) | PASS — `version: dev-1`, `policies_sha256 35bcd687…`, `thresholds_sha256 3e1d34ae…`, `combined_hash 8a4ba203e3baaf86eabb2e299992166289cae938ec9ea9a7bccadf6e6e068e6a`; 17 fixtures, 0 failures |
| 35 | Integration wiring tests (`test_policy_self_checks_wiring.py`, `test_health.py`) | PASS — invalid/missing policy file refuses startup; mismatching fixture refuses startup; live policy/fixture drift flips readiness to 503; readiness payload carries `policy_version`/`policy_hash` |

## Phase 2 verification record (actual runs, 2026-10-19)

Rows 36+ continue the numbered record. Full evidence:
`project_memory/TESTING_AND_VERIFICATION.md` (V36+).

| # | Command | Result |
|---|---|---|
| 36 | `uv run --frozen pytest -q` | PASS — **520 passed** (461 unit + 47 integration + 12 security; DB-backed integration against the Compose PostgreSQL) |
| 37 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps; Gitleaks 8.30.1 `git` scan: 13 commits, no leaks found |
| 38 | `uv run --frozen pytest tests/security tests/unit/test_gateway.py -q` | PASS — **31 passed** (no-bypass + gateway failure-mode suites) |
| 39 | `uv run --frozen pytest tests/integration/test_gateway_end_to_end.py tests/integration/test_gateway_wiring.py -q` | PASS — **5 passed** (real-PostgreSQL decision/outcome chain order and linkage; startup registry/gateway wiring; unregistered-policy-tool startup refusal) |
| 40 | `uv run --frozen pytest tests/unit/test_policy_self_checks.py tests/integration/test_policy_self_checks_wiring.py -q` | PASS — **41 passed** — 21 fixtures against the real engine, startup + readiness wiring |
| 41 | `uv run --frozen mypy src`; `ruff check src tests`; `ruff format --check src tests` | PASS — no issues, 45 source files (strict); lint/format clean (included in gate step 37) |

## Definition of Done checklist (blueprint section 21, Phase 0b)

| DoD item | Status |
|---|---|
| Host-auth signing/verification and replay-rejection tests pass | **PASS** — verifier matrix (unit), middleware denial matrix (integration), live container proof (rows 26–27); forged/mutated/stale/unknown-key/replayed all denied with documented codes; DB failure → 503 |
| Migrations apply and re-apply idempotently | PASS (rows 22–23, 25) |
| `DevPrincipalResolver` cannot start outside dev/test | PASS (row 28; settings validator + resolver + factory guard tests; `model_construct` bypass attempt rejected) |
| Policy self-check scaffolding runs at startup and in CI and fails on a deliberately mismatching fixture | PASS — startup refusal on mismatch and on unreadable file; readiness drift → 503; the gate runs the suite that proves it |
| `/docs`, `/redoc`, `/openapi.json` remain absent outside dev/test | PASS — gating tests unchanged and green |
| Gitleaks runs in `check.sh`; fails when unavailable or on a finding | PASS (row 24; pinned 8.30.1; missing/mismatch fails the gate) |
| No secrets committed | PASS (row 29; only documented disposable dev values; one-value allowlist documented in `.gitleaks.toml`) |
| `check.sh` exits non-zero on any failure | PASS — 8 steps; failure path unchanged |
| Phase 0b is not complete merely because the application starts | PASS — all invariant tests above actually ran and are recorded |

## Definition of Done checklist (blueprint section 21, Phase 1)

| DoD item | Status |
|---|---|
| Table-driven policy tests cover allowed/forbidden/malformed/cross-scope/unknown/error | **PASS** — `tests/unit/test_policy_engine.py` (64 tests; full matrix incl. malformed requests, cross-scope, unknown tool, error/threshold rows) + loader/model/url suites |
| Strict contracts fail closed on unknown/invalid values | PASS — `extra="forbid"`, strict ints, anchored tool-id pattern, canonical enums without aliases/coercions; covered by `test_policy_models.py`, `test_policy_loader.py`, `test_urls.py` |
| ADR-007 self-check fixtures pass against the real engine (startup + readiness) | PASS — 17 fixtures (7 mandated names retained) pass via `check_policy_self_checks` (row 34) and through app startup/readiness (row 35) |
| No LLM involved in authorization (engine imports no model provider; gate greps intact) | PASS — static imports only; `check.sh` prohibited-pattern greps remain clean |
| Quality gate green (`check.sh`, Gitleaks clean) | PASS — rows 32–33 |

## Definition of Done checklist (blueprint section 21, Phase 2)

| DoD item | Status |
|---|---|
| No-bypass tests prove the mock side-effect sink changes only after a valid gateway `ALLOW` | **PASS** — `tests/security/test_gateway_no_bypass.py` (denied paths never execute; sink empty under every denial and under audit outage) + `tests/integration/test_gateway_end_to_end.py` (sink record only after chained decision/outcome events) |
| Unknown or denied actions have no side effect | PASS — unknown tool, registered-but-disabled tool, invalid arguments, resource/destination mismatches, cross-user scope, deadline expiry, disabled egress: all DENIED with adapter call count 0 and empty sink |
| Every adapter invocation originates from the gateway; direct calls fail closed | PASS — sentinel-guarded `ExecutionAuthorization` (direct construction raises); adapters verify the digest and reject non-authorizations; gateway issues authorization only after a durable `ALLOW` decision event |
| Exceptions during policy/validation/audit prerequisites never continue to a side effect | PASS — engine exception yields `policy_evaluation_error` DENIED; audit append failure on a would-be ALLOW yields `audit_unavailable` DENIED; both leave the sink empty |
| Timeouts and bounded result sizes enforced with typed outcomes | PASS — sleeping adapter with 1 ms timeout yields `TIMEOUT`; oversized result yields `RESULT_REJECTED`/`ResultTooLarge`; wrong-schema result yields `RESULT_REJECTED`/`ResultSchemaMismatch`; per-tool concurrency limit == 1 enforced under `gather` |
| Invalid registry/policy configuration refuses startup | PASS — DESTRUCTIVE/duplicate/mismatched/oversized registrations raise at construction; policy tool without adapter refuses `create_app` (`ToolRegistryConfigError`, tested) |
| Post-authorization tool/argument mutation fails the action-digest check | PASS — `tests/unit/test_mock_adapters.py` (changed arguments, different tool/action) and `tests/unit/test_action_digest.py` coverage |
| Policy engine remains the sole `ALLOW` producer; gateway may only downgrade | PASS — the gateway constructs no ALLOW; audit/deadline/evaluation overrides are BLOCK/DENIED; `ASK_USER` never executes |
| Full suite + gate green; docs/memory/ADR updated | PASS — rows 36-41; ADR-009; this file; `SECURITY_INVARIANTS`, `POLICY_DECISION_MATRIX`, `KNOWN_LIMITATIONS`, memory refresh |

## Phase 3 verification record (actual runs, 2026-10-19)

Rows 42+ continue the numbered record. Full evidence:
`project_memory/TESTING_AND_VERIFICATION.md` (V43+).

| # | Command | Result |
|---|---|---|
| 42 | `uv run --frozen pytest -q` | PASS — **600 passed** (517 unit + 60 integration + 23 security; DB-backed integration against the Compose PostgreSQL) |
| 43 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps; ruff format/lint clean (136 files); mypy 55 source files; Gitleaks 8.30.1 dir+git: 19 commits, no leaks found |
| 44 | Phase 3 targeted suites (`test_input_normalization`, `test_input_heuristics`, `test_input_defense_config`, `test_context_labels`, `test_sessions`, `test_input_defense_failure`) | PASS — 64 passed (detector behavior, quoted-context downgrade, strict config, failure semantics) |
| 45 | Phase 3 integration suites (`test_input_defense_wiring`, `test_session_security_state`) | PASS — 13 passed (startup wiring + refusal; binding, guessed-ID, bounded counters, TTL/max-age expiry, rotation isolation against real PostgreSQL) |
| 46 | `uv run --frozen alembic upgrade head` → `downgrade -1` → `upgrade head` → `check` | PASS — `c7f1a2b3d4e5` applies, downgrades, and re-applies cleanly; "No new upgrade operations detected" |
| 47 | Manual service smoke (benign/attack/quoted/external/zero-width/homoglyph) | PASS — PASS / REJECT / FLAG / QUARANTINE / REJECT(OBFUSCATED+DIRECT) / FLAG(HOMOGLYPH_INDICATORS) with documented honest limits |

## Definition of Done checklist (blueprint section 21, Phase 3)

| DoD item | Status |
|---|---|
| Injection attempts on user input and external/tool content raise typed findings | **PASS** — 10 versioned heuristic rules; unit matrix covers direct override, secret/system-prompt extraction, developer mode, jailbreak, external-only assistant-directed instructions; findings carry codes, offsets, and versions |
| Benign and quoted/educational mentions are not treated as attacks | PASS — qualification windows downgrade to `QUOTED_INSTRUCTION_CONTEXT` (FLAG); benign hard-negative parametrized cases raise no findings |
| Detector/provider outage never fails open | PASS — every intake/detector/normalizer/classifier fault yields `DETECTOR_UNAVAILABLE` with the configured non-PASS disposition; no finding code can map to PASS; oversize/unsupported/invalid-encoding rejected before heuristics |
| Trust labels are attached and preserved through context assembly | PASS — six canonical labels; external email forced to `EXTERNAL_UNTRUSTED` for authenticated requesters; duplicate/empty segment sets refused; deterministic JSON rendering includes the label |
| Session signals are bound, bounded, and expire | PASS — every operation requires `(tenant_id, subject_id)` with mismatch = not found; 24 h inactivity/7 d absolute expiry with lazy deletion; counters clamped at 1,000,000; rotation inherits nothing (real-PostgreSQL tests) |
| Detection cannot influence authorization or execution | PASS — no import/wiring path into policy facts, engine, or gateway; service exposes no invocation method (asserted); invariants #10/#11/#15/#23 updated honestly in `docs/SECURITY_INVARIANTS.md` |
| Strict configuration refuses startup when invalid or incomplete | PASS — duplicate keys, missing/unknown finding codes, invalid content types, and PASS mappings all refuse startup (unit + app-wiring tests) |
| Quality gate green; docs/memory/ADR updated | PASS — rows 42-47; ADR-010; this file; `SECURITY_INVARIANTS`, `KNOWN_LIMITATIONS`, `THREAT_MODEL`, `ARCHITECTURE`, README, memory refresh |

## Phase 4 verification record (actual runs, 2026-10-19)

Rows 48+ continue the numbered record. Full evidence:
`project_memory/TESTING_AND_VERIFICATION.md` (V51+).

| # | Command | Result |
|---|---|---|
| 48 | `uv run --frozen pytest -q` | PASS — **661 passed** (568 unit + 64 integration + 29 security; DB-backed integration against the Compose PostgreSQL) |
| 49 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps; ruff format/lint clean (151 files); mypy 60 source files; Gitleaks 8.30.1 dir+git: 23 commits, no leaks found |
| 50 | `uv run --frozen pytest -q tests/unit/test_intent_models.py tests/unit/test_intent_extractors.py tests/unit/test_intent_validation.py tests/unit/test_intent_service.py tests/security/test_intent_no_grant.py` | PASS — 56 passed (sealing/binding/expiry, strict extractor output/retry/outage, exact constraints/tracker/DST, issuance/limits, no-grant security) |
| 51 | `uv run --frozen pytest -q tests/integration/test_intent_wiring.py tests/unit/test_settings.py` | PASS — 63 passed (app wiring/end-to-end allow/limit/clarification/wrong request against real PostgreSQL; settings TTL) |
| 52 | Manual `IntentManifestService` smoke (summarize/read/forward/greeting) | PASS — ACTIVE with resolved UTC window / ACTIVE / REJECTED / REQUIRES_CLARIFICATION, with no manifest for rejected or clarified requests |

## Definition of Done checklist (blueprint section 21, Phase 4)

| DoD item | Status |
|---|---|
| Malformed model output and extractor outages do not grant permission | **PASS** — strict bounded parser rejects duplicate keys/unknown fields/oversize; malformed output retries are bounded; timeout/outage map to `IntentExtractorUnavailable`; every failure path returns no manifest (unit + security tests) |
| Ambiguous intent grants no permission | PASS — service returns `REQUIRES_CLARIFICATION` with no manifest; app integration proves no execution; missing/invalid trusted timezone fails closed |
| Tool arguments are compared with concrete intent limits | PASS — gateway verifies action, exact resource set, canonical destination, exact parameter values, and bounded uses after argument/resource validation; mismatches map to intent reason codes with zero adapter calls |
| Manifest mutation/replay/expiry/rebinding cannot execute | PASS — sentinel-sealed manifest + full request/principal/tenant/policy-version/policy-hash/expiry verification; 6 security tests cover forged, expired, rebound, and wrong-action cases |
| All execution still routes through the gateway | PASS — single `invoke_tool` chokepoint unchanged; app-built gateway requires the tracker/manifest; legacy no-tracker gateways remain denied without a manifest (security test) |
| Policy remains the sole `ALLOW` producer | PASS — intent constraints are applied after the engine and never enter `PolicyEvaluationRequest`; intent can only downgrade |
| Quality gate green; docs/memory/ADR updated | PASS — rows 48-51; ADR-011; this file; `SECURITY_INVARIANTS`, `KNOWN_LIMITATIONS`, `THREAT_MODEL`, `ARCHITECTURE`, README, memory refresh |

## Phase 5 verification record (actual runs, 2026-10-26)

Rows 53+ continue the numbered record. Full evidence:
`project_memory/TESTING_AND_VERIFICATION.md` (V57+).

| # | Command | Result |
|---|---|---|
| 53 | `uv run --frozen pytest -q` | PASS — **734 passed** (613 unit + 80 integration + 41 security; real-PostgreSQL approval/audit tests against the Compose database) |
| 54 | `bash scripts/check.sh` | PASS — exit 0, all 8 steps; ruff format/lint clean; mypy 63 source files; Gitleaks 8.30.1 dir+git: 27 commits, no leaks found; prohibited-pattern and constant-time-confinement checks clean |
| 55 | Targeted Phase 5 suites (`test_approval_flow`, `test_gateway_approval`, `test_gateway_wiring`, `test_migrations`, `test_risk_engine`, `test_approver_rules`, `test_settings`, `test_gateway_no_bypass`) | PASS — **157 passed** (11 real-PostgreSQL approval lifecycle/concurrency, 5 gateway approval gating, 2 wiring, 1 migration, 30 risk, 24 approver rules, 60 settings, 24 no-bypass) |
| 56 | `alembic upgrade head` → `downgrade -1` → `upgrade head` → `check` | PASS — `e5a1c2b3d4f6` applies, downgrades to `c7f1a2b3d4e5`, re-applies cleanly; "No new upgrade operations detected" |
| 57 | Dedup regression (`test_duplicate_derived_resource_ids_are_collapsed_before_risk_and_audit`) | PASS — duplicate resource-id argument values collapse to one distinct target before risk, approval digest, authorization, and audit |
| 58 | Post-commit `bash scripts/check.sh` after `ad9e76a`/`0b2f1c9`/`8cce014` (V62) | PASS — exit 0, all 8 steps; 734 tests; ruff/mypy clean (63 source files); Gitleaks 8.30.1 dir+git clean across 30 commits |

## Definition of Done checklist (blueprint section 21, Phase 5)

| DoD item | Status |
|---|---|
| Risk calculations are unit tested | **PASS** — `tests/unit/test_risk_engine.py` covers every `risk-v1` weight, the v2 breadth boundaries (0/1/2/4/5/8/9+), cap/version, rationale/codes, invalid counts (bool/str/float/negative/oversize), and preserves single-resource scores |
| Hard denies cannot be overridden | PASS — a presented valid approval on an engine `BLOCK`/hard-deny action is ignored and not consumed; `tests/security/test_gateway_no_bypass.py` and `tests/integration/test_gateway_approval.py` assert zero adapter calls and unchanged sink |
| Approval mutation/replay/expiry tests prove no unauthorized execution | PASS — canonical digest recomputation plus stored resource/destination/policy version/hash verification; real-PostgreSQL mutation, replay, denial, pending, expiry, and exactly-one-winner concurrency tests; all failures map to typed no-execution outcomes |
| Approval is one-time and atomic under concurrency | PASS — `SELECT ... FOR UPDATE` decision/consumption with same-transaction audit; five concurrent consumers yield one `consumed` and four `replay`; a consumed row cannot be replayed |
| Verified principal/rule/tenant gates approval; no self-approval by default | PASS — strict rule parser/evaluator; tenant equality; self-approval only with explicit `self_approval_allowed`; requester-only unsatisfiable rules refused before creation |
| No secrets/raw content stored or logged | PASS — token returned once, only SHA-256 stored; approval rows carry canonical facts and provenance, not arguments/content; tests assert token digests and redacted audit payloads |
| Execution still occurs only via `invoke_tool`; policy remains sole `ALLOW` producer | PASS — approval only makes an engine `ASK_USER` executable; the engine decision stays `ASK_USER`, `ALLOW` needs none, and `BLOCK` dominates; single gateway chokepoint unchanged |
| Quality gate green; docs/memory/ADR updated | PASS — rows 53-58; ADR-012; this file; `SECURITY_INVARIANTS`, `KNOWN_LIMITATIONS`, `THREAT_MODEL`, `ARCHITECTURE`, `POLICY_DECISION_MATRIX`, README, memory refresh |

## Phase 6 verification record (actual runs, 2026-10-26)

Rows 59+ continue the numbered record. Full evidence:
`project_memory/TESTING_AND_VERIFICATION.md` (V63+).

| # | Command | Result |
|---|---|---|
| 59 | `alembic current` → `upgrade head` → `downgrade -1` → `upgrade head` → `check` (test DB, §5.4 env) | PASS — at `e5a1c2b3d4f6 (head)`; `upgrade head` is a no-op; `downgrade -1` reaches `c7f1a2b3d4e5`; re-upgrade returns to head; "No new upgrade operations detected". Phase 6 adds no schema object |
| 60 | `uv run --frozen pytest -q`; then `uv run --frozen mypy src`, `ruff check src tests`, `ruff format --check src tests` | PASS — **766 passed** (640 unit + 85 integration + 41 security) including real-PostgreSQL approval/DLP binding tests; mypy clean (64 source files); ruff format/lint clean |
| 61 | Targeted Phase 6 suites: `test_output_dlp.py`, `test_gateway.py`, `test_gateway_approval.py`, `test_gateway_wiring.py`, `test_gateway_end_to_end.py`, `test_gateway_no_bypass.py`, `test_intent_no_grant.py` | PASS — **93 passed** (19 DLP config/detection/redaction/fail-closed, 8 gateway DLP execution/response cases, 2 approval class-binding, 3 startup trust-coverage, plus unchanged e2e/no-bypass/intent suites) |
| 62 | Post-commit `bash scripts/check.sh` after docs `98cfdde` and memory `9e78933` | PASS — exit 0, all 8 steps; ruff format/lint clean (166 files formatted); mypy clean (64 source files); **766 passed** (640 unit + 85 integration + 41 security); Gitleaks 8.30.1 dir+git "no leaks found" (**36 commits scanned**); prohibited-pattern greps clean; `compare_digest` confined to `security/constant_time.py` |

## Definition of Done checklist (blueprint section 21, Phase 6)

| DoD item | Status |
|---|---|
| Canary data never reaches an unauthorized mock sink | **PASS** — `tests/unit/test_gateway.py::test_synthetic_canary_never_reaches_an_enabled_sink` enables the sink, presents canary arguments, and asserts a `dlp_egress_blocked` denial, zero adapter calls, and byte-identical sink state; `test_output_dlp.py` covers the same at the detector boundary and real-PostgreSQL e2e/no-bypass suites assert the unchanged sink |
| Release and deny outcomes are typed and audited | PASS — `PASS`/`REDACT`/`BLOCK`/`REVIEW` and `dlp_egress_blocked`/`dlp_inspection_failed` are closed enums; `InvocationOutcome.response_blocked` marks suppression; decision/outcome audit events carry the additive redacted `dlp` record; integration tests assert durable order and payload shape |
| DLP logs/evidence stay redacted | PASS — findings store stable code/category/count/bounded field paths only; tests serialize reports/audit payloads and require canary values, email strings, and credential values to be absent; field paths reject control characters and length over 256 |
| False-positive cases are documented | PASS — `docs/OUTPUT_DLP_FALSE_POSITIVES.md` records tested benign cases, known false positives, intentional false negatives, fail-closed cases, and tuning guidance; benign-lookalike regression tests exist in `test_output_dlp.py` |
| Gateway remains the only execution path | PASS — the mandatory `OutputDefenseService` is constructor-injected; no adapter call occurs on any egress denial or release suppression; execution authorization and the single `invoke_tool` chokepoint are unchanged; no-bypass security tests stay green |
| All prior suites and the 8-step gate stay green; docs/memory/ADR updated | PASS — rows 59-62; **766** tests; mypy 64 files; ADR-013; this file; `SECURITY_INVARIANTS`, `KNOWN_LIMITATIONS`, `THREAT_MODEL`, `ARCHITECTURE`, `POLICY_DECISION_MATRIX`, `OUTPUT_DLP_FALSE_POSITIVES`, README, `.env.example`, memory refresh; post-commit gate V66 green after `98cfdde`/`9e78933` |

## How to continue (next session)

Phase 7 — Audit persistence and verification (blueprint §16, §21 Phase 7): add the full
structured event taxonomy (`REQUEST_RECEIVED`, `PRINCIPAL_RESOLVED`/`_REJECTED`,
`INPUT_INSPECTED`, `INTENT_CREATED`/`_FAILED`, `TOOL_CALL_PROPOSED`, `POLICY_EVALUATED`,
`APPROVAL_*`, `TOOL_EXECUTION_STARTED`/`_COMPLETED`/`_FAILED`, `EGRESS_INSPECTED`,
`OUTPUT_INSPECTED`, `RESPONSE_RELEASED`/`_SUPPRESSED`, `SECURITY_ALERT_RAISED`) with
stable names/schema versions, `trace_id`/`request_id`/`event_id`, component/version,
policy version, reason codes, durations, and safe references so a complete
request-to-tool sequence is correlatable. Promote the additive `dlp` evidence to
first-class DLP events (ADR-013 deferral) and verify it. Build the chain verifier over
the exact stored `canonical_event_bytes` (ADR-002), with mutation/reordering detection
and fixed canonical-byte vectors; keep the concurrent-writer test. Write the
retention/data-handling document and privacy tests proving raw secrets/full payloads are
absent from default logs. Preserve the ADR-008 engine contract, ADR-009 gateway contract,
ADR-010 advisory boundary, ADR-011 intent boundary, ADR-012 approval boundary, and
ADR-013 DLP boundary; keep all suites and the 8-step gate green.
