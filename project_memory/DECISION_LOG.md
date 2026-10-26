# Decision Log

Two levels of decisions are recorded:

1. **ADRs** — security/architecture contracts. One file per decision under [../docs/adr/](../docs/adr/)
   with the index in [../docs/DECISIONS.md](../docs/DECISIONS.md) (blueprint §22.4: the index must not duplicate
   full ADR content).
2. **Implementation decisions** — choices made within blueprint constraints, recorded here
   and in [../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md).

When a decision changes: create a **superseding ADR** (for contract decisions) and update
the index; never silently rewrite the historical rationale.

## ADRs (all Accepted; ADR-001–ADR-007 dated 2026-10-19, later ADRs dated by phase)

| ADR | Decision | Implementation phase | File |
|---|---|---|---|
| ADR-001 | Host-to-gateway HMAC-SHA256 authentication + development-resolver guard | Phase 0b | [../docs/adr/ADR-001-host-hmac-authentication.md](../docs/adr/ADR-001-host-hmac-authentication.md) |
| ADR-002 | Postgres-serialized audit hash-chain append + exact canonical byte format | Phase 7 (append-protocol scaffolding in 0b) | [../docs/adr/ADR-002-audit-hash-chain.md](../docs/adr/ADR-002-audit-hash-chain.md) |
| ADR-003 | v1 token streaming disabled: buffer, inspect, release | Phase 6/8 | [../docs/adr/ADR-003-no-token-streaming.md](../docs/adr/ADR-003-no-token-streaming.md) |
| ADR-004 | AI SOC analyzer treated as an injection target; alert-only | Phase 10 | [../docs/adr/ADR-004-soc-alert-only.md](../docs/adr/ADR-004-soc-alert-only.md) |
| ADR-005 | SQLAlchemy 2.x async persistence with asyncpg | Phase 0b | [../docs/adr/ADR-005-sqlalchemy-async-persistence.md](../docs/adr/ADR-005-sqlalchemy-async-persistence.md) |
| ADR-006 | Alembic for all schema changes; `create_all` only in isolated unit fixtures | Phase 0b | [../docs/adr/ADR-006-alembic-migrations.md](../docs/adr/ADR-006-alembic-migrations.md) |
| ADR-007 | Policy decision matrix mirrored in docs/config + startup self-checks | Phase 1 (scaffolding in 0b) | [../docs/adr/ADR-007-policy-matrix-self-checks.md](../docs/adr/ADR-007-policy-matrix-self-checks.md) |
| ADR-008 | Deterministic policy engine with strict typed contracts + versioned policy bundle | Phase 1 | [../docs/adr/ADR-008-policy-engine-typed-contracts.md](../docs/adr/ADR-008-policy-engine-typed-contracts.md) |
| ADR-009 | Tool registry, execution authorization, and the enforced gateway | Phase 2 | [../docs/adr/ADR-009-tool-registry-and-enforced-gateway.md](../docs/adr/ADR-009-tool-registry-and-enforced-gateway.md) |
| ADR-010 | Advisory input threat defense, trust labels, and session signals | Phase 3 | [../docs/adr/ADR-010-advisory-input-defense-and-session-signals.md](../docs/adr/ADR-010-advisory-input-defense-and-session-signals.md) |
| ADR-011 | Server-issued, sealed intent manifests and concrete action constraints | Phase 4 | [../docs/adr/ADR-011-server-issued-intent-manifests.md](../docs/adr/ADR-011-server-issued-intent-manifests.md) |
| ADR-012 | `risk-v2` bounded breadth factor + durable one-time human approvals bound to the canonical action digest | Phase 5 | [../docs/adr/ADR-012-risk-v2-and-human-approvals.md](../docs/adr/ADR-012-risk-v2-and-human-approvals.md) |
| ADR-013 | Mandatory two-phase output DLP, exact destination trust, and complete-response release/suppression | Phase 6 | [../docs/adr/ADR-013-output-dlp-and-egress.md](../docs/adr/ADR-013-output-dlp-and-egress.md) |

## Implementation decisions (Phase 0a, within blueprint constraints)

| Decision | Rationale | Recorded in |
|---|---|---|
| App factory `create_app(settings)` **plus** module-level `app` | Tests pass explicit settings; the module-level app supports the documented `uvicorn ai_security.api.app:app` command needed by the Phase 0b refusal test | [../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md) |
| `APP_ENV` required, no default | Fail closed: a missing/unknown environment must never boot into a permissive mode | code + docs |
| Readiness probe uses asyncpg directly (2 s timeout) until Phase 0b | SQLAlchemy persistence is 0b; dependency is overridable in tests (blueprint §20.1) | ADR-005 context; IMPLEMENTATION_STATE |
| Sample-password refusal implemented in 0a for `DATABASE_URL`; HMAC sample-key refusal deferred to 0b | Matches what is actually consumed: 0a reads `DATABASE_URL`, not `HOST_AUTH_KEYS_JSON` | IMPLEMENTATION_STATE |
| Dev dependency `httpx2` instead of `httpx` | Starlette 1.9 `TestClient` requires `httpx2` and deprecates `httpx`; maintained successor in the HTTPX family (blueprint §5.1 references HTTPX) | IMPLEMENTATION_STATE |
| `StrEnum` (Python 3.12) instead of `(str, Enum)` | Ruff UP042; Python 3.12 is the fixed runtime | code + pyproject |
| Ruff `extend-exclude` for the blueprint and `archive/` markdown | Authoritative spec documents must never be reformatted (they contain Python fences) | `../pyproject.toml` |
| mypy strict with `asyncpg` `ignore_missing_imports` override | Keep strict typing without false failures on a dependency that ships no `py.typed` | `../pyproject.toml` |
| Compose API host port **8080** (container stays 8000) | Host port 8000 is commonly occupied by unrelated local emulators (DynamoDB Local during verification); bindings remain 127.0.0.1-only | `../docker-compose.yml`, README |
| Base images pinned by digest (`python:3.12.8-slim-bookworm`, `uv:0.13.1`) | Blueprint §5.1 pinning; reproducible builds | `../Dockerfile` |
| `.env.example` carries the full blueprint §5.4 variable set; header explains which values are 0a vs 0b | One authoritative environment template; no surprise variables in 0b | `../.env.example` |
| No `config/`, `migrations/`, `evaluation/` directories in 0a | They belong to Phases 0b/0b/9 per phase gates | IMPLEMENTATION_STATE |

## Implementation decisions (Phase 0b, within blueprint constraints)

| Decision | Rationale | Recorded in |
|---|---|---|
| Pure-ASGI middleware keyed on the `/v1/` path prefix (not per-route dependencies) | Enforcement is fail-closed and independent of route existence; runs before routing and identically under `PRINCIPAL_RESOLVER=dev` (no bypass) | `../src/ai_security/api/middleware.py`; middleware tests |
| Atomic replay rejection in one statement (`ON CONFLICT ... WHERE expires_at < now() RETURNING`) | Concurrency-safe single-use semantics without read-then-write races; expanded rows re-register | `../src/ai_security/persistence/nonce_repository.py`; concurrency tests |
| Nonce-store failure → 503, never fail-open | Blueprint §9.4 spirit: inability to prove nonce freshness must deny | middleware + tests |
| Denial surface stabilized as machine-readable detail codes (400/401/413/503) | Lets later phases and tests distinguish causes without leaking key material | `../src/ai_security/identity/host_auth.py`, middleware |
| `HOST_AUTH_KEYS_JSON` required; strict records (`extra="forbid"`, base64 ≥32 bytes, duplicate IDs rejected, all-zero sample refused outside dev/test) | Fail closed on every key-configuration sloppiness; keep the 0a sample-refusal pattern | `../src/ai_security/settings.py`; settings tests |
| Dev-resolver guard in three places (settings validator, resolver constructor, factory) | Defense in depth against future call sites constructing the resolver directly | `../src/ai_security/identity/resolver.py`; tests incl. `model_construct` bypass attempt |
| Audit append follows ADR-002 verbatim (advisory-lock key `3141592653589793`, chain `v1`, canonical bytes stored, unique sequence) | Lock protocol is contract-level; scaffolding must be byte-exact now so Phase 7 changes nothing structural | `../src/ai_security/persistence/audit_repository.py`; vector + concurrency tests |
| Interim policy matrix evaluator shipped as explicit scaffolding (`policy/interim_matrix.py`) with the ADR-007 fixture contract; Phase 1 replaces the evaluator, not the contract | Self-checks must exist in 0b; an honest transcription beats a fake engine | `../src/ai_security/policy/`; `../config/policy_self_checks.yaml` |
| Readiness re-evaluates the fixture file on every probe | Post-startup file drift (tampering/edits) flips readiness to 503 — drift detection by construction | `../src/ai_security/api/dependencies.py`; wiring tests |
| Gitleaks pinned to exactly 8.30.1 in `check.sh`; `.gitleaks.toml` extends defaults with one narrowly allowlisted dev value | Reproducible gate; the Compose dev key is public by design and allowlisted explicitly rather than suppressing the rule | `../scripts/check.sh`, `../.gitleaks.toml` |
| Container ships `config/`, `migrations/`, `alembic.ini`; `make migrate` is the documented command | The image must be able to run its own migration and must contain the startup-required fixtures | `../Dockerfile`, `../Makefile` |
| Integration tests auto-create `firewall_test` and run Alembic; skip cleanly without PostgreSQL | Tests exercise the real schema path (ADR-006: no `create_all` in integration) while staying runnable anywhere | `../tests/integration/conftest.py` |

## Implementation decisions (Phase 1, within blueprint constraints; contract in ADR-008)

| Decision | Rationale | Recorded in |
|---|---|---|
| Engine in `firewall/policy_engine.py`; document models/loader in `policy/`; canonical enums in `tools/base.py`, `data_security/classification.py`, `firewall/decision.py` | Blueprint §4 layout; §6.1 "defined exactly once" | ADR-008 |
| Fact separation: request carries upstream facts only; policy flags come only from the loaded bundle | §10.2 order; policy facts must never be caller-supplied | ADR-008; engine tests |
| Evaluation order = §10.2 steps with stable `DecisionReason` codes | Documented deterministic order; reason vocabulary is an observable contract | `../src/ai_security/firewall/decision.py`; engine tests |
| `TOOL_ID_PATTERN` anchored (`^…$`) | Pydantic `pattern=` uses search semantics; the unanchored pattern accepted an invalid id containing a space | `../src/ai_security/policy/models.py`; model tests |
| `risk_score` strict int 0-100 (`strict=True`) | Reject string/bool coercion silently changing a score | `../src/ai_security/firewall/policy_engine.py`; model tests |
| Unicode hosts allowed and IDNA-encoded; path/query printable ASCII only; whitespace/controls/zone-ids/trailing dots rejected | Terminate the IDNA-vs-ASCII ambiguity explicitly; keep destinations canonical for exact matching | `../src/ai_security/security/urls.py`; url tests |
| Loader uses `yaml.compose` node walk for duplicate keys + `yaml.safe_load` for parsing | The gate prohibits `yaml.load(` in `src/`; duplicate-key rejection without violating the invariant | `../src/ai_security/policy/loader.py`; loader tests |
| Fixture-level `tool_policy` override (strict `ToolPolicy` model) | §10.5 "dedicated test scenario" without weakening the starter policy | `../config/policy_self_checks.yaml`; self-check tests |
| `PolicyBundle` exposes version + per-file sha256 + `combined_hash`; readiness payload gains `policy_version`/`policy_hash` | ADR-007 metadata requirement; drift must be observable | `../src/ai_security/policy/{models,self_checks}.py`, `../src/ai_security/api/routes_health.py` |
| No hot reload: process keeps startup bundle; readiness detects file drift (503) | §10.6 atomic reload is future work; fail-closed behavior today is drift detection | `../docs/KNOWN_LIMITATIONS.md`; wiring tests |
| `TestPrincipalResolver` test-only, not selectable via settings/factory | Test adapter must not weaken the dev-resolver guard (ADR-001) | `../src/ai_security/identity/adapters.py`; adapter tests |
| Thresholds 40/80 marked experimental in the config header | §11.4 defaults, uncalibrated until Phase 9; no threshold can override hard deny | `../config/risk_thresholds.yaml` |

## Implementation decisions (Phase 2, within blueprint constraints; contract in ADR-009)

| Decision | Rationale | Recorded in |
|---|---|---|
| Registry/policy consistency **one-directional**: policy tools require registrations (startup refusal); extra registrations stay policy-disabled (`unknown_tool`) | §14.1 capability inventory (`mock_files.search`) exceeds the §10.5 enabled set; drift in policy→capability still fails closed | ADR-009; `tests/unit/test_tool_registry.py`, `tests/integration/test_gateway_wiring.py` |
| Exact `(tool_id, action_id)` identity; no `action_id` naming convention enforced | Conventions add no security value; the pair is the policy/audit identifier | ADR-009; `tests/unit/test_tool_registry.py` |
| Gateway-issued sentinel-guarded `ExecutionAuthorization` + SHA-256 canonical action digest; adapters re-verify before side effects | §12.4 "every adapter invocation originated from the gateway"; §13.2 digest binding pre-built for Phase 5; direct/forged construction raises `UngatedExecutionError` | ADR-009; `tests/unit/test_mock_adapters.py`, `tests/security/test_gateway_no_bypass.py` |
| Gateway only downgrades: engine is the sole `ALLOW` producer; audit outage on would-be ALLOW → `BLOCK`/`audit_unavailable`; outcome-audit failure → `AUDIT_FAILED` (no result); denial audit failure keeps the denial | §16.4 fail-closed default without weakening denials (no side effect exists to roll back) | ADR-009; `tests/unit/test_gateway.py`, integration tests |
| `risk-v1` computed in-gateway (side-effect, external destination, registration data class; cap 100; factor codes recorded) | §11.3 deterministic factors; §6.1 forbids model-supplied risk; weights experimental until Phase 9 | ADR-009; `tests/unit/test_risk_engine.py`, `docs/POLICY_DECISION_MATRIX.md` |
| Per-tool timeout (`asyncio.timeout`), per-process concurrency (`asyncio.Semaphore` per running loop via `WeakKeyDictionary`), result schema/canonicalizability/≤1 MiB checks | §12.3 steps 9-11 bounded execution with typed outcomes (`TIMEOUT`, `RESULT_REJECTED`) | ADR-009; `tests/unit/test_gateway.py` |
| Strictness tightening: `ToolArguments`/`ToolResult` `strict=True`; resource/destination argument annotations must be exactly `str` | Prevent coercion smuggling and non-str resource values past derivation/consistency checks | ADR-009; registry tests |
| New observable reason codes: `policy_evaluation_error`, `audit_unavailable` (gateway), `binding_mismatch`, `deadline_exceeded` (engine facts, 21 fixtures) | Fail-closed overrides must be observable and fixture-covered | ADR-009; `config/policy_self_checks.yaml` |
| Mock sink stores content digest/size only; registration `data_class: PUBLIC`; egress disabled in starter policy | §14.1 mock-only, §16.3 privacy; content classification is Phase 6 | ADR-009; `tests/unit/test_mock_adapters.py` |

## Deferred decisions (updated after Phase 1)

| Topic | Status | Needed by |
|---|---|---|
| Policy self-check fixture content shape | **DECIDED (0b; extended 1; extended 2):** strict YAML `{fixtures: [...]}`; each `case` is a full `PolicyEvaluationRequest`; optional fixture-level `tool_policy` override; 21 fixtures incl. 7 mandated rows and the Phase 2 binding/deadline/inconsistent-facts rows | done |
| Gitleaks install method on macOS | **DECIDED:** operator installs (brew); gate pins 8.30.1 and fails clearly when missing/mismatched | done |
| Git initialization + baseline commit scope | **DONE:** baseline `41e10da` + 0b commits + Phase 1 commit series; no remote | done |
| ADR format enrichment ("alternatives considered" / "tests/verification" sections) | Still open; ADR-008 was created with the established Status/Context/Decision/Consequences/References shape | next ADR |
| `risk_score` fact source | **DECIDED (2/5, ADR-009/012):** computed by the versioned `risk-v2` engine in the gateway (all `risk-v1` factors + one bounded distinct-resource breadth factor); never caller-supplied. Calibration remains Phase 9 | done (calibration later) |
| Policy hot-reload (atomic reload per §10.6) | Open; readiness detects drift today, process keeps startup bundle | Not scheduled (documented limitation) |

## Implementation decisions (Phase 3, within blueprint constraints; contract in ADR-010)

| Decision | Rationale | Recorded in |
|---|---|---|
| Detector output is advisory and is not wired into `PolicyEvaluationRequest`, the engine, or the gateway | Invariant #10 must hold by construction: a missed attack cannot widen permissions, and a finding cannot grant them; routes/model consumption arrive later | ADR-010; `input_defense/service.py`; security tests |
| Every `FindingCode` must be dispositioned; no mapping to PASS; duplicate keys/unknown codes refuse startup | Detection failure/oversize/invalid input must never be reported clean; config sloppiness fails closed | `input_defense/config.py`, `config/input_defense.yaml`; config tests |
| Intake order size → content type → UTF-8 → JSON structure → normalization → heuristics → optional classifier | Prevents decoding/parsing hostile input before bounds; each violation becomes a typed finding | `input_defense/service.py`, `normalize.py`; failure tests |
| Normalization is copy-only; JSON depth is iterative | Original content is never mutated/stored; hostile nesting cannot exhaust the Python stack | `input_defense/normalize.py`; normalization tests |
| Ten versioned regex rules; quoted/educational/defensive contexts downgrade to `QUOTED_INSTRUCTION_CONTEXT`; assistant-directed rules only for external/tool content | Honest heuristic behavior without overclaiming intent detection; avoid treating documentation as an attack | `input_defense/heuristics.py`; heuristic tests |
| Six structured trust labels; external content forced `EXTERNAL_UNTRUSTED` even for authenticated requesters; duplicate/empty segments refused | Provenance must survive assembly and rendering; authentication of the requester does not trust quoted external content | `input_defense/context_labels.py`; label tests |
| Session store requires `(tenant_id, subject_id)` on every operation; mismatch = not found; 24 h/7 d lazy expiry; bounded counters; rotation never inherits | Invariant #23 without side channels; no raw prompts/findings stored; session state is not yet an authorization input | `persistence/session_repository.py`; migration `c7f1a2b3d4e5`; DB tests |
| Shared strict YAML helper (`security/safe_yaml.py`) used by policy and input-defense loaders | One duplicate-key-safe parser; keeps the gate's prohibition on `yaml.load` intact | `security/safe_yaml.py`, `policy/loader.py`, `input_defense/config.py` |
| Optional `LocalClassifier` protocol exists but is not configured/wired | Leaves room for Phase 4+ model-assisted detection without granting detector authority or adding a dependency now | `input_defense/service.py`; ADR-010 |

## Implementation decisions (Phase 4, within blueprint constraints; contract in ADR-011)

| Decision | Rationale | Recorded in |
|---|---|---|
| Extractors return validated proposals; only `IntentManifestService` issues manifests | Model output is untrusted; issuance must apply registry/policy validation and server bindings before authority exists | ADR-011; `tests/unit/test_intent_service.py` |
| Sealed frozen dataclass with a module-private sentinel instead of a caller-constructible model | Direct/forged construction must be impossible in-process; no transport contract exists yet | ADR-011; `tests/unit/test_intent_models.py` |
| Goal stored only as SHA-256 digest | Minimize sensitive text retention while still binding the manifest to the request purpose | ADR-011; manifest model tests |
| Exact-match constraints only (no wildcards/prefixes/ranges/floats) | A constraint language that cannot express broad scope cannot accidentally widen policy | ADR-011; validator tests |
| `max_uses` reserved after policy `ALLOW` and before decision audit; reservations survive later audit failure | Never consume authority for an action policy would deny; conservative on partial failure (no side effect occurred) | ADR-011; gateway tests |
| Optional `intent_tracker` on the gateway; app always supplies it | Preserves Phase 2 in-process tests without weakening production wiring | ADR-011; `tests/integration/test_intent_wiring.py` |
| Mock extractor recognizes exactly two demo scenarios and rejects send/forward/delete/upload/share | Honest demo behavior; avoids pretending a mock understands general language | ADR-011; extractor/service tests |
| `LocalModelIntentExtractor` injected-client interface, bounded 65,536-byte output, duplicate-key and unknown-field rejection, 2 retries default | Pin the untrusted boundary now; a real provider stays Phase 8 and cannot set version/bindings | ADR-011; extractor tests |
| Relative dates resolve only from the host-signed principal timezone; missing/invalid timezone fails closed | Prompt/model/IP/header time sources are attacker-influenced; DST correctness is testable | ADR-011; time-window tests |
| `IntentUsageTracker` in-memory with 10,000 live-manifest cap | Simple fail-closed enforcement for a single-process app; shared state is a later operational concern | ADR-011; `docs/KNOWN_LIMITATIONS.md` |
| No `/v1` manifest transport or signed serialization in Phase 4 | The blueprint assigns routes/providers to Phase 8; an in-process sealed object avoids inventing a transport contract | ADR-011; known limitations |

## Implementation decisions (Phase 5, within blueprint constraints; contract in ADR-012)

| Decision | Rationale | Recorded in |
|---|---|---|
| `risk-v2` preserves every `risk-v1` weight and adds exactly one bounded breadth factor (2–4/5–8/9+ distinct resources → +5/+10/+15, cap 100) | Additive, testable evolution without silently rewriting prior scores; a version bump is required for algorithm changes | ADR-012; `firewall/risk_engine.py`; risk tests |
| Packaged resource ids are validated then deduplicated in first-occurrence order before risk/digest/audit | Two argument names may carry the same target; the approval contract requires a distinct set and duplicate values must not inflate breadth | ADR-012; `firewall/gateway.py`; dedup regression |
| Approver rules are a strict declarative grammar (`role:<role>` / `principal:<subject>` with `|`), parsed at registry startup | No executable expressions; malformed/oversized/duplicate rules fail startup; evaluation uses only the verified principal | ADR-012; `identity/approver_rules.py`; rule/registry tests |
| Self-approval is default-deny and requires `self_approval_allowed`, valid only with `approval_eligible`; a requester-only rule with self-approval disabled is refused before storage | Prevents a policy from creating an unsatisfiable or self-granting approval path | ADR-012; policy model tests; approval tests |
| Approval tokens are 256-bit CSPRNG values returned once; the row stores only the SHA-256 digest; IDs are 32 lowercase hex | Token theft from storage is not replayable; digest comparison uses the project constant-time helper | ADR-012; `firewall/approval.py`; lifecycle tests |
| TTL defaults to 900 s and is bounded to 60–86,400 s; expiry is lazy on decide/consume (pending or approved → expired + audit) | Bounded approval lifetime without a background sweeper dependency; every observed expiry is audited | ADR-012; settings/approval tests |
| `SELECT ... FOR UPDATE` decisions/consumption; decision/consumption audit appended in the same transaction via `append_in_session` | Exactly one consumer under concurrency; no state transition without its evidence | ADR-012; `persistence/approval_repository.py`; concurrency/audit tests |
| Approval is consulted only for an engine `ASK_USER`; `ALLOW` needs none and `BLOCK`/hard deny ignores it without consuming | Approval is a gate, never policy authority; hard denies stay dominant | ADR-012; gateway approval/security tests |
| The gateway does not auto-create approval requests; the Phase 8 host workflow must call the service with host-verified facts | Avoid inventing a route/UX contract and prevent model output from fabricating approval facts | ADR-012; known limitations |
| Failure mapping is typed (`approval_invalid` / `approval_denied` / `approval_expired`) with no adapter call; storage errors log only the tool id | Preserve the no-execution guarantee and log hygiene on every failure path | ADR-012; security tests |
| Consuming an approval burns it even if a later execution step fails | Deliberate anti-replay tradeoff; a retry requires a fresh approval | ADR-012; known limitation #44 |

## Implementation decisions (Phase 6, within blueprint constraints; contract in ADR-013)

| Decision | Rationale | Recorded in |
|---|---|---|
| `ToolGateway` requires an `OutputDefenseService`; no `None`/no-op default; the app loads `OUTPUT_DLP_PATH` and injects it | A gateway must not silently omit DLP; absence of configuration refuses startup rather than disabling inspection | ADR-013; `firewall/gateway.py`, `api/app.py`; wiring tests |
| Two-phase inspection: egress on validated arguments before resource/risk/policy/approval/execution; release on the complete buffered result | Classify before any side effect and suppress before any bytes escape; ADR-003 streaming remains disabled | ADR-013; `dlp.py`, gateway tests |
| Effective class = max(registry declaration, findings); findings can only raise it | Registration remains the floor; DLP must not become a policy authority or lower sensitivity | ADR-013; DLP/gateway tests |
| Destination trust is exact-canonical and must exactly cover every registered `EXTERNAL_MUTATION` destination at startup (missing or dead entry refuses startup) | No wildcard ambiguity or untrusted-by-omission destinations; capability changes must update policy | ADR-013; `output_dlp.yaml`, wiring tests |
| Closed outcomes: egress `PASS`/`BLOCK` (+ fail-closed error), release `PASS`/`REDACT`/`BLOCK`/`REVIEW`; `BLOCK`/`REVIEW`/failure set `result=None` + `response_blocked` | Typed, auditable behavior with no partial release; `REVIEW` is conservatively a block until a review transport exists | ADR-013; `decision.py`, `models.py`; unit/security tests |
| Redaction is span-preserving/idempotent, merges overlapping spans under the highest-severity category, and starts credential redaction at the first value character | Prevent tails of longer matches or multi-word secrets from leaking; over-redaction is preferred | ADR-013; `dlp.py`; `e586c81`; DLP tests |
| Oversize content, excessive fields/depth, unsafe paths, or a saturated finding report that would skip configured patterns are inspection failures; per-pattern truncation records the evaluated finding | A partial scan must not report PASS; a saturated report must not hide an unevaluated blocking pattern | ADR-013; `e8919cb`; DLP tests |
| DLP evidence is an optional additive `dlp` record on existing schema-v1 events; no new event types or migration in Phase 6 | Avoid a premature taxonomy while keeping evidence correlated and redacted; first-class events/verifier are Phase 7 | ADR-013; `audit/models.py`; e2e tests |
| Approval consumption additionally binds `side_effect_class` and the effective `data_class`; egress denial precedes approval and never consumes a grant | A stale approval created for a lower class must not authorize newly classified content | ADR-013; `approval.py`/repository; real-PostgreSQL tests |
| Shipped detectors are five deterministic patterns (canary, private-key header, `sk-` API key, credential assignment, email); no classifier/entropy/semantic/multilingual support; false positives/negatives documented | Honest, testable detection with a clear boundary; no overclaim that PASS means safe | ADR-013; `config/output_dlp.yaml`; `docs/OUTPUT_DLP_FALSE_POSITIVES.md` |
