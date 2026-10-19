# Decision Log

Two levels of decisions are recorded:

1. **ADRs** — security/architecture contracts. One file per decision under [../docs/adr/](../docs/adr/)
   with the index in [../docs/DECISIONS.md](../docs/DECISIONS.md) (blueprint §22.4: the index must not duplicate
   full ADR content).
2. **Implementation decisions** — choices made within blueprint constraints, recorded here
   and in [../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md).

When a decision changes: create a **superseding ADR** (for contract decisions) and update
the index; never silently rewrite the historical rationale.

## ADRs (all Accepted, dated 2026-10-19)

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
| `risk_score` fact source | **DECIDED (2, ADR-009):** computed by the versioned `risk-v1` engine in the gateway (side-effect/destination/registration-data-class factors); never caller-supplied. Factor expansion + approvals in Phase 5; calibration in Phase 9 | done (calibration later) |
| Policy hot-reload (atomic reload per §10.6) | Open; readiness detects drift today, process keeps startup bundle | Not scheduled (documented limitation) |
