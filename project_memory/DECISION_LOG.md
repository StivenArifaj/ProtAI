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

## Deferred decisions (updated after 0b)

| Topic | Status | Needed by |
|---|---|---|
| Policy self-check fixture content shape | **DECIDED (0b):** strict YAML `{fixtures: [...]}`, one case per matrix row with `expected_decision` (+ optional `expected_reason`); 16 fixtures incl. 7 mandated rows | done |
| Gitleaks install method on macOS | **DECIDED:** operator installs (brew); gate pins 8.30.1 and fails clearly when missing/mismatched | done |
| Git initialization + baseline commit scope | **DONE:** baseline `41e10da` + 0b commits; no remote | done |
| ADR format enrichment ("alternatives considered" / "tests/verification" sections) | Still open; no new ADR was needed in 0b (ADR-001..007 already existed) | Phase 1 (if a new ADR is created) |
