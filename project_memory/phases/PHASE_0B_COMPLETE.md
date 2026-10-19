# Phase 0b — Security Foundation — COMPLETE (VERIFIED)

- **Status:** COMPLETE — technical DoD all PASS, verified 2026-10-19 (including the
  Docker Compose path). Authentication, replay rejection, persistence, migrations, the
  resolver guard, policy self-check scaffolding, and Gitleaks are implemented and tested.
- **Blueprint:** §21 (Phase 0b), §9 (host authentication), §16.2 (audit append protocol),
  §20.3 (quality gate), spec v1.2.

## Scope delivered

| Deliverable (blueprint §21) | Delivered as | Status |
|---|---|---|
| HMAC-SHA256 host auth per §9.2/ADR-001 | `identity/signing.py` (exact four headers, newline-joined `v1` signing message, `hmac.compare_digest`), `identity/host_auth.py` (full rejection surface), `api/middleware.py` (pure-ASGI middleware on the `/v1/*` path prefix, fail closed independent of route existence) | VERIFIED |
| Timestamp tolerance + atomic nonce replay rejection | `settings.host_auth_timestamp_tolerance_seconds` (60 s) / `host_auth_nonce_ttl_seconds` (300 s, ≥2×tolerance enforced); `persistence/nonce_repository.py` single-statement atomic upsert (`ON CONFLICT ... WHERE expires_at < now() ... RETURNING`); duplicate → 401 `replayed_nonce`; store failure → 503 (never fail-open) | VERIFIED |
| Request bounds before buffering | content-length check, chunked-body cap, oversize → 413 `request_too_large` before signature work; `settings.request_max_bytes` (64 KiB) | VERIFIED |
| SQLAlchemy 2.x async persistence (ADR-005) | `persistence/database.py` (engine/session factory, `pool_pre_ping`, 2 s connect timeout, never-raising `healthy()`), models `host_request_nonces` + `audit_events` | VERIFIED |
| Alembic baseline + documented migration command (ADR-006) | async `migrations/env.py` reading settings; baseline `d15b46c49950`; `make migrate`; applies fresh and re-applies idempotently; `alembic check` clean | VERIFIED |
| DevPrincipalResolver guard (§9.3) | `identity/resolver.py` (constructible only under `development`/`test`, one fixed synthetic principal, `HostPrincipalResolver` fails closed until Phase 1); settings validator refuses `dev` outside dev/test; both app factory and resolver guard tested, plus a live refusal command | VERIFIED |
| Policy self-check scaffolding (ADR-007) | `policy/interim_matrix.py` (documented transcription of `docs/POLICY_DECISION_MATRIX.md`), `policy/self_checks.py` (strict YAML loader/runner/probe), `config/policy_self_checks.yaml` (16 fixtures incl. the 7 mandated rows); startup refuses on any mismatch; `/health/ready` re-evaluates live (drift → 503) | VERIFIED |
| Gitleaks in `scripts/check.sh` | 8-step gate; Gitleaks 8.30.1 pinned, `dir` + `git` scans redacted, fails if missing/mismatched; `.gitleaks.toml` extends default rules with one narrow allowlist for the documented disposable dev key only | VERIFIED |
| Authentication-failure + startup-invariant tests | 231 tests total (up from 25): verifier rejection matrix, middleware denial matrix end-to-end, repository concurrency, migration idempotency, self-check wiring, refusal checks | VERIFIED |

## Security properties actually enforced now (do not overstate)

- Every request whose path starts with `/v1/` (routes exist or not) requires a valid
  HMAC-SHA256 signature from a configured host key, within the timestamp window, with a
  previously-unseen nonce; the middleware runs before routing, before principal
  resolution, and identically under `PRINCIPAL_RESOLVER=dev`.
- Signature comparison is constant-time (`compare_digest` confined to
  `security/constant_time.py`; enforced by the gate). Body is capped before buffering.
- Nonce registration is one atomic statement; concurrent duplicates cannot both succeed.
- Audit appends use the ADR-002 protocol (transaction-scoped advisory lock + unique
  `(chain_id, sequence_number)`) with fixed canonical byte vectors; the verifier and
  event emission are Phase 7.
- Startup fails closed: configuration validation, dev-resolver refusal outside dev/test,
  and policy self-checks all refuse startup rather than degrade.
- Still absent (do not claim): authorization/policy engine, tool gateway, risk engine,
  approvals, input/output defense, DLP/egress, event emission, rate limiting, SOC.

## Conformance notes (documented, not hidden)

- The interim matrix evaluator is scaffolding labeled as such (`policy/__init__.py`,
  code docstring); Phase 1 replaces it with the real engine while keeping the fixture
  contract (ADR-007).
- `HostPrincipalResolver` deliberately fails closed (raises) until Phase 1 wires real
  key→principal metadata; signed requests reaching a future principal-requiring route
  would receive no principal, not a guessed one.
- `check.sh` pins Gitleaks to 8.30.1 (the version verified locally); a different local
  version fails the gate intentionally. No CI system exists (unchanged from 0a).
- `.gitleaks.toml` allowlists exactly one value: the disposable Compose development
  host-auth key (public by design, refused by settings outside dev/test when replaced by
  the all-zero sample).
- `.env.example` comments refreshed: `HOST_AUTH_KEYS_JSON` etc. are now consumed and
  validated at startup.

## Verification evidence (this session 2026-10-19; full list in docs/TESTING)

Fresh runs, in order:

1. `uv run --frozen pytest -q` → **231 passed** (unit + integration incl. live PostgreSQL).
2. `uv run --frozen mypy` → Success, 25 source files; `ruff check`/`format --check` clean.
3. `uv run --frozen pytest tests/integration -k "host_auth or nonce or principal" -q` →
   **18 passed**, 19 deselected.
4. `uv run --frozen alembic upgrade head` (twice) → already at `d15b46c49950`;
   `alembic check` → "No new upgrade operations detected".
5. `bash scripts/check.sh` → exit 0, all 8 steps (Gitleaks dir+git no leaks; invariant
   greps; 231 tests).
6. Docker: `docker compose build api`; `docker compose run --rm api alembic upgrade
   head` → baseline applied; live `protai-api-1`: `/health/live` 200, `/health/ready`
   200 `{"config":true,"database":true,"policy_self_checks":true}`.
7. Live auth proof against the container (Compose dev key): unsigned `/v1/echo` → 400
   `missing_headers`; correctly signed request → 404 Not Found (auth passed, nonce
   registered, body replayed; no `/v1` route exists yet); replay of the same signed
   request → 401 `replayed_nonce`.
8. Live startup refusals: `APP_ENV=production PRINCIPAL_RESOLVER=dev` → ValidationError
   "PRINCIPAL_RESOLVER=dev is refused outside development/test";
   `POLICY_SELF_CHECKS_PATH=/nonexistent.yaml` → `PolicySelfCheckConfigError` (refused
   startup).
9. `gitleaks git` over all commits → no leaks; commit series: `0aa11d9`, `9b3f153`,
   `42e8b71`, `4d18e27`, `28bede9`, `a5794cc`, `d180b89` on top of baseline `41e10da`.

## Definition of Done (blueprint §21, Phase 0b) — final status

| DoD item | Status |
|---|---|
| Host-auth signing/verification and replay-rejection tests pass | **PASS** — verifier matrix (unit) + middleware denial matrix (integration) + live container proof |
| Migrations apply and re-apply idempotently | PASS — fresh apply, second run no-op, `alembic check` clean (host + container) |
| `DevPrincipalResolver` cannot start outside dev/test | PASS — settings validator + construction guard + factory guard + live refusal command |
| Policy self-check scaffolding runs at startup and in CI and fails on a deliberately mismatching fixture | PASS — startup refusal test (mismatch + missing file), readiness drift → 503, gate runs the suite |
| `/docs`, `/redoc`, `/openapi.json` remain absent outside dev/test | PASS — environment-gating tests unchanged and passing |
| Gitleaks runs in `check.sh`; fails when unavailable or on a finding | PASS — pinned 8.30.1; missing/mismatch → `CHECK FAILED`; scanned clean incl. history |
| No secrets committed | PASS — Gitleaks git scan clean; only documented disposable dev values exist |
| `check.sh` exits non-zero on any failure | PASS — 8 steps; failure path unchanged from 0a |

## Limitations added by this phase (honest list)

- Nonce/audit tables grow unbounded; no pruning/retention job yet (expired nonces can
  re-register, but stale rows remain until an operational cleanup task exists).
- No audit event is emitted yet anywhere; only the append repository + chain math exist.
- `HostPrincipalResolver` fails closed; no real principal metadata path until Phase 1.
- The interim matrix evaluator is a transcription, not the Phase 1 policy engine.
- `/v1/*` has no routes yet: authenticated requests answer 404 after passing auth.
- Rate limiting/deadlines absent (Phase 8); request-size bound exists.

## Handoff

Next task: **Phase 1 — Typed contracts and deterministic policy engine** (blueprint §21;
read §§6, 10, 11.4, ADR-007; replace `policy/interim_matrix.py` with the real engine while
keeping the self-check fixture contract). Preconditions: none blocking — Phase 0b passed
its DoD; proceed per the autonomy mandate.
