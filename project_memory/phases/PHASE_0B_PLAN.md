# Phase 0b — Security Foundation — PLAN (NOT STARTED)

- **Status:** NOT STARTED. Do not begin until Phase 0a is reviewed and passes its DoD
  (blueprint §21/§24) and the operator gives the go-ahead.
- **Blueprint:** §21 (Phase 0b deliverables/rules/commands/DoD), §9 (auth contract),
  §20.3 (check command), §16.2 (audit scaffolding context); ADR-001, ADR-002, ADR-005,
  ADR-006, ADR-007.
- **This document is a plan, not an implementation.** Verify everything against the
  blueprint before coding; if a detail below is ambiguous, raise it instead of guessing.

## Objective

Make the gateway's security foundation real and testable: authenticated host-to-gateway
requests with replay protection, an async persistence layer with migrations, a guarded
development principal resolver, policy self-check scaffolding wired into readiness, and
secret scanning in the quality gate.

## Deliverables checklist (blueprint §21)

1. **HMAC-SHA256 host authentication (§9.2, ADR-001).** For every `/v1/*` route, require
   headers `X-Gateway-Key-Id`, `X-Gateway-Timestamp` (Unix seconds ASCII),
   `X-Gateway-Nonce` (≥128 bits random), `X-Gateway-Signature` (lowercase hex
   HMAC-SHA256). The signing message is the exact UTF-8 newline-joined fields
   `v1 / key_id / METHOD / PATH / timestamp / nonce / sha256_hex(exact raw body)` with
   **no trailing newline**. Constant-time comparison via a `security/constant_time.py`
   helper (`hmac.compare_digest`). Validate key_id/timestamp/nonce/path contain no
   newline or control characters. Signed routes reject query strings, non-ASCII path
   bytes, duplicate-slash paths, dot-segment paths, and percent-encoded path forms.
   Body-size limits enforced **before** buffering bytes for signature verification.
   Never log signatures, request bodies, or secrets. Key configuration comes from
   `HOST_AUTH_KEYS_JSON` (records: exactly `secret_b64` ≥32 bytes, `host_id`,
   `audience`, `allowed_tenants`); refuse the all-zero sample secret outside
   `development`/`test`.
2. **Timestamp + replay protection (§9.2).** Reject clock skew beyond
   `HOST_AUTH_TIMESTAMP_TOLERANCE_SECONDS` (default 60). After signature validation,
   atomically insert `(key_id, nonce, expires_at)` into `host_request_nonces` with a
   unique constraint on `(key_id, nonce)`; a duplicate is a replay and MUST be rejected.
   Nonces must remain valid at least the acceptance window plus skew margin; expired
   rows may be deleted afterwards. **A database failure during replay protection means
   reject the request.**
3. **SQLAlchemy 2.x async layer with asyncpg (ADR-005).** Engine/session factory wired
   to settings; the readiness database probe folds into this layer conceptually (keep
   the external readiness behavior intact). No `create_all` in runtime code (ADR-006).
4. **Alembic baseline (ADR-006).** `alembic.ini` + `migrations/`; baseline revision
   covering at least `host_request_nonces` (and audit-repository append scaffolding
   tables per ADR-002, kept minimal for 0b). Documented command:
   `uv run alembic upgrade head`; re-running reports already at head. `create_all` only
   in isolated unit-test fixtures.
5. **`DevPrincipalResolver` startup guard (§9.3).** Constructible only under
   `APP_ENV=development|test`; returns one fixed synthetic principal; ignores
   caller-supplied identity fields; **never bypasses HMAC**. Settings validator and app
   factory both fail startup when `PRINCIPAL_RESOLVER=dev` outside dev/test; no
   query/header/body override can re-enable it at runtime.
6. **Policy self-check scaffolding (ADR-007).** `config/policy_self_checks.yaml` plus a
   loader/runner wired into startup and readiness; it must fail on a deliberately
   mismatching fixture. Representative rows derive from
   [../../docs/POLICY_DECISION_MATRIX.md](../../docs/POLICY_DECISION_MATRIX.md) (see open questions if the fixture shape is
   ambiguous).
7. **Gitleaks in `scripts/check.sh`.** `dir` and `git` scans (git scan applies once the
   repo is under git; the script must handle the pre-git state deliberately), redacted
   output; **fail non-zero if Gitleaks is missing or reports findings**. Do not silence
   it when absent.
8. **Authentication-failure and startup-invariant tests.** At minimum: forged
   signature; signed-body mutation; stale timestamp; unknown key ID; replayed nonce;
   nonce-registration DB failure → reject; dev-resolver refusal in staging/production;
   docs remain gated in all four environments.
9. **Audit append scaffolding (ADR-002 scope).** Follow the lock protocol for the
   append routine skeleton (transaction-scoped advisory lock, sequence/prev-hash read,
   canonical bytes stored in a `BYTEA` column). The full chain + verifier remain
   Phase 7; do not claim the audit invariant early.

## Explicit non-goals for 0b

- No real tools/adapters, no cloud model calls, no `/v1` business routes beyond what
  auth testing requires, no policy engine (Phase 1), no input defense (3), no DLP (6),
  no full audit chain (7). Do not implement later-phase controls "while here".

## Prerequisites

- Operator go-ahead after Phase 0a review (blueprint gate).
- Recommended: `git init` + baseline commit so 0b is a reviewable diff.
- Docker Desktop running for the database; ports 5432/8080 free.
- Gitleaks available on PATH (install method is an operator choice; `check.sh` must
  fail clearly if it is missing).

## Files expected to be touched (suggested; confirm against blueprint §4/§12 and
[../ARCHITECTURE_MAP.md](../ARCHITECTURE_MAP.md) before coding)

- New: `src/ai_security/identity/` (host auth verification, dev resolver guard),
  `src/ai_security/security/constant_time.py`, `src/ai_security/persistence/`
  (engine/session, nonce repository), `migrations/` + `alembic.ini`,
  `config/policy_self_checks.yaml` (+ loader), new tests under `tests/unit/` and
  `tests/integration/` (test names must include `host_auth`, `nonce`, `principal` to
  satisfy the §21 `-k` command).
- Modified: `src/ai_security/settings.py` (consume `PRINCIPAL_RESOLVER`,
  `HOST_AUTH_*`, size limits), `api/app.py` (guard + wiring), `api/dependencies.py`
  (readiness integration for self-checks), `scripts/check.sh` (Gitleaks),
  `.env.example` (only if variable semantics change), `pyproject.toml`/`uv.lock`
  (SQLAlchemy + Alembic), plus the mandated docs/state updates
  ([../../docs/IMPLEMENTATION_STATE.md](../../docs/IMPLEMENTATION_STATE.md),
  [KNOWN_LIMITATIONS.md](../../docs/KNOWN_LIMITATIONS.md),
  [SECURITY_INVARIANTS.md](../../docs/SECURITY_INVARIANTS.md) statuses, new/updated
  ADRs if contracts change).

## Dependencies to add (justify per §22.2 in the task report)

| Dependency | Why | License | Runtime impact |
|---|---|---|---|
| `sqlalchemy[asyncio]` 2.x | Mandated persistence contract (ADR-005) | MIT | Core dependency of the gateway |
| `alembic` | Mandated migration tool (ADR-006) | MIT | Dev/ops tooling, not request path |
| Gitleaks (external binary) | §21 secret scanning in `check.sh` | MIT (project) | Local gate only; must fail if absent |

## Commands and expected results (blueprint §21, verbatim intent)

| Command | Expected |
|---|---|
| `uv run alembic upgrade head` | Applies the baseline to an empty DB; running again reports already at head |
| `uv run pytest tests/integration -k "host_auth or nonce or principal"` | Valid signed requests succeed; forged signature, signed-body mutation, stale timestamp, unknown key ID, replayed nonce each → documented denial, no protected processing |
| `APP_ENV=production PRINCIPAL_RESOLVER=dev uv run uvicorn ai_security.api.app:app` | Refuses to start with a clear error |
| `bash scripts/check.sh` | Includes both Gitleaks scans; fails non-zero if Gitleaks unavailable or a secret is found |

## Definition of Done (blueprint §21)

Host-auth signing/verification and replay-rejection tests pass; migrations apply to an
empty database and re-apply idempotently per Alembic revision state;
`DevPrincipalResolver` cannot start outside `APP_ENV=development|test`; policy
self-check scaffolding runs at startup and in CI and fails on a deliberately mismatching
fixture; `/docs`, `/redoc`, `/openapi.json` remain absent outside dev/test; Gitleaks runs
in `check.sh`; no secrets committed; `check.sh` exits non-zero on any failure. **"Phase
0b is not complete merely because the application starts"** — the security-invariant
tests must actually pass and their commands must be recorded.

## Security constraints that must hold (frozen contracts)

- All `/v1/*` enforce HMAC before principal resolution/policy/approval, including
  `PRINCIPAL_RESOLVER=dev`. No auth-bypass mode in any environment.
- Replay-protection DB failure → reject. Constant-time comparisons for signatures and
  action/nonce digests; reject malformed lengths before comparing.
- Audit append scaffolding follows ADR-002's lock protocol exactly; stored
  `canonical_event_bytes` are what a verifier hashes (Phase 7).
- Do not weaken or delete existing Phase 0a tests; extend them.
- No secrets in code, logs, fixtures, or memory files.

## Open questions for the operator (resolve before or during early 0b)

1. Git initialization + commit scope (recommended prerequisite).
2. Gitleaks installation method on macOS.
3. Policy self-check fixture shape (which matrix rows become startup fixtures; if
   ambiguous, propose and ask — do not invent policy).
4. Scope of the audit append scaffolding: minimum needed for ADR-002 conformance now
   versus waiting for Phase 7 (blueprint says scaffolding in 0b; keep it minimal and
   tested).

## Verification and handoff

At completion: run the four §21 commands; run `bash scripts/check.sh`; record results in
[../TESTING_AND_VERIFICATION.md](../TESTING_AND_VERIFICATION.md); update [../IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md),
[../NEXT_SESSION.md](../NEXT_SESSION.md) (point at Phase 1), [../CHANGELOG.md](../CHANGELOG.md),
[../KNOWN_ISSUES_AND_LIMITATIONS.md](../KNOWN_ISSUES_AND_LIMITATIONS.md) (close items 1/9/11/13 as applicable), the
[../../docs/](../../docs/) state files, and create `phases/PHASE_0B_COMPLETE.md` from
[PHASE_TEMPLATE.md](PHASE_TEMPLATE.md).
