# Next Session Handoff

**Last updated: 2026-10-19.** Read [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) first if you have not.

## Where we are

Phase 0a is complete and verified (including the Docker Compose path). Nothing else
exists: no authentication, no policy engine, no firewall, no DLP, no audit persistence.
The repository is not yet under git. The Compose stack is stopped; the database volume
is preserved.

## Preconditions to start Phase 0b

1. **Phase 0a review gate.** Blueprint §21/§24: do not start Phase 0b until Phase 0a is
   reviewed and passes its Definition of Done. The technical DoD is PASS
   ([phases/PHASE_0A_COMPLETE.md](phases/PHASE_0A_COMPLETE.md)); the operator's explicit review/go-ahead is the
   remaining gate.
2. **Recommended (operator's decision):** initialize git and commit the Phase 0a
   baseline so Phase 0b changes are a reviewable diff.
3. Docker Desktop running (for the database); confirm ports 5432 and 8080 are free.

## The next task: Phase 0b — Security foundation (blueprint §21)

Full executable plan: [phases/PHASE_0B_PLAN.md](phases/PHASE_0B_PLAN.md). Summary of deliverables:

1. Host-to-gateway HMAC-SHA256 authentication per §9.2 and ADR-001: headers
   (`X-Gateway-Key-Id`, `X-Gateway-Timestamp`, `X-Gateway-Nonce`, `X-Gateway-Signature`),
   the exact newline-separated signing message, constant-time verification, request-size
   bounds, canonical path rules (no query strings, no non-ASCII/duplicate-slash/
   dot-segment/percent-encoded paths on signed routes).
2. Timestamp tolerance (`HOST_AUTH_TIMESTAMP_TOLERANCE_SECONDS`, default 60 s) and
   atomic nonce replay rejection in `host_request_nonces` (unique `(key_id, nonce)`);
   a database failure during replay protection means **reject**.
3. SQLAlchemy 2.x async database layer with asyncpg (ADR-005).
4. Alembic baseline migration plus a documented migration command (ADR-006); applies to
   an empty database and re-applies idempotently.
5. `DevPrincipalResolver` startup guard (§9.3): constructible only under
   `APP_ENV=development|test`; returns one fixed synthetic principal; never bypasses HMAC;
   settings validator and app factory both refuse startup otherwise.
6. `config/policy_self_checks.yaml` and startup/CI policy self-check scaffolding wired
   into readiness (ADR-007).
7. Gitleaks secret scanning in `scripts/check.sh` (`dir` and `git` scans, redacted;
   fail if the scanner is missing or reports findings).
8. Authentication-failure and startup security-invariant tests.

## Read before coding (minimum)

- Blueprint: §9 (whole), §20.3, §21 (Phase 0b), §5.1/§5.4, §16.2 (audit scaffolding
  context), §22 (operating protocol).
- ADR-001, ADR-002, ADR-005, ADR-006, ADR-007 ([../docs/adr/](../docs/adr/)).
- [../docs/SECURITY_INVARIANTS.md](../docs/SECURITY_INVARIANTS.md) (invariants #2, #17, #18 become partially testable in 0b).
- [../docs/KNOWN_LIMITATIONS.md](../docs/KNOWN_LIMITATIONS.md) items 1, 9, 11 (auth absent, secret scanning absent,
  migrations absent).

## Verification commands and expected results (blueprint §21)

| Command | Expected |
|---|---|
| `uv run alembic upgrade head` | Applies the baseline to an empty database; running again reports already at head |
| `uv run pytest tests/integration -k "host_auth or nonce or principal"` | Valid signed requests succeed; forged signature, signed-body mutation, stale timestamp, unknown key ID, and replayed nonce each return the documented denial with no protected processing |
| `APP_ENV=production PRINCIPAL_RESOLVER=dev uv run uvicorn ai_security.api.app:app` | Refuses to start with a clear error |
| `bash scripts/check.sh` | Includes both Gitleaks scans; fails non-zero if Gitleaks is unavailable or reports a secret |

## Security constraints that must hold throughout 0b

- All `/v1/*` routes enforce the HMAC contract **before** principal resolution, policy
  evaluation, or approval processing — including when `PRINCIPAL_RESOLVER=dev`.
- No auth-bypass mode exists in any environment and no runtime override can re-enable
  the development resolver.
- Audit-repository append scaffolding follows ADR-002's lock protocol; the full hash
  chain is completed in Phase 7.
- No real tools; no cloud model calls; do not weaken existing tests; no secrets.
- Every new control ships with its tests, and `check.sh` must fail on any failure.

## Definition of Done (blueprint §21, condensed)

Host-auth signing/verification and replay-rejection tests pass; migrations apply and
re-apply idempotently; `DevPrincipalResolver` cannot start outside dev/test; policy
self-check scaffolding runs at startup and in CI and fails on a deliberately mismatching
fixture; `/docs`, `/redoc`, `/openapi.json` remain absent outside dev/test; Gitleaks runs
in `check.sh`; no secrets committed; `check.sh` exits non-zero on any failure.
"Phase 0b is not complete merely because the application starts" — the invariant tests
must actually pass and their commands must be recorded.

## Open decisions / notes for the operator

- **Git initialization and commit scope** (recommended before or at the start of 0b).
- **Gitleaks installation method** on macOS; `check.sh` must fail clearly when it is
  unavailable (do not silence it).
- **Policy self-check fixture shape:** derive representative rows from
  [../docs/POLICY_DECISION_MATRIX.md](../docs/POLICY_DECISION_MATRIX.md); if the intended fixture content is ambiguous,
  raise it instead of inventing policy.
- **ADR format enrichment:** blueprint §22.4 names "alternatives considered" and
  "tests/verification" as ADR content; new ADRs created in 0b can include those sections
  even though ADR-001..007 do not (see [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md), "Conformance note").
