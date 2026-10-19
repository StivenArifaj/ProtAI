# Known Issues and Limitations

Severity: **High** (blocks security goals) / **Medium** / **Low**. Status labels follow
[README.md](README.md). "Section" refers to the master blueprint v1.2. The canonical long-form list
(with phase pointers) is [../docs/KNOWN_LIMITATIONS.md](../docs/KNOWN_LIMITATIONS.md) (items 1–15); this file adds
severity, status, and next actions. Keep both consistent.

## Security controls absent (High — do not claim otherwise)

| # | Issue | Severity | Status | Blueprint | Next action |
|---|---|---|---|---|---|
| 1 | No host authentication; no `/v1/*` routes exist; HMAC/timestamp/nonce are Phase 0b | High | NOT IMPLEMENTED | §9, §21 | Phase 0b |
| 2 | No authorization: no policy engine, principal resolver, tool registry, firewall gateway, risk engine, or approvals | High | NOT IMPLEMENTED | §§10–13 | Phases 0b–5 |
| 3 | No input/output protection: no injection detection, provenance labels, intent extraction, DLP, or egress policy | High | NOT IMPLEMENTED | §§3, 8, 15 | Phases 3–6 |
| 4 | No audit chain or audit persistence of any kind | High | NOT IMPLEMENTED | §16 | Phase 7 (append scaffolding 0b) |
| 5 | No AI SOC analytics | Medium | NOT IMPLEMENTED | §17 | Phase 10 |
| 6 | No rate limiting or request bounds | Medium | NOT IMPLEMENTED | §18.2 | Phase 8 |
| 7 | No persisted state at all (no schema, no migrations, no session/approval storage) | High | NOT IMPLEMENTED | §§13, 20.2 | Phases 0b–7 |

## Environment and tooling gaps

| # | Issue | Severity | Status | Next action |
|---|---|---|---|---|
| 8 | Repository not under git: no history, "fresh clone" unverifiable, no diff-based review | Medium | VERIFIED (git exit 128) | Operator decision: `git init` + baseline commit (recommended before 0b) |
| 9 | Compose credentials are disposable public dev values; the HMAC all-zero sample secret refusal arrives in 0b | Low | PARTIAL (password refusal implemented; HMAC refusal 0b) | Phase 0b |
| 10 | Container hardening minimal: non-root + digest pins only; no seccomp/read-only rootfs/image scanning | Medium | PARTIAL | Phase 10 hardening |
| 11 | No secret scanning in the gate (Gitleaks is Phase 0b) | Medium | NOT IMPLEMENTED | Phase 0b |
| 12 | No SBOM (CycloneDX is Phase 10) | Low | NOT IMPLEMENTED | Phase 10 |
| 13 | No schema/migrations (Alembic baseline is 0b); readiness probe is the only DB use | Medium | NOT IMPLEMENTED | Phase 0b |
| 14 | No CI configuration; `check.sh` is the only gate | Low | NOT IMPLEMENTED | Out of scope for 0a–0b (documented) |
| 15 | No markdown linter installed in this environment; memory-file link checks are ad hoc | Low | VERIFIED (not installed) | Install only if the operator wants it |
| 16 | ADR files omit explicit "alternatives considered" / "tests/verification" sections named in blueprint §22.4 | Low | VERIFIED (format nuance) | New ADRs in 0b can include them; do not rewrite ADR-001..007 silently |

## Behavioral notes (expected behavior, not defects)

| # | Note | Next action |
|---|---|---|
| 17 | Readiness 503 is expected when PostgreSQL is down/unreachable; the API itself can still be alive (liveness 200) | None |
| 18 | Readiness opens a short-lived asyncpg connection per check (2 s timeout) | Moves behind the persistence layer in Phase 0b |
| 19 | Compose API host port is 8080 (host port 8000 is commonly occupied by unrelated local services); container port remains 8000 | None |
| 20 | `uv lock` resolves 38 packages while `uv sync` checks 36 (installed set) — both expected | None |

## How issues graduate

Close an item only by (a) implementing the control with tests, (b) recording evidence in
[TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md), and (c) updating [../docs/KNOWN_LIMITATIONS.md](../docs/KNOWN_LIMITATIONS.md),
[../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md), and this file in the same task.
