# Known Issues and Limitations

Severity: **High** (blocks security goals) / **Medium** / **Low**. Status labels follow
[README.md](README.md) ("RESOLVED (0b)" marks items closed in Phase 0b). "Section" refers to the
master blueprint v1.2. The canonical long-form list (with phase pointers) is
[../docs/KNOWN_LIMITATIONS.md](../docs/KNOWN_LIMITATIONS.md) (items 1–20); this file adds
severity, status, and next actions. Keep both consistent.

## Security controls absent (High — do not claim otherwise)

| # | Issue | Severity | Status | Blueprint | Next action |
|---|---|---|---|---|---|
| 1 | Host authentication: **implemented** for the `/v1/*` path prefix (HMAC + timestamp + atomic nonce replay + size bounds, fail-closed); no `/v1/*` routes exist yet; principal resolution beyond dev fails closed | High | **PARTIAL (0b)** | §9, §21 | Phase 1 (principal metadata), Phase 8 (routes) |
| 2 | No authorization: no policy engine (only ADR-007 self-check scaffolding), tool registry, firewall gateway, risk engine, or approvals | High | NOT IMPLEMENTED | §§10–13 | Phases 1–5 |
| 3 | No input/output protection: no injection detection, provenance labels, intent extraction, DLP, or egress policy | High | NOT IMPLEMENTED | §§3, 8, 15 | Phases 3–6 |
| 4 | Audit: append repository + ADR-002 lock protocol + fixed vectors exist and are tested; no event emission anywhere and no verifier | High | **PARTIAL (0b)** | §16 | Phase 7 |
| 5 | No AI SOC analytics | Medium | NOT IMPLEMENTED | §17 | Phase 10 |
| 6 | No rate limiting or request deadlines; request-size bound exists (64 KiB, 413) | Medium | **PARTIAL (0b)** | §18.2 | Phase 8 |
| 7 | Persisted state: only `host_request_nonces` and `audit_events` via Alembic baseline; no session/approval storage; no pruning job for nonce/audit rows | High | **PARTIAL (0b)** | §§13, 20.2 | Phases 0b–7 (retention task) |

## Environment and tooling gaps

| # | Issue | Severity | Status | Next action |
|---|---|---|---|---|
| 8 | Repository not under git | Medium | **RESOLVED (0b)** — baseline `41e10da` + 7 Phase 0b commits on `main`; no remote | Configure a remote only if the operator wants one |
| 9 | Compose dev values; HMAC all-zero sample secret refusal | Low | **RESOLVED (0b)** — both the sample password and the all-zero HMAC sample secret are refused outside development/test | None |
| 10 | Container hardening minimal: non-root + digest pins only; no seccomp/read-only rootfs/image scanning | Medium | PARTIAL | Phase 10 hardening |
| 11 | No secret scanning in the gate | Medium | **RESOLVED (0b)** — Gitleaks 8.30.1 pinned in `check.sh` (dir+git, redacted); `.gitleaks.toml` allowlists one documented dev value; history scanned clean | None (local-only until CI exists) |
| 12 | No SBOM (CycloneDX is Phase 10) | Low | NOT IMPLEMENTED | Phase 10 |
| 13 | No schema/migrations | Medium | **RESOLVED (0b)** — Alembic baseline `d15b46c49950` (`host_request_nonces`, `audit_events`); idempotent; `alembic check` clean | Extend per phase |
| 14 | No CI configuration; `check.sh` (8 steps) is the only gate | Low | NOT IMPLEMENTED | Out of scope for 0a–0b (documented) |
| 15 | No markdown linter installed in this environment; memory-file link checks are ad hoc | Low | VERIFIED (not installed) | Install only if the operator wants it |
| 16 | ADR files omit explicit "alternatives considered" / "tests/verification" sections named in blueprint §22.4 | Low | VERIFIED (format nuance) | New ADRs can include them; do not rewrite ADR-001..007 silently |
| 21 | `HostPrincipalResolver` fails closed (raises) until Phase 1 provides key→principal metadata; signed requests reach no principal | Medium | BY DESIGN (0b) | Phase 1 |
| 22 | Interim policy evaluator is a scaffolding transcription (`policy/interim_matrix.py`), not the Phase 1 engine | Medium | BY DESIGN (0b) | Phase 1 (keep fixture contract) |
| 23 | `check.sh` fails on any Gitleaks version ≠ 8.30.1 (deliberate pin) | Low | BY DESIGN | Update pin deliberately if the scanner is upgraded |

## Behavioral notes (expected behavior, not defects)

| # | Note | Next action |
|---|---|---|
| 17 | Readiness 503 is expected when PostgreSQL is down/unreachable; the API itself can still be alive (liveness 200). Readiness also reports `policy_self_checks`, re-evaluated per probe (file drift → 503, deliberate) | None |
| 18 | Readiness runs `SELECT 1` through the persistence layer (`pool_pre_ping`, 2 s connect timeout); short-lived connection per check remains acceptable locally | None |
| 19 | Compose API host port is 8080 (host port 8000 is commonly occupied by unrelated local services); container port remains 8000 | None |
| 20 | `uv lock` resolves 38 packages while `uv sync` checks 36 (installed set) — both expected | None |
| 24 | Authenticated `/v1/*` requests answer 404 until routes land (auth passes first — verified live in 0b) | Phase 8 (routes) |

## How issues graduate

Close an item only by (a) implementing the control with tests, (b) recording evidence in
[TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md), and (c) updating [../docs/KNOWN_LIMITATIONS.md](../docs/KNOWN_LIMITATIONS.md),
[../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md), and this file in the same task.
