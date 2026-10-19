# Known Issues and Limitations

Severity: **High** (blocks security goals) / **Medium** / **Low**. Status labels follow
[README.md](README.md) ("RESOLVED (0b)"/"RESOLVED (1)"/"RESOLVED (2)" mark items closed in Phase 0b/1/2). "Section"
refers to the master blueprint v1.2. The canonical long-form list (with phase pointers) is
[../docs/KNOWN_LIMITATIONS.md](../docs/KNOWN_LIMITATIONS.md) (items 1–24); this file adds
severity, status, and next actions. Keep both consistent.

## Security controls absent (High — do not claim otherwise)

| # | Issue | Severity | Status | Blueprint | Next action |
|---|---|---|---|---|---|
| 1 | Host authentication: **implemented** for the `/v1/*` path prefix (HMAC + timestamp + atomic nonce replay + size bounds, fail-closed); no `/v1/*` routes exist yet; principal resolution beyond dev/test fails closed | High | **PARTIAL (0b/1)** | §9, §21 | Later phase (principal metadata), Phase 8 (routes) |
| 2 | Execution is mock-only and in-process: registry, gateway, execution authorization, `risk-v1`, and mock adapters exist and are tested, but there are no real connectors and no sandbox; approvals and manifest/intent binding are still missing | High | **PARTIAL (2)** | §§10–13 | Phases 4–5 (binding/approvals), Phase 10 (isolation) |
| 3 | No input/output protection: no injection detection, provenance labels, intent extraction, DLP, or egress policy | High | NOT IMPLEMENTED | §§3, 8, 15 | Phases 3–6 |
| 4 | Audit: append repository + ADR-002 lock protocol + fixed vectors exist and are tested; the gateway emits the Phase 2 event subset (decision/outcome) into the chain; the full taxonomy, retention, and verifier are missing | High | **PARTIAL (0b/2)** | §16 | Phase 7 |
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
| 21 | `HostPrincipalResolver` fails closed (raises) until a later phase provides key→principal metadata; signed requests reach no principal | Medium | BY DESIGN (0b/1) | Later phase |
| 22 | Interim policy evaluator (`policy/interim_matrix.py`) was scaffolding, not the real engine | Medium | **RESOLVED (1)** — deleted; the deterministic engine + fixture suite replaced it | None (readiness drift detection retained) |
| 23 | `check.sh` fails on any Gitleaks version ≠ 8.30.1 (deliberate pin) | Low | BY DESIGN | Update pin deliberately if the scanner is upgraded |
| 25 | Engine consumes upstream-supplied facts; since Phase 2 the gateway produces them (registry capability, validated arguments/resource IDs, canonical destination, `risk-v1` score). `manifest`/intent facts do not exist yet | Medium | **RESOLVED (2, partially)** — remaining: manifest/intent facts | Phase 4 |
| 26 | No policy hot-reload: the process keeps its startup-loaded bundle; readiness detects file drift (503) but does not reload | Low | BY DESIGN (1) | Phase 2+ (not scheduled) |
| 27 | Destination allowlisting is exact-match only (no wildcards); non-ASCII paths/queries and IPv6 zone IDs are rejected | Low | BY DESIGN (1) | Revisit when wildcard matching semantics are documented |
| 28 | Risk thresholds 40/80 are experimental defaults, not empirically calibrated | Low | BY DESIGN (1) | Phase 9 (evaluation/calibration) |

| 29 | No approvals: `ASK_USER` returns a typed no-execution result; no approval storage/consumption | Medium | BY DESIGN (2) | §13 | Phase 5 |
| 30 | No manifest/intent binding: the gateway validates principal/request/args/resources/destination/deadline only | Medium | BY DESIGN (2) | §11.1–11.2 | Phase 4 |
| 31 | Content-level DLP absent: data class is a registration-declared fact; no canary/pattern inspection of payloads | High | BY DESIGN (2) | §15 | Phase 6 |
| 32 | Execution authorization is an in-process guardrail, not a sandbox: malicious in-process code could bypass private internals | High | BY DESIGN (2) | §14.2 | Phase 10 |
| 33 | Concurrency bounds and the in-memory sink are per process/event loop; no cross-worker coordination | Medium | BY DESIGN (2) | §18.2 | Later operational phase |
| 34 | `risk-v1` weights uncalibrated; factor set minimal (no identity/session/history factors) | Low | BY DESIGN (2) | §11.3–11.4 | Phases 5/9 |

## Behavioral notes (expected behavior, not defects)

| # | Note | Next action |
|---|---|---|
| 17 | Readiness 503 is expected when PostgreSQL is down/unreachable; the API itself can still be alive (liveness 200). Readiness also reports `policy_self_checks` + `policy_version`/`policy_hash`, re-evaluated per probe (policy or fixture file drift → 503, deliberate) | None |
| 18 | Readiness runs `SELECT 1` through the persistence layer (`pool_pre_ping`, 2 s connect timeout); short-lived connection per check remains acceptable locally | None |
| 19 | Compose API host port is 8080 (host port 8000 is commonly occupied by unrelated local services); container port remains 8000 | None |
| 20 | `uv lock` resolves 38 packages while `uv sync` checks 36 (installed set) — both expected | None |
| 24 | Authenticated `/v1/*` requests answer 404 until routes land (auth passes first — verified live in 0b) | Phase 8 (routes) |
| 35 | An audit append failure after an executed mock side effect yields `AUDIT_FAILED` with no result returned; the in-memory sink is not rolled back (no compensating action in v1) | Documented; revisit with real connectors |

## How issues graduate

Close an item only by (a) implementing the control with tests, (b) recording evidence in
[TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md), and (c) updating [../docs/KNOWN_LIMITATIONS.md](../docs/KNOWN_LIMITATIONS.md),
[../docs/IMPLEMENTATION_STATE.md](../docs/IMPLEMENTATION_STATE.md), and this file in the same task.
