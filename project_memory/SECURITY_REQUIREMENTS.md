# Security Requirements

The complete v1 security contract, per control, with honest status. Status labels follow
[README.md](README.md). **This file summarizes and links; it does not replace
[../docs/SECURITY_INVARIANTS.md](../docs/SECURITY_INVARIANTS.md)** (the 25 mandatory invariants, blueprint §20.2) or the
blueprint itself. Never mark a control implemented because a document describes it —
only tests and evidence do that.

## Control status matrix

| # | Control | Requirement (summary) | Blueprint | Status |
|---|---|---|---|---|
| 1 | Config fail-closed | Required `APP_ENV` (unknown rejected); `DATABASE_URL` scheme check; sample dev password refused outside dev/test | §5.4, §22.2 | **PARTIAL (0a/0b/1, tested)** — current variables incl. policy/threshold paths and host-auth keys |
| 2 | Documentation gating | `/docs`, `/redoc`, `/openapi.json` absent outside `development`/`test` | §18.2, §20.2 #18 | **PARTIAL (0a, tested)** — resolver guard half is 0b |
| 3 | Log/error hygiene | No secrets, raw payloads, or stack traces in logs/errors by default | §16.3, §20.2 #14 | **PARTIAL (0a, tested)** — SecretStr masking, health non-leakage, policy errors name files without dumping documents |
| 4 | HMAC host auth | Every `/v1/*` verifies HMAC-SHA256 before principal resolution/policy/approval; exact signing message; constant-time; body-size limits before buffering | §9.2, ADR-001 | **IMPLEMENTED (0b)** — path-prefix middleware, identical under `PRINCIPAL_RESOLVER=dev`; denial matrix unit+integration+live; size bound → 413 |
| 5 | Replay protection | Timestamp tolerance (default 60 s); unique `(key_id, nonce)` atomic insert; duplicate = reject; DB failure = reject | §9.2, §9.4 | **IMPLEMENTED (0b)** — single-statement upsert; replay → 401 `replayed_nonce`; store failure → 503; concurrency-proven |
| 6 | Dev-resolver guard | `DevPrincipalResolver` only under `APP_ENV=development/ test`; one fixed synthetic principal; never bypasses HMAC; startup fails otherwise; no runtime override | §9.3, ADR-001 | **IMPLEMENTED (0b, held in 1)** — settings + constructor + factory guards; `model_construct` bypass attempt rejected; test adapter is test-only and not selectable |
| 7 | Principal verification | Protected operations require a verified principal; model/unsigned fields are never identity; tenant scope is part of authorization | §9, §13.2 | **PARTIAL (0b/1)** — HMAC-authenticated host context exists; the engine blocks without an explicit `principal_resolved` fact; real key→principal mapping still fails closed (later phase); no protected operations exist |
| 8 | Typed contracts | `extra="forbid"`; canonical `SideEffectClass`/`DataClass` enums; unknown/missing/invalid values fail closed; no aliases or coercion | §6.1, §10.3, §20.2 #25 | **IMPLEMENTED (1)** — enums defined exactly once; strict ints; anchored tool-id pattern; model/loader/url/engine suites all green |
| 9 | Policy determinism | Documented evaluation order; evaluation before any execution; policy errors → no execution; no LLM in authorization | §10.2, §22.2 | **IMPLEMENTED (1, engine-level)** — §10.2 order with stable reason codes; invalid config refuses startup; no I/O/model calls (gate-checked); gateway consumption is Phase 2 |
| 10 | Policy matrix + self-checks | v1 matrix enforced; mirrored in config; startup and CI self-checks fail on a mismatching fixture; policy versioned and audited | §10.3, §10.6–10.7, ADR-007 | **IMPLEMENTED (1, decision level)** — engine enforces the matrix; 17 fixtures (7 mandated) pass at startup + readiness; versioned bundle with sha256 hashes exposed in health metadata; audit-event provenance is Phase 7 |
| 11 | Hard-deny dominance | Hard deny cannot be overridden by risk score, model confidence, or approval | §11.4, §13 | **PARTIAL (1)** — `hard_deny` → BLOCK dominates all scores (tested incl. the low-risk fixture; model confidence never enters); execution-side proof is Phase 2 |
| 12 | Gateway no-bypass | Every tool call routed through the gateway; adapters never invoked directly; decision recorded before execution; unknown/denied = no side effect | §12.1–12.4 | NOT IMPLEMENTED (2) |
| 13 | Tool isolation | Mock tools only in v1; files under a sandbox root via resource IDs; egress disabled by default; no shell execution | §14 | **PARTIAL (1)** — starter policy registers only mock read actions with `mock_external_sink.write` egress disabled (engine denies `external_egress_disabled`); registry/mock adapters/sandbox land in Phase 2 |
| 14 | Input defense | Heuristics + provenance labels; detector never policy authority; detector outage = explicit failure mode, never bypass | §§2–3, §11 | NOT IMPLEMENTED (3) |
| 15 | Intent binding | Bounded, request-bound `IntentManifest`; action-constraint validation; semantic similarity never authorizes | §11.1–11.2, §8 | NOT IMPLEMENTED (4) |
| 16 | Risk engine | Deterministic, versioned, 0–100 residual after mandatory gates; thresholds configurable and tested | §11.3–11.4 | NOT IMPLEMENTED (5) |
| 17 | Approvals | Bound to verified principal + exact action + canonical arguments digest + target + data class + policy version + expiry; one-time token (store SHA-256 digest only); constant-time compare; atomic consumption; self-approval denied by default; unsatisfiable rule → BLOCK; no approval secret in logs/URLs/context | §13 | NOT IMPLEMENTED (5) |
| 18 | Session/context security | Session state bound to verified tenant/subject; guessed/borrowed/rotated references cannot read, extend, or create another session's signals | §20.2 #23 | NOT IMPLEMENTED (3/5) |
| 19 | DLP output/egress | Inspect before release AND before any side effect; destination-aware policy; classification from resource metadata/configured policy only (never self-assessment); unclassified = fail closed | §15 | NOT IMPLEMENTED (6) |
| 20 | Streaming ban (v1) | Buffer the complete bounded response, inspect, then release or fully suppress; no partial tokens before inspection | §15.1, ADR-003 | NOT IMPLEMENTED (6/8) |
| 21 | Audit chain | Append-only writer only; Postgres transaction-scoped advisory lock; exact canonical bytes and formula; verifier hashes stored bytes; tamper-**evident** (not tamper-proof) | §16.2, ADR-002 | **PARTIAL (0b)** — append protocol + canonical bytes + fixed vectors + 5-writer contiguity implemented; emission and verifier Phase 7 |
| 22 | Privacy/retention | No raw prompts, contexts, documents, tool arguments, secrets, or full DLP matches in default logs; digests/lengths/categories; opt-in redacted capture; no raw logs to cloud models | §16.3 | NOT IMPLEMENTED (7) |
| 23 | Operational fail-closed | If the audit write cannot complete, sensitive/irreversible actions do not execute; weaker behavior only by explicit config + tests | §16.4 | NOT IMPLEMENTED (7) |
| 24 | Request bounds | Size limits, deadlines, bounded concurrency, rate limits per verified principal; explicit statuses; no traces leaked | §18.2 | NOT IMPLEMENTED (8) |
| 25 | SOC alert-only | Deterministic rules first; analyzer fields labeled `EXTERNAL_UNTRUSTED`; no tool/policy/audit/containment powers; adversarial fixtures | §17, ADR-004 | NOT IMPLEMENTED (10) |
| 26 | Secrets handling | No real secrets/private data in code or fixtures; sample dev values refused outside dev/test; Gitleaks in `check.sh` from 0b | §5.4, §15.5, §22.2 | **IMPLEMENTED (0b)** — sample DB password + all-zero HMAC secret refused; Gitleaks 8.30.1 pinned in the gate (dir+git clean) |
| 27 | Regression discipline | Every discovered bug gets a minimal regression test; tests fail non-zero; never weaken a test to pass | §22.2–22.3 | Practice verified in 0a; enforced per phase |
| 28 | Container/runtime hardening | Non-root runtime, locked deps, digest-pinned bases; later: sandboxing, scanning, read-only rootfs | §5.1 | **PARTIAL (0a)** — non-root + digests verified; hardening Phase 10 |

## Fixed contracts (blueprint "final non-negotiable principle")

1. Transport: HMAC-authenticated host-to-gateway requests (§9.2, ADR-001) — no bypass mode.
2. Persistence: SQLAlchemy 2.x async + asyncpg + Alembic (ADR-005, ADR-006).
3. Audit chain: Postgres advisory-lock append with the exact ADR-002 canonical bytes.
4. v1 response streaming disabled: buffer → inspect → release (ADR-003).
5. Approval consumption atomic and one-time (§13).
6. AI SOC analyzer read-only/alert-only; attacker-influenced fields untrusted (ADR-004).

These are design decisions, not open questions.

## The system's core principle (hold every change to this)

> The input defense reduces the chance of model manipulation. The independent firewall
> limits what a manipulated model can do. Tool isolation limits the damage if another
> control fails. Egress protection prevents sensitive data from leaving through
> allowed-looking actions. Audit and evaluation provide evidence rather than assurances.
> — blueprint §24 (final principle)

No model score, prompt, tag, detector label, or aggregate risk score can replace
deterministic authorization at the point where a real side effect occurs.
