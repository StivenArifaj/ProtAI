# Known Limitations

As of **Phase 1 (typed contracts and deterministic policy engine, 2026-10-19)**. This
list must be updated every phase; anything not explicitly implemented must remain listed
here or in `docs/IMPLEMENTATION_STATE.md`.

## Security controls still absent (do not claim otherwise)

1. **No execution surface: the policy engine decides, nothing acts.** The deterministic
   engine and strict contracts exist and are fully tested, but there is no tool registry,
   gateway, or adapter execution, so no decision has a side effect yet. The system does
   not "block" any action at runtime; it produces tested, fail-closed decisions over
   caller-supplied facts. Any claim of enforcement beyond `/v1` authentication is false
   until the Phase 2 gateway lands (invariants #1, #9, #10, #12).
2. **No input/output protection.** No prompt-injection detection, provenance labelling,
   intent extraction, DLP, or egress enforcement at a sink exists (engine-level
   destination decisions are inputs, not enforcement).
3. **No audit event emission or verifier.** The append repository, hash-chain formula,
   and serialized append protocol exist and are tested, but nothing writes audit events
   yet, and the verifier is Phase 7. The engine's `DecisionRecord` is not yet persisted.
4. **No AI SOC.** No analytics component exists.
5. **No rate limiting or request deadlines.** `/v1/*` routes do not exist; when they do,
   Phase 8 adds limits. A request-size bound (64 KiB default) exists since Phase 0b.
6. **Principal resolution is dev-only, test-only, or fail-closed.** `DevPrincipalResolver`
   returns one fixed synthetic principal under `development`/`test`;
   `TestPrincipalResolver` is constructible only under `APP_ENV=test` and is not
   reachable via settings/factory; `HostPrincipalResolver` raises (fails closed) until a
   later phase provides key→principal metadata. The engine requires an explicit
   `principal_resolved` fact and blocks otherwise.
7. **`/v1/*` has no routes yet.** Authenticated requests answer `404` after passing
   authentication (verified in the Phase 0b Docker proof).
8. **Policy facts are upstream-supplied in Phase 1.** `risk_score` and destination data
   are validated facts the engine consumes; the deterministic risk engine (Phase 5),
   registry (Phase 2), and validator (Phase 2/4) that produce them in production do not
   exist yet. The engine cannot and does not verify their origin.
9. **No policy hot-reload.** The process keeps its startup-loaded bundle; readiness
   detects file drift (503) but does not reload. Atomic reload (blueprint section 10.6)
   is future work.
10. **Destination allowlisting is exact-match only.** No wildcard or pattern matching in
    v1; non-ASCII paths/queries and IPv6 zone IDs are rejected outright.
11. **Risk thresholds (40/80) are experimental defaults** and not empirically calibrated;
    calibration arrives with the Phase 9 evaluation protocol. No threshold can override a
    hard denial.

## Environment and tooling

12. **Compose credentials are disposable development values.** The PostgreSQL password
    (`firewall_dev_only`) and the Compose host-auth key are public and dev-only; the
    settings validator refuses the documented sample database password **and** the
    all-zero HMAC sample secret outside `development`/`test`.
13. **Container hardening is minimal.** The image runs as a non-root user (uid 10001,
    verified in Compose) and installs only locked dependencies from digest-pinned base
    images, but no seccomp/AppArmor profile, read-only root filesystem, or image
    vulnerability scanning is in place yet.
14. **Secret scanning is local-only.** Gitleaks 8.30.1 is pinned in `scripts/check.sh`
    (`dir` + `git`, redacted, fails if missing or on findings); there is no CI system, so
    the scan runs when the operator runs the gate. `.gitleaks.toml` allowlists exactly
    the one documented disposable Compose dev key.
15. **No SBOM.** CycloneDX artifact generation is Phase 10.
16. **Minimal schema.** The only tables are `host_request_nonces` and `audit_events`
    (Alembic baseline `d15b46c49950`). No pruning/retention job runs; the nonce and audit
    tables grow until an operational cleanup lands (expired nonces technically
    re-register, but stale rows remain).
17. **No CI configuration.** `scripts/check.sh` (8 steps) is the gate.

## Verification gaps in this environment

18. **No coverage measurement.**
19. **No markdown linter installed;** memory-file link checks are scripted ad hoc.
20. **"Fresh clone" is now meaningful** (the repository is under git with a baseline
    commit), but the clean-copy approximation from Phase 0a has not been repeated as a
    true `git clone` in a new directory.

## Behavioral notes

21. Readiness depends on PostgreSQL being reachable; a `503 not_ready` response is
    expected when the database is down and is not an error of the API itself. Readiness
    also reports `policy_self_checks` plus `policy_version`/`policy_hash`,
    re-evaluated on every probe: editing the policy or fixture file at runtime flips
    readiness to 503 (deliberate drift detection).
22. The readiness probe uses the SQLAlchemy layer since Phase 0b (`pool_pre_ping`, 2 s
    connect timeout); a short-lived connection per check remains acceptable locally.
23. Compose publishes the API on host port 8080 (host port 8000 is commonly occupied by
    unrelated local services); the container listens on 8000. Bindings are 127.0.0.1-only.
24. Gitleaks must be exactly 8.30.1 locally or `check.sh` fails by design (pin, not a
    floating version).
