# Known Limitations

As of **Phase 2 (tool registry and enforced gateway, 2026-10-19)**. This list must be
updated every phase; anything not explicitly implemented must remain listed here or in
`docs/IMPLEMENTATION_STATE.md`.

## Security controls still absent or narrowed (do not claim otherwise)

1. **Execution is in-process and mock-only.** The registry, gateway, execution
   authorization, and four deterministic mock adapters exist and are tested (email
   search/read, file search/read, text summarize, in-memory external sink). There are no
   real connectors, no shell, no arbitrary network access, and no operating-system
   sandbox. The digest-bound authorization is an in-process guardrail against accidental
   bypass; malicious in-process code could still forge calls through private internals.
   Process isolation is Phase 10.
2. **No input/output protection.** No prompt-injection detection, provenance labelling,
   intent extraction, content-level DLP/canary inspection, or output sanitization exists.
   Destination decisions are enforced for registered mock tools; content classification
   is a registration-declared fact, not inspection.
3. **Approvals are not implemented.** `ASK_USER` is returned as a typed no-execution
   result; no approval request is stored or consumable until Phase 5. The starter policy
   enables no approval-eligible tool.
4. **Manifest/intent binding is not implemented.** The gateway validates principal,
   request, arguments, resource IDs, destination, and deadline; it does not yet bind a
   `manifest` or intent/action constraints (Phase 4).
5. **Audit coverage is a Phase 2 subset.** The gateway emits `POLICY_EVALUATED` and
   `TOOL_EXECUTION_COMPLETED`/`_FAILED` into the ADR-002 chain; the full taxonomy,
   verifier, retention, and query/API surfaces are Phase 7. A denial whose audit append
   fails is kept as a denial (no side effect exists) and the append is logged; decision
   audit failure on a would-be `ALLOW` blocks execution.
6. **No AI SOC.** No analytics component exists.
7. **No rate limiting or request deadlines.** `/v1/*` routes do not exist; the gateway
   enforces per-call deadlines and per-tool concurrency, but Phase 8 adds request-level
   limits. A request-size bound (64 KiB default) exists since Phase 0b.
8. **Principal resolution is dev-only, test-only, or fail-closed.** `DevPrincipalResolver`
   returns one fixed synthetic principal under `development`/`test`;
   `TestPrincipalResolver` is constructible only under `APP_ENV=test` and is not reachable
   via settings/factory; `HostPrincipalResolver` raises (fails closed) until a later phase
   provides key→principal metadata.
9. **`/v1/*` has no routes yet.** Authenticated requests answer `404` after passing
   authentication (verified in the Phase 0b Docker proof); the gateway is used
   in-process/in tests only until Phase 8.
10. **Risk scoring is a minimal, uncalibrated factor set.** `risk-v1` scores declared
    side-effect class, external destination, and registration data class with initial
    weights (no anomaly, identity, session, or historical factors); calibration is
    Phase 9. Thresholds (40/80) remain experimental. No threshold can override a hard
    denial.
11. **Concurrency bounds are per process/per event loop.** `asyncio.Semaphore` limits are
    not shared across workers (no Redis/DB limiter); the in-memory sink is not shared
    between processes either. Multi-worker deployment is a later operational concern.
12. **No policy hot-reload.** The process keeps its startup-loaded bundle; readiness
    detects file drift (503) but does not reload. Atomic reload (blueprint section 10.6)
    is future work.
13. **Destination allowlisting is exact-match only.** No wildcard or pattern matching in
    v1; non-ASCII paths/queries and IPv6 zone IDs are rejected outright.
14. **Capability inventory exceeds the enabled policy.** `mock_files.search` is
    registered (blueprint section 14.1) but absent from the starter policy, so it is
    registered-but-disabled and denied `unknown_tool`. Enabling it requires a policy edit
    and fixture coverage; this is deliberate.

## Environment and tooling

15. **Compose credentials are disposable development values.** The PostgreSQL password
    (`firewall_dev_only`) and the Compose host-auth key are public and dev-only; the
    settings validator refuses the documented sample database password **and** the
    all-zero HMAC sample secret outside `development`/`test`.
16. **Container hardening is minimal.** The image runs as a non-root user (uid 10001,
    verified in Compose) and installs only locked dependencies from digest-pinned base
    images, but no seccomp/AppArmor profile, read-only root filesystem, or image
    vulnerability scanning is in place yet.
17. **Secret scanning is local-only.** Gitleaks 8.30.1 is pinned in `scripts/check.sh`
    (`dir` + `git`, redacted, fails if missing or on findings); there is no CI system, so
    the scan runs when the operator runs the gate. `.gitleaks.toml` allowlists exactly
    the one documented disposable Compose dev key.
18. **No SBOM.** CycloneDX artifact generation is Phase 10.
19. **Minimal schema.** The only tables are `host_request_nonces` and `audit_events`
    (Alembic baseline `d15b46c49950`). No pruning/retention job runs; the nonce and audit
    tables grow until an operational cleanup lands (expired nonces technically
    re-register, but stale rows remain). The Phase 2 event payloads live inside
    `audit_events.canonical_event_bytes`, not in a queryable typed table.
20. **No CI configuration.** `scripts/check.sh` (8 steps) is the gate.

## Verification gaps in this environment

21. **No coverage measurement.**
22. **No markdown linter installed;** memory-file link checks are scripted ad hoc.
23. **"Fresh clone" has not been repeated since Phase 0a.** The repository is under git
    with a linear history, but the clean-copy approximation was not rerun as a true
    `git clone` in a new directory.

## Behavioral notes

24. Readiness depends on PostgreSQL being reachable; a `503 not_ready` response is
    expected when the database is down and is not an error of the API itself. Readiness
    also reports `policy_self_checks` plus `policy_version`/`policy_hash`,
    re-evaluated on every probe: editing the policy or fixture file at runtime flips
    readiness to 503 (deliberate drift detection).
25. Audit append failure after an already-executed mock side effect yields outcome
    `AUDIT_FAILED` with no result returned; the side effect is not rolled back (the sink is
    in-memory mock state). Real compensating actions are out of scope for v1.
