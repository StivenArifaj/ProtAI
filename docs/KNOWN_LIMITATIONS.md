# Known Limitations

As of **Phase 0b (security foundation, 2026-10-19)**. This list must be updated every
phase; anything not explicitly implemented must remain listed here or in
`docs/IMPLEMENTATION_STATE.md`.

## Security controls still absent (do not claim otherwise)

1. **No authorization.** No policy engine, tool registry, firewall gateway, risk engine,
   or approval workflow exists. The `policy/` package is explicit scaffolding: an interim
   transcription of the decision matrix used only for startup/readiness self-checks
   (ADR-007); it does not authorize anything because no action surface exists. Any
   statement that the system "blocks" or "allows" actions beyond `/v1` authentication is
   currently false.
2. **No input/output protection.** No prompt-injection detection, provenance labelling,
   intent extraction, DLP, or egress policy exists.
3. **No audit event emission or verifier.** The append repository, hash-chain formula,
   and serialized append protocol exist and are tested, but nothing writes audit events
   yet, and the verifier is Phase 7.
4. **No AI SOC.** No analytics component exists.
5. **No rate limiting or request deadlines.** `/v1/*` routes do not exist; when they do,
   Phase 8 adds limits. A request-size bound (64 KiB default) exists since Phase 0b.
6. **Principal resolution is dev-only or fail-closed.** `DevPrincipalResolver` returns
   one fixed synthetic principal under `development`/`test`; `HostPrincipalResolver`
   raises (fails closed) until Phase 1 provides key→principal metadata. Signed requests
   to a future principal-requiring route would receive no principal, not a guessed one.
7. **`/v1/*` has no routes yet.** Authenticated requests answer `404` after passing
   authentication (verified in the Phase 0b Docker proof).

## Environment and tooling

8. **Compose credentials are disposable development values.** The PostgreSQL password
   (`firewall_dev_only`) and the Compose host-auth key are public and dev-only; the
   settings validator refuses the documented sample database password **and** the
   all-zero HMAC sample secret outside `development`/`test`.
9. **Container hardening is minimal.** The image runs as a non-root user (uid 10001,
   verified in Compose) and installs only locked dependencies from digest-pinned base
   images, but no seccomp/AppArmor profile, read-only root filesystem, or image
   vulnerability scanning is in place yet.
10. **Secret scanning is local-only.** Gitleaks 8.30.1 is pinned in `scripts/check.sh`
    (`dir` + `git`, redacted, fails if missing or on findings); there is no CI system, so
    the scan runs when the operator runs the gate. `.gitleaks.toml` allowlists exactly
    the one documented disposable Compose dev key.
11. **No SBOM.** CycloneDX artifact generation is Phase 10.
12. **Minimal schema.** The only tables are `host_request_nonces` and `audit_events`
    (Alembic baseline `d15b46c49950`). No pruning/retention job runs; the nonce and audit
    tables grow until an operational cleanup lands (expired nonces technically
    re-register, but stale rows remain).
13. **No CI configuration.** `scripts/check.sh` (8 steps) is the gate.

## Verification gaps in this environment

14. **No coverage measurement.**
15. **No markdown linter installed;** memory-file link checks are scripted ad hoc.
16. **"Fresh clone" is now meaningful** (the repository is under git with a baseline
    commit), but the clean-copy approximation from Phase 0a has not been repeated as a
    true `git clone` in a new directory.

## Behavioral notes

17. Readiness depends on PostgreSQL being reachable; a `503 not_ready` response is
    expected when the database is down and is not an error of the API itself. Readiness
    also reports `policy_self_checks`, re-evaluated on every probe: editing the fixture
    file at runtime flips readiness to 503 (deliberate drift detection).
18. The readiness probe uses the SQLAlchemy layer since Phase 0b (`pool_pre_ping`, 2 s
    connect timeout); a short-lived connection per check remains acceptable locally.
19. Compose publishes the API on host port 8080 (host port 8000 is commonly occupied by
    unrelated local services); the container listens on 8000. Bindings are 127.0.0.1-only.
20. Gitleaks must be exactly 8.30.1 locally or `check.sh` fails by design (pin, not a
    floating version).
