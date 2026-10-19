# Known Limitations

As of **Phase 0a (repository foundation, 2026-10-19)**. This list must be updated every
phase; anything not explicitly implemented must remain listed here or in
`docs/IMPLEMENTATION_STATE.md`.

## Security controls (entirely absent — do not claim otherwise)

1. **No host authentication.** No `/v1/*` route exists yet; HMAC-SHA256 host auth,
   timestamp tolerance, and nonce replay rejection are Phase 0b. The API currently
   exposes only unauthenticated health endpoints by design.
2. **No authorization.** No policy engine, principal resolver, tool registry, firewall
   gateway, risk engine, or approval workflow exists. Any statement that the system
   "blocks" or "allows" actions is currently false.
3. **No input/output protection.** No prompt-injection detection, provenance labelling,
   intent extraction, DLP, or egress policy exists.
4. **No audit chain.** No audit persistence, hash chain, or verifier exists.
5. **No AI SOC.** No analytics component exists.
6. **No rate limiting or request bounds.** `/v1/*` routes do not exist; when they do,
   Phase 8 adds limits. Health endpoints are cheap and unauthenticated.

## Environment and tooling

7. **Compose credentials are disposable development values.** The PostgreSQL password
   (`firewall_dev_only`) is public and refused outside `development`/`test` by settings
   validation. The HMAC all-zero sample secret in `.env.example` is likewise public;
   Phase 0b adds the corresponding refusal check.
8. **Container hardening is minimal.** The image runs as a non-root user (uid 10001,
   verified in Compose) and installs only locked dependencies from digest-pinned base
   images, but no seccomp/AppArmor profile, read-only root filesystem, or image
   vulnerability scanning is in place yet.
9. **No secret scanning yet.** Gitleaks runs in `check.sh` starting Phase 0b; until
   then, secret detection is manual.
10. **No SBOM.** CycloneDX artifact generation is Phase 10.
11. **No migrations.** Alembic baseline and `alembic.ini` are Phase 0b; there is no
    database schema yet, only the readiness probe.
12. **No CI configuration.** `scripts/check.sh` is the gate; wiring an external CI
    system is outside Phase 0a scope.

## Verification gaps in this environment

13. **No git history.** The repository is not yet a git repository (initialization and
    commit policy are the operator's decision); "fresh clone" verification was
    approximated by a clean directory copy without the virtualenv or caches.

## Behavioral notes

14. Readiness depends on PostgreSQL being reachable; with Compose the API waits for a
    healthy database. A `503 not_ready` response is expected when the database is down
    and is not an error condition of the API itself.
15. The readiness probe opens a short-lived asyncpg connection per check (2 s timeout).
    This is acceptable for Phase 0a and will move behind the persistence layer in
    Phase 0b.
