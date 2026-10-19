# ADR-001: Host-to-gateway HMAC-SHA256 authentication and development-resolver guard

- **Status:** Accepted
- **Date:** 2026-10-19
- **Implementation:** Phase 0b

## Context

The gateway is the single enforcement chokepoint for tool execution. If any caller can
forge a principal assertion or replay a captured request, every downstream policy
decision is built on an unverified identity. v1 must have no HTTP auth-bypass mode,
including in development where a test resolver exists.

## Decision

- Every `/v1/*` route enforces HMAC-SHA256 host authentication in every environment
  (blueprint section 9.2), before principal resolution, policy evaluation, or approval
  processing.
- Requests carry a key ID, timestamp, nonce, and signature over the exact request
  bytes; verification is constant-time; timestamp tolerance and nonce uniqueness
  (unique `(key_id, nonce)` with atomic replay rejection) are mandatory. A database
  failure during replay protection means reject.
- `HOST_AUTH_KEYS_JSON` records contain exactly `secret_b64` (>= 32 random bytes),
  `host_id`, `audience`, `allowed_tenants`. The sample all-zero secret in
  `.env.example` is refused when `APP_ENV` is not `development`/`test`.
- `DevPrincipalResolver` is a principal test adapter, not an authentication mode: it is
  constructible only under `APP_ENV=development|test`, returns one fixed synthetic
  principal, ignores caller-supplied identity fields, and never bypasses HMAC. Settings
  validation and the app factory both fail startup when `PRINCIPAL_RESOLVER=dev`
  outside dev/test, and no runtime override can re-enable it.

## Consequences

- Local development requires signing requests (or using the documented dev tooling) —
  an accepted cost for having no auth-bypass mode.
- The signing canonicalization (including the verified principal assertion) becomes a
  stable contract; changes require an ADR update.

## References

Blueprint v1.2 sections 9.1-9.2, 18.2, 20.2 (17, 18), 21 (Phase 0b).
