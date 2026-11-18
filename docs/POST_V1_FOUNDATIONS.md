# Post-v1 Foundations (Experimental — Not Part of v1)

**Status:** Additive prototypes on branch `post-v1-foundations`. These are **not** part
of the v1 release and are **not** production-ready. They live in `src/ai_security/soc/`
and are enabled only through explicit operator code — none are wired into the v1
request path.

This document distinguishes what is a working foundation vs. what still requires
significant engineering for a real company deployment (per blueprint §23).

## Summary

| Item | What exists here | What's still needed for production |
|---|---|---|
| Distributed/shared rate limiter | `DistributedRateLimiter` + pluggable `RateLimiterStore` + Redis implementation with atomic Lua script | Wire into `create_app` via settings; provision Redis; define per-route limits; load tests at scale |
| External audit checkpoint | `ExternalAuditCheckpointer` — content-free sealed checkpoints with HMAC seal chain | Real sink (S3/object storage); periodic checkpointer job; verify against chain head; key management |
| Approval revocation/resumption | `ApprovalRevocationService` / `ApprovalResumptionService` with content-free audit payloads | DB migrations (revoked/resumed statuses, tables); wire into routes; approver authorization; notification |
| Connector framework | `ConnectorRegistry`, `ConnectorRegistration`, `Connector` protocol — disabled by default | Real connector implementations (each needs its own threat-model review); secret store integration; network egress policy |
| Agent-framework adapter | Documented in `docs/COMPANY_INTEGRATION.md` Pattern A | Per-framework adapter library (LangChain, AutoGen, etc.) |
| Graphical UI | Documented in `docs/PRODUCT_INTERACTION_MODEL.md` (future areas) | Full frontend; backend query/admin APIs; RBAC/SSO |
| Production hardening | Documented in `docs/COMPANY_INTEGRATION.md` | seccomp/AppArmor, read-only root FS, image scanning, backup/retention, TLS, WAF |

## Security Properties Preserved

All foundations are **additive and authority-free**:

- No new authority path: the gateway remains the only execution path; policy remains the
  sole `ALLOW` producer.
- Rate limiter denials are fail-closed on store errors (deny, never allow).
- Checkpoints contain only hashes/sequence numbers/seals — never raw audit content.
- Revocation/resumption require explicit human action; no auto-execution; audit payloads
  are content-free.
- Connectors are registered but **disabled by default**; enabling is an explicit operator
  action requiring a separate threat-model review.
- All constant-time comparisons go through `security/constant_time.py` (gate enforced).

## Verification

- 39 new unit tests (`tests/unit/test_distributed_rate_limiter.py`,
  `test_external_checkpoint.py`, `test_connector_framework.py`, `test_approval_lifecycle.py`)
- All 987 v1 tests still pass (v1 unchanged)
- mypy clean, ruff clean, constant-time gate passes

## Honest Limitations

1. **Not wired into v1.** No settings, no routes, no startup wiring. These are libraries
   only; calling them requires explicit operator code.
2. **No production integrations.** Redis client, S3 sink, secret store, and real
   connectors are not provided — they're injected interfaces.
3. **No UI.** No frontend was built. UI remains a documented future area.
4. **No real connectors.** The connector framework is an interface/registration layer
   only; no email/files/database/SaaS connector is implemented.
5. **No DB migrations for revocation/resumption.** The service layer exists, but the
   repository methods and schema changes for durable revocation are not implemented.
6. **Experimental maturity.** Do not present these as production-ready. Per blueprint
   §23, controlled integration and company deployment require separate reviews.

## What Would Be Needed to Productize (next steps, per blueprint §23)

1. Separate threat-model review per real connector
2. Settings + startup wiring for distributed limiter and checkpoint sink
3. DB migrations + repository methods for revocation/resumption
4. Approval delivery/notification channel (out-of-band token transport)
5. Audit query API + alert dashboard (backend before UI)
6. Real connector implementations behind explicit `ENABLE_CONNECTOR_*` config flags
7. seccomp/AppArmor, read-only root FS, image scanning, TLS, backup/retention
8. Full threat-model review and company security sign-off before any real side effect
