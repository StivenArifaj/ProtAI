# ProtAI Console (post-v1 dashboard)

The console is a **web dashboard** for the six actors in
`docs/PRODUCT_INTERACTION_MODEL.md`. It is opt-in, additive, and authority-free: it
never exposes an execution path, containment action, or raw audit content.

## What it connects to

| Surface | API | Notes |
|---|---|---|
| Audit chain | `GET /admin/audit/events`, `/audit/verify`, `/audit/checkpoints` | Redacted event views, verifier result, sealed checkpoints |
| Alerts | `/admin/alerts`, `/alerts/rules`, `/alerts/triage/{seq}` | Content-free evidence; triage notes are local annotations |
| Summarizer | `/admin/alerts/summarize` | Unverified hypothesis only; opt-in; no authority |
| Approvals | `/admin/approvals`, `/approvals/{id}/decide`, `/revoke` | One-time token pasted in a form; never stored or logged |
| Tools / connectors | `/admin/tools`, `/admin/connectors` | Enable/disable with recorded threat-review id; no invoke button |
| Policy | `/admin/policies`, `/admin/configs` | Active bundle version/hash, matrix, config summary; restart required |
| Limiter / checkpoints | `/admin/limiter`, `/admin/audit/checkpoints` | Per-process caveat shown explicitly |
| Health / live | `/admin/overview`, `/admin/events/stream` | SSE heartbeat + alert count changes; Pause/Resume |
| Evaluation | `/admin/evaluation/reports` | Measurement-only reports |
| Auth | `/admin/auth/login`, `/admin/meta/session`, `/admin/auth/users` | Local provider now; `AuthProvider` interface for SSO |

## Security boundary

1. **No execution.** No route calls a tool adapter or the gateway. The gateway remains
   the only execution path; policy remains the sole `ALLOW` producer.
2. **No containment.** Alerts are read-only. No block/kill/revoke-session controls.
3. **No token persistence.** Approval tokens are pasted once, used through the existing
   one-time decision service, and never written to browser storage, URLs, or logs.
4. **No raw content.** Every response is a strict Pydantic model containing only IDs,
   codes, counts, digests, sizes, and timestamps.
5. **Own auth.** The browser never sees the host HMAC key. `/admin/*` uses a console
   session cookie with CSRF header for writes; every endpoint checks a permission.
6. **RBAC.** Six roles map to the six actors. Cross-tenant reads behave as not-found.

## Run locally

```bash
# 1. Enable the console in your environment (dev values only):
#    CONSOLE_ENABLED=true
#    CONSOLE_ADMIN_USERNAME=admin
#    CONSOLE_ADMIN_PASSWORD=<unique 12+ char value>
#    CONSOLE_STATIC_DIR=web/dist

# 2. Build the frontend
cd web && npm install && npm run build && cd ..

# 3. Start the API (from repo root, with the v1 env in place)
uv run uvicorn ai_security.api.app:app --host 127.0.0.1 --port 8080

# 4. Open http://127.0.0.1:8080 and sign in with the configured admin credentials.
```

Demo actors available in development: `admin`, `analyst`, `approver`, `operator`
(all share the documented sample password from `.env.example` — dev only).

Default dev credentials are refused outside `development`/`test` when the console is
enabled; set a unique `CONSOLE_ADMIN_PASSWORD` for any shared deployment.

## Known limitations (honest)

- **Local sessions are in-memory** and not shared across workers. An SSO adapter is a
  documented interface, not an implementation.
- **Triage annotations and checkpoints are process-local.** They are not durable and
  are not authoritative security inputs.
- **No real connectors ship.** The connector framework is a registration interface;
  enabling one requires a separate threat-model review.
- **No UI-driven execution or resumption.** Approved actions cannot be resumed through
  the dashboard; that remains future work.
- **Rate limits are per-process**, as in v1.
- **The console is post-v1** and is merged only after explicit operator approval.

## Verification

- 11 backend console tests with a stubbed session layer (auth, RBAC, CSRF, redaction,
  every read route, SPA serving)
- 6 frontend unit tests (UI primitives + DecisionTrace)
- TypeScript check and production build
- All v1 tests and the 12-step gate remain green
