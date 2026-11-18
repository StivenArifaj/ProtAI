# Next Session Handoff

**Last updated: 2026-11-18.** v1 (Phases 0a–10) plus post-v1 foundations and the full
web console are **COMPLETE — VERIFIED — MERGED TO MAIN**.

## Where we are

`main` HEAD is `e3dba05` (merge of `dashboard/console`), pushed to `origin/main`, clean.
History: `c38d92f` (Phase 9) → `b0788a5` (Phase 10) → `44c09a0` (interaction/integration
docs) → `c448ddd` (post-v1 foundations) → `4eeffb2` (console) → `e3dba05` (merge).

## What now exists beyond v1

- **Post-v1 foundations** (`src/ai_security/soc/`): distributed rate limiter with Redis
  Lua atomic script, external audit checkpointer, approval revocation/resumption
  services, connector registration framework. Documented in `docs/POST_V1_FOUNDATIONS.md`.
- **Full web console**: FastAPI `/admin` API (`src/ai_security/console/`) with local
  PBKDF2 auth, HttpOnly cookie + separate CSRF token, six-role RBAC, SSO-ready
  `AuthProvider`, strict redacted schemas, read projections for every service, SSE
  stream, and narrow human actions (triage, approve/deny, revoke, connector enable,
  checkpoint seal). No execution/containment authority.
- **React 19 + Vite + TS frontend** (`web/`): OKLCH dark design system, Fira Sans/Code,
  command palette (⌘K), collapsible rail, live status bar, signature Decision Trace +
  Chain Ribbon, 8 working screens. Docs: `docs/CONSOLE.md`.

## Verification evidence (actual)

- `uv run --frozen pytest -q`: **1037 passed, 103 skipped** (no PostgreSQL), 1 warning
- Console API tests: **11 passed** (`tests/unit/test_console.py`)
- Frontend Vitest: **6 passed**; `npm run typecheck` and `npm run build` pass
- `bash scripts/check.sh`: **exit 0, all 12 steps**, Gitleaks clean, invariant/constant-time
  greps clean, evaluation suites green
- Real Chromium smoke test (headless, stubbed data layer): all 8 screens rendered with
  correct titles, ⌘K palette visible, checkpoint seal + user creation writes succeeded,
  mobile 375px has no horizontal overflow, no runtime JS errors
- Post-merge gate rerun on `main`: all 12 steps pass

## Honest limitations

- PostgreSQL was unavailable during this session (Docker daemon down), so DB-backed
  integration tests skipped; console tests use a stubbed session layer. Real-DB behavior
  of the new `/admin` reads is exercised by projections over the same repositories.
- Local console sessions are in-memory (not shared across workers); SSO adapter is an
  interface, not an implementation.
- Triage annotations and checkpoints are process-local, not durable.
- No real connectors ship; no UI-driven execution, resumption, or containment.
- `npm audit` reported 4 advisories in transitive dev/build packages; review before any
  internet-facing deployment.

## Next steps

No further implementation was requested. Potential follow-ups: real DB validation of
`/admin` reads with Docker running; SSO adapter; durable triage/checkpoint storage;
real connectors behind threat-review gates; dependency advisory review.

## Real-stack verification (2026-11-18, second session)

- Docker Desktop started; `protai-db-1` (postgres:17.2-alpine) healthy on 127.0.0.1:5432.
- `alembic upgrade head` applied all four migrations successfully.
- `uv run --frozen pytest -q` against real PostgreSQL: **1141 passed, 0 skipped**.
- Generated real signed gateway traffic via `TestClient` + real HMAC signatures:
  12 valid read+summarize requests (200), 15 blocked external-sink previews (200 with
  `dlp_egress_blocked` decisions), 4 injection rejections (403), 8 external-content
  requests sourced from the free DummyJSON quotes API (all 200). The built-in local
  intent extractor is the deterministic offline "AI" — no cloud API/key was used.
- Audit chain reached 766 events including `TOOL_EXECUTION_COMPLETED`,
  `RESPONSE_RELEASED`, `POLICY_EVALUATED` BLOCK events, and 5 real
  `SECURITY_ALERT_RAISED` events emitted by deterministic rules over that evidence.
- Console verified in real Chromium against the live DB: all 8 screens render real
  data (732→766 events, live alerts, BLOCK reasons), 8-node Decision Trace shows
  `POLICY: BLOCK`, triage annotation persisted across reload, ⌘K palette works,
  mobile 375px clean, no runtime JS errors.
- **Bug found and fixed:** alert rule IDs longer than 32 chars broke emission because
  `AuditEvent.risk_version` is capped at 32. Emitter now truncates the audited field;
  regression test added (`test_emitter_handles_long_rule_ids`).
- **UI fix:** ChainRibbon no longer marks the oldest visible event as a gap.
- Final 12-step gate: all pass; 1141 backend + 64 alert + 14 abuse + 6 frontend tests.

## Cloud intent provider (ADR-018, 2026-11-18)

- Added opt-in `MODEL_PROVIDER=cloud` with `OpenAIChatIntentModelClient`
  (`src/ai_security/intent/cloud_provider.py`): OpenAI-compatible `/chat/completions`,
  fixed system instruction, user text in user role only, `temperature=0`, JSON-object
  format, no redirects, no env proxy trust, bounded timeout/response.
- Key sent only in Authorization header; never logged, stored, echoed in errors, or
  exposed to the console. Output is duplicate-key-checked, bounded, and remains
  advisory — the gateway/policy still decide. Failures yield no manifest.
- Settings require `CLOUD_MODEL_API_KEY`, exact `CLOUD_MODEL_NAME`, and a validated
  HTTPS origin (loopback allowed in dev/test). `ALLOW_EXTERNAL_MODEL_CALLS=true`
  remains refused (v1 placeholder flag).
- 16 unit tests pass. End-to-end with a local fake OpenAI-compatible endpoint:
  `COMPLETED` for the supported request, `REQUIRES_CLARIFICATION` (no execution) for
  an out-of-scope request. No real cloud key was used or stored in the repo.
- Real key is supplied by the operator via `CLOUD_MODEL_API_KEY` at runtime.
- Final gate: 1157 backend tests + 64 alert + 14 abuse + 6 frontend tests pass;
  all 12 steps green; Gitleaks clean (test fixtures use non-key-shaped placeholders).
