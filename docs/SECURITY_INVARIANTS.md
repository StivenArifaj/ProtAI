# Security Invariants

The 25 mandatory invariants from blueprint v1.2 section 20.2, with honest status as of
**Phase 0a**. An invariant may only be marked implemented when its tests exist and pass;
the current phase implements no security control beyond configuration validation,
environment gating of documentation, and non-leakage on health endpoints.

Legend: **Implemented** (tests written and passing) / **Partial** (only the listed part)
/ **Not implemented** (planned phase noted).

| # | Invariant (abbreviated) | Status |
|---|---|---|
| 1 | Unknown tool/action -> no execution | Not implemented (Phase 2) |
| 2 | Missing/invalid principal -> no protected action | Not implemented (Phase 0b-1) |
| 3 | Policy evaluation error -> no execution | Not implemented (Phase 1) |
| 4 | Invalid arguments or unexpected fields -> no execution | Not implemented (Phase 1-2) |
| 5 | Hard deny -> no execution regardless of risk score or model confidence | Not implemented (Phase 1/5) |
| 6 | Missing approval -> no execution | Not implemented (Phase 5) |
| 7 | Changed approved arguments -> no execution | Not implemented (Phase 5) |
| 8 | Reused/expired approval -> no execution | Not implemented (Phase 5) |
| 9 | Egress/DLP block -> sink is unchanged | Not implemented (Phase 6) |
| 10 | Detector false negative -> firewall still enforces permissions | Not implemented (Phase 2-3) |
| 11 | Detector/provider outage -> no automatic fail-open | Not implemented (Phase 3-4) |
| 12 | Every adapter call has a correlated gateway decision event | Not implemented (Phase 2/7) |
| 13 | Audit-chain tampering is detected by the verifier | Not implemented (Phase 7) |
| 14 | Secrets and full private payloads do not appear in default logs or API error messages | **Partial (Phase 0a):** settings rendering masks `DATABASE_URL` (tested); readiness failure returns only booleans and logs only the exception class; no `/v1/*` payloads exist yet. Full coverage with later phases. |
| 15 | Tool output fed to the model is labeled untrusted | Not implemented (Phase 2-3) |
| 16 | Local/mock operation works with no internet access and no API keys | **Partial (Phase 0a):** the test suite and health endpoints run offline with no API keys; full mock-agent operation arrives with Phases 2-8. |
| 17 | Invalid HMAC signature, signed-body mutation, stale timestamp, unknown key ID, replayed nonce, or nonce-registration DB failure -> no protected processing | Not implemented (Phase 0b) |
| 18 | `DevPrincipalResolver` cannot start outside dev/test; it never bypasses HMAC; `/docs`, `/redoc`, `/openapi.json` absent outside dev/test | **Partial (Phase 0a):** documentation gating implemented and tested for all four environments; resolver guard and HMAC bypass prohibition are Phase 0b. |
| 19 | Concurrent audit appends produce one contiguous sequence; canonicalization vectors stable | Not implemented (Phase 7; canonical-bytes decision recorded in ADR-002) |
| 20 | Concurrent approval consumption allows at most one consumer; altered target/nonce/digest -> no execution | Not implemented (Phase 5) |
| 21 | No response bytes released before full DLP inspection; oversized/DLP-blocked outputs fully suppressed | Not implemented (Phase 6) |
| 22 | AI SOC analysis cannot call tools, change policies, edit logs, or trigger containment | Not implemented (Phase 10; decision recorded in ADR-004) |
| 23 | Session security state bound to verified tenant/subject; guessed/borrowed/rotated/cross-user references cannot read, extend, or create another session's signals | Not implemented (Phase 3/5) |
| 24 | Only a verified principal satisfying `required_approver_rule` can approve; self-approval requires explicit policy; unsatisfiable rule -> `BLOCK` | Not implemented (Phase 5) |
| 25 | Unknown/missing/invalid `SideEffectClass` or `DataClass` fail closed; no aliases or coercions | Not implemented (Phase 1) |

## Phase 0a scope statement

Phase 0a contributes only these testable properties:

- configuration errors fail startup with clear messages (unknown `APP_ENV`, missing
  required values, non-`postgresql+asyncpg` scheme, sample password outside dev/test);
- health endpoints reveal only status booleans and never credentials or stack traces;
- `/docs`, `/redoc`, and `/openapi.json` are absent outside `development`/`test`.

Everything else in this table remains future work; the repository must not claim it.
