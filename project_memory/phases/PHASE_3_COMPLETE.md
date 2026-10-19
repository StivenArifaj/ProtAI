# Phase 3 — Input Threat Defense and Context Provenance — COMPLETE (VERIFIED)

- **Status:** COMPLETE — technical DoD all PASS, verified 2026-10-19. Strict advisory
  input detection (intake, copy-only normalization, versioned heuristics, typed
  findings, failure semantics), six-label context provenance with deterministic
  assembly/rendering, and a bound/bounded/expiring session-signal store are implemented
  and tested (**600 tests**).
- **Blueprint:** §21 (Phase 3), §§7-8, §2.2; invariants #10/#11/#15/#16 and §7.4 session
  metadata. ADR-010 (new, this phase); ADR-009 and all frozen Phase 0b-2 contracts kept.

## Scope delivered

| Deliverable (§21) | Delivered as | Status |
|---|---|---|
| Intake limits | `input_defense/service.py` + `normalize.py` + strict `config/input_defense.yaml`: size bound, content-type allowlist (parameters stripped, case-insensitive), UTF-8 validation, bounded JSON structure and nesting depth | VERIFIED |
| Normalization copy | `input_defense/normalize.py`: strict decode; copy-only NFKC; signals for zero-width/control/format characters, escape and Base64 density, mixed scripts; original bytes/string never mutated | VERIFIED |
| Versioned heuristics | `input_defense/heuristics.py` — `input-heuristics-v1`, 10 deterministic regex rules with stable `FindingCode`s; quoted/educational/defensive context downgraded to `QUOTED_INSTRUCTION_CONTEXT` (FLAG); assistant-directed rules only for `EXTERNAL_UNTRUSTED`/`TOOL_RESULT` | VERIFIED |
| Typed detector findings | `input_defense/models.py` — frozen strict `FindingCode`/`Disposition`/`DetectorFinding`/`IntakeReport`; versions, codes, offsets, and digests only (no raw content) | VERIFIED |
| Trust labels | `input_defense/context_labels.py` — six canonical labels from §2.2; external email forced `EXTERNAL_UNTRUSTED` even for an authenticated requester; labels preserved in deterministic sorted-JSON rendering | VERIFIED |
| Prompt/context assembly | `context_labels.py` — `ContextSegment`/`AgentContext` with duplicate/empty-ID refusal; labeled structured rendering, no string-deletion "sanitizing" | VERIFIED |
| Detector failure behavior | `input_defense/service.py` — all intake/normalizer/heuristic/classifier faults become `DETECTOR_UNAVAILABLE` with the configured non-PASS disposition; no exception text echoed; classifier optional | VERIFIED |
| Session security metadata (§7.4) | `input_defense/sessions.py`, `persistence/session_repository.py`, migration `c7f1a2b3d4e5`: 256-bit opaque IDs; `(tenant_id, subject_id)` binding re-checked on every read/write/rotate; bounded counters/timestamps; 24 h inactivity + 7 d absolute lazy expiry; rotation creates a fresh zero-state ID | VERIFIED |
| Strict configuration | `input_defense/config.py` + shared `security/safe_yaml.py`: schema/version check, duplicate-key refusal, exhaustive dispositions for all 14 codes, refusal of PASS mappings/unknown or missing codes/invalid content types | VERIFIED |
| Startup wiring | `api/app.py` — config loaded/validated at startup; `app.state.input_defense_config`, `input_defense_service`, `session_security`; no agent route consumes them yet | VERIFIED |
| Tests | 80 new tests: 5 new unit suites + settings additions, 1 security suite, 2 integration suites (real PostgreSQL for sessions) | VERIFIED |

## Security properties actually enforced now (do not overstate)

- **Advisory only:** detector findings have no path into `PolicyEvaluationRequest`, the
  engine, the gateway, risk scoring, or execution; the service exposes no invocation
  surface (asserted in tests). The deterministic engine remains the sole `ALLOW`
  producer.
- **Mapped, never open:** every `FindingCode` must have an exhaustive disposition, and
  anything outside `PASS` is valid; a PASS mapping, duplicate/missing/unknown code, or
  duplicate YAML key refuses startup. PASS < FLAG < QUARANTINE < REJECT is monotonic
  (`strongest_disposition`).
- **Faults never PASS:** oversize, unsupported content type, invalid encoding, malformed
  JSON structure, and detector/normalizer/classifier exceptions all yield typed
  non-PASS outcomes (`DETECTOR_UNAVAILABLE` for faults); raw content is not echoed in
  reports.
- **Provenance survives:** external email is `EXTERNAL_UNTRUSTED` regardless of
  authentication; assembly refuses empty/duplicate identifiers; rendering always carries
  the label next to the text.
- **Session metadata is not authorization:** binding mismatch returns not-found; IDs are
  CSPRNG-generated; only counters and timestamps are stored (no content); lazy expiry
  enforces both windows; counters clamp at 1,000,000; rotation does not inherit state.
- **Still absent (do not claim):** `/v1` routes and agent runtime, any consumer of
  findings/labels (manifest or intent binding is Phase 4), content DLP (Phase 6),
  approvals, real connectors, semantic/classifier detection in the default build, cross-
  worker session semantics beyond PostgreSQL row state, rate limiting, audit verifier.

## Conformance notes (documented, not hidden)

- `dev-1` dispositions are deliberate starting points: overrides, secret extraction,
  oversize, unsupported, encoding, structure, nesting, and detector-unavailable map to
  REJECT; untrusted instruction to QUARANTINE; obfuscation/quoted/control/homoglyph/
  excessive encoding to FLAG. They are configuration, not hard-coded policy truth.
- Heuristics are substring/regex evidence with stable codes, not a classifier: novel
  paraphrases can pass. Homoglyph/zero-width signals raise FLAG unless another rule
  justifies REJECT.
- Session expiry is lazy: an expired row is deleted on the next access, not by a
  background sweeper. The store is per-database, not per-process.
- The detector and labels are advisory in Phase 3 by design; ADR-010 records the
  boundary and the explicit Phase 4+ consumption decision.

## Verification evidence (fresh runs 2026-10-19; detail in ../TESTING_AND_VERIFICATION.md V43-V49)

1. `uv run --frozen pytest -q` → **600 passed** (517 unit + 60 integration + 23
   security; DB-backed integration against the Compose PostgreSQL).
2. `bash scripts/check.sh` → exit 0, all 8 steps; ruff format/lint clean (136 files);
   mypy clean (55 source files); Gitleaks 8.30.1 dir+git: 19 commits, no leaks.
3. Phase 3 targeted suites → **64 passed** (normalization, attack/benign matrix, strict
   config, labels, expiry math, non-PASS failure semantics).
4. Phase 3 integration suites → **13 passed** (startup wiring/refusals; session binding,
   guessed IDs, bounded counters, TTL/max-age, rotation isolation against real
   PostgreSQL).
5. Alembic cycle → `c7f1a2b3d4e5` applies, downgrades, re-applies; `alembic check`:
   "No new upgrade operations detected".
6. Manual service smoke → PASS / REJECT (direct) / FLAG (quoted) / QUARANTINE (external
   email) / REJECT (zero-width+direct) / FLAG (homoglyph only), matching the documented
   limits.

## Definition of Done (blueprint §21, Phase 3) — final status

All eight DoD items **PASS**; item-by-item evidence is in
[`../../docs/IMPLEMENTATION_STATE.md`](../../docs/IMPLEMENTATION_STATE.md) (Phase 3
checklist) and the test files cited above.

## Limitations added by this phase (honest list)

- Detection is advisory and unconsumed; Phase 4 is the first authorized consumer.
- No semantic classifier in the default build; heuristics are deterministic and
  versioned, with the honest false-negative surface above.
- Trust labels are not yet enforced by any execution path (no `/v1` routes exist).
- Session metadata does not authorize; lazy expiry only; no sweeper or cross-region
  coordination.
- Raw content is intentionally not persisted, so findings cannot be replayed from
  storage.

## Handoff

Next task: **Phase 4 — Intent extraction and action validation** (blueprint §21, §§8-9).
Preconditions: none blocking — Phase 3 passed its DoD; proceed per the autonomy mandate.
