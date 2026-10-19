# Phase 3 — Input threat defense and context provenance

**Status: COMPLETE — VERIFIED (2026-10-19).** Blueprint v1.2 §21 Phase 3, §§7-8, §2.2;
invariants #10/#11/#15/#16, and §7.4 session metadata. Outcome and evidence:
[PHASE_3_COMPLETE.md](PHASE_3_COMPLETE.md).

## Scope and deliverables

| Deliverable (§21) | Implementation |
|---|---|
| Intake limits | `input_defense/normalize.py` + `config/input_defense.yaml`: byte limit, content-type allowlist, JSON nesting-depth bound, bounded input for all later stages |
| Normalization copy | `input_defense/normalize.py`: strict UTF-8 decode, NFKC detection copy, flags for invalid encoding, control/format/zero-width chars, homoglyph indicators, excessive percent/entity encoding; the original bytes/string are never mutated |
| Versioned heuristics | `input_defense/heuristics.py`: `input-heuristics-v1` deterministic rules with stable codes (`DIRECT_OVERRIDE_PATTERN`, `SECRET_EXTRACTION_REQUEST`, `UNTRUSTED_INSTRUCTION`, `OBFUSCATED_CONTENT`, ...); quoted/educational/defensive context downgraded to `QUOTED_INSTRUCTION_CONTEXT` (FLAG), never REJECT on that evidence alone |
| Typed detector findings | `input_defense/models.py`: frozen strict models (`FindingCode`, `Disposition`, `DetectorFinding`, `IntakeReport`), versions + content digests only (no raw payloads) |
| Trust labels | `input_defense/context_labels.py`: canonical `TrustLabel` enum from §2.2; structured `ContextSegment`s; labels survive context assembly; external content is `EXTERNAL_UNTRUSTED` even when the requesting principal is authenticated |
| Prompt/context assembly | `context_labels.py`: deterministic `AgentContext` assembly + rendering with per-segment labels; no string-deletion "sanitizing" |
| Detector failure behavior | `input_defense/service.py`: any unexpected detector/classifier error becomes `DETECTOR_UNAVAILABLE` with a configured non-PASS disposition; exception text is not echoed; classifier is an optional protocol and never required to start |
| Session security metadata (§7.4) | `input_defense/sessions.py`, `persistence/session_repository.py`, migration: CSPRNG internal IDs (256-bit), tenant/subject binding re-checked on every read/write, bounded counters/timestamps only, 24 h inactivity TTL + 7 d maximum age with lazy expiry, rotation creates a fresh ID with no inherited state |

## Decisions (within blueprint constraints)

- The detector is advisory evidence for intake disposition only; it never authorizes a
  tool call. `PolicyEvaluationRequest` gains **no** detector facts, so a detector result
  cannot widen permissions. Gateway behavior is unchanged.
- Heuristics are deterministic and versioned; no model call in the decision path. An
  optional classifier interface exists for later phases but is not wired and never
  required.
- Configuration is a strict, duplicate-key-rejecting, versioned YAML document loaded at
  startup (same rigor as the policy bundle; shared `security/safe_yaml.py` helper).
  `DETECTOR_UNAVAILABLE`/`OVERSIZE_INPUT`/`INVALID_ENCODING`/structure errors must never
  map to `PASS` (validator refuses).
- Disposition combination is monotonic: PASS < FLAG < QUARANTINE < REJECT (strongest
  finding wins). No content is deleted or rewritten; normalization exists only for
  detection.
- Session state stores only counters/timestamps and the bound tenant/subject; it is a
  detection signal and is never read by the policy engine or gateway authorization path.
- No `/v1` routes in this phase (Phase 8); the service and session repository are
  constructed at startup and exposed on `app.state` for tests and later routes.

## Non-goals

Complete injection detection (explicitly not claimed), model-based classification,
semantic intent matching (Phase 4), content DLP (Phase 6), rate limits (Phase 8),
real prompt/model integration (Phase 4/8).

## Verification plan

- Unit: intake/normalization, heuristics (direct/indirect, multilingual/homoglyph,
  zero-width, invalid encodings, oversized, benign quoted/educational hard negatives),
  config validation, context labeling, session IDs.
- Security: detector outage is never PASS; detector cannot invoke gateway/adapters
  (surfaces are separate); external content keeps `EXTERNAL_UNTRUSTED` through assembly;
  oversized input is rejected before heuristic work.
- Integration: config wiring refuses invalid config; session state cross-user/
  cross-tenant/guessed/rotation denial and TTL lazy cleanup against PostgreSQL.
- Gate: full `pytest`, `mypy`, ruff, Gitleaks (`check.sh`), plus the unchanged Phase 0b/
  1/2 suites.

## Definition of Done (blueprint §21 Phase 3)

Direct/indirect attack and benign hard-negative tests pass; untrusted source labels
survive to the agent context; detector failure behavior is explicit and cannot bypass the
gateway; no claim of complete injection detection; gate green; memory/docs updated.
