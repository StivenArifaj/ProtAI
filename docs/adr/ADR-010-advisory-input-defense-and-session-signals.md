# ADR-010: Advisory input threat defense, trust labels, and session signals

- **Status:** Accepted
- **Date:** 2026-10-19
- **Implementation:** Phase 3

## Context

Blueprint sections 7.2-7.4 require an input pipeline for user requests, tool results, and
email/external content: bounded intake, a normalized detection copy, deterministic
injection detection that never executes or renders input, structured trust labels for
context assembly, and a bounded per-session store for multi-turn security signals. Section
7.6 requires honest handling of detector uncertainty; section 20.2 invariants #10, #11,
#15, and #23 become testable here. Phase 2 established the policy engine, registry, and
gateway as the only authorization/execution path. This ADR records how detection stays
advisory and how session state stays bound to a verified principal without exposing a new
authorization path.

## Decision

- **Detection is evidence, never authority.** The detector consumes bytes and returns an
  `IntakeReport` (findings, disposition, provenance, digests). It does not construct or
  mutate `PolicyEvaluationRequest`, does not call the engine or gateway, and exposes no
  execution method. A false negative cannot widen permissions; a positive finding cannot
  grant them. Wiring detection into routes and model context is later-phase work.
- **Disposition is monotonic and configured.** `PASS < FLAG < QUARANTINE < REJECT`; the
  report disposition is the strongest configured disposition over its findings. The
  versioned config (`config/input_defense.yaml`, schema 1) must enumerate **every**
  `FindingCode`; unknown/missing codes, duplicate YAML keys, invalid content types, and
  any mapping to `PASS` refuse startup. Detector failure therefore always has a non-PASS
  disposition (`DETECTOR_UNAVAILABLE` → `REJECT` in `dev-1`).
- **Intake fails closed before detection.** Byte length, declared content type
  (parameters stripped, case-insensitive), and strict UTF-8 decoding are checked in that
  order. Oversize, unsupported type, and invalid encoding produce explicit findings and
  are never treated as clean or sent to heuristics.
- **Normalization is copy-only.** Control characters, zero-width/Cf characters,
  excessive percent/HTML-entity encoding, long Base64 blobs, NFKC changes, and mixed
  Latin/Cyrillic-Greek tokens are reported as typed signals on a detection copy; the
  original input is never mutated or stored. JSON depth is inspected iteratively so a
  hostile document cannot exhaust the Python stack.
- **Heuristics are deterministic and versioned.** Ten named regex rules
  (`input-heuristics-v1`) cover direct overrides, instruction disclosure, developer mode,
  jailbreak phrasing, secret/system-prompt extraction, and assistant-directed external
  instructions. Findings carry detector/heuristics versions and character offsets, never
  raw content. Quoted, educational, defensive, or "for example" contexts downgrade a
  match to `QUOTED_INSTRUCTION_CONTEXT` (flagged, not proof of an attack); untrusted-
  instruction rules apply only to `EXTERNAL_UNTRUSTED`/`TOOL_RESULT` content.
- **Context provenance is structured.** `ContextSegment`/`AgentContext` require unique
  non-empty segment IDs and one of the six blueprint trust labels. External email content
  is forced to `EXTERNAL_UNTRUSTED` even when the requesting principal is authenticated;
  tool results are `TOOL_RESULT`; model output is `MODEL_GENERATED`. Rendering is
  deterministic sorted JSON including the label, so later prompts can distinguish
  instructions from data.
- **Session signals are bounded and bound.** The PostgreSQL table stores
  `(session_id, tenant_id, subject_id, created_at, last_seen_at, four counters)` only —
  no prompts, findings, or content. Every read/write/rotate requires the verified
  tenant/subject; a mismatch behaves exactly like a missing row (no side channel).
  Inactivity TTL is 24 h (blueprint §7.4) and absolute age 7 days; expiry is enforced on
  read and write with lazy deletion, so a write can never extend an expired session.
  Counters are incremented with `LEAST(...)` so they cannot exceed 1,000,000. Rotation
  creates a new opaque ID with zero counters and never inherits signals; the old row is
  unchanged. This state is **not** an authorization input in Phase 3.
- **Optional classifier is diagnostic only.** A `LocalClassifier` protocol exists for
  later model-assisted detection but is not configured or required. A classifier
  exception or latency beyond the evaluation budget produces `DETECTOR_UNAVAILABLE`; the
  decision path never fails open because a model is unavailable.
- **Config safety is shared.** Duplicate-key rejection moved to
  `security/safe_yaml.py` and is used by both the policy loader and the input-defense
  loader; parsing uses `yaml.safe_load` on a pre-checked node tree (the gate prohibits
  `yaml.load` in `src/`).

## Consequences

- Invariants #10, #11, #15, and #23 have concrete tests: detector faults and intake
  violations are non-PASS; context labels survive assembly/rendering; session state
  cannot be read, extended, created, or inherited across bindings or rotation.
- Detection accuracy is intentionally modest and documented; quoted/educational content
  can still raise flags, and semantic intent, multilingual confusable coverage beyond
  mixed-script tokens, and model-assisted detection remain later work. Homoglyph
  normalization does not currently convert confusables before regex matching.
- No `/v1` route exposes the service or session store; route-level binding and rate
  limiting are re-verified in Phases 5/8. Content DLP (Phase 6) is separate and has not
  been added.

## References

Blueprint v1.2 sections 2.2, 7.2-7.6, 8.1-8.3, 20.2 (#10, #11, #15, #23), 21 (Phase 3);
ADR-002 (audit chain), ADR-007 (self-checks), ADR-008 (engine facts), ADR-009 (gateway);
`src/ai_security/input_defense/*`, `src/ai_security/security/safe_yaml.py`,
`src/ai_security/persistence/session_repository.py`; `config/input_defense.yaml`;
`project_memory/phases/PHASE_3_PLAN.md`.
