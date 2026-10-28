# Project Memory — AI Agent Security & Safety Platform

This directory is the persistent operational memory for long coding sessions on this
repository. It lets a new agent (or human) recover project state, decisions, and next
steps without relying on any prior conversation.

**The master blueprint is authoritative.** `AI_Agent_Security_Platform_Master_Blueprint_v1.2.md`
(repository root) is the specification. If anything here conflicts with the blueprint,
the blueprint wins and this memory must be corrected. Never implement from memory notes
alone; always read the cited blueprint section first.

## Autonomous operation (mandatory)

**The default is to proceed. Do not wait for operator review between phases or tasks
unless the blueprint explicitly defines an approval gate that requires it.** After a
phase passes its Definition of Done: update `docs/` state files and this memory, commit,
and continue to the next eligible phase in dependency order.

The agent must decide ordinary engineering questions itself (specification-answered,
conventional, or small reversible details). Ask the operator only when proceeding would
require: inventing a product requirement, an irreversible or externally consequential
decision without authorization, unavailable credentials/accounts, accepting a material
unresolved security risk, or violating a required approval gate. See
[AGENT_WORK_PROTOCOL.md](AGENT_WORK_PROTOCOL.md) ("Autonomous execution") for the full
rule and decision procedure.

## Reading order

**New session / cold start:**

1. [README.md](README.md) (this file) — orientation and rules.
2. [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) — what the project is and is not.
3. [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) — what actually exists right now (source of truth).
4. [NEXT_SESSION.md](NEXT_SESSION.md) — the exact next task and how to start it.
5. [AGENT_WORK_PROTOCOL.md](AGENT_WORK_PROTOCOL.md) — the mandatory working rules.
6. Read deeper files ([ARCHITECTURE_MAP.md](ARCHITECTURE_MAP.md), [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md), ...) only as
   the task requires.

**Resuming mid-phase:** [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) → [NEXT_SESSION.md](NEXT_SESSION.md) → the relevant
`phases/PHASE_*.md` record → [CHANGELOG.md](CHANGELOG.md).

## Status labels used in this memory

| Label | Meaning |
|---|---|
| VERIFIED | Backed by evidence from a command actually run; see [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) |
| REPORTED — NOT REVERIFIED | Claimed somewhere but not confirmed by a fresh run |
| PARTIAL | Only the listed subset exists/works |
| NOT IMPLEMENTED | Planned; no code exists |
| BLOCKED | Cannot proceed without an external decision or fix |
| UNKNOWN | Not yet investigated |

Rules: never upgrade a label without running the evidence; never mark something
implemented because a document describes it; record discrepancies instead of hiding them.

## Current snapshot (2026-10-28)

- **Phase 0a (repository foundation): COMPLETE and VERIFIED.** See
  [phases/PHASE_0A_COMPLETE.md](phases/PHASE_0A_COMPLETE.md).
- **Phase 0b (security foundation): COMPLETE and VERIFIED** (including the Docker path).
  See [phases/PHASE_0B_COMPLETE.md](phases/PHASE_0B_COMPLETE.md).
- **Phase 1 (typed contracts and deterministic policy engine): COMPLETE and VERIFIED.**
  See [phases/PHASE_1_COMPLETE.md](phases/PHASE_1_COMPLETE.md).
- **Phase 2 (tool registry and enforced gateway): COMPLETE and VERIFIED.** See
  [phases/PHASE_2_COMPLETE.md](phases/PHASE_2_COMPLETE.md).
- **Phase 3 (input threat defense and provenance): COMPLETE and VERIFIED.** See
  [phases/PHASE_3_COMPLETE.md](phases/PHASE_3_COMPLETE.md).
- **Phase 4 (intent extraction and action validation): COMPLETE and VERIFIED.** See
  [phases/PHASE_4_COMPLETE.md](phases/PHASE_4_COMPLETE.md).
- **Phase 5 (risk engine and approval workflow): COMPLETE and VERIFIED.** See
  [phases/PHASE_5_COMPLETE.md](phases/PHASE_5_COMPLETE.md); ADR-012.
- **Phase 6 (output DLP and egress policy): COMPLETE and VERIFIED.** See
  [phases/PHASE_6_COMPLETE.md](phases/PHASE_6_COMPLETE.md); ADR-013;
  [../docs/OUTPUT_DLP_FALSE_POSITIVES.md](../docs/OUTPUT_DLP_FALSE_POSITIVES.md).
- **Phase 7 (audit persistence and verification): COMPLETE and VERIFIED.** See
  [phases/PHASE_7_COMPLETE.md](phases/PHASE_7_COMPLETE.md); ADR-014;
  [../docs/AUDIT_RETENTION_AND_DATA_HANDLING.md](../docs/AUDIT_RETENTION_AND_DATA_HANDLING.md).
- **Phase 8 (HTTP ingress, bounded runtime, local model): COMPLETE and VERIFIED.** See
  [phases/PHASE_8_COMPLETE.md](phases/PHASE_8_COMPLETE.md); ADR-015;
  [../docs/API_INTEGRATION.md](../docs/API_INTEGRATION.md).
- The repository is **under git** (baseline `41e10da` + every phase series on `main`);
  `origin` = `https://github.com/StivenArifaj/ProtAI.git`, pushed every stage.
- Enforced today: `/v1/*` host HMAC authentication + atomic replay rejection + request
  bounds + host-signed principal assertions; the signed request/preview/approval-decision
  routes (requests = sole execution surface); a bounded two-call demo runtime; per-process
  per-principal rate limits and request deadlines; deterministic policy engine + 21
  self-check fixtures (startup/readiness); typed tool registry + startup consistency;
  mock-only adapters; the `invoke_tool` gateway as the only execution path (digest-bound
  execution authorization, deadlines, timeouts, concurrency/result bounds, audit-first
  mandatory lifecycle); `risk-v2` scoring; complete §16.1 audit taxonomy with a
  fail-closed gateway lifecycle, ingress/approval/intent producers, first-class redacted
  DLP events, derived correlation metadata, and an exact-stored-bytes chain verifier;
  strict advisory input detection gating the request path; trust-labelled context
  assembly and bound session signals; server-issued sealed intent manifests with exact
  constraints and trusted-timezone dates (mock or optional strict local provider);
  durable one-time human approvals with a decision route and row-locked consumption;
  mandatory two-phase output DLP/egress with destination trust and whole-response
  release/redaction/suppression; pinned Gitleaks in the gate. **Absent:** general agent
  planning, real connectors, approval delivery/UI/revocation/expiry sweeper,
  approved-action resumption, a shared rate limiter, cloud model calls, streaming,
  external audit anchor/retention automation, process isolation, an evaluation harness,
  and a SOC — do not present the system as providing them.
- **Phase 9 (evaluation harness and benchmark adapters) is the next task** — see
  [NEXT_SESSION.md](NEXT_SESSION.md).

## Files in this directory

| File | Purpose |
|---|---|
| [README.md](README.md) | Entry point, reading order, update rules. |
| [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) | Identity, scope, non-goals, stack, operator context. |
| [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) | Source of truth for what exists now (labels + evidence pointers). |
| [NEXT_SESSION.md](NEXT_SESSION.md) | Exact handoff for the next task (Phase 9). |
| [ARCHITECTURE_MAP.md](ARCHITECTURE_MAP.md) | Current implemented architecture and target v1 map. |
| [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) | Complete security contract with status per control and blueprint refs. |
| [DECISION_LOG.md](DECISION_LOG.md) | Consolidated decisions; links to ADRs (ADRs live in `docs/adr/`). |
| [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) | How to verify; fresh and historical evidence records. |
| [KNOWN_ISSUES_AND_LIMITATIONS.md](KNOWN_ISSUES_AND_LIMITATIONS.md) | Gaps with severity, status, and next action. |
| [PHASE_ROADMAP.md](PHASE_ROADMAP.md) | All phases (blueprint §21) with status; release maturity (§23). |
| [FILE_MAP.md](FILE_MAP.md) | Navigation map of every repository file. |
| [AGENT_WORK_PROTOCOL.md](AGENT_WORK_PROTOCOL.md) | Mandatory operating rules for coding agents (15 rules + checklists). |
| [CHANGELOG.md](CHANGELOG.md) | Concise dated history of project activity. |
| [phases/PHASE_0A_COMPLETE.md](phases/PHASE_0A_COMPLETE.md) | Phase 0a completion record. |
| [phases/PHASE_0B_COMPLETE.md](phases/PHASE_0B_COMPLETE.md) | Phase 0b completion record. |
| [phases/PHASE_0B_PLAN.md](phases/PHASE_0B_PLAN.md) | Phase 0b executable plan (executed; kept for reference). |
| [phases/PHASE_1_PLAN.md](phases/PHASE_1_PLAN.md) / [phases/PHASE_1_COMPLETE.md](phases/PHASE_1_COMPLETE.md) | Phase 1 plan and completion record. |
| [phases/PHASE_2_PLAN.md](phases/PHASE_2_PLAN.md) / [phases/PHASE_2_COMPLETE.md](phases/PHASE_2_COMPLETE.md) | Phase 2 plan and completion record. |
| [phases/PHASE_3_PLAN.md](phases/PHASE_3_PLAN.md) / [phases/PHASE_3_COMPLETE.md](phases/PHASE_3_COMPLETE.md) | Phase 3 plan and completion record. |
| [phases/PHASE_4_PLAN.md](phases/PHASE_4_PLAN.md) / [phases/PHASE_4_COMPLETE.md](phases/PHASE_4_COMPLETE.md) | Phase 4 plan and completion record. |
| [phases/PHASE_5_PLAN.md](phases/PHASE_5_PLAN.md) / [phases/PHASE_5_COMPLETE.md](phases/PHASE_5_COMPLETE.md) | Phase 5 plan and completion record. |
| [phases/PHASE_6_COMPLETE.md](phases/PHASE_6_COMPLETE.md) | Phase 6 completion record. |
| [phases/PHASE_7_COMPLETE.md](phases/PHASE_7_COMPLETE.md) | Phase 7 completion record. |
| [phases/PHASE_8_COMPLETE.md](phases/PHASE_8_COMPLETE.md) | Phase 8 completion record. |
| [phases/PHASE_TEMPLATE.md](phases/PHASE_TEMPLATE.md) | Template for future phase records. |

## Relationship to `docs/`

- `docs/` holds the specification-adjacent documents (architecture, threat model,
  invariants, policy matrix, ADRs) and the phase-state documents mandated by blueprint
  §22.4 (`docs/IMPLEMENTATION_STATE.md`, `docs/DECISIONS.md`, `docs/KNOWN_LIMITATIONS.md`,
  `docs/adr/`).
- This directory is the operational memory layer: it summarizes, links, and adds
  session-handoff material. It never replaces `docs/` and never contradicts it.
- Keep `docs/IMPLEMENTATION_STATE.md` and [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) consistent whenever
  phase state changes (update both in the same task).

## Update rules

Update this memory **after every completed work session** (and during one if a decision
or blocker appears):

1. [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) — reflect reality; update the "last inspected" line.
2. [NEXT_SESSION.md](NEXT_SESSION.md) — always point at exactly what to do next.
3. [CHANGELOG.md](CHANGELOG.md) — append a dated entry.
4. `phases/PHASE_*.md` — update the current phase record.
5. [KNOWN_ISSUES_AND_LIMITATIONS.md](KNOWN_ISSUES_AND_LIMITATIONS.md) — add or close gaps.
6. [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) — record commands actually run and their results.
7. [DECISION_LOG.md](DECISION_LOG.md) — record new decisions (create an ADR if a security contract changes).
8. [FILE_MAP.md](FILE_MAP.md) — add new files.

**Never store secrets, credentials, tokens, or private data in any file in this
directory** (this includes sample values — refer to `.env.example` by location instead).
