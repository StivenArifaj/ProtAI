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

## Current snapshot (2026-10-19)

- **Phase 0a (repository foundation): COMPLETE and VERIFIED** (including the Docker
  Compose path). See [phases/PHASE_0A_COMPLETE.md](phases/PHASE_0A_COMPLETE.md).
- **Phase 0b (security foundation): NOT STARTED.** Plan: [phases/PHASE_0B_PLAN.md](phases/PHASE_0B_PLAN.md).
- The repository is **not yet under git version control** (no history); recommended first
  step is `git init` plus a baseline commit — operator's decision.
- No security controls beyond configuration validation, documentation gating, and
  health-endpoint non-leakage exist. Do not present the system as providing
  authorization, DLP, or audit.

## Files in this directory

| File | Purpose |
|---|---|
| [README.md](README.md) | Entry point, reading order, update rules. |
| [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) | Identity, scope, non-goals, stack, operator context. |
| [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) | Source of truth for what exists now (labels + evidence pointers). |
| [NEXT_SESSION.md](NEXT_SESSION.md) | Exact handoff for the next task (Phase 0b). |
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
| [phases/PHASE_0B_PLAN.md](phases/PHASE_0B_PLAN.md) | Phase 0b executable plan (not started). |
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
