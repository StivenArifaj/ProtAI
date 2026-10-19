# ADR-004: AI SOC analyzer treated as an injection target and alert-only

- **Status:** Accepted
- **Date:** 2026-10-19
- **Implementation:** Phase 10

## Context

The security analytics component consumes audit events whose fields may contain
attacker-controlled text (prompts, tool arguments, retrieved content). A summarizer or
"AI analyst" reading those events is itself an indirect prompt-injection target with
privileged visibility into the system's own telemetry.

## Decision

- All event fields influenced by requests, tools, or retrieved content are treated as
  untrusted data when read by the SOC analyzer.
- The analyzer is strictly read-only and alert-only: it cannot call tools, modify
  policies, edit or delete logs, or trigger containment actions in v1. Deterministic
  rules own any actioning; alert rules and their actions are tested.
- Adversarial-log tests must prove injected event strings cannot trigger tools, policy
  changes, log edits, or containment.
- Any future capability that gives the analyzer write or action privileges requires a
  new ADR with an explicit threat-model update.

## Consequences

- Incident response stays human/deterministic-driven in v1; the SOC accelerates
  triage, not remediation.
- The alert-only boundary is testable and auditable, at the cost of automation
  convenience.

## References

Blueprint v1.2 sections 17, 20.2 (22), 21 (Phase 10).
