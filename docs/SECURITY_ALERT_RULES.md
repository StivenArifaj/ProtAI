# Security Alert Rules (Phase 10)

This document describes the deterministic alert rules implemented in Phase 10
(blueprint section 17.1). Alerts are **evidence/notification only** — no rule may
block, allow, consume an approval, revoke a session, edit policy, or trigger
containment (ADR-004, ADR-017).

## Configuration

Alert rules are configured in a versioned, strict configuration file loaded at
startup. Invalid configuration fails closed: no default rules, no silent skipping.
All thresholds and observation windows are bounded to prevent resource exhaustion
from attacker-influenced configuration.

See `src/ai_security/soc/config.py` for the config schema and `docs/adr/ADR-017.md`
for the trust contract.

## Implemented Rules

| Rule ID | Kind | Severity | Default Window | Default Threshold | Fires When |
|---|---|---|---|---|---|
| `blocked-calls-10-per-hour` | `repeated_blocked_calls` | HIGH | 3600s | 10 | More than 10 policy `BLOCK` decisions within the window |
| `approval-failures-5-per-hour` | `repeated_approval_failures` | MEDIUM | 3600s | 5 | More than 5 approval denials/expiries within the window |
| `broad-resource-access-5-per-hour` | `broad_resource_access` | MEDIUM | 3600s | 5 | A single principal touches more than 5 distinct tool/action pairs within the window |
| `burst-reads-10-per-hour` | `burst_reads_across_resources` | MEDIUM | 3600s | 10 | More than 10 distinct resources are read via `ALLOW` decisions within the window |
| `external-destinations-10-per-hour` | `repeated_external_destination_attempts` | HIGH | 3600s | 10 | More than 10 calls to external destinations within the window |

All rules are **enabled by default**. Rule IDs are stable; changing a rule's
semantics requires a new rule ID (old IDs are never reused).

## Evidence

Emitted `SECURITY_ALERT_RAISED` events carry content-free evidence only:
- `risk_version`: the rule ID (e.g. `blocked-calls-10-per-hour`)
- `risk_score`: the observed count
- `policy_version`: severity (e.g. `severity:HIGH`)
- `policy_hash`: `count:<N>:window:<W>:evidence:<TOKENS>`
- `risk_factor_codes`: content-free evidence tokens (e.g.
  `BLOCKED_CALLS_EXCEED_THRESHOLD`)

No raw audit text, user content, tool output, destination URLs, or exception
messages are ever included in alert events.

## Rule Semantics

### `repeated_blocked_calls`

Counts policy `BLOCK` decisions across all tools and principals within the
observation window. Fires when the count strictly exceeds the threshold.

Designed to detect: automated probing, brute-force attempts, or a compromised
agent repeatedly attempting unauthorized actions.

### `repeated_approval_failures`

Counts `APPROVAL_DECIDED` events with decision `BLOCK` plus `APPROVAL_EXPIRED`
events within the window. Fires when the combined count strictly exceeds the
threshold.

Designed to detect: attempts to obtain approvals that are repeatedly denied or
allowed to lapse, which may indicate an attacker probing approver boundaries.

### `broad_resource_access`

Counts distinct `(tool_id, action_id)` pairs per principal within the window.
Fires when the maximum count for any single principal strictly exceeds the
threshold.

Designed to detect: a single principal accessing an unusually broad set of
tools/actions, which may indicate compromised credentials or privilege
escalation.

### `burst_reads_across_resources`

Counts distinct `tool_id` values on `ALLOW` decisions within the window.
Blocked calls are excluded. Fires when the count strictly exceeds the threshold.

Designed to detect: automated scraping or bulk reads across many resources.

### `repeated_external_destination_attempts`

Counts events with a non-empty `destination` field within the window. Fires when
the count strictly exceeds the threshold.

Designed to detect: repeated attempts to reach external destinations, which may
indicate data exfiltration or a compromised adapter.

## Threshold Tuning

Thresholds are configurable per deployment. Do not tune thresholds to make alerts
"look better" — thresholds should reflect operational tolerances, not desired
alert rates. Any threshold change requires a new config version and must be
documented here.

## Testing

Each rule has unit tests asserting:
- The rule fires only on its documented pattern (true positive)
- The rule stays silent on benign or threshold-boundary evidence (false positive
  suppression)
- Rules are content-free: they never match on raw text or payloads

See `tests/unit/test_soc_rules.py` and `tests/unit/test_soc_config.py`.
