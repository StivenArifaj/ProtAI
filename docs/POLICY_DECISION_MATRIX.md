# Policy Decision Matrix

Status: **specification only.** This document mirrors the mandatory v1 baseline from
blueprint v1.2 section 10.3. The policy engine that enforces it is not implemented yet
(Phases 1-5), so nothing here is enforced today. When `config/risk_thresholds.yaml` and
the policy engine exist, they MUST mirror this matrix, and the policy self-check suite
MUST test representative rows at startup and in CI.

`Risk` is the deterministic 0-100 residual risk score calculated only after mandatory
checks pass. Side-effect classes are the canonical `SideEffectClass` enum
(`READ_ONLY`, `LOCAL_MUTATION`, `EXTERNAL_MUTATION`, `DESTRUCTIVE`); data classes are
the canonical `DataClass` enum (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`).

| Preconditions / side-effect class | Data class and destination | Risk 0-39 | Risk 40-79 | Risk 80-100 | V1 rule |
|---|---|---|---|---|---|
| Any hard-denied action, invalid schema, missing/invalid principal, unavailable mandatory policy, failed required DLP/egress check, or expired/replayed approval | Any | **BLOCK** | **BLOCK** | **BLOCK** | Hard constraints dominate every score and approval. |
| `READ_ONLY` | Data the principal is already authorized to read; no egress | **ALLOW** if all policy checks pass | **ASK_USER** only if policy marks clarification/approval eligible; otherwise **BLOCK** | **BLOCK** | Detector confidence alone never grants access. |
| `LOCAL_MUTATION` | `PUBLIC` or `INTERNAL`, destination is approved | **ALLOW** if explicitly permitted | **ASK_USER** if approval is configured; otherwise **BLOCK** | **BLOCK** | Write is allowed only by explicit tool/action policy. |
| `LOCAL_MUTATION` | `CONFIDENTIAL` | **ASK_USER** if the action is approval-eligible; otherwise **BLOCK** | **ASK_USER** if eligible; otherwise **BLOCK** | **BLOCK** | No implicit permission from read access. |
| `LOCAL_MUTATION` | `RESTRICTED` | **BLOCK** in v1 | **BLOCK** in v1 | **BLOCK** in v1 | Restricted-data writes are not registered in the initial release. |
| `EXTERNAL_MUTATION` | `PUBLIC`, exact destination is allowlisted, method/payload schema approved | **ALLOW** only if external egress is explicitly enabled | **ASK_USER** if eligible; otherwise **BLOCK** | **BLOCK** | External network and sending tools are disabled by default. |
| `EXTERNAL_MUTATION` | `INTERNAL` | **ASK_USER** only for an explicitly enabled, approved destination; otherwise **BLOCK** | **ASK_USER** if eligible; otherwise **BLOCK** | **BLOCK** | Must pass destination and payload checks before execution. |
| `EXTERNAL_MUTATION` | `CONFIDENTIAL` or `RESTRICTED` | **BLOCK** in v1 | **BLOCK** in v1 | **BLOCK** in v1 | No exception through score or human approval in the initial release. |
| `DESTRUCTIVE` | Any | **BLOCK** in v1 | **BLOCK** in v1 | **BLOCK** in v1 | Destructive tools are not registered in the initial release. |

## Decision precedence (mandatory)

1. Hard deny / invalid state
2. Policy permissions and resource scope
3. Required DLP/egress and approval rules
4. Risk thresholds for otherwise eligible actions
5. Allow only if every required gate passed

A score of 0 cannot make a forbidden action legal. An approval cannot override a hard
deny. `ASK_USER` is valid only when the policy explicitly says the action is approvable;
otherwise unresolved risk becomes `BLOCK`. Unknown, missing, or invalid enum values MUST
fail closed (`BLOCK`); no string aliases and no coercion into an allowed class.

## Implementation notes

- Initial starter policy (blueprint section 10.5) allows only: `mock_email.search`,
  `mock_email.read`, `text.summarize`, `mock_files.read`; `mock_external_sink.write` is
  disabled by default and enabled only in a dedicated egress-blocking test scenario.
- The initial policy MUST deny arbitrary shell execution, unrestricted network
  requests, real external email sending, file deletion, arbitrary database writes, and
  cross-user resource access.
- Policy YAML uses safe loading and validated Pydantic models; no mini-language,
  dynamic expressions, or code execution (section 10.4).
