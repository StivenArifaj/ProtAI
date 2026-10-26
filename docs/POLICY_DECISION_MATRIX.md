# Policy Decision Matrix

Status: **implemented (Phases 1-2; approval gate Phase 5; output DLP/egress Phase 6).**
This document mirrors the mandatory v1 baseline
from blueprint v1.2 section 10.3 as a specification; the deterministic engine
(`src/ai_security/firewall/policy_engine.py`) enforces it against
`config/policies.yaml` + `config/risk_thresholds.yaml`, and the fixture suite
(`config/policy_self_checks.yaml`) exercises it at startup, on every readiness probe, and
in the table-driven unit tests (ADR-007, ADR-008). Since Phase 2 the gateway
(`src/ai_security/firewall/gateway.py`) is the only execution path and derives the
engine's input facts from the validated call and registry (ADR-009). The engine consumes
validated facts and makes no network calls and no model calls — decisions are data.

`Risk` is the deterministic 0-100 residual risk score calculated only after mandatory
checks pass. Since Phase 2 the gateway computes it with the versioned risk engine
(`src/ai_security/firewall/risk_engine.py`); Phase 5 adds one bounded resource-breadth
factor under version `risk-v2`, calibration remains Phase 9, and a caller can never
supply the score.
Side-effect classes are the canonical `SideEffectClass` enum
(`READ_ONLY`, `LOCAL_MUTATION`, `EXTERNAL_MUTATION`, `DESTRUCTIVE`); data classes are
the canonical `DataClass` enum (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`).
Since Phase 6 the data class used for risk, policy, approval binding, and audit is the
**effective class**: `max(registry declaration, deterministic DLP findings)`. DLP can only
raise it, never lower it (ADR-013).

Output DLP is a separate gate, not a new policy-engine input. Egress inspection runs on
validated arguments after principal/binding/intent checks and before resource
authorization, risk, policy, approval consultation, or execution; a non-`PASS` report is
a pre-execution denial (`dlp_egress_blocked`, or `dlp_inspection_failed` when inspection
cannot complete), so it never reaches the engine and no approval can override it. Response
inspection runs after execution on the complete buffered result; `BLOCK`/`REVIEW`/failure
suppress the whole response (`RESPONSE_BLOCKED`) while preserving the engine's decision
and reason. `PASS`/`REDACT` release bytes; `REDACT` records `dlp.released_digest`.

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

- Evaluation order (engine): principal → tool membership → side-effect class match →
  argument validity → hard deny → resource scope → destination → matrix rows with the
  configured thresholds. Every outcome carries a stable `DecisionReason` code
  (`firewall/decision.py`); the code vocabulary is part of the observable contract.
- Initial starter policy (blueprint section 10.5) lives in `config/policies.yaml`
  (`version: dev-1`) and allows only: `mock_email.search`, `mock_email.read`,
  `text.summarize`, `mock_files.read`. `mock_external_sink.write` is registered with
  `external_egress_enabled: false`; the dedicated egress self-check scenarios enable it
  per-fixture via the documented `tool_policy` override (never by weakening the starter
  document). Tools absent from the document are denied (`unknown_tool`).
- The starter policy denies arbitrary shell execution, unrestricted network requests,
  real external email sending, file deletion, arbitrary database writes, and cross-user
  resource access by construction: none of those tools exist in the document, and
  `DESTRUCTIVE`/`RESTRICTED` rows are hard-blocked in v1.
- Thresholds (`config/risk_thresholds.yaml`, 40/80) are validated
  (`ask_user_at_or_above < block_at_or_above`) and marked experimental until the Phase 9
  calibration; no threshold can override a hard denial.
- Policy YAML uses safe loading (`yaml.safe_load` with duplicate-key detection) and
  validated Pydantic models; no mini-language, dynamic expressions, or code execution
  (section 10.4). Config version/hash are exposed in readiness metadata (ADR-007).
- Phase 2 execution facts: the gateway validates arguments strictly, derives resource
  IDs/destination from the validated fields (caller-declared targets must match), asks the
  adapter's pure `check_resource_access`, and computes `risk_score` with `risk-v2`
  (including the bounded resource-breadth factor). A
  registration absent from the policy stays registered but policy-disabled
  (`unknown_tool`); a policy tool without a registration refuses startup. The engine
  remains the sole `ALLOW` producer; the gateway may only downgrade (audit failure,
  deadlines, evaluation errors).
- Gateway operational reason codes are part of the observable contract:
  `binding_mismatch`, `deadline_exceeded` (engine facts), `policy_evaluation_error`,
  `audit_unavailable` (gateway fail-closed overrides), the Phase 5 approval codes
  `approval_granted`, `approval_denied`, `approval_expired`, `approval_invalid`, and
  the Phase 6 DLP codes `dlp_egress_blocked` / `dlp_inspection_failed`.
  `ASK_USER` remains a no-execution result unless the caller presents an `approval_id`
  that the gateway atomically consumes as an approved, unexpired, exact-action grant.
  The engine decision stays `ASK_USER`; approval is an execution gate, not an `ALLOW`.
  A `BLOCK`/hard deny never consults approval. Pending, denied, expired, replayed,
  mismatched, forged, or storage-unavailable approvals execute nothing.
- Phase 6 egress/response behavior: the gateway requires an `OutputDefenseService` (no
  no-op default), loads the strict versioned `config/output_dlp.yaml`, and refuses startup
  unless the destination trust map exactly covers every registered
  `EXTERNAL_MUTATION` destination. `BLOCK`-scope patterns deny regardless of destination;
  `CLASSIFY` patterns compare the raised class with the destination's `max_data_class`.
  Response `BLOCK`/`REVIEW`/inspection failure return `result=None` with
  `InvocationOutcome.response_blocked`; redaction is span-preserving/idempotent and must
  still satisfy the registered result schema/size or the whole response is suppressed.
  Audit evidence is an optional additive `dlp` field on existing events (schema v1); DLP
  event types and the verifier are Phase 7.
- Known deviations / limits (documented, tested): destinations match exactly (no
  wildcards in v1); no policy hot-reload (readiness detects file drift; the running
  process keeps its startup-loaded bundle); data class is the registration floor raised
  by deterministic, pattern-based inspection (no classifier, entropy, semantic, or
  multilingual detection; no per-resource metadata); Phase 4 manifests are enforced as
  post-policy constraints and do not enter engine facts; approval routes/UI/token
  transport, revocation, and background expiry are Phase 8 (ADR-012).
