# Policy Decision Matrix

Status: **implemented (Phase 1).** This document mirrors the mandatory v1 baseline from
blueprint v1.2 section 10.3 as a specification; the deterministic engine
(`src/ai_security/firewall/policy_engine.py`) enforces it against
`config/policies.yaml` + `config/risk_thresholds.yaml`, and the fixture suite
(`config/policy_self_checks.yaml`) exercises it at startup, on every readiness probe, and
in the table-driven unit tests (ADR-007, ADR-008). The engine consumes validated facts and
makes no network calls and no model calls — decisions are data.

`Risk` is the deterministic 0-100 residual risk score calculated only after mandatory
checks pass (Phase 1 consumes the fact; the scoring engine itself is Phase 5).
Side-effect classes are the canonical `SideEffectClass` enum
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
- Known deviations / limits (documented, tested): destinations match exactly (no
  wildcards in v1); no policy hot-reload (readiness detects file drift; the running
  process keeps its startup-loaded bundle); `Destination` and `risk_score` facts are
  supplied by upstream layers as they land (registry, validator, risk engine).
