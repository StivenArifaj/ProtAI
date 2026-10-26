# ADR-013: Output DLP and destination-aware egress enforcement

- **Status:** Accepted
- **Date:** 2026-10-26
- **Phase:** 6 (output DLP and egress policy)
- **Blueprint:** §§6.1, 15.1-15.5, 16.1, 16.3, 20.2 #9/#21, 21 (Phase 6)
- **Reference commit:** `df70cd9` (implementation/tests), `e8919cb` (finding-cap
  fail-closed fix), `e586c81` (complete credential-value redaction)

## Context

Before Phase 6, the only data-classification fact was the `DataClass` declared by a tool
registration, and egress was controlled by the policy engine's hard rules plus an exact
destination allowlist. That design cannot stop a confidential value that was pasted into
an otherwise PUBLIC action, and it cannot redact sensitive text in a tool result before
the result reaches the caller. Blueprint §15 requires two distinct controls:

1. **Response release** — inspect the complete final result, then release, redact, or
   suppress it; token streaming is disabled (ADR-003), so no partial bytes escape.
2. **Outbound data flow** — inspect tool-bound content before an external side effect and
   compare its sensitivity with the destination's trust.

The control must remain deterministic, configurable, redacted in evidence, and fail
closed. It must not become a new `ALLOW` producer: the policy engine remains the sole
`ALLOW` producer, the detector and intent layer remain advisory/narrowing, and approvals
can only make an engine `ASK_USER` executable.

## Decision

### 1. Output defense is a mandatory gateway dependency

`ToolGateway` now requires an `OutputDefenseService` constructed from a startup-validated
`OutputDlpConfig`. There is no `None`/no-op default in production or tests, so a gateway
cannot silently omit DLP. The app loads `OUTPUT_DLP_PATH` (default
`config/output_dlp.yaml`), exposes the loaded config/service on `app.state`, and injects
the service into the gateway.

Inspection is two-phase and ordered:

- **Egress** runs after principal/binding checks, intent verification, and
  argument/resource/destination validation, but **before** resource authorization, risk
  scoring, policy evaluation, approval consultation, or execution. A non-`PASS` egress
  report is a pre-execution denial.
- **Output release** runs after the adapter returns, on the complete buffered result,
  before any result is returned. A suppressed result is never released partially.

Read-only actions are also inspected on egress so a sensitive value in a search/read
request is classified and can raise the effective data class. They must not carry a
destination; doing so is an inspection failure.

### 2. Configuration is strict, bounded, and startup-fail-closed

`OutputDlpConfig` (`schema_version`, stable `version`, `limits`, `patterns`,
`destinations`) uses `extra="forbid"` and frozen models. Loading is via the shared
duplicate-key-rejecting safe YAML parser; missing files, invalid UTF-8, unknown fields,
bad versions, duplicate pattern codes/expressions, duplicate destination names/URLs, and
invalid regexes all raise `OutputDlpConfigError` and refuse startup.

Hard bounds:

- at most 64 patterns and 64 destination trust entries;
- pattern length ≤ 512 characters, no control characters, no empty-string match;
- a pattern may not match any configured redaction marker (otherwise redaction could
  re-match its own output);
- `max_scan_bytes` 1 byte-4 MiB, `max_findings` 1-128, `max_matches_per_pattern` 1-256;
- at most 4,096 scanned string fields, traversal depth 16, field paths ≤ 256 characters;
- at most 32 field paths per finding, 64 findings in an audit record.

Oversize content, excessive nesting/field counts, non-string mapping keys, unsafe field
paths, invalid declared classes, or a saturated finding report that would leave patterns
unevaluated are inspection failures, not silent skips. Per-pattern match truncation still
records the evaluated finding (and therefore its category/class), so it does not hide a
known match. Any inspection failure produces a fail-closed report with
`DataClass.restricted`, `inspection_error=true`, no findings, and a digest of the bytes
that were available.

### 3. Detection is deterministic and configuration-driven

The shipped `1.0.1` configuration defines five detectors:

| Code | Category | Class | Egress | Release |
|---|---|---|---|---|
| `synthetic_canary` | `SYNTHETIC_CANARY` | `RESTRICTED` | `BLOCK` | `BLOCK` |
| `private_key` | `PRIVATE_KEY` | `RESTRICTED` | `BLOCK` | `BLOCK` |
| `api_key` | `API_KEY` | `RESTRICTED` | `BLOCK` | `BLOCK` |
| `credential_assignment` | `CREDENTIAL` | `CONFIDENTIAL` | `BLOCK` | `REDACT` |
| `email_address` | `PII_EMAIL` | `CONFIDENTIAL` | `CLASSIFY` | `REDACT` |

Canaries use the synthetic `CANARY_SECRET_...` shape only; no real credential is
committed. Detection scans every string value in the canonical JSON projection of the
arguments/result and records only the stable code, category, match count (capped), and
schema field paths. Matched text is never stored in `DlpFinding`, `DlpReport`, audit
payloads, or logs. There is no entropy scan, classifier, multilingual PII detector, or
semantic-leakage detector in Phase 6; those require a test set and false-positive analysis
(§15.2) and are not claimed.

### 4. Effective data class is a floor, never a ceiling

The runtime class for an action is:

```text
effective = max(registry.declared_data_class, matched_pattern.data_class...)
```

A detector can only raise sensitivity. Registry `CONFIDENTIAL`/`RESTRICTED` stays
blocked by the policy engine for external egress even if no pattern matches. The
effective class is used consistently for risk scoring, policy evaluation, approval
binding/consumption, and audit; the renderer never re-lowers it.

### 5. Destination trust is exact-canonical and must cover capability exactly

Each `DestinationTrust` entry has a stable name, an already-canonical https destination
(canonicalized, then required to equal the input), a documentation/audit trust label
(`INTERNAL`/`PARTNER`/`PUBLIC`), and `max_data_class`. Lookup is exact; no prefix or
wildcard matching.

At startup, `ToolRegistry.external_destinations()` is compared with the trust map and
must match exactly. A missing entry would let a registered external mutation bypass the
destination-aware class check; a dead entry can hide a typo. Either mismatch refuses
startup. The shipped map trusts only the mock sink
`https://mock-sink.invalid/collect` for `PUBLIC` data.

Egress outcomes use stable `EgressReason` values: `passed`, `category_blocked`,
`destination_missing`, `destination_not_configured`, `class_above_destination`.
`BLOCK`-scope detectors deny regardless of destination; `CLASSIFY` detectors let the
trust bound decide. An external-mutation registration without a canonical destination is
denied (`destination_missing`).

### 6. Typed outcomes, redaction, and suppression

`DlpOutcome` is `PASS`/`REDACT`/`BLOCK`/`REVIEW`; `DlpPhase` distinguishes `EGRESS` from
`OUTPUT`. For response release, the most restrictive configured disposition wins
(`BLOCK` > `REVIEW` > `REDACT` > `PASS`).

- `PASS` releases the original result.
- `REDACT` applies an explicit, span-preserving transformation to every string value.
  Overlapping matches are merged (not dropped) and labeled with the highest-severity
  category, so a longer match's tail cannot survive. Redaction markers are fixed
  `[REDACTED:<CATEGORY>]` strings that no configured pattern may match. The credential
  detector redacts the complete value through the end of the line so a multi-word
  passphrase cannot leave its tail. The transformed
  payload must still validate against the registered result schema and result-size bound;
  otherwise the entire response is suppressed and the report becomes
  `BLOCK`/`inspection_error`.
- `BLOCK`, `REVIEW`, and every inspection failure suppress the complete result:
  `result=None`, `InvocationOutcome.response_blocked`; the engine's decision/reason are
  preserved and `dlp_output` explains the disposition. `REVIEW` is treated as
  whole-response suppression because no review queue or token transport exists in v1.
- A released result keeps the original `content_digest` (over the unreleased canonical
  result) and adds `released_digest` (SHA-256 of the released canonical result). This
  preserves provenance while allowing the caller's digest assertions to target the
  redacted bytes.

### 7. Audit evidence is additive and redacted

Rather than inventing Phase 7 event types early, Phase 6 adds an optional `dlp`
`DlpAuditRecord` field to existing `POLICY_EVALUATED` and execution outcome events under
`schema_version=1`. It carries phase/outcome, egress reason, effective class, finding
codes/categories/counts, bounded control-character-free field paths, config version/hash,
content digest/size, truncation/inspection flags, destination trust facts, and
`released_digest`. It never carries matched text, raw arguments, result bodies, or
exception messages. `AuditEvent.to_payload()` omits `None`, so existing events and the
canonical stored bytes remain compatible without a migration.

New `EGRESS_INSPECTED`/`OUTPUT_INSPECTED`/`RESPONSE_*` event types and a verifier are
explicitly deferred to the Phase 7 taxonomy.

### 8. Approval consumption is bound to the effective class

Phase 5 approvals stored `side_effect_class` and `data_class`, but consumption previously
compared only the digest and provenance. Since DLP can raise the class without changing
the canonical action digest, a stale PUBLIC-bound approval could otherwise authorize
newly classified content. `ApprovalService.consume` now also requires the stored
`side_effect_class` and `data_class` to match the gateway's current facts. A mismatch
returns `mismatch` without consuming the grant; a correctly bound approval remains
one-time.

Approval is still consulted only for an engine `ASK_USER`. A DLP denial happens before
policy, so an approval cannot override it and is never consumed; `BLOCK` and hard denies
are unaffected.

### 9. Wiring and non-goals

`OUTPUT_DLP_PATH` is added to settings and `.env.example`. The app loads and validates the
file, validates exact destination coverage, and exposes `output_dlp_config` and
`output_defense` on `app.state`. No `/v1` route exists yet, so all Phase 6 enforcement is
in-process/in tests.

Not in Phase 6:

- no real connector or local-model path, so no inspection of content fetched inside a
  future adapter or of model prompts/streams;
- no per-resource classification metadata from a real store; the floor is the
  registration class plus deterministic argument/result inspection;
- no local-write destination mapping (only external mutations require destinations);
- no review queue/UI or release token for `REVIEW`;
- no entropy/classifier/multilingual semantic detection; false positives and negatives
  are documented in `docs/OUTPUT_DLP_FALSE_POSITIVES.md`;
- no migration (audit JSON is additive);
- no Phase 7 event taxonomy or chain verifier.

## Consequences

- A canary or private key in tool arguments is blocked before risk/policy/execution, and
  a canary in a result suppresses the whole response. The mock sink stays empty on every
  unauthorized path (tested).
- Email addresses in mock results are redacted by default, including sender fields; tests
  and callers that need exact bytes must compare `dlp.released_digest`.
- DLP-raised sensitivity can block an action that policy would otherwise allow. This is
  intentional defense in depth; it may also create false positives (documented).
- Configuration is code-adjacent: changing patterns changes the DLP config hash in audit
  evidence, not the policy hash. Operators must treat the DLP file as security
  configuration and review changes.
- The detector is pattern-based and cannot prove content is safe. `PASS` means "no
  configured pattern matched", never "no sensitive data".
- Real adapters added later must route payloads through this service; the gateway
  inspects only validated arguments and complete buffered results.

## Verification

- `tests/unit/test_output_dlp.py` — strict loading/unknown fields/duplicates/bad
  versions/non-UTF-8/missing file; canonical destination requirement; empty-match,
  marker, and control-character rejection; canary block with no match text in the report;
  destination-class denial; registry floor; benign hard negatives; missing destination;
  non-egress destination misuse; redaction idempotence/digest/overlap; complete
  credential-value redaction; BLOCK vs REVIEW;
  oversize failures; release helpers; finding-cap fail-closed regression.
- `tests/unit/test_gateway.py` — canary egress denial before risk; destination-class
  denial; egress inspection failure; response email redaction with preserved original
  digest; canary response suppression; oversize suppression; review suppression;
  redaction schema-failure suppression.
- `tests/integration/test_gateway_approval.py` — DLP block precedes approval and does not
  consume it; a stale data-class approval cannot authorize classified content; a matching
  approval executes once.
- `tests/integration/test_approval_flow.py` — consumption rejects side-effect/data-class
  mismatches without consuming.
- `tests/integration/test_gateway_wiring.py` — startup refuses a missing DLP file, a
  missing sink trust entry, and a dead trust entry.
- `tests/integration/test_gateway_end_to_end.py` — real-PostgreSQL redacted result digest
  linkage and non-leakage.
- Fresh full suite and 8/8 gate evidence in
  `project_memory/TESTING_AND_VERIFICATION.md` (V63+).

## References

- Blueprint v1.2 §§6.1, 15.1-15.5, 16.1, 16.3, 20.2, 21 (Phase 6).
- ADR-003 (no token streaming), ADR-008 (policy engine), ADR-009 (registry/gateway),
  ADR-012 (approvals).
- `src/ai_security/data_security/{dlp,classification}.py`,
  `src/ai_security/firewall/{gateway,approval,models,decision}.py`,
  `src/ai_security/audit/models.py`, `src/ai_security/api/app.py`,
  `config/output_dlp.yaml`, `docs/OUTPUT_DLP_FALSE_POSITIVES.md`.
