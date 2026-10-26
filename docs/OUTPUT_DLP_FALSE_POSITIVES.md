# Output DLP: False Positives and False Negatives

Status: **Phase 6, configuration `1.0.1`** (blueprint v1.2 §15.2/§15.5). This document is
required by the Phase 6 Definition of Done: detection behavior must have documented
false-positive and false-negative cases, and the documents must not imply that pattern
matching finds all secrets or PII.

The detector is deterministic, configuration-driven, and content-only. `PASS` means
"no configured pattern matched", never "the content is safe". Matched values are never
logged; evidence contains only codes, categories, counts, field paths, and digests.

## Tested benign cases (hard negatives)

`tests/unit/test_output_dlp.py::test_benign_similar_strings_do_not_match` sends this
payload through both egress and response phases and requires `PASS` with no findings:

```text
CANARY_SECRET is a label, sk-short is not a key,
-----BEGIN PUBLIC KEY----- is public, password is configured elsewhere,
reach the team at localhost without a dot
```

Why each stays benign:

| Input | Why it does not match |
|---|---|
| `CANARY_SECRET is a label` | The canary pattern requires `CANARY_SECRET_` followed by 4+ uppercase/digit/underscore characters; a space ends the token. |
| `sk-short` | The API-key pattern requires at least 20 characters after `sk-`. |
| `-----BEGIN PUBLIC KEY-----` | The private-key pattern requires `PRIVATE KEY` (optionally preceded by an uppercase token such as `RSA`), not `PUBLIC KEY`. |
| `password is configured elsewhere` | The credential pattern requires an assignment operator `:` or `=`. |
| `localhost` | The email pattern requires `@` and a dotted domain with a 2+ character TLD. |

Additional negative coverage: duplicate/invalid configuration, empty-match patterns,
redaction-marker matches, control characters, non-canonical destinations, missing
destinations, non-egress actions carrying a destination, and benign values beside a
redacted value (`safe: keep me`) are all exercised.

## Known false positives

These are accepted consequences of deterministic matching. Tune the configuration for the
deployment; do not assume the defaults fit every corpus.

### Email address (`email_address`, `PII_EMAIL`)

- **Every** email address is classified `CONFIDENTIAL`, including internal, role, and
  synthetic addresses. On external egress, that may block the action through the policy
  engine or the destination class bound; in a response, it is redacted.
- Documentation, quoted email samples, changelogs, and test fixtures containing addresses
  are redacted/suppressed like live personal data.
- Mock email results contain synthetic `@...example` addresses, so sender/recipient
  fields become `[REDACTED:PII_EMAIL]` by default. Tests that need exact result bytes
  compare `dlp.released_digest`, not the original content.
- A redacted result may no longer satisfy a strict result schema (for example, a field
  constrained to an email shape). The gateway then suppresses the whole response
  (`RESPONSE_BLOCKED`) instead of releasing a schema-invalid value.

### Credential assignment (`credential_assignment`, `CREDENTIAL`)

- Any keyword (`password`, `passwd`, `secret`, `api_key`/`api-key`, `access_token`,
  `refresh_token`) followed by `:` or `=` and a value of at least six characters matches,
  even in prose, documentation, code samples, configuration examples, or an incident
  report quoting a placeholder.
- The detector is line-scoped: it redacts from the first non-space value character to the
  end of the line. A trailing comment or explanatory text on the same line is
  over-redacted. This is deliberate: leaving the tail of a multi-word passphrase would be
  worse than removing benign trailing text.
- Quoted and unquoted values both match. `api_key: SET_ME` matches because `SET_ME` is a
  six-character placeholder.

### Synthetic canary (`synthetic_canary`)

- Any uppercase token shaped `CANARY_SECRET_XXXX` matches, including documentation
  labels, test names, and benign identifiers. The match is `RESTRICTED`, blocks egress,
  and blocks the response, so a false positive is loud.
- A canary-like string in a quoted security example is not context-downgraded; unlike
  input-defense heuristics, output DLP has no quote/education exception.

### Private key (`private_key`)

- The header `-----BEGIN ... PRIVATE KEY-----` matches even in documentation, source
  examples, or a redacted incident excerpt. Egress is blocked and the response is
  suppressed.
- The pattern intentionally matches the header only. It does not need the body to block.

### API key (`api_key`)

- Any `sk-` token with 20+ characters matches, including synthetic fixtures, fake keys
  from documentation, and non-OpenAI identifiers that happen to use that shape.
- `sk-` short values do not match; this is a false negative (below), not a false positive.

### Cross-cutting false positives

- A detected class can only raise sensitivity, so a legitimate action may become
  `CONFIDENTIAL`/`RESTRICTED` and be blocked by risk/policy/destination rules even though
  the content was benign.
- Overlapping matches are merged and labeled with the highest-severity category; the
  marked span may be larger than any single detector's match.
- A `REVIEW` disposition suppresses the complete response; there is no review queue in
  Phase 6, so “review” is operationally a block for the caller.
- Redaction/schema/size failures suppress the entire result, even if only one field
  matched.

## Known false negatives (do not rely on the detector for these)

The shipped configuration has **no entropy scan, no classifier, no semantic model, and no
multilingual PII support**. The following are expected to pass or to be only partially
redacted:

- **Spaced, split, or encoded secrets.** A secret split across fields, lines, or messages,
  Base64/hex/URL-encoded, compressed, or inserted with zero-width characters may not
  match. Cross-chunk detection is not implemented because streaming is disabled.
- **Secrets without a configured keyword or prefix.** Cloud keys (`AKIA...`), GitHub
  tokens (`ghp_...`), Slack tokens (`xoxb-...`), JWTs, bearer tokens in prose, and
  high-entropy random strings are not detected unless they match one of the five shapes.
- **Short credential values.** The credential pattern requires six characters after the
  assignment operator; short test values may not match.
- **Non-line-scoped separators.** `password` split from its value across lines is not
  matched; only the same line is inspected.
- **Private-key bodies without a header.** DER/base64 blobs or partial keys with no
  `BEGIN ... PRIVATE KEY` header are not detected.
- **Non-email PII.** Phone numbers, postal addresses, names, dates of birth, government
  IDs, account numbers, IP addresses, and similar identifiers are not detected. Only
  email addresses are configured as PII in `1.0.1`.
- **Multilingual/Unicode PII and Unicode email forms.** The email pattern is ASCII-only
  and is not an internationalized-email parser; non-ASCII local parts/domains may be
  missed.
- **Semantic leakage and paraphrase.** A model can describe a secret, summarize a private
  document, or leak meaning without reproducing a matched pattern. Nothing in Phase 6
  evaluates meaning.
- **Secrets in mapping keys.** Only string *values* are scanned and redacted; JSON object
  keys are schema-controlled and are not transformed. A future adapter must not put
  untrusted secret material in keys.
- **Numbers/booleans as secrets.** Only strings are scanned; a secret represented as a
  numeric field is not inspected unless the adapter serializes it as a string.
- **Canary shape variants.** Lowercase, mixed-case, hyphenated, or shorter canaries do not
  match the uppercase-underscore pattern. Tests must use the configured shape.
- **Content beyond limits.** Content larger than `max_scan_bytes` (256 KiB shipped) or
  deeper than 16 levels is not scanned; it fails closed (block/suppress) rather than
  passing. That is safe but may hide a benign oversize result from the caller.

## What is fail-closed rather than a false negative

The following are treated as inspection failures and never silently pass:

- oversize canonical content;
- too many string fields (>4,096), excessive nesting (>16), or overlong field paths;
- a finding report saturated before all configured patterns were evaluated (a fix
  recorded in `e8919cb`);
- unreadable/invalid configuration at startup;
- redaction that produces a schema-invalid or oversize result;
- a non-canonical/missing required destination for an external mutation;
- a read-only action that presents a destination.

Failures produce `BLOCK`/`inspection_error=true` (with `max_data_class=RESTRICTED`),
egress denial, or `InvocationOutcome.response_blocked`, and they are audited.

## Tuning guidance

- Treat `config/output_dlp.yaml` as security configuration: review changes, keep the
  version stable and bump it on edits, and note that the DLP config hash (not the policy
  hash) changes.
- Every pattern must have a unique `code`, a valid regex, no empty-string match, and no
  match against `[REDACTED:<CATEGORY>]` markers; invalid configuration refuses startup.
- Prefer `BLOCK` for hard categories and `CLASSIFY` only where the destination trust map
  should decide. Prefer `REDACT` for response-only PII and `BLOCK`/`REVIEW` when partial
  release is unacceptable.
- Destination trust entries must exactly match the registry's external-mutation
  capabilities; a missing or dead entry refuses startup.
- Re-run `test_benign_similar_strings_do_not_match` and the full suite after any pattern
  change. Add the new benign/attack pairs to `tests/unit/test_output_dlp.py`.

## See also

- `config/output_dlp.yaml` — the shipped patterns, limits, and trust map.
- `docs/adr/ADR-013-output-dlp-and-egress.md` — ordering, outcomes, audit evidence.
- `docs/KNOWN_LIMITATIONS.md` — Phase 6 limits (no classifier, no real connectors).
- Blueprint v1.2 §§15.2, 15.5, 19.2 (separate DLP/egress evaluation).
