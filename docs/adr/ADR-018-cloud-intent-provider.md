# ADR-018: Opt-in cloud intent provider

**Status:** Accepted
**Date:** 2026-11-18
**Implementation phase:** post-v1 (additive, opt-in)

## Context

ADR-015 established a deterministic mock extractor and an optional local
Ollama-compatible provider. Operators with a cloud LLM key asked to use it for intent
extraction instead. v1 deliberately refuses `ALLOW_EXTERNAL_MODEL_CALLS=true` because no
cloud adapter existed and model output must never become an authority.

## Decision

Add `MODEL_PROVIDER=cloud` as an explicit opt-in, implemented by
`OpenAIChatIntentModelClient` in `src/ai_security/intent/cloud_provider.py`:

1. **Explicit selection.** `MODEL_PROVIDER=cloud` requires `CLOUD_MODEL_API_KEY`,
   `CLOUD_MODEL_NAME` (exact model), and a validated `CLOUD_MODEL_BASE_URL`. No key, no
   cloud calls — the default remains the offline mock.
2. **Validated transport.** HTTPS origin required outside development/test (loopback
   allowed there), no credentials/query/fragment/path in the origin, fixed
   `/chat/completions` path, no redirects, no environment proxy trust, bounded timeout
   and response size.
3. **Key handling.** The key is sent only in an `Authorization: Bearer` header. It is
   never logged, returned in an error, stored, or exposed to the console. Non-200 and
   network errors are generic typed failures.
4. **Untrusted output.** The response envelope is duplicate-key-checked, bounded, and
   parsed to a plain string. It goes through the existing `LocalModelIntentExtractor`,
   which validates it into advisory constraints. The system prompt is fixed; all
   user/tool text is passed in the user message, never concatenated into instructions.
5. **No authority.** Model output cannot produce `ALLOW`, skip policy, change approvals,
   or write audit. Failures yield no manifest and no execution (`503 model_unavailable`).

`ALLOW_EXTERNAL_MODEL_CALLS=true` remains refused: that flag was a v1 placeholder with
no adapter; the cloud provider is selected only by `MODEL_PROVIDER=cloud`.

## Consequences

- Positive: real LLM intent extraction is available without weakening any invariant;
  all existing strict validation and the gateway remain authoritative.
- Negative: cloud calls introduce cost, latency, and a data-egress consideration. The
  operator is responsible for the provider contract and for reviewing what request text
  is sent. Network I/O occurs only when this provider is explicitly selected.
- `npm`/Python dependencies are unchanged (the existing `httpx2` client is reused).

## Verification

- 16 unit tests (parsing, bounded output, key header, non-200/key-leak, settings)
- End-to-end against a local OpenAI-compatible fake endpoint: `MODEL_PROVIDER=cloud`
  produced `COMPLETED` for the supported request and `REQUIRES_CLARIFICATION` (no
  execution) for an out-of-scope request.

## Opt-in fallback (2026-11-18)

`CLOUD_FALLBACK_TO_MOCK=true` wraps the cloud extractor with
`FallbackIntentExtractor`: on a typed `IntentExtractorUnavailable` (quota, outage,
malformed response) it falls back to the deterministic offline mock. This is opt-in
and advisory-only — the gateway and policy still enforce every action. Without it, a
cloud failure yields `503 model_unavailable` and no execution (fail closed).
