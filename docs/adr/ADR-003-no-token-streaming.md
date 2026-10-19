# ADR-003: v1 token streaming disabled — buffer, inspect, then release

- **Status:** Accepted
- **Date:** 2026-10-19
- **Implementation:** enforced from Phase 6/8 (no streaming route exists before then)

## Context

Streaming a model or tool response releases bytes to the caller before output DLP and
release policy have seen the complete content. Once bytes leave, a later block cannot
recall them; streaming and complete-output inspection are mutually exclusive for the
same response.

## Decision

- v1 never streams tokens or chunks to clients. Responses are buffered fully, inspected
  end-to-end by output DLP/egress policy, and only then released or suppressed in full
  (blueprint section 15.1).
- Oversized or DLP-blocked outputs are fully suppressed, not partially released.
- If a future version adds streaming, it requires a new ADR describing how inspection
  guarantees are preserved (e.g., protocol-level buffering with explicit trust
  boundaries); the default remains non-streaming.

## Consequences

- Higher time-to-first-byte on long outputs; accepted for correctness.
- Clients cannot rely on incremental delivery in v1; API contracts should document
  complete-response semantics.

## References

Blueprint v1.2 sections 15.1, 18.2, 20.2 (21).
