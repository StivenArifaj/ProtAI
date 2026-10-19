# ADR-002: Postgres-serialized audit hash-chain append and canonical byte format

- **Status:** Accepted
- **Date:** 2026-10-19
- **Implementation:** Phase 7 (append protocol scaffolding in Phase 0b)

## Context

Audit integrity is an asset: if events can be silently modified or reordered, no
incident trail or evaluation result can be trusted. Concurrent appends that each read
the same previous hash would fork the chain.

## Decision

- Audit events form a hash chain per chain key with a monotonically increasing sequence
  number and a `prev_hash` link; the writer is append-only.
- Appends are serialized by PostgreSQL inside a single transaction (row lock/advisory
  lock per chain) so concurrent writers produce exactly one contiguous sequence. The
  lock protocol is fixed in Phase 0b scaffolding; the full chain is completed in
  Phase 7.
- The canonical byte format for hashing is fixed: deterministic JSON canonicalization
  (sorted keys, fixed separators, fixed number/unicode handling) with fixed test
  vectors, so hashes are stable across runs and machines.
- A verifier recomputes the chain and detects mutation, deletion gaps, and reordering.
- Raw private payloads and secrets are not included in default audit fields or logs
  (redaction by default; `AUDIT_RAW_CONTENT_MODE=never`).

## Consequences

- Appends serialize on a per-chain lock; throughput is bounded by write latency. This
  is acceptable for v1 scale and is documented rather than worked around.
- Any change to canonicalization is a breaking change to the verifier and requires an
  ADR update and vector refresh.

## References

Blueprint v1.2 sections 16, 20.2 (13, 19), 21 (Phase 7).
