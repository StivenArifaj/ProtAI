"""Policy scaffolding (Phase 0b): deterministic self-check fixtures for the v1
decision matrix (ADR-007).

The real policy engine (blueprint sections 10.4-10.5) arrives in Phase 1. For Phase 0b,
``interim_matrix`` provides an honest, documented transcription of the v1 matrix from
``docs/POLICY_DECISION_MATRIX.md`` that is sufficient to evaluate the self-check
fixtures from ``config/policy_self_checks.yaml``; ``self_checks`` loads those fixtures,
runs them, and reports mismatches. Phase 1 replaces the interim evaluator with the real
engine while keeping the fixture contract.
"""
