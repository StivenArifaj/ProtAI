"""Firewall domain: the deterministic authorization path (blueprint sections 10-13).

Phase 1 provides the decision contract (``decision.py``) and the policy engine
(``policy_engine.py``); the gateway, action validator, risk engine, and approvals arrive
in later phases. Nothing in this package performs I/O or calls an LLM.
"""
