"""Policy domain: validated documents, safe YAML loading, and self-check fixtures.

- ``models.py`` — strict policy document models (``config/policies.yaml``,
  ``config/risk_thresholds.yaml``) and the ``PolicyBundle`` the engine evaluates.
- ``loader.py`` — the only sanctioned YAML entry point (safe loading, duplicate-key
  rejection, strict validation, content hashes).
- ``self_checks.py`` — ADR-007 fixtures loaded from ``config/policy_self_checks.yaml``
  and evaluated against the real engine at startup and on every readiness probe.

The deterministic engine itself lives in ``ai_security.firewall.policy_engine``
(blueprint section 4 layout); it never performs I/O and consults only the loaded bundle.
"""
