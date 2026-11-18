"""Security analytics / AI SOC package (blueprint section 17; ADR-004, ADR-017).

This package implements Phase 10 alerting and optional read-only audit summarization.
It is **read-only and alert-only**: deterministic alert rules observe existing audit
evidence and may emit ``SECURITY_ALERT_RAISED`` events through the normal audit
recorder. Alerts are evidence/notification only — no rule may block, allow, consume an
approval, revoke a session, edit policy, or trigger containment. The optional
summarizer is an unverified hypothesis generator with no tool/policy/audit/approval
access; its output is labeled ``EXTERNAL_UNTRUSTED`` and can at most annotate an alert.

No component in this package imports or calls adapters, the policy engine, the
gateway, or any external model provider. It is intentionally authority-free.
"""

from __future__ import annotations

from ai_security.soc.config import (
    AlertRule,
    AlertRuleConfig,
    AlertRuleFiring,
    AlertSeverity,
    load_alert_config,
)
from ai_security.soc.emitter import AlertEmission, AlertEmitter, content_free_evidence
from ai_security.soc.rules import (
    AlertRuleEvaluator,
    EvaluationContext,
    evaluate_rules,
)

__all__ = [
    "AlertEmitter",
    "AlertEmission",
    "AlertRule",
    "AlertRuleConfig",
    "AlertRuleEvaluator",
    "AlertRuleFiring",
    "AlertSeverity",
    "EvaluationContext",
    "content_free_evidence",
    "evaluate_rules",
    "load_alert_config",
]
