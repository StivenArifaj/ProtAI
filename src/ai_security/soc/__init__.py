"""Security analytics / AI SOC package (blueprint section 17; ADR-004, ADR-017).

This package implements Phase 10 alerting and optional read-only audit summarization.
It is **read-only and alert-only**: deterministic alert rules observe existing audit
evidence and may emit ``SECURITY_ALERT_RAISED`` events through the normal audit
recorder. Alerts are evidence/notification only — no rule may block, allow, consume an
approval, revoke a session, edit policy, or trigger containment. The optional
summarizer is an unverified hypothesis generator with no tool/policy/audit/approval
access; its output is labeled ``EXTERNAL_UNTRUSTED`` and can at most annotate an alert.

Phase 10 foundations (post-v1 additive) are also in this package:

- ``distributed_rate_limiter`` — shared-store rate limiting across workers
- ``external_checkpoint`` — externally anchored audit-chain checkpoints
- ``approval_lifecycle`` — approval revocation and resumption (chain-approval)
- ``connector_framework`` — interface and registration contract for real company
  connectors (email, files, databases, SaaS); real connectors are NOT implemented here

No component in this package imports or calls adapters, the policy engine, the
gateway, or any external model provider. It is intentionally authority-free.
"""

from __future__ import annotations

from ai_security.soc.approval_lifecycle import (
    APPROVAL_STATUS_RESUMED,
    APPROVAL_STATUS_REVOKED,
    ApprovalResumptionService,
    ApprovalRevocationService,
    ResumptionOutcome,
    RevocationOutcome,
    RevocationRecord,
)
from ai_security.soc.config import (
    AlertRule,
    AlertRuleConfig,
    AlertRuleFiring,
    AlertSeverity,
    load_alert_config,
)
from ai_security.soc.connector_framework import (
    Connector,
    ConnectorContext,
    ConnectorPermission,
    ConnectorRegistration,
    ConnectorRegistry,
    ConnectorResult,
    ConnectorSideEffect,
    ConnectorStatus,
)
from ai_security.soc.distributed_rate_limiter import (
    DEFAULT_MAX_ENTRIES,
    DEFAULT_WINDOW_SECONDS,
    DistributedRateLimiter,
    RateLimitDecision,
    RateLimiterStore,
    RedisRateLimiterStore,
)
from ai_security.soc.emitter import AlertEmission, AlertEmitter, content_free_evidence
from ai_security.soc.external_checkpoint import (
    Checkpoint,
    CheckpointRecord,
    CheckpointSink,
    ExternalAuditCheckpointer,
    content_free_checkpoint_id,
)
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
    "ApprovalResumptionService",
    "ApprovalRevocationService",
    "APPROVAL_STATUS_RESUMED",
    "APPROVAL_STATUS_REVOKED",
    "Checkpoint",
    "CheckpointRecord",
    "CheckpointSink",
    "Connector",
    "ConnectorContext",
    "ConnectorPermission",
    "ConnectorRegistration",
    "ConnectorRegistry",
    "ConnectorResult",
    "ConnectorSideEffect",
    "ConnectorStatus",
    "content_free_checkpoint_id",
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_WINDOW_SECONDS",
    "DistributedRateLimiter",
    "EvaluationContext",
    "ExternalAuditCheckpointer",
    "RateLimiterStore",
    "RateLimitDecision",
    "RedisRateLimiterStore",
    "ResumptionOutcome",
    "RevocationOutcome",
    "RevocationRecord",
    "content_free_evidence",
    "content_free_checkpoint_id",
    "evaluate_rules",
    "load_alert_config",
]
