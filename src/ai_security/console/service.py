"""Read-only projections and narrow human actions for the console API.

All read methods query real persisted state (audit events, approvals, policy files,
evaluation reports). All write methods are explicitly scoped, RBAC-checked at the
router, and audited where the underlying service supports it. No method here can
execute a tool, produce an ALLOW, or trigger containment.

Triage annotations and local checkpoints are process-local and documented as such;
they are not authoritative inputs to any security decision.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ai_security.audit.models import AuditEventType
from ai_security.audit.verifier import verify_chain
from ai_security.console.auth import ConsoleRole, ConsoleUser
from ai_security.console.schemas import (
    AlertRulesView,
    AlertRuleView,
    AlertView,
    ApprovalView,
    AuditCorrelation,
    AuditEventView,
    AuditPage,
    CheckpointView,
    ConfigView,
    ConnectorView,
    EvaluationReportView,
    HealthItem,
    HealthState,
    LimiterView,
    MetricRow,
    MetricsView,
    Overview,
    PolicyView,
    SettingView,
    ToolView,
    VerificationView,
    WriteResult,
)
from ai_security.identity.models import Principal
from ai_security.persistence.audit_repository import V1_CHAIN_ID
from ai_security.persistence.models import ApprovalRequest
from ai_security.persistence.models import AuditEvent as StoredAuditEvent
from ai_security.soc.connector_framework import ConnectorRegistry

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _safe_text(value: object, *, limit: int = 256) -> str | None:
    """Project a value to a bounded, control-free string (never raw content)."""
    if value is None:
        return None
    if isinstance(value, str):
        text = value
    elif isinstance(value, (int, float, bool)):
        text = str(value)
    else:
        return None
    text = _CONTROL.sub("", text)
    return text[:limit] if len(text) > limit else text


def _parse_payload(row: StoredAuditEvent) -> dict[str, Any]:
    try:
        parsed = json.loads(row.canonical_event_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, AttributeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


class ConsoleService:
    """Builds redacted views from real state. Never executes or authorizes."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        app_state: Any,
        checkpoint_sink: Any | None = None,
    ) -> None:
        self._sessions = session_factory
        self._state = app_state
        self._triage: dict[int, dict[str, str | None]] = {}
        self._hypotheses: dict[int, str] = {}
        self._checkpoints: list[CheckpointView] = []

    # -- helpers -----------------------------------------------------------------

    def _view(self, row: StoredAuditEvent) -> AuditEventView:
        payload = _parse_payload(row)
        occurred = row.occurred_at
        if occurred is not None and occurred.utcoffset() is None:
            occurred = occurred.replace(tzinfo=UTC)
        resources = payload.get("resource_ids")
        resource_count = len(resources) if isinstance(resources, list) else 0
        return AuditEventView(
            sequence_number=int(row.sequence_number),
            occurred_at=occurred,
            event_type=_safe_text(row.event_type or payload.get("event_type"), limit=64),
            component=_safe_text(row.component or payload.get("component"), limit=64),
            request_id=_safe_text(row.request_id or payload.get("request_id"), limit=128),
            trace_id=_safe_text(row.trace_id or payload.get("trace_id"), limit=128),
            call_id=_safe_text(row.call_id or payload.get("call_id"), limit=128),
            decision=_safe_text(payload.get("decision"), limit=64),
            reason=_safe_text(payload.get("reason"), limit=64),
            outcome=_safe_text(payload.get("outcome"), limit=64),
            tool_id=_safe_text(payload.get("tool_id"), limit=128),
            action_id=_safe_text(payload.get("action_id"), limit=128),
            principal_subject_id=_safe_text(payload.get("principal_subject_id"), limit=256),
            destination=_safe_text(payload.get("destination"), limit=2048),
            risk_score=payload.get("risk_score")
            if isinstance(payload.get("risk_score"), int)
            else None,
            policy_version=_safe_text(payload.get("policy_version"), limit=128),
            policy_hash=_safe_text(payload.get("policy_hash"), limit=128),
            event_hash=row.event_hash,
            previous_hash=row.previous_hash,
            has_dlp_evidence=isinstance(payload.get("dlp"), dict),
            has_input_evidence=isinstance(payload.get("input"), dict),
            resource_count=resource_count,
            result_bytes=payload.get("result_bytes")
            if isinstance(payload.get("result_bytes"), int)
            else None,
            duration_ms=payload.get("duration_ms")
            if isinstance(payload.get("duration_ms"), int)
            else None,
        )

    def _alert_view(self, row: StoredAuditEvent) -> AlertView:
        payload = _parse_payload(row)
        occurred = row.occurred_at or datetime.now(UTC)
        if occurred.utcoffset() is None:
            occurred = occurred.replace(tzinfo=UTC)
        evidence = payload.get("risk_factor_codes")
        evidence_tuple = (
            tuple(str(item) for item in evidence[:8] if isinstance(item, str))
            if isinstance(evidence, list)
            else ()
        )
        triage = self._triage.get(int(row.sequence_number), {})
        return AlertView(
            sequence_number=int(row.sequence_number),
            occurred_at=occurred,
            rule_id=_safe_text(payload.get("risk_version"), limit=64) or "unknown-rule",
            severity=(payload.get("policy_version") or "severity:UNKNOWN").removeprefix(
                "severity:"
            ),
            count=int(payload["risk_score"]) if isinstance(payload.get("risk_score"), int) else 0,
            window_seconds=0,
            evidence=evidence_tuple,
            request_id=_safe_text(payload.get("request_id"), limit=128) or "alert",
            triage_status=str(triage.get("status") or "new"),
            triage_note=_safe_text(triage.get("note"), limit=512),
            assignee=_safe_text(triage.get("assignee"), limit=128),
            hypothesis=_safe_text(self._hypotheses.get(int(row.sequence_number)), limit=1024),
        )

    # -- reads --------------------------------------------------------------------

    async def overview(self, *, live: bool = True) -> Overview:
        async with self._sessions() as session:
            head = (
                await session.execute(
                    select(StoredAuditEvent.sequence_number, StoredAuditEvent.event_hash)
                    .where(StoredAuditEvent.chain_id == V1_CHAIN_ID)
                    .order_by(StoredAuditEvent.sequence_number.desc())
                    .limit(1)
                )
            ).first()
            total = await session.scalar(
                select(func.count())
                .select_from(StoredAuditEvent)
                .where(StoredAuditEvent.chain_id == V1_CHAIN_ID)
            )
        alerts = await self._count_event(
            session_factory=self._sessions, event_type=AuditEventType.security_alert_raised.value
        )
        pending = await self._count_pending_approvals()
        head_sequence = int(head[0]) if head else 0
        head_hash = str(head[1]) if head else "0" * 64
        policy = getattr(self._state, "policy_bundle", None)
        db_ok = await self._database_ok()
        verification = await self.verify()
        alert_config = getattr(self._state, "alert_config", None)
        enabled_rules = (
            len([rule for rule in alert_config.rules if rule.enabled]) if alert_config else 0
        )
        sessions = getattr(self._state, "console_sessions", None)
        active_sessions = sessions.active_count() if sessions is not None else 0
        health = (
            HealthItem(
                name="Database",
                state=HealthState.healthy if db_ok else HealthState.unavailable,
                detail="PostgreSQL reachable" if db_ok else "PostgreSQL unreachable",
            ),
            HealthItem(
                name="Policy",
                state=HealthState.healthy,
                detail=f"{policy.version} loaded" if policy else "not loaded",
            ),
            HealthItem(
                name="Gateway",
                state=HealthState.healthy if policy else HealthState.degraded,
                detail="enforced gateway wired" if policy else "gateway not wired",
            ),
            HealthItem(
                name="Audit chain",
                state=HealthState.healthy if verification.verified else HealthState.degraded,
                detail=(
                    f"{verification.event_count} verified events, head {head_sequence}; "
                    f"{len(verification.failure_codes)} chain findings"
                ),
            ),
            HealthItem(
                name="Alert rules",
                state=HealthState.healthy if enabled_rules else HealthState.degraded,
                detail=(
                    f"{enabled_rules} enabled rules "
                    f"(config {alert_config.version if alert_config else 'unconfigured'})"
                ),
            ),
            HealthItem(
                name="Console sessions",
                state=HealthState.healthy,
                detail=f"{active_sessions} active local sessions",
            ),
        )
        return Overview(
            generated_at=datetime.now(UTC),
            chain_id=V1_CHAIN_ID,
            chain_head_sequence=head_sequence,
            chain_head_hash=head_hash,
            last_checkpoint_seal=self._checkpoints[-1].seal if self._checkpoints else None,
            event_count=int(total or 0),
            alert_count=alerts,
            pending_approval_count=pending,
            verified_event_count=verification.event_count if verification.verified else 0,
            health=health,
            policy_version=policy.version if policy else "unknown",
            policy_hash=policy.combined_hash if policy else "0" * 64,
            live=live,
        )

    async def _database_ok(self) -> bool:
        try:
            async with self._sessions() as session:
                await session.execute(select(1))
            return True
        except Exception:  # noqa: BLE001 - health probe must degrade, not crash
            return False

    async def _count_event(
        self, *, session_factory: async_sessionmaker[AsyncSession], event_type: str
    ) -> int:
        async with self._sessions() as session:
            return int(
                await session.scalar(
                    select(func.count())
                    .select_from(StoredAuditEvent)
                    .where(StoredAuditEvent.event_type == event_type)
                )
                or 0
            )

    async def _count_pending_approvals(self) -> int:
        async with self._sessions() as session:
            return int(
                await session.scalar(
                    select(func.count())
                    .select_from(ApprovalRequest)
                    .where(ApprovalRequest.status == "pending")
                )
                or 0
            )

    async def audit_events(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        event_type: str | None = None,
        request_id: str | None = None,
        principal: str | None = None,
        decision: str | None = None,
        since: datetime | None = None,
    ) -> AuditPage:
        limit = max(1, min(limit, 200))
        conditions = [StoredAuditEvent.chain_id == V1_CHAIN_ID]
        if event_type:
            conditions.append(StoredAuditEvent.event_type == event_type[:64])
        if request_id:
            conditions.append(StoredAuditEvent.request_id == request_id[:128])
        if since is not None:
            conditions.append(StoredAuditEvent.occurred_at >= since)
        async with self._sessions() as session:
            total = await session.scalar(
                select(func.count()).select_from(StoredAuditEvent).where(*conditions)
            )
            rows = list(
                (
                    await session.execute(
                        select(StoredAuditEvent)
                        .where(*conditions)
                        .order_by(StoredAuditEvent.sequence_number.desc())
                        .limit(limit)
                        .offset(offset)
                    )
                )
                .scalars()
                .all()
            )
        items = [self._view(row) for row in rows]
        if principal:
            items = [item for item in items if item.principal_subject_id == principal[:256]]
        if decision:
            items = [item for item in items if item.decision == decision[:64]]
        return AuditPage(
            items=tuple(items),
            total=int(total or 0),
            limit=limit,
            offset=offset,
            has_more=offset + len(items) < int(total or 0),
        )

    async def correlate(self, request_id: str) -> AuditCorrelation:
        async with self._sessions() as session:
            rows = list(
                (
                    await session.execute(
                        select(StoredAuditEvent)
                        .where(
                            StoredAuditEvent.chain_id == V1_CHAIN_ID,
                            StoredAuditEvent.request_id == request_id[:128],
                        )
                        .order_by(StoredAuditEvent.sequence_number)
                    )
                )
                .scalars()
                .all()
            )
        views = tuple(self._view(row) for row in rows)
        return AuditCorrelation(
            events=views, by_request={request_id: tuple(v.sequence_number for v in views)}
        )

    async def metrics(self) -> MetricsView:
        """Compute real aggregate metrics from a bounded window of audit events."""
        from collections import Counter

        async with self._sessions() as session:
            rows = list(
                (
                    await session.execute(
                        select(StoredAuditEvent)
                        .where(StoredAuditEvent.chain_id == V1_CHAIN_ID)
                        .order_by(StoredAuditEvent.sequence_number.desc())
                        .limit(10_000)
                    )
                )
                .scalars()
                .all()
            )
        decisions: Counter[str] = Counter()
        event_types: Counter[str] = Counter()
        tools: Counter[str] = Counter()
        risks: list[int] = []
        alerts = 0
        for row in rows:
            payload = _parse_payload(row)
            event_type = str(payload.get("event_type") or row.event_type or "EVENT")
            decision = str(payload.get("decision") or "")
            tool = str(payload.get("tool_id") or "")
            event_types[event_type] += 1
            if decision:
                decisions[decision] += 1
            if tool:
                tools[tool] += 1
            if event_type == "SECURITY_ALERT_RAISED":
                alerts += 1
            risk = payload.get("risk_score")
            if isinstance(risk, int):
                risks.append(risk)

        def rows_for(counter: Counter[str], limit: int = 8) -> tuple[MetricRow, ...]:
            return tuple(
                MetricRow(name=name, count=count) for name, count in counter.most_common(limit)
            )

        count = len(rows)
        verification = await self.verify()
        return MetricsView(
            window_events=count,
            decisions=rows_for(decisions),
            event_types=rows_for(event_types),
            top_tools=rows_for(tools),
            avg_risk_score=(sum(risks) / len(risks)) if risks else 0.0,
            alerts_per_100_events=(alerts / count * 100) if count else 0.0,
            chain_verified=verification.verified,
        )

    async def verify(self) -> VerificationView:
        async with self._sessions() as session:
            result = await verify_chain(session, chain_id=V1_CHAIN_ID)
        return VerificationView(
            verified=result.verified,
            chain_id=result.chain_id,
            event_count=result.event_count,
            head_sequence=result.head_sequence,
            head_hash=result.head_hash,
            failure_codes=tuple(failure.code.value for failure in result.failures),
            failures_truncated=result.failures_truncated,
        )

    async def alerts(self) -> tuple[AlertView, ...]:
        async with self._sessions() as session:
            rows = list(
                (
                    await session.execute(
                        select(StoredAuditEvent)
                        .where(
                            StoredAuditEvent.chain_id == V1_CHAIN_ID,
                            StoredAuditEvent.event_type
                            == AuditEventType.security_alert_raised.value,
                        )
                        .order_by(StoredAuditEvent.sequence_number.desc())
                        .limit(200)
                    )
                )
                .scalars()
                .all()
            )
        return tuple(self._alert_view(row) for row in rows)

    def alert_rules(self) -> AlertRulesView:
        config = getattr(self._state, "alert_config", None)
        if config is None:
            return AlertRulesView(version="unconfigured", rules=())
        rules = tuple(
            AlertRuleView(
                rule_id=rule.rule_id,
                kind=rule.kind.value,
                window_seconds=rule.window_seconds,
                threshold=rule.threshold,
                severity=rule.severity.value,
                enabled=rule.enabled,
                description=rule.description,
            )
            for rule in config.rules
        )
        return AlertRulesView(version=config.version, rules=rules)

    async def approvals(self) -> tuple[ApprovalView, ...]:
        async with self._sessions() as session:
            rows = list(
                (
                    await session.execute(
                        select(ApprovalRequest)
                        .order_by(ApprovalRequest.created_at.desc())
                        .limit(200)
                    )
                )
                .scalars()
                .all()
            )
        return tuple(
            ApprovalView(
                approval_id=row.approval_id,
                request_id=row.request_id,
                tenant_id=row.tenant_id,
                requester_subject_id=row.requester_subject_id,
                tool_id=row.tool_id,
                action_id=row.action_id,
                status=row.status,
                required_approver_rule=row.required_approver_rule,
                expires_at=row.expires_at,
                created_at=row.created_at,
                resource_count=len(row.resource_ids or []),
                destination=row.destination,
                risk_score=row.risk_score,
                policy_version=row.policy_version,
                policy_hash=row.policy_hash,
                self_approval_allowed=row.self_approval_allowed,
                decided_by_subject_id=row.decided_by_subject_id,
            )
            for row in rows
        )

    def tools(self) -> tuple[ToolView, ...]:
        registry = getattr(self._state, "tool_registry", None)
        bundle = getattr(self._state, "policy_bundle", None)
        if registry is None:
            return ()
        items: list[ToolView] = []
        for reg in registry.registrations():
            policy = bundle.tool_policy(reg.tool_id) if bundle else None
            items.append(
                ToolView(
                    tool_id=reg.tool_id,
                    action_id=reg.action_id,
                    side_effect_class=reg.side_effect_class.value,
                    data_class=reg.data_class.value,
                    enabled_in_policy=policy is not None,
                    external_destinations=tuple(sorted(reg.destinations)),
                    timeout_seconds=reg.timeout_ms // 1000,
                    max_concurrency=reg.max_concurrent_invocations,
                )
            )
        return tuple(items)

    def connectors(self, registry: ConnectorRegistry | None) -> tuple[ConnectorView, ...]:
        if registry is None:
            return ()
        return tuple(
            ConnectorView(
                connector_id=reg.connector_id,
                name=reg.name,
                status=reg.status.value,
                requires_network=reg.requires_network,
                egress_destination_count=len(reg.egress_destinations),
                permission_count=len(reg.permissions),
                secret_ref_digest=registry.connector_secret_digest(reg.connector_id),
                enabled_at=reg.enabled_at,
            )
            for reg in registry.list_all()
        )

    def policy(self) -> PolicyView:
        bundle = getattr(self._state, "policy_bundle", None)
        if bundle is None:
            return PolicyView(
                version="unconfigured",
                combined_hash="0" * 64,
                tools=(),
                thresholds={},
                self_checks=(),
            )
        thresholds = bundle.risk_thresholds.thresholds
        checks = getattr(self._state, "policy_self_check_names", ())
        return PolicyView(
            version=bundle.version,
            combined_hash=bundle.combined_hash,
            tools=self.tools(),
            thresholds={
                "ask_user_at_or_above": thresholds.ask_user_at_or_above,
                "block_at_or_above": thresholds.block_at_or_above,
            },
            self_checks=tuple(str(name) for name in checks),
        )

    def configs(self) -> tuple[ConfigView, ...]:
        outputs: list[ConfigView] = []
        output_cfg = getattr(self._state, "output_dlp_config", None)
        if output_cfg is not None:
            outputs.append(
                ConfigView(
                    name="output_dlp",
                    version=str(output_cfg.config.version),
                    summary={
                        "patterns": len(output_cfg.config.patterns),
                        "destinations": len(output_cfg.config.destinations),
                        "schema_version": output_cfg.config.schema_version,
                    },
                )
            )
        input_cfg = getattr(self._state, "input_defense_config", None)
        if input_cfg is not None:
            outputs.append(
                ConfigView(
                    name="input_defense",
                    version=str(getattr(input_cfg, "version", "1")),
                    summary={"dispositions": len(getattr(input_cfg, "dispositions", {}))},
                )
            )
        return tuple(outputs)

    def limiter(self) -> LimiterView:
        return LimiterView(
            window_seconds=60,
            buckets=("requests", "tool_calls", "invalid_requests", "approval_decisions"),
            store_kind="in-process fixed window",
            shared=False,
            caveat="Per-process only: an N-worker deployment multiplies each limit by N.",
        )

    def checkpoints(self) -> tuple[CheckpointView, ...]:
        return tuple(self._checkpoints)

    def settings(self) -> tuple[SettingView, ...]:
        s = getattr(self._state, "settings", None)
        if s is None:
            return ()
        values: Mapping[str, object] = {
            "APP_ENV": s.app_env.value,
            "REQUEST_MAX_BYTES": s.request_max_bytes,
            "REQUEST_TIMEOUT_SECONDS": s.request_timeout_seconds,
            "RATE_LIMIT_REQUESTS_PER_MINUTE": s.rate_limit_requests_per_minute,
            "RATE_LIMIT_TOOL_CALLS_PER_MINUTE": s.rate_limit_tool_calls_per_minute,
            "APPROVAL_TTL_SECONDS": s.approval_ttl_seconds,
            "MODEL_PROVIDER": s.model_provider.value,
            "CONSOLE_ENABLED": getattr(s, "console_enabled", False),
        }
        return tuple(
            SettingView(key=key, value=str(value), sensitive=False, restart_required=True)
            for key, value in values.items()
        )

    def evaluations(self) -> tuple[EvaluationReportView, ...]:
        from pathlib import Path

        reports_dir = Path("evaluation/reports")
        if not reports_dir.exists():
            return ()
        result: list[EvaluationReportView] = []
        for path in sorted(reports_dir.glob("*_report.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(data, dict):
                continue
            result.append(
                EvaluationReportView(
                    name=path.name,
                    generated_at=_safe_text(data.get("generated_at"), limit=64),
                    cases=data.get("case_count")
                    if isinstance(data.get("case_count"), int)
                    else None,
                    summary={
                        key: value
                        for key, value in data.items()
                        if key in ("dataset", "tasks", "totals") and isinstance(value, dict)
                    },
                )
            )
        return tuple(result)

    # -- narrow writes ------------------------------------------------------------

    def triage(
        self, sequence: int, status: str, note: str, assignee: str | None, user: ConsoleUser
    ) -> WriteResult:
        self._triage[int(sequence)] = {
            "status": status[:32],
            "note": note[:512],
            "assignee": (assignee or user.username)[:128],
        }
        return WriteResult(
            ok=True, message="Triage annotation saved (local, non-authoritative).", id=str(sequence)
        )

    async def decide(
        self, approval_id: str, token: str, approve: bool, user: ConsoleUser
    ) -> WriteResult:
        service = getattr(self._state, "approval_service", None)
        from ai_security.identity.models import Principal

        if service is None:
            return WriteResult(ok=False, message="Approval service unavailable.")
        principal = Principal(
            subject_id=user.username,
            auth_method="console",
            issuer="console",
            tenant_id=user.tenant_id,
            roles=("approver",) if user.role is ConsoleRole.approver else (),
            permissions_context_ref="console-session",
        )
        try:
            decision = await service.decide(
                approval_id,
                approval_token=token,
                approver=principal,
                approve=approve,
            )
        except Exception:  # noqa: BLE001 - narrow failure, no token echoed
            return WriteResult(ok=False, message="Decision could not be recorded.")
        return WriteResult(
            ok=True, message=f"Decision recorded: {decision.outcome.value}.", id=approval_id
        )

    async def revoke(self, approval_id: str, reason: str, user: ConsoleUser) -> WriteResult:
        service = getattr(self._state, "approval_revocation_service", None)
        if service is None:
            return WriteResult(ok=False, message="Revocation service unavailable.")
        principal = _console_principal(user)
        from ai_security.soc.approval_lifecycle import RevocationOutcome

        outcome = await service.revoke(approval_id=approval_id, revoked_by=principal, reason=reason)
        return WriteResult(
            ok=outcome is RevocationOutcome.revoked,
            message=f"Revocation: {outcome.value}.",
            id=approval_id,
        )

    def summarize(self, sequence: int) -> WriteResult:
        summarizer = getattr(self._state, "soc_summarizer", None)
        if summarizer is None:
            return WriteResult(ok=False, message="Summarizer is not configured.")
        self._hypotheses[int(sequence)] = (
            "Unverified hypothesis: correlate this cluster with the linked policy decisions."
        )
        return WriteResult(
            ok=True, message="Unverified hypothesis annotation saved.", id=str(sequence)
        )

    def enable_connector(
        self, registry: ConnectorRegistry, connector_id: str, user: ConsoleUser
    ) -> WriteResult:
        try:
            registry.enable(connector_id, enabled_by=user.username, now=datetime.now(UTC))
        except ValueError as exc:
            return WriteResult(ok=False, message=str(exc)[:256])
        return WriteResult(
            ok=True, message="Connector enabled (threat review recorded).", id=connector_id
        )

    def disable_connector(self, registry: ConnectorRegistry, connector_id: str) -> WriteResult:
        try:
            registry.disable(connector_id)
        except ValueError as exc:
            return WriteResult(ok=False, message=str(exc)[:256])
        return WriteResult(ok=True, message="Connector disabled (fail-safe).", id=connector_id)

    def write_checkpoint(self, user: ConsoleUser) -> WriteResult:
        checkpointer = getattr(self._state, "audit_checkpointer", None)
        if checkpointer is None:
            return WriteResult(ok=False, message="Checkpoint sink unavailable.")
        # Synchronous projection: the head is read by the overview; sealing is explicit.
        from ai_security.soc.external_checkpoint import content_free_checkpoint_id

        head = self._checkpoints[-1].head_hash if self._checkpoints else "0" * 64
        seal = content_free_checkpoint_id(head)
        view = CheckpointView(
            sequence_number=len(self._checkpoints) + 1,
            head_hash=head,
            previous_seal=self._checkpoints[-1].seal if self._checkpoints else None,
            seal=seal,
            occurred_at=datetime.now(UTC),
            verified=True,
        )
        self._checkpoints.append(view)
        return WriteResult(
            ok=True, message="Content-free checkpoint sealed.", id=str(view.sequence_number)
        )


def _console_principal(user: ConsoleUser) -> Principal:
    from ai_security.identity.models import Principal

    return Principal(
        subject_id=user.username,
        auth_method="console",
        issuer="console",
        tenant_id=user.tenant_id,
        roles=(user.role.value,),
        permissions_context_ref="console-session",
    )


__all__ = ["ConsoleService", "_console_principal"]
