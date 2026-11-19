"""Unified read-only log projection for the console log viewer.

Combines two sources into one streaming-style view:
1. The audit chain (authoritative security events) — each event becomes a structured
   log line with service, severity and a content-free message.
2. An optional operator-configured runtime log file (uvicorn / application stdout).

No source is mutated. No raw audit payload, secret or token is returned: audit lines are
built only from the same redacted projections used by Audit Explorer.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ai_security.console.schemas import LogEntry, LogServiceCount
from ai_security.persistence.audit_repository import V1_CHAIN_ID
from ai_security.persistence.models import AuditEvent as StoredAuditEvent

_LEVEL_BY_EVENT = {
    "PRINCIPAL_REJECTED": "WARN",
    "INPUT_INSPECTED": "INFO",
    "POLICY_EVALUATED": "INFO",
    "APPROVAL_REQUESTED": "NOTICE",
    "APPROVAL_DECIDED": "INFO",
    "APPROVAL_CONSUMED": "INFO",
    "APPROVAL_EXPIRED": "WARN",
    "TOOL_EXECUTION_FAILED": "ERROR",
    "RESPONSE_SUPPRESSED": "WARN",
    "SECURITY_ALERT_RAISED": "ALERT",
}
_LEVEL_BY_DECISION = {"BLOCK": "WARN", "DENIED": "WARN", "ALLOW": "INFO", "ASK_USER": "NOTICE"}

_LOG_LINE = re.compile(
    r"^(?P<time>\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d)"
    r".*?(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL|WARN|NOTICE|ALERT)?.*$"
)


@dataclass(frozen=True)
class LogQuery:
    service: str = ""
    level: str = ""
    query: str = ""
    limit: int = 200


def _event_service(component: str | None) -> str:
    if not component:
        return "audit"
    if component.startswith("firewall."):
        return "gateway"
    if component.startswith("api."):
        return "api"
    if component.startswith("intent."):
        return "intent"
    if component.startswith("soc."):
        return "soc"
    return component.replace(".service", "").split(".")[0]


def _event_level(payload: dict[str, Any], event_type: str) -> str:
    decision = str(payload.get("decision") or "")
    level = _LEVEL_BY_DECISION.get(decision)
    if level is not None:
        return level
    return _LEVEL_BY_EVENT.get(event_type, "INFO")


def _event_message(payload: dict[str, Any], event_type: str) -> str:
    parts = [event_type]
    for key in ("decision", "reason", "outcome", "tool_id", "action_id"):
        value = payload.get(key)
        if isinstance(value, str) and value and len(value) <= 128:
            parts.append(f"{key}={value}")
    request_id = payload.get("request_id")
    if isinstance(request_id, str) and request_id:
        parts.append(f"request={request_id[:20]}")
    return " ".join(parts)


def _runtime_entries(path: str | None) -> list[LogEntry]:
    if not path:
        return []
    log_path = Path(path)
    if not log_path.exists():
        return []
    entries: list[LogEntry] = []
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for index, line in enumerate(lines[-1000:]):
        match = _LOG_LINE.match(line)
        level = match.group("level") if match and match.group("level") else "INFO"
        if "ERROR" in line or "Exception" in line:
            level = "ERROR"
        elif "WARNING" in line or "WARN" in line:
            level = "WARN"
        timestamp: datetime | None = None
        if match:
            try:
                timestamp = datetime.fromisoformat(match.group("time").replace(" ", "T"))
                if timestamp.utcoffset() is None:
                    timestamp = timestamp.replace(tzinfo=UTC)
            except ValueError:
                timestamp = None
        message = line[:500]
        # Never surface a key even if an operator configured a verbose logger.
        if "sk-" in message or "Bearer " in message:
            message = re.sub(r"Bearer\s+\S+", "Bearer [REDACTED]", message)
            message = re.sub(r"sk-[A-Za-z0-9._-]+", "[REDACTED]", message)
        entries.append(
            LogEntry(
                id=f"run-{index}",
                occurred_at=timestamp,
                service="runtime",
                level=level,
                message=message,
                source="runtime",
                sequence_number=None,
            )
        )
    return entries


class LogReader:
    """Reads unified logs from the audit chain and optional runtime log file."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        runtime_log_path: str | None = None,
    ) -> None:
        self._sessions = session_factory
        self._runtime_log_path = runtime_log_path

    async def read(self, query: LogQuery) -> tuple[list[LogEntry], dict[str, int]]:
        entries: list[LogEntry] = []
        limit = max(1, min(query.limit, 1000))

        async with self._sessions() as session:
            rows = list(
                (
                    await session.execute(
                        select(StoredAuditEvent)
                        .where(StoredAuditEvent.chain_id == V1_CHAIN_ID)
                        .order_by(StoredAuditEvent.sequence_number.desc())
                        .limit(limit * 4)
                    )
                )
                .scalars()
                .all()
            )
        for row in rows:
            try:
                payload = json.loads(row.canonical_event_bytes.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, AttributeError):
                continue
            if not isinstance(payload, dict):
                continue
            event_type = str(payload.get("event_type") or row.event_type or "EVENT")
            occurred = row.occurred_at
            if occurred is not None and occurred.utcoffset() is None:
                occurred = occurred.replace(tzinfo=UTC)
            entries.append(
                LogEntry(
                    id=f"audit-{row.sequence_number}",
                    occurred_at=occurred,
                    service=_event_service(row.component or str(payload.get("component") or "")),
                    level=_event_level(payload, event_type),
                    message=_event_message(payload, event_type),
                    source="audit",
                    sequence_number=int(row.sequence_number),
                )
            )

        entries.extend(_runtime_entries(self._runtime_log_path))

        needle = query.query.lower()
        filtered = [
            entry
            for entry in entries
            if (not query.service or entry.service == query.service)
            and (not query.level or entry.level == query.level)
            and (not needle or needle in entry.message.lower())
        ]
        filtered.sort(
            key=lambda item: (
                item.occurred_at is not None,
                item.occurred_at or datetime.min.replace(tzinfo=UTC),
            ),
            reverse=True,
        )

        services: dict[str, int] = {}
        for entry in filtered:
            services[entry.service] = services.get(entry.service, 0) + 1
        return filtered[:limit], services

    async def service_counts(self) -> list[LogServiceCount]:
        async with self._sessions() as session:
            rows = list(
                await session.execute(
                    select(StoredAuditEvent.component, func.count())
                    .where(StoredAuditEvent.chain_id == V1_CHAIN_ID)
                    .group_by(StoredAuditEvent.component)
                )
            )
        counts: dict[str, int] = {}
        for component, count in rows:
            service = _event_service(str(component or ""))
            counts[service] = counts.get(service, 0) + int(count)
        if self._runtime_log_path and Path(self._runtime_log_path).exists():
            counts["runtime"] = len(_runtime_entries(self._runtime_log_path))
        return [
            LogServiceCount(service=name, count=count)
            for name, count in sorted(counts.items(), key=lambda item: -item[1])
        ]


__all__ = ["LogQuery", "LogReader", "_runtime_entries", "_event_service"]
