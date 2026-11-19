"""Mount the console API onto the FastAPI app (additive; disabled by default).

The console is wired only when ``CONSOLE_ENABLED=true``. It never changes v1 behavior:
no new execution path, no host-HMAC exposure, no authority granted to the browser.
"""

from __future__ import annotations

import json
from typing import Any, cast

from fastapi import FastAPI

from ai_security.console.auth import ConsoleRole, LocalAuthProvider, SessionStore, hash_password
from ai_security.console.logs import LogReader
from ai_security.console.routes import router as console_router
from ai_security.console.service import ConsoleService
from ai_security.settings import Settings
from ai_security.soc.config import AlertRuleConfig
from ai_security.soc.connector_framework import ConnectorRegistry
from ai_security.soc.external_checkpoint import ExternalAuditCheckpointer
from ai_security.soc.summarizer import AuditSummarizer

SAMPLE_CONSOLE_PASSWORD = "CONSOLE_DEV_ONLY_PASSWORD"  # noqa: S105 - documented sample


class MemoryCheckpointSink:
    """Process-local checkpoint sink (documented: not durable across restarts)."""

    async def write(self, payload: bytes, *, sequence: int) -> None:
        self.last_payload = payload
        self.last_sequence = sequence

    async def read_latest(self) -> bytes | None:
        return getattr(self, "last_payload", None)


def load_alert_config_from_file(path: str) -> AlertRuleConfig:
    """Load the strict alert config; missing/invalid config fails closed to no rules."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return AlertRuleConfig(version="unconfigured", rules=())
    return AlertRuleConfig.model_validate(data)


def mount_console(app: FastAPI, settings: Settings) -> None:
    """Attach console state and routes. Idempotent per app instance."""
    if getattr(app.state, "console_mounted", False):
        return

    username = settings.console_admin_username
    # The configured value is plaintext (dev sample or operator secret); only the
    # PBKDF2 hash is retained in memory.
    password_hash = hash_password(settings.console_admin_password.get_secret_value())
    users: dict[str, tuple[str, ConsoleRole, str | None]] = {
        username: (password_hash, ConsoleRole.admin, None),
    }
    # Three additional demo actors, each with the documented sample password.
    for name, role in (
        ("analyst", ConsoleRole.analyst),
        ("approver", ConsoleRole.approver),
        ("operator", ConsoleRole.operator),
    ):
        users[name] = (hash_password(SAMPLE_CONSOLE_PASSWORD), role, None)

    provider = LocalAuthProvider(users)
    app.state.console_auth_provider = provider
    app.state.console_user_records = users
    app.state.console_sessions = SessionStore()

    sink = MemoryCheckpointSink()
    app.state.audit_checkpointer = ExternalAuditCheckpointer(
        seal_key=b"console-local-seal-key-change-me-32bytes",
        sink=sink,
    )
    app.state.connector_registry = ConnectorRegistry()
    app.state.soc_summarizer = AuditSummarizer(enabled=False)

    app.state.alert_config = load_alert_config_from_file(settings.alert_rules_path)

    # Hook a revocation service if the post-v1 foundation is available.
    try:
        from ai_security.soc.approval_lifecycle import ApprovalRevocationService

        repository = getattr(app.state, "approval_repository", None)
        recorder = getattr(app.state, "audit_recorder", None)
        if repository is not None and recorder is not None:
            app.state.approval_revocation_service = ApprovalRevocationService(
                repository=cast(Any, repository),
                recorder=cast(Any, recorder),
                sink=None,
            )
        else:
            app.state.approval_revocation_service = None
    except Exception:  # noqa: BLE001 - optional foundation
        app.state.approval_revocation_service = None

    app.state.console_service = ConsoleService(
        session_factory=app.state.database.session_factory,
        app_state=app.state,
        checkpoint_sink=sink,
    )
    app.state.log_reader = LogReader(
        app.state.database.session_factory,
        runtime_log_path=settings.console_runtime_log_path or None,
    )
    app.include_router(console_router)
    app.state.console_mounted = True


__all__ = ["MemoryCheckpointSink", "mount_console"]
