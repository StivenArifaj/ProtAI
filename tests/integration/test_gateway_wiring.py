"""App wiring for the Phase 2 gateway (blueprint section 21).

``create_app`` must build the registry only when every policy-declared tool has a
compatible adapter; otherwise startup refuses (fail closed). The resulting registry and
gateway are available on ``app.state`` as the single execution path.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from ai_security.api.app import create_app
from ai_security.audit.writer import ChainAuditRecorder
from ai_security.firewall.approval import ApprovalService
from ai_security.firewall.gateway import ToolGateway
from ai_security.settings import Settings
from ai_security.tools.registry import ToolRegistry, ToolRegistryConfigError

SettingsFactory = Callable[..., Settings]
REPO_POLICIES = Path("config/policies.yaml")


def test_create_app_builds_registry_and_gateway(
    settings_factory: SettingsFactory, migrated_database: str
) -> None:
    app = create_app(settings_factory())
    registry = app.state.tool_registry
    gateway = app.state.tool_gateway
    assert isinstance(registry, ToolRegistry)
    assert isinstance(gateway, ToolGateway)
    assert gateway._registry is registry  # noqa: SLF001 - wiring identity check
    assert isinstance(gateway._recorder, ChainAuditRecorder)  # noqa: SLF001 - wiring check
    approval_service = app.state.approval_service
    assert isinstance(approval_service, ApprovalService)
    assert gateway._approval_service is approval_service  # noqa: SLF001 - wiring check
    assert registry.resolve("mock_email.read", "read") is not None
    assert registry.resolve("mock_files.search", "search") is not None
    assert registry.resolve("mock_email.delete", "delete") is None


def test_startup_refuses_a_policy_tool_without_an_adapter(
    settings_factory: SettingsFactory, tmp_path: Path
) -> None:
    policy = tmp_path / "policies.yaml"
    policy.write_text(
        REPO_POLICIES.read_text(encoding="utf-8")
        + "\n  mock_unknown.run:\n    side_effect_class: READ_ONLY\n",
        encoding="utf-8",
    )
    with pytest.raises(ToolRegistryConfigError):
        create_app(settings_factory(policy_path=str(policy)))
