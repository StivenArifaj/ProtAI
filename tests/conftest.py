"""Deterministic test environment.

These environment values are set before any test module imports the application so the
module-level app (``ai_security.api.app``) always sees a valid test configuration even
when the developer's shell or a local ``.env`` file carries other values. Tests that
assert validation behavior construct ``Settings`` explicitly with ``_env_file=None``.
"""

from __future__ import annotations

import os
from collections.abc import Callable

import pytest

from ai_security.settings import Settings

TEST_DATABASE_URL = "postgresql+asyncpg://firewall:firewall_dev_only@127.0.0.1:5432/firewall_test"

os.environ["APP_ENV"] = "test"
os.environ["LOG_LEVEL"] = "WARNING"
os.environ["DATABASE_URL"] = TEST_DATABASE_URL


@pytest.fixture
def settings_factory() -> Callable[..., Settings]:
    """Build explicit ``Settings`` objects independent of the process environment."""

    def factory(**overrides: object) -> Settings:
        values: dict[str, object] = {
            "app_env": "test",
            "log_level": "WARNING",
            "database_url": TEST_DATABASE_URL,
        }
        values.update(overrides)
        return Settings(_env_file=None, **values)

    return factory
