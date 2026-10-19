"""Deterministic test environment.

These environment values are set before any test module imports the application so the
module-level app (``ai_security.api.app``) always sees a valid test configuration even
when the developer's shell or a local ``.env`` file carries other values. Tests that
assert validation behavior construct ``Settings`` explicitly with ``_env_file=None``.

All key material here is deterministic, public test data — never a real credential.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable

import pytest

from ai_security.settings import Settings

TEST_DATABASE_URL = "postgresql+asyncpg://firewall:firewall_dev_only@127.0.0.1:5432/firewall_test"

# Deterministic public test keys: 32 bytes of 0x01 (and 0x02) are NOT the all-zero
# sample secret, so they are valid in every environment (blueprint section 5.4).
TEST_SECRET_B64 = base64.b64encode(b"\x01" * 32).decode()
TEST_SECRET_B64_ALT = base64.b64encode(b"\x02" * 32).decode()
TEST_HOST_AUTH_KEYS_JSON = json.dumps(
    {
        "test-key": {
            "secret_b64": TEST_SECRET_B64,
            "host_id": "test-host",
            "audience": "ai-agent-security-gateway",
            "allowed_tenants": ["test-tenant"],
        }
    }
)

os.environ["APP_ENV"] = "test"
os.environ["LOG_LEVEL"] = "WARNING"
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ["PRINCIPAL_RESOLVER"] = "dev"
os.environ["HOST_AUTH_KEYS_JSON"] = TEST_HOST_AUTH_KEYS_JSON


@pytest.fixture
def settings_factory() -> Callable[..., Settings]:
    """Build explicit ``Settings`` objects independent of the process environment.

    When the caller selects a non-development-like ``app_env``, environment-appropriate
    defaults are supplied for the security settings the caller did not override
    (``principal_resolver=host``; a non-sample key), mirroring how a real deployment
    must configure them. Explicit caller overrides are never rewritten.
    """

    def factory(**overrides: object) -> Settings:
        values: dict[str, object] = {
            "app_env": "test",
            "log_level": "WARNING",
            "database_url": TEST_DATABASE_URL,
            "principal_resolver": "dev",
            "host_auth_keys_json": TEST_HOST_AUTH_KEYS_JSON,
        }
        values.update(overrides)
        if values["app_env"] not in ("development", "test"):
            if "principal_resolver" not in overrides:
                values["principal_resolver"] = "host"
            if "host_auth_keys_json" not in overrides:
                values["host_auth_keys_json"] = TEST_HOST_AUTH_KEYS_JSON
        return Settings(_env_file=None, **values)

    return factory
