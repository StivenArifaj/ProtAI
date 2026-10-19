"""Shared FastAPI dependencies.

Phase 0a provides only the settings accessor and the readiness database probe. The
probe is a dependency so tests can override it without a live database; the real probe
uses asyncpg directly because SQLAlchemy persistence arrives in Phase 0b (ADR-005).
"""

from __future__ import annotations

import contextlib
import logging
from typing import Annotated

import asyncpg
from fastapi import Depends, Request

from ai_security.settings import Settings

logger = logging.getLogger(__name__)

READINESS_CONNECT_TIMEOUT_SECONDS = 2.0


def get_settings(request: Request) -> Settings:
    """Return the validated settings bound to this application instance."""
    settings: Settings = request.app.state.settings
    return settings


async def check_database(settings: Settings) -> bool:
    """Return True only if a live ``SELECT 1`` succeeds. Never raises, never logs secrets."""
    try:
        connection = await asyncpg.connect(
            dsn=settings.database_dsn,
            timeout=READINESS_CONNECT_TIMEOUT_SECONDS,
            command_timeout=READINESS_CONNECT_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        logger.debug("readiness database probe failed: %s", type(exc).__name__)
        return False
    try:
        await connection.fetchval("SELECT 1")
        return True
    except Exception as exc:
        logger.debug("readiness database query failed: %s", type(exc).__name__)
        return False
    finally:
        with contextlib.suppress(Exception):
            await connection.close()


async def database_ready(settings: Annotated[Settings, Depends(get_settings)]) -> bool:
    """Readiness dependency: overridable in tests per blueprint section 20.1."""
    return await check_database(settings)
