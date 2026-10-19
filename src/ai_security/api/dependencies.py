"""Shared FastAPI dependencies.

The settings accessor, the readiness database probe, and the readiness policy
self-check probe. Both probes are exposed as dependencies so tests can override them
without a live database or fixture file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import Depends, Request

from ai_security.persistence.database import Database
from ai_security.policy.self_checks import policy_self_checks_pass
from ai_security.settings import Settings


def get_settings(request: Request) -> Settings:
    """Return the validated settings bound to this application instance."""
    settings: Settings = request.app.state.settings
    return settings


def get_database(request: Request) -> Database:
    """Return the persistence layer bound to this application instance."""
    database: Database = request.app.state.database
    return database


async def database_ready(database: Annotated[Database, Depends(get_database)]) -> bool:
    """Readiness dependency: overridable in tests per blueprint section 20.1."""
    return await database.healthy()


async def policy_self_checks_ok(settings: Annotated[Settings, Depends(get_settings)]) -> bool:
    """Readiness dependency: re-evaluates the ADR-007 fixtures on every probe."""
    return policy_self_checks_pass(Path(settings.policy_self_checks_path))
