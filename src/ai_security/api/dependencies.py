"""Shared FastAPI dependencies.

The settings accessor and the readiness database probe. The probe goes through the
process-wide ``Database`` layer (SQLAlchemy async + asyncpg, ADR-005) and is exposed as
a dependency so tests can override it without a live database.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from ai_security.persistence.database import Database
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
