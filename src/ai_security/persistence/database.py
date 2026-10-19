"""Async engine/session construction (blueprint ADR-005).

One ``Database`` instance is built per application process from validated settings; it
owns the engine and the async session factory. Nothing here opens a connection at
construction time, so the app factory stays side-effect free.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ai_security.settings import Settings

logger = logging.getLogger(__name__)

# Bound on establishing a connection (readiness probes must not hang); applies to the
# TCP connect only, not to query execution.
CONNECT_TIMEOUT_SECONDS = 2.0


@dataclass
class Database:
    """Engine + async session factory bound to one configured database."""

    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]

    @classmethod
    def from_settings(cls, settings: Settings) -> Database:
        connect_args: dict[str, Any] = {"timeout": CONNECT_TIMEOUT_SECONDS}
        engine = create_async_engine(
            settings.database_url.get_secret_value(),
            pool_pre_ping=True,
            connect_args=connect_args,
        )
        return cls(
            engine=engine,
            session_factory=async_sessionmaker(engine, expire_on_commit=False),
        )

    async def dispose(self) -> None:
        """Release pooled connections (application shutdown)."""
        await self.engine.dispose()

    async def healthy(self) -> bool:
        """Readiness probe: a live ``SELECT 1``. Never raises, never logs secrets."""
        try:
            async with self.engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
            return True
        except Exception as exc:  # fail closed for readiness; probe must not raise
            logger.debug("readiness database probe failed: %s", type(exc).__name__)
            return False
