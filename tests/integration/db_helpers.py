"""Helpers for integration tests that exercise the persistence layer directly.

Each scenario creates its own engine (``NullPool``) inside the test's single event loop
and disposes it within the same loop — no pooled connections ever outlive a test, so
tests stay independent of each other and of loop scoping.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool


@dataclass
class DatabaseHarness:
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]

    @classmethod
    def open(cls, url: str, **engine_kwargs: Any) -> DatabaseHarness:
        engine = create_async_engine(url, poolclass=NullPool, **engine_kwargs)
        return cls(
            engine=engine,
            session_factory=async_sessionmaker(engine, expire_on_commit=False),
        )

    async def dispose(self) -> None:
        await self.engine.dispose()
