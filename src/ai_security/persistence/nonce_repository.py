"""Host-auth replay protection (blueprint section 9.2).

``register`` atomically records ``(key_id, nonce)``; an insert that conflicts with an
*unexpired* row means the nonce was already used inside the acceptance window — a
replay that MUST be rejected. A conflict with an *expired* row re-registers the nonce
(the window has passed). Any database failure surfaces as ``NonceRegistrationError``:
the caller must reject the request (fail closed).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .models import HostRequestNonce


class NonceRegistrationError(RuntimeError):
    """The nonce store could not record/verify the nonce; reject the request."""


class NonceRegistrar(Protocol):
    """Atomic replay-protection interface consumed by the API middleware."""

    async def register(self, *, key_id: str, nonce: str, ttl_seconds: int) -> bool:
        """True if the nonce is fresh; False if it was already used and is unexpired."""
        ...


class SqlAlchemyNonceRepository:
    """PostgreSQL implementation: one atomic insert per request."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def register(self, *, key_id: str, nonce: str, ttl_seconds: int) -> bool:
        expires_at = datetime.now(UTC) + timedelta(seconds=ttl_seconds)
        insert_statement = pg_insert(HostRequestNonce).values(
            key_id=key_id, nonce=nonce, expires_at=expires_at
        )
        statement = insert_statement.on_conflict_do_update(
            index_elements=[HostRequestNonce.key_id, HostRequestNonce.nonce],
            set_={"expires_at": insert_statement.excluded.expires_at},
            where=HostRequestNonce.expires_at < func.now(),
        ).returning(HostRequestNonce.key_id)
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    result = await session.execute(statement)
                    return result.first() is not None
        except (SQLAlchemyError, OSError) as exc:
            raise NonceRegistrationError(
                "nonce persistence failed; the request must be rejected (section 9.2)"
            ) from exc
