"""Integration-test database fixtures.

The suite expects the local development PostgreSQL (``docker compose up -d db``) with a
dedicated ``firewall_test`` database — never the application database. The test database
is created if missing and migrated with the real Alembic chain (production uses the
same chain; tests never call ``create_all`` for schema the application relies on). If
PostgreSQL is unreachable, database-dependent fixtures skip with a clear reason instead
of failing tests for unrelated reasons.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _asyncpg_admin_dsn(database_url: str) -> str:
    """The test database's server, but pointed at the ``postgres`` maintenance DB."""
    plain = database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
    parts = urlsplit(plain)
    return urlunsplit(("postgresql", parts.netloc, "/postgres", "", ""))


async def _ensure_test_database(database_url: str) -> None:
    plain = database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
    database_name = urlsplit(plain).path.lstrip("/")
    connection = await asyncpg.connect(_asyncpg_admin_dsn(database_url), timeout=2)
    try:
        exists = await connection.fetchval(
            "SELECT 1 FROM pg_database WHERE datname = $1", database_name
        )
        if not exists:
            await connection.execute(f'CREATE DATABASE "{database_name}"')
    finally:
        await connection.close()


def _run_alembic(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv: sys.executable + literal arguments
        [sys.executable, "-m", "alembic", *arguments],
        cwd=REPO_ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture(scope="session")
def migrated_database() -> str:
    """The migrated ``firewall_test`` database URL, or skip if PostgreSQL is unreachable."""
    database_url = os.environ["DATABASE_URL"]
    try:
        asyncio.run(_ensure_test_database(database_url))
    except (OSError, TimeoutError, asyncpg.PostgresError) as exc:
        pytest.skip(
            "PostgreSQL test database is not reachable "
            f"({type(exc).__name__}); start it with `docker compose up -d db`"
        )
    result = _run_alembic("upgrade", "head")
    assert result.returncode == 0, f"alembic upgrade head failed:\n{result.stderr}"
    return database_url
