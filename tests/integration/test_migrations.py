"""Alembic baseline tests (ADR-006).

The session fixture already applied the baseline (``upgrade head``) to the test
database; this test re-runs the documented command to prove idempotency: exit 0, no
new upgrade applied, and the database reports exactly the head revision.
"""

from __future__ import annotations

import os
import subprocess
import sys

from conftest import REPO_ROOT


def run_alembic(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv: sys.executable + literal arguments
        [sys.executable, "-m", "alembic", *arguments],
        cwd=REPO_ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        check=False,
    )


def test_upgrade_head_is_idempotent(migrated_database: str) -> None:
    second_run = run_alembic("upgrade", "head")
    assert second_run.returncode == 0, second_run.stderr
    combined = second_run.stderr + second_run.stdout
    assert "Running upgrade" not in combined

    current = run_alembic("current")
    assert current.returncode == 0, current.stderr
    assert "(head)" in current.stdout
