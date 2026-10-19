"""Settings validation tests (blueprint sections 5.1, 5.4, 18.2)."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from ai_security.settings import SAMPLE_DATABASE_PASSWORD, Settings

REAL_LOOKING_URL = "postgresql+asyncpg://firewall:correct-horse-battery@db:5432/firewall"


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "app_env": "development",
        "log_level": "INFO",
        "database_url": REAL_LOOKING_URL,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_valid_development_settings_construct() -> None:
    settings = make_settings()
    assert settings.app_env.value == "development"
    assert settings.log_level.value == "INFO"


def test_log_level_defaults_to_info(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    settings = Settings(_env_file=None, app_env="development", database_url=REAL_LOOKING_URL)
    assert settings.log_level.value == "INFO"


def test_app_env_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_ENV", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, database_url=REAL_LOOKING_URL)


def test_database_url_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="development")


def test_unknown_app_env_fails_startup() -> None:
    with pytest.raises(ValidationError):
        make_settings(app_env="prod")


def test_unknown_log_level_fails_startup() -> None:
    with pytest.raises(ValidationError):
        make_settings(log_level="VERBOSE")


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://firewall:x@db:5432/firewall",
        "postgresql+psycopg://firewall:x@db:5432/firewall",
        "mysql://firewall:x@db:3306/firewall",
    ],
)
def test_non_asyncpg_scheme_is_rejected(url: str) -> None:
    with pytest.raises(ValidationError, match="postgresql\\+asyncpg://"):
        make_settings(database_url=url)


@pytest.mark.parametrize("env", ["staging", "production"])
def test_sample_database_password_refused_outside_dev_test(env: str) -> None:
    sample_url = f"postgresql+asyncpg://firewall:{SAMPLE_DATABASE_PASSWORD}@db:5432/firewall"
    with pytest.raises(ValidationError, match="sample development database password"):
        make_settings(app_env=env, database_url=sample_url)


@pytest.mark.parametrize("env", ["development", "test"])
def test_sample_database_password_allowed_in_dev_test(env: str) -> None:
    sample_url = f"postgresql+asyncpg://firewall:{SAMPLE_DATABASE_PASSWORD}@db:5432/firewall"
    settings = make_settings(app_env=env, database_url=sample_url)
    assert settings.app_env.value == env


def test_database_dsn_strips_sqlalchemy_scheme() -> None:
    settings = make_settings()
    assert settings.database_dsn == ("postgresql://firewall:correct-horse-battery@db:5432/firewall")


def test_credentials_do_not_appear_in_repr_or_str() -> None:
    settings = make_settings()
    for rendered in (repr(settings), str(settings)):
        assert "correct-horse-battery" not in rendered
        assert "correct-horse" not in rendered
    assert "correct-horse-battery" not in str(settings.database_url)


def test_documentation_flag_matches_environment() -> None:
    for env in ("development", "test"):
        assert make_settings(app_env=env).app_env.documentation_enabled is True
    for env in ("staging", "production"):
        assert (
            make_settings(app_env=env, database_url=REAL_LOOKING_URL).app_env.documentation_enabled
            is False
        )


def test_settings_factory_fixture_is_valid(settings_factory: Callable[..., Settings]) -> None:
    settings = settings_factory()
    assert settings.app_env.value == "test"
