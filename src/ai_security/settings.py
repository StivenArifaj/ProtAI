"""Application settings with fail-closed validation.

Phase 0a scope: ``APP_ENV``, ``LOG_LEVEL``, and ``DATABASE_URL`` only. The remaining
variables from blueprint section 5.4 (host-auth keys, principal resolver, model
provider, request bounds) are introduced in Phase 0b together with the controls that
consume them, so this module never pretends to validate configuration it does not use.

Validation rules enforced here:

- ``APP_ENV`` is required and must be one of the known environments; unknown values
  fail startup instead of silently defaulting.
- ``DATABASE_URL`` must use the ``postgresql+asyncpg://`` scheme (ADR-005).
- The sample development database password is refused outside ``development``/``test``
  (blueprint section 5.4: "Add a check that refuses the development secret in
  non-development environments").
"""

from __future__ import annotations

from enum import StrEnum
from urllib.parse import unquote, urlsplit

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DATABASE_URL_REQUIRED_PREFIX = "postgresql+asyncpg://"
# Publicly documented sample value; the validator below refuses it outside dev/test.
SAMPLE_DATABASE_PASSWORD = "firewall_dev_only"  # noqa: S105


class AppEnv(StrEnum):
    """Deployment environment. Unknown values are rejected by validation."""

    development = "development"
    test = "test"
    staging = "staging"
    production = "production"

    @property
    def documentation_enabled(self) -> bool:
        """FastAPI docs/OpenAPI are exposed only in these environments (blueprint 18.2)."""
        return self in (AppEnv.development, AppEnv.test)


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseSettings):
    """Validated runtime configuration loaded from environment variables/.env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_env: AppEnv
    log_level: LogLevel = LogLevel.INFO
    database_url: SecretStr

    @field_validator("database_url")
    @classmethod
    def _require_asyncpg_scheme(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if not raw.startswith(DATABASE_URL_REQUIRED_PREFIX):
            raise ValueError(
                "DATABASE_URL must use the postgresql+asyncpg:// scheme (ADR-005); "
                "other drivers are not part of the v1 stack"
            )
        return value

    @model_validator(mode="after")
    def _refuse_sample_database_password_outside_dev(self) -> Settings:
        if self.app_env in (AppEnv.development, AppEnv.test):
            return self
        password = urlsplit(self.database_url.get_secret_value()).password
        if password is not None and unquote(password) == SAMPLE_DATABASE_PASSWORD:
            raise ValueError(
                "refusing the sample development database password outside "
                "development/test; generate real credentials (blueprint section 5.4)"
            )
        return self

    @property
    def database_dsn(self) -> str:
        """Raw DSN for the asyncpg driver, which does not understand SQLAlchemy schemes."""
        return self.database_url.get_secret_value().replace(
            DATABASE_URL_REQUIRED_PREFIX, "postgresql://", 1
        )
