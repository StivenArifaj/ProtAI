"""Application settings with fail-closed validation.

Implemented scope: ``APP_ENV``, ``LOG_LEVEL``, ``DATABASE_URL`` (Phase 0a) and the
Phase 0b security-foundation settings that actually have consumers: the principal
resolver selection, the host-authentication key configuration, timestamp tolerance and
nonce TTL, and the request-size bound. Later-phase variables (model provider, session
signals, audit raw-content mode) are introduced together with the controls that consume
them, so this module never pretends to validate configuration it does not use.

Validation rules enforced here:

- ``APP_ENV`` is required and must be one of the known environments; unknown values
  fail startup instead of silently defaulting.
- ``DATABASE_URL`` must use the ``postgresql+asyncpg://`` scheme (ADR-005).
- The sample development database password is refused outside ``development``/``test``
  (blueprint section 5.4).
- ``HOST_AUTH_KEYS_JSON`` is required: it must define at least one key whose record
  contains exactly ``secret_b64`` (strict Base64 of at least 32 random bytes),
  ``host_id``, ``audience``, and ``allowed_tenants``. The documented all-zero sample
  secret is refused outside ``development``/``test`` (blueprint sections 5.4, 9.2).
- ``PRINCIPAL_RESOLVER=dev`` is refused outside ``development``/``test`` (blueprint
  section 9.3, ADR-001).
- ``HOST_AUTH_NONCE_TTL_SECONDS`` must cover at least twice the timestamp tolerance so
  nonces outlive the full acceptance window plus skew margin (section 9.2).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from enum import StrEnum
from typing import Any
from urllib.parse import unquote, urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

DATABASE_URL_REQUIRED_PREFIX = "postgresql+asyncpg://"
# Publicly documented sample values; the validators below refuse them outside dev/test.
SAMPLE_DATABASE_PASSWORD = "firewall_dev_only"  # noqa: S105
SAMPLE_HOST_AUTH_SECRET_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="  # noqa: S105
SAMPLE_HOST_AUTH_SECRET_BYTES = b"\x00" * 32

HOST_AUTH_SECRET_MIN_BYTES = 32
CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,128}")


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

    @property
    def development_like(self) -> bool:
        """Environments where conspicuously development-only adapters may exist."""
        return self in (AppEnv.development, AppEnv.test)


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class PrincipalResolverKind(StrEnum):
    """Which principal adapter the gateway may construct (blueprint section 9.1-9.3).

    ``dev`` is the conspicuously development-only test adapter; it is refused outside
    development/test. ``host`` is the declared production integration point: the
    principal is derived from the HMAC-verified host assertion. The host resolver's
    typed-assertion handling arrives with the typed contracts in Phase 1; it fails
    closed until then instead of resolving an unverified principal.
    """

    dev = "dev"
    host = "host"


class HostAuthKey(BaseModel):
    """One ``HOST_AUTH_KEYS_JSON`` record (blueprint section 5.4; exactly these fields)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    secret_b64: SecretStr
    host_id: str = Field(min_length=1, max_length=256)
    audience: str = Field(min_length=1, max_length=256)
    allowed_tenants: list[str]

    @field_validator("secret_b64")
    @classmethod
    def _strict_base64_min_32_bytes(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        try:
            decoded = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("secret_b64 must be strict Base64 encoding") from exc
        if len(decoded) < HOST_AUTH_SECRET_MIN_BYTES:
            raise ValueError(
                f"secret_b64 must decode to at least {HOST_AUTH_SECRET_MIN_BYTES} bytes "
                "of cryptographically random data (section 5.4)"
            )
        return value

    @field_validator("host_id", "audience")
    @classmethod
    def _no_control_characters(cls, value: str) -> str:
        if CONTROL_CHARACTERS.search(value):
            raise ValueError("must not contain control characters")
        return value

    @field_validator("allowed_tenants")
    @classmethod
    def _tenant_ids_are_clean(cls, value: list[str]) -> list[str]:
        for tenant in value:
            if not tenant or CONTROL_CHARACTERS.search(tenant):
                raise ValueError("allowed_tenants entries must be non-empty and control-free")
        return value

    @property
    def secret_bytes(self) -> bytes:
        """Raw secret bytes for HMAC computation (never logged, never serialized)."""
        return base64.b64decode(self.secret_b64.get_secret_value(), validate=True)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key id {key!r}")
        result[key] = value
    return result


def parse_host_auth_keys(raw_json: str) -> dict[str, HostAuthKey]:
    """Parse and validate ``HOST_AUTH_KEYS_JSON`` into key-id -> record.

    The full configuration is validated here; any malformed record fails startup
    instead of being skipped or coerced.
    """
    try:
        data = json.loads(raw_json, object_pairs_hook=_reject_duplicate_json_keys)
    except ValueError as exc:
        raise ValueError(f"HOST_AUTH_KEYS_JSON is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not data:
        raise ValueError("HOST_AUTH_KEYS_JSON must be a JSON object with at least one key id")
    keys: dict[str, HostAuthKey] = {}
    for key_id, record in data.items():
        if KEY_ID_PATTERN.fullmatch(key_id) is None:
            raise ValueError(
                f"HOST_AUTH_KEYS_JSON key id {key_id!r} is malformed; allowed: "
                "1-128 characters of [A-Za-z0-9._-]"
            )
        try:
            keys[key_id] = HostAuthKey.model_validate(record)
        except ValueError as exc:
            raise ValueError(f"HOST_AUTH_KEYS_JSON record {key_id!r} is invalid: {exc}") from exc
    return keys


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

    principal_resolver: PrincipalResolverKind = PrincipalResolverKind.dev
    host_auth_keys_json: SecretStr
    host_auth_timestamp_tolerance_seconds: int = Field(default=60, gt=0)
    host_auth_nonce_ttl_seconds: int = Field(default=300, gt=0)
    request_max_bytes: int = Field(default=65536, gt=0)
    policy_self_checks_path: str = Field(default="config/policy_self_checks.yaml", min_length=1)

    _host_auth_keys: dict[str, HostAuthKey] = PrivateAttr(default_factory=dict)

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
        if self.app_env.development_like:
            return self
        password = urlsplit(self.database_url.get_secret_value()).password
        if password is not None and unquote(password) == SAMPLE_DATABASE_PASSWORD:
            raise ValueError(
                "refusing the sample development database password outside "
                "development/test; generate real credentials (blueprint section 5.4)"
            )
        return self

    @model_validator(mode="after")
    def _validate_host_auth_configuration(self) -> Settings:
        keys = parse_host_auth_keys(self.host_auth_keys_json.get_secret_value())
        if not self.app_env.development_like:
            for key_id, record in keys.items():
                if record.secret_bytes == SAMPLE_HOST_AUTH_SECRET_BYTES:
                    raise ValueError(
                        f"refusing the sample all-zero host-auth secret for key {key_id!r} "
                        "outside development/test; generate a real secret (blueprint section 5.4)"
                    )
        self._host_auth_keys = keys
        return self

    @model_validator(mode="after")
    def _refuse_dev_resolver_outside_dev(self) -> Settings:
        if (
            self.principal_resolver is PrincipalResolverKind.dev
            and not self.app_env.development_like
        ):
            raise ValueError(
                "PRINCIPAL_RESOLVER=dev is refused outside development/test "
                "(blueprint section 9.3, ADR-001)"
            )
        return self

    @model_validator(mode="after")
    def _nonce_ttl_covers_acceptance_window(self) -> Settings:
        if self.host_auth_nonce_ttl_seconds < 2 * self.host_auth_timestamp_tolerance_seconds:
            raise ValueError(
                "HOST_AUTH_NONCE_TTL_SECONDS must be at least twice "
                "HOST_AUTH_TIMESTAMP_TOLERANCE_SECONDS so nonces outlive the full "
                "acceptance window plus skew margin (blueprint section 9.2)"
            )
        return self

    @property
    def host_auth_keys(self) -> dict[str, HostAuthKey]:
        """Validated host-auth key records, keyed by key id."""
        return self._host_auth_keys

    @property
    def database_dsn(self) -> str:
        """Raw DSN for direct asyncpg use (SQLAlchemy uses ``database_url``)."""
        return self.database_url.get_secret_value().replace(
            DATABASE_URL_REQUIRED_PREFIX, "postgresql://", 1
        )
