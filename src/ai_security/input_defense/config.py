"""Versioned, strict input-defense configuration (blueprint section 7.2).

The document is loaded once at startup; invalid, unreadable, non-UTF-8, duplicate-key,
or incomplete configuration refuses startup (fail closed). Dispositions are exhaustive:
every ``FindingCode`` must be mapped, and no code may map to ``PASS`` — a detector
failure or an intake violation must never be silently treated as clean.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ai_security.security.safe_yaml import SafeYamlError, parse_unique_yaml

from .models import Disposition, FindingCode

CONTENT_TYPE_PATTERN = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
CONFIG_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class InputDefenseConfigError(RuntimeError):
    """The input-defense configuration is missing, malformed, or unsafe (fail closed)."""


class InputDefenseLimits(BaseModel):
    """Bounded intake limits (blueprint section 7.2 step 1)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_bytes: int = Field(ge=1, le=1_048_576, strict=True)
    max_json_depth: int = Field(ge=1, le=128, strict=True)
    evaluation_timeout_ms: int = Field(ge=1, le=10_000, strict=True)


class InputDefenseConfig(BaseModel):
    """Complete input-defense policy: limits, content types, dispositions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(ge=1, strict=True)
    version: str = Field(min_length=1, max_length=128)
    limits: InputDefenseLimits
    content_types: tuple[str, ...] = Field(min_length=1, max_length=32)
    dispositions: dict[FindingCode, Disposition]

    @field_validator("version")
    @classmethod
    def _stable_version(cls, value: str) -> str:
        if not CONFIG_VERSION_PATTERN.fullmatch(value):
            raise ValueError("version must be a stable identifier (letters/digits/._-)")
        return value

    @field_validator("content_types")
    @classmethod
    def _normalized_content_types(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        for raw in value:
            base = raw.strip().lower()
            if not CONTENT_TYPE_PATTERN.fullmatch(base):
                raise ValueError(f"invalid content type {raw!r}")
            if base in normalized:
                raise ValueError(f"duplicate content type {base!r}")
            normalized.append(base)
        return tuple(normalized)

    @field_validator("dispositions")
    @classmethod
    def _exhaustive_non_pass(
        cls, value: dict[FindingCode, Disposition]
    ) -> dict[FindingCode, Disposition]:
        missing = sorted(set(FindingCode) - set(value))
        if missing:
            raise ValueError(
                "dispositions must cover every finding code; missing: "
                + ", ".join(code.value for code in missing)
            )
        for code, disposition in value.items():
            if disposition is Disposition.pass_:
                raise ValueError(
                    f"finding code {code.value} must not map to PASS; a fired finding "
                    "or detector failure can never be treated as clean"
                )
        return value

    def base_content_type(self, declared: str) -> str | None:
        """Return the normalized base type if allowlisted, else ``None``."""
        base = declared.split(";", 1)[0].strip().lower()
        return base if base in self.content_types else None


class LoadedInputDefenseConfig(BaseModel):
    """Configuration plus the SHA-256 of the exact file bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    config: InputDefenseConfig
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def load_input_defense_config(path: str | Path) -> LoadedInputDefenseConfig:
    """Load ``config/input_defense.yaml``; any problem refuses startup."""
    config_path = Path(path)
    try:
        raw = config_path.read_bytes()
    except OSError as exc:
        raise InputDefenseConfigError(
            f"input-defense config {config_path} cannot be read: {exc}"
        ) from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputDefenseConfigError(
            f"input-defense config {config_path} is not valid UTF-8"
        ) from exc
    try:
        data = parse_unique_yaml(text)
    except SafeYamlError as exc:
        raise InputDefenseConfigError(f"input-defense config {config_path}: {exc}") from exc
    try:
        config = InputDefenseConfig.model_validate(data)
    except ValidationError as exc:
        raise InputDefenseConfigError(
            f"input-defense config {config_path} failed strict validation: "
            f"{exc.error_count()} error(s)"
        ) from exc
    return LoadedInputDefenseConfig(config=config, sha256=hashlib.sha256(raw).hexdigest())
