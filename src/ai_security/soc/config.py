"""Versioned, strict alert-rule configuration (blueprint section 17.1).

Alert rules are deterministic, auditable, and configurable. Each rule has a stable ID,
a bounded observation window, a threshold, and a severity. Rules read existing audit
evidence only; they never authorize, block, consume, revoke, or contain.

The configuration file is validated at load time (fail closed on invalid config). All
thresholds and windows are bounded so an attacker cannot craft a configuration that
exhausts memory or CPU by observing a huge audit window or an enormous threshold.

Alert emission is content-free: emitted ``SECURITY_ALERT_RAISED`` events carry rule id,
severity, count, window, and a content-free evidence summary — never raw audit text,
user content, tool output, or exception messages.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

#: Stable rule identifiers — renamed or removed rules are a breaking change.
_RULE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
#: Evidence summary tokens are short, control-free, content-free codes.
_EVIDENCE_TOKEN_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

# Bounds (blueprint 17.1: thresholds are configurable and tested; bounded to avoid
# resource exhaustion from attacker-influenced configuration).
_MIN_WINDOW_SECONDS = 60
_MAX_WINDOW_SECONDS = 86_400  # 24 hours
_MIN_THRESHOLD = 1
_MAX_THRESHOLD = 10_000
_MAX_RULES = 128
_MAX_CONFIG_VERSION_LEN = 64


class AlertSeverity(StrEnum):
    """Stable alert severity levels."""

    low = "LOW"
    medium = "MEDIUM"
    high = "HIGH"
    critical = "CRITICAL"


class AlertRuleKind(StrEnum):
    """Deterministic alert-rule kinds implemented in Phase 10."""

    repeated_blocked_calls = "repeated_blocked_calls"
    broad_resource_access = "broad_resource_access"
    burst_reads_across_resources = "burst_reads_across_resources"
    repeated_external_destination_attempts = "repeated_external_destination_attempts"
    repeated_approval_failures = "repeated_approval_failures"


class AlertRule(BaseModel):
    """One deterministic alert rule.

    ``window_seconds`` and ``threshold`` are bounded. ``rule_id`` is stable across
    releases so alert consumers can rely on it; changing a rule's semantics requires a
    new rule id (old ids are never reused).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(pattern=_RULE_ID_PATTERN.pattern)
    kind: AlertRuleKind
    window_seconds: Annotated[int, Field(ge=_MIN_WINDOW_SECONDS, le=_MAX_WINDOW_SECONDS)]
    threshold: Annotated[int, Field(ge=_MIN_THRESHOLD, le=_MAX_THRESHOLD)]
    severity: AlertSeverity
    enabled: bool = True
    description: str = Field(min_length=1, max_length=512)

    @field_validator("description")
    @classmethod
    def _description_is_content_free(cls, value: str) -> str:
        """The description itself must not contain raw user/tool content."""
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise ValueError("rule description must not contain control characters")
        return value


class AlertRuleConfig(BaseModel):
    """Versioned alert-rule configuration.

    ``version`` is a stable identifier; changing the file's semantics requires a new
    version. The config is loaded once at startup and never hot-reloaded (consistent
    with the rest of v1 configuration).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(
        min_length=1,
        max_length=_MAX_CONFIG_VERSION_LEN,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$",
    )
    rules: tuple[AlertRule, ...] = Field(default=(), max_length=_MAX_RULES)

    @field_validator("version")
    @classmethod
    def _validate_config_version_field(cls, version: str) -> str:
        """Reject placeholder versions that suggest an unconfigured system."""
        if version.lower() in ("unset", "none", "default", "placeholder", "tbd"):
            raise ValueError(f"alert config version {version!r} is reserved")
        return version

    @field_validator("rules")
    @classmethod
    def _rule_ids_are_unique(cls, value: tuple[AlertRule, ...]) -> tuple[AlertRule, ...]:
        ids = [rule.rule_id for rule in value]
        if len(set(ids)) != len(ids):
            raise ValueError("alert rule ids must be unique")
        return value

    @model_validator(mode="after")
    def _enabled_rules_have_semantics(self) -> AlertRuleConfig:
        """Every enabled rule kind has a corresponding evaluator in ``rules.py``."""
        known_kinds = {kind.value for kind in AlertRuleKind}
        for rule in self.rules:
            if rule.enabled and rule.kind.value not in known_kinds:
                raise ValueError(
                    f"no evaluator for alert rule kind {rule.kind.value!r} (rule {rule.rule_id!r})"
                )
        return self

    def enabled_rules(self) -> tuple[AlertRule, ...]:
        """Return rules that are enabled, in config order."""
        return tuple(rule for rule in self.rules if rule.enabled)

    def rule_by_id(self, rule_id: str) -> AlertRule | None:
        """Look up a rule by its stable id."""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None


class AlertRuleFiring(BaseModel):
    """One rule firing — content-free evidence only.

    ``count`` is the number of matching events observed in the window. ``evidence`` is
    a tuple of short, uppercase, content-free tokens describing *what* matched (event
    types, decision codes, destination labels), never the raw content.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(pattern=_RULE_ID_PATTERN.pattern)
    kind: AlertRuleKind
    severity: AlertSeverity
    count: int = Field(ge=1, le=_MAX_THRESHOLD)
    window_seconds: int
    first_event_index: int | None = Field(default=None, ge=0)
    last_event_index: int | None = Field(default=None, ge=0)
    evidence: tuple[str, ...] = Field(default=(), max_length=32)

    @field_validator("evidence")
    @classmethod
    def _evidence_tokens_are_content_free(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for token in value:
            if _EVIDENCE_TOKEN_PATTERN.fullmatch(token) is None:
                raise ValueError(f"evidence token {token!r} is not content-free")
        return value


def _validate_config_version(version: str) -> str:
    """Reject placeholder versions that suggest an unconfigured system."""
    if version.lower() in ("unset", "none", "default", "placeholder", "tbd"):
        raise ValueError(f"alert config version {version!r} is reserved")
    return version


def load_alert_config(data: dict[str, object]) -> AlertRuleConfig:
    """Load and validate alert-rule configuration from a parsed mapping.

    Invalid configuration fails closed: no default rules, no silent skipping. An empty
    rules tuple is valid (alerting is disabled).
    """
    if "version" not in data:
        raise ValueError("alert config must declare a version")
    _validate_config_version(str(data["version"]))
    return AlertRuleConfig.model_validate(data)


__all__ = [
    "AlertRule",
    "AlertRuleConfig",
    "AlertRuleFiring",
    "AlertSeverity",
    "AlertRuleKind",
    "load_alert_config",
]
