"""Alert-rule configuration validation tests (Phase 10).

Alert config is versioned, strict, and bounded. Invalid configuration fails closed
with no default rules and no silent skipping.
"""

from __future__ import annotations

import pytest

from ai_security.soc.config import (
    AlertRuleConfig,
    AlertRuleKind,
    AlertSeverity,
    load_alert_config,
)

MIN_CONFIG = {
    "version": "alerts-v1",
    "rules": [],
}

FULL_CONFIG = {
    "version": "alerts-v1",
    "rules": [
        {
            "rule_id": "blocked-calls-10-per-hour",
            "kind": "repeated_blocked_calls",
            "window_seconds": 3600,
            "threshold": 10,
            "severity": "HIGH",
            "enabled": True,
            "description": "More than 10 blocked calls in an hour",
        },
        {
            "rule_id": "approval-failures-5-per-hour",
            "kind": "repeated_approval_failures",
            "window_seconds": 3600,
            "threshold": 5,
            "severity": "MEDIUM",
            "enabled": True,
            "description": "More than 5 approval failures in an hour",
        },
    ],
}


def test_empty_config_is_valid() -> None:
    config = AlertRuleConfig.model_validate(MIN_CONFIG)
    assert config.version == "alerts-v1"
    assert config.enabled_rules() == ()
    assert config.rule_by_id("anything") is None


def test_full_config_loads() -> None:
    config = AlertRuleConfig.model_validate(FULL_CONFIG)
    assert config.version == "alerts-v1"
    rules = config.enabled_rules()
    assert len(rules) == 2
    assert rules[0].rule_id == "blocked-calls-10-per-hour"
    assert rules[0].kind is AlertRuleKind.repeated_blocked_calls
    assert rules[0].window_seconds == 3600
    assert rules[0].threshold == 10
    assert rules[0].severity is AlertSeverity.high
    assert rules[0].enabled is True


def test_disabled_rule_is_not_enabled() -> None:
    data = dict(FULL_CONFIG)
    data["rules"] = [dict(FULL_CONFIG["rules"][0], enabled=False)]
    config = AlertRuleConfig.model_validate(data)
    assert config.enabled_rules() == ()


def test_rule_by_id() -> None:
    config = AlertRuleConfig.model_validate(FULL_CONFIG)
    rule = config.rule_by_id("blocked-calls-10-per-hour")
    assert rule is not None
    assert rule.rule_id == "blocked-calls-10-per-hour"
    assert config.rule_by_id("nonexistent") is None


def test_version_is_required() -> None:
    data = {"rules": []}
    with pytest.raises(ValueError):
        AlertRuleConfig.model_validate(data)


def test_reserved_version_is_rejected() -> None:
    for reserved in ("unset", "none", "default", "placeholder", "tbd", "UNSET"):
        data = dict(MIN_CONFIG)
        data["version"] = reserved
        with pytest.raises(ValueError):
            AlertRuleConfig.model_validate(data)


def test_duplicate_rule_ids_rejected() -> None:
    data = dict(FULL_CONFIG)
    data["rules"] = [dict(FULL_CONFIG["rules"][0]), dict(FULL_CONFIG["rules"][0])]
    with pytest.raises(ValueError):
        AlertRuleConfig.model_validate(data)


def test_window_seconds_bounded() -> None:
    data = dict(FULL_CONFIG)
    data["rules"] = [
        dict(
            FULL_CONFIG["rules"][0],
            rule_id="window-too-small",
            window_seconds=1,  # below MIN (60)
        )
    ]
    with pytest.raises(ValueError):
        AlertRuleConfig.model_validate(data)

    data["rules"] = [
        dict(
            FULL_CONFIG["rules"][0],
            rule_id="window-too-large",
            window_seconds=86_401,  # above MAX (86_400)
        )
    ]
    with pytest.raises(ValueError):
        AlertRuleConfig.model_validate(data)

    data["rules"] = [
        dict(
            FULL_CONFIG["rules"][0],
            rule_id="window-ok",
            window_seconds=3600,
        )
    ]
    config = AlertRuleConfig.model_validate(data)
    assert config.enabled_rules()[0].window_seconds == 3600


def test_threshold_bounded() -> None:
    data = dict(FULL_CONFIG)
    data["rules"] = [
        dict(
            FULL_CONFIG["rules"][0],
            rule_id="threshold-too-small",
            threshold=0,  # below MIN (1)
        )
    ]
    with pytest.raises(ValueError):
        AlertRuleConfig.model_validate(data)

    data["rules"] = [
        dict(
            FULL_CONFIG["rules"][0],
            rule_id="threshold-too-large",
            threshold=10_001,  # above MAX (10_000)
        )
    ]
    with pytest.raises(ValueError):
        AlertRuleConfig.model_validate(data)


def test_too_many_rules_rejected() -> None:
    data = dict(MIN_CONFIG)
    data["rules"] = [
        dict(
            FULL_CONFIG["rules"][0],
            rule_id=f"rule-{i}",
        )
        for i in range(129)
    ]
    with pytest.raises(ValueError):
        AlertRuleConfig.model_validate(data)


def test_description_no_control_characters() -> None:
    data = dict(FULL_CONFIG)
    data["rules"] = [
        dict(
            FULL_CONFIG["rules"][0],
            rule_id="bad-description",
            description="bad\x07description",
        )
    ]
    with pytest.raises(ValueError):
        AlertRuleConfig.model_validate(data)


def test_load_alert_config_valid() -> None:
    config = load_alert_config(FULL_CONFIG)
    assert isinstance(config, AlertRuleConfig)
    assert len(config.enabled_rules()) == 2


def test_rule_id_pattern_strict() -> None:
    data = dict(FULL_CONFIG)
    data["rules"] = [
        dict(
            FULL_CONFIG["rules"][0],
            rule_id="BAD ID",  # spaces not allowed
        )
    ]
    with pytest.raises(ValueError):
        AlertRuleConfig.model_validate(data)


def test_unknown_rule_kind_enabled_rejected() -> None:
    data = dict(FULL_CONFIG)
    data["rules"] = [
        dict(
            FULL_CONFIG["rules"][0],
            rule_id="unknown-kind",
            kind="not_a_real_kind",
        )
    ]
    with pytest.raises(ValueError):
        AlertRuleConfig.model_validate(data)
