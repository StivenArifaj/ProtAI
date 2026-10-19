"""Settings validation tests (blueprint sections 5.1, 5.4, 9.2, 9.3, 18.2)."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable

import pytest
from pydantic import ValidationError

from ai_security.settings import (
    SAMPLE_DATABASE_PASSWORD,
    SAMPLE_HOST_AUTH_SECRET_B64,
    Settings,
    parse_host_auth_keys,
)

REAL_LOOKING_URL = "postgresql+asyncpg://firewall:correct-horse-battery@db:5432/firewall"

# Public deterministic test key material (not the all-zero sample secret).
VALID_SECRET_B64 = base64.b64encode(b"\x07" * 32).decode()
VALID_KEYS_JSON = json.dumps(
    {
        "test-key": {
            "secret_b64": VALID_SECRET_B64,
            "host_id": "test-host",
            "audience": "ai-agent-security-gateway",
            "allowed_tenants": ["demo"],
        }
    }
)


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "app_env": "development",
        "log_level": "INFO",
        "database_url": REAL_LOOKING_URL,
        "principal_resolver": "dev",
        "host_auth_keys_json": VALID_KEYS_JSON,
    }
    values.update(overrides)
    if values["app_env"] not in ("development", "test") and "principal_resolver" not in overrides:
        values["principal_resolver"] = "host"
    return Settings(_env_file=None, **values)


def make_keys_json(**record_overrides: object) -> str:
    record: dict[str, object] = {
        "secret_b64": VALID_SECRET_B64,
        "host_id": "test-host",
        "audience": "ai-agent-security-gateway",
        "allowed_tenants": ["demo"],
    }
    record.update(record_overrides)
    return json.dumps({"test-key": record})


def test_valid_development_settings_construct() -> None:
    settings = make_settings()
    assert settings.app_env.value == "development"
    assert settings.log_level.value == "INFO"


def test_log_level_defaults_to_info(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    settings = Settings(
        _env_file=None,
        app_env="development",
        database_url=REAL_LOOKING_URL,
        host_auth_keys_json=VALID_KEYS_JSON,
    )
    assert settings.log_level.value == "INFO"


def test_app_env_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_ENV", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, database_url=REAL_LOOKING_URL)


def test_database_url_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="development")


def test_host_auth_keys_json_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOST_AUTH_KEYS_JSON", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="development", database_url=REAL_LOOKING_URL)


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
        assert VALID_SECRET_B64 not in rendered
    assert "correct-horse-battery" not in str(settings.database_url)


def test_host_auth_keys_do_not_render_secrets() -> None:
    settings = make_settings()
    record = settings.host_auth_keys["test-key"]
    assert VALID_SECRET_B64 not in repr(record)
    assert len(record.secret_bytes) == 32


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


def test_policy_self_checks_path_defaults_and_overrides() -> None:
    assert make_settings().policy_self_checks_path == "config/policy_self_checks.yaml"
    overridden = make_settings(policy_self_checks_path="/etc/policy_checks.yaml")
    assert overridden.policy_self_checks_path == "/etc/policy_checks.yaml"


def test_policy_paths_default_and_override() -> None:
    settings = make_settings()
    assert settings.policy_path == "config/policies.yaml"
    assert settings.risk_thresholds_path == "config/risk_thresholds.yaml"
    overridden = make_settings(
        policy_path="/etc/policies.yaml",
        risk_thresholds_path="/etc/risk_thresholds.yaml",
    )
    assert overridden.policy_path == "/etc/policies.yaml"
    assert overridden.risk_thresholds_path == "/etc/risk_thresholds.yaml"


@pytest.mark.parametrize(
    "field",
    ["policy_path", "risk_thresholds_path", "policy_self_checks_path"],
)
def test_empty_policy_paths_are_rejected(field: str) -> None:
    with pytest.raises(ValidationError):
        make_settings(**{field: ""})


# --- Host-auth key configuration (blueprint sections 5.4, 9.2) ---


def test_host_auth_keys_parse_into_records() -> None:
    settings = make_settings()
    record = settings.host_auth_keys["test-key"]
    assert record.host_id == "test-host"
    assert record.audience == "ai-agent-security-gateway"
    assert record.allowed_tenants == ["demo"]
    assert record.secret_bytes == b"\x07" * 32


def test_host_auth_keys_accept_empty_tenant_list() -> None:
    json_text = make_keys_json(allowed_tenants=[])
    settings = make_settings(host_auth_keys_json=json_text)
    assert settings.host_auth_keys["test-key"].allowed_tenants == []


def test_host_auth_keys_reject_empty_object() -> None:
    with pytest.raises(ValidationError, match="at least one key id"):
        make_settings(host_auth_keys_json="{}")


def test_host_auth_keys_reject_non_json() -> None:
    with pytest.raises(ValidationError, match="not valid JSON"):
        make_settings(host_auth_keys_json="{not json")


def test_host_auth_keys_reject_duplicate_key_ids() -> None:
    duplicated = (
        '{"a": {"secret_b64": "'
        + VALID_SECRET_B64
        + '", "host_id": "h", "audience": "a", "allowed_tenants": []},'
        + ' "a": {"secret_b64": "'
        + VALID_SECRET_B64
        + '", "host_id": "h2", "audience": "a", "allowed_tenants": []}}'
    )
    with pytest.raises(ValidationError, match="duplicate key id"):
        make_settings(host_auth_keys_json=duplicated)


def test_host_auth_keys_reject_missing_field() -> None:
    bad = json.dumps({"test-key": {"secret_b64": VALID_SECRET_B64, "host_id": "h"}})
    with pytest.raises(ValidationError, match="audience"):
        make_settings(host_auth_keys_json=bad)


def test_host_auth_keys_reject_extra_field() -> None:
    bad = make_keys_json(role="admin")
    with pytest.raises(ValidationError, match="extra_forbidden|Extra inputs"):
        make_settings(host_auth_keys_json=bad)


def test_host_auth_keys_reject_non_base64_secret() -> None:
    with pytest.raises(ValidationError, match="strict Base64"):
        make_settings(host_auth_keys_json=make_keys_json(secret_b64="not base64 !!!"))  # noqa: S106


def test_host_auth_keys_reject_short_secret() -> None:
    short = base64.b64encode(b"\x01" * 16).decode()
    with pytest.raises(ValidationError, match="at least 32 bytes"):
        make_settings(host_auth_keys_json=make_keys_json(secret_b64=short))


def test_host_auth_keys_reject_control_characters_in_host_id() -> None:
    with pytest.raises(ValidationError, match="control characters"):
        make_settings(host_auth_keys_json=make_keys_json(host_id="bad\nhost"))


def test_host_auth_keys_reject_malformed_key_id() -> None:
    bad = json.dumps(
        {
            "bad key id!": {
                "secret_b64": VALID_SECRET_B64,
                "host_id": "h",
                "audience": "a",
                "allowed_tenants": [],
            }
        }
    )
    with pytest.raises(ValidationError, match="malformed"):
        make_settings(host_auth_keys_json=bad)


@pytest.mark.parametrize("env", ["staging", "production"])
def test_sample_host_auth_secret_refused_outside_dev_test(env: str) -> None:
    sample = json.dumps(
        {
            "sample-key": {
                "secret_b64": SAMPLE_HOST_AUTH_SECRET_B64,
                "host_id": "h",
                "audience": "a",
                "allowed_tenants": [],
            }
        }
    )
    with pytest.raises(ValidationError, match="all-zero host-auth secret"):
        make_settings(app_env=env, host_auth_keys_json=sample, principal_resolver="host")


@pytest.mark.parametrize("env", ["development", "test"])
def test_sample_host_auth_secret_allowed_in_dev_test(env: str) -> None:
    sample = json.dumps(
        {
            "sample-key": {
                "secret_b64": SAMPLE_HOST_AUTH_SECRET_B64,
                "host_id": "h",
                "audience": "a",
                "allowed_tenants": [],
            }
        }
    )
    settings = make_settings(app_env=env, host_auth_keys_json=sample)
    assert settings.app_env.value == env


# --- Principal resolver guard (blueprint section 9.3, ADR-001) ---


@pytest.mark.parametrize("env", ["staging", "production"])
def test_dev_resolver_refused_outside_dev_test(env: str) -> None:
    with pytest.raises(ValidationError, match="PRINCIPAL_RESOLVER=dev is refused"):
        make_settings(app_env=env, principal_resolver="dev")


@pytest.mark.parametrize("env", ["development", "test"])
def test_dev_resolver_allowed_in_dev_test(env: str) -> None:
    assert make_settings(app_env=env).principal_resolver.value == "dev"


@pytest.mark.parametrize("env", ["development", "test", "staging", "production"])
def test_host_resolver_allowed_everywhere(env: str) -> None:
    settings = make_settings(app_env=env, principal_resolver="host")
    assert settings.principal_resolver.value == "host"


# --- Timestamp tolerance / nonce TTL / request bound (blueprint section 9.2) ---


def test_nonce_ttl_must_cover_acceptance_window() -> None:
    with pytest.raises(ValidationError, match="twice"):
        make_settings(host_auth_timestamp_tolerance_seconds=60, host_auth_nonce_ttl_seconds=119)


def test_nonce_ttl_equal_to_twice_tolerance_is_accepted() -> None:
    settings = make_settings(
        host_auth_timestamp_tolerance_seconds=60, host_auth_nonce_ttl_seconds=120
    )
    assert settings.host_auth_nonce_ttl_seconds == 120


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("host_auth_timestamp_tolerance_seconds", 0),
        ("host_auth_timestamp_tolerance_seconds", -1),
        ("host_auth_nonce_ttl_seconds", 0),
        ("request_max_bytes", 0),
        ("request_max_bytes", -5),
    ],
)
def test_non_positive_bounds_are_rejected(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        make_settings(**{field: value})


def test_parse_host_auth_keys_function_validates_directly() -> None:
    keys = parse_host_auth_keys(VALID_KEYS_JSON)
    assert set(keys) == {"test-key"}
    with pytest.raises(ValueError, match="at least one key id"):
        parse_host_auth_keys("{}")


def test_input_defense_and_session_defaults_match_the_blueprint() -> None:
    settings = make_settings()
    assert settings.input_defense_path == "config/input_defense.yaml"
    assert settings.session_signal_ttl_seconds == 86400
    assert settings.session_max_age_seconds == 604800


def test_session_ttl_must_not_exceed_max_age() -> None:
    with pytest.raises(ValidationError, match="SESSION_SIGNAL_TTL_SECONDS"):
        make_settings(session_signal_ttl_seconds=604801, session_max_age_seconds=604800)


def test_session_windows_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        make_settings(session_signal_ttl_seconds=0)
    with pytest.raises(ValidationError):
        make_settings(session_max_age_seconds=0)


def test_intent_manifest_ttl_is_short_lived_and_bounded() -> None:
    assert make_settings().intent_manifest_ttl_seconds == 300
    with pytest.raises(ValidationError):
        make_settings(intent_manifest_ttl_seconds=0)
    with pytest.raises(ValidationError):
        make_settings(intent_manifest_ttl_seconds=3601)
    assert make_settings(intent_manifest_ttl_seconds=60).intent_manifest_ttl_seconds == 60
