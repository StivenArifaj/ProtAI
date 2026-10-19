"""Concrete action-versus-intent validation, use tracking, and time resolution."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ai_security.intent.models import (
    IntentConstraint,
    IntentManifest,
    RelativeTimeScope,
    _issue_intent_manifest,
)
from ai_security.intent.time_window import resolve_relative_window
from ai_security.intent.validator import (
    IntentConstraintViolation,
    IntentUsageTracker,
    validate_intent_constraints,
)
from ai_security.tools.mock_email import EmailReadArguments
from ai_security.tools.mock_external_sink import DESTINATION, SinkWriteArguments
from ai_security.tools.mock_text import SummarizeArguments

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


def constraint(**overrides: object) -> IntentConstraint:
    values: dict[str, object] = {
        "tool_id": "mock_email.read",
        "action_id": "read",
        "allowed_resource_ids": ("email-1",),
    }
    values.update(overrides)
    return IntentConstraint(**values)


def manifest(
    *,
    manifest_id: str = "manifest-1",
    constraints: tuple[IntentConstraint, ...] | None = None,
    expires_at: datetime | None = None,
) -> IntentManifest:
    return _issue_intent_manifest(
        manifest_id=manifest_id,
        request_id="req-1",
        principal_subject_id="dev-user",
        tenant_id="dev-tenant",
        policy_version="dev-1",
        policy_hash="a" * 64,
        extractor_version="mock-intent-v1",
        created_at=NOW,
        expires_at=expires_at or NOW + timedelta(seconds=300),
        goal_digest="b" * 64,
        constraints=constraints if constraints is not None else (constraint(),),
        time_window=None,
    )


def test_resources_must_be_within_the_exact_manifest_scope() -> None:
    value = manifest()
    args = EmailReadArguments(email_id="email-1")
    assert (
        validate_intent_constraints(
            value,
            tool_id="mock_email.read",
            action_id="read",
            arguments=args,
            resource_ids=("email-1",),
            destination=None,
        )
        is None
    )
    assert (
        validate_intent_constraints(
            value,
            tool_id="mock_email.read",
            action_id="read",
            arguments=EmailReadArguments(email_id="email-2"),
            resource_ids=("email-2",),
            destination=None,
        )
        is IntentConstraintViolation.resource_scope
    )


def test_action_must_match_exactly() -> None:
    value = manifest()
    assert (
        validate_intent_constraints(
            value,
            tool_id="mock_email.read",
            action_id="delete",
            arguments=EmailReadArguments(email_id="email-1"),
            resource_ids=("email-1",),
            destination=None,
        )
        is IntentConstraintViolation.no_matching_action
    )


def test_destination_is_denied_unless_explicitly_allowed() -> None:
    value = manifest(
        constraints=(
            IntentConstraint(
                tool_id="mock_external_sink.write",
                action_id="write",
            ),
        )
    )
    args = SinkWriteArguments(destination=DESTINATION, content="canary")
    assert (
        validate_intent_constraints(
            value,
            tool_id="mock_external_sink.write",
            action_id="write",
            arguments=args,
            resource_ids=(),
            destination=DESTINATION,
        )
        is IntentConstraintViolation.destination_scope
    )

    allowed = manifest(
        constraints=(
            IntentConstraint(
                tool_id="mock_external_sink.write",
                action_id="write",
                allowed_destinations=(DESTINATION,),
            ),
        )
    )
    assert (
        validate_intent_constraints(
            allowed,
            tool_id="mock_external_sink.write",
            action_id="write",
            arguments=args,
            resource_ids=(),
            destination=DESTINATION,
        )
        is None
    )


def test_parameter_values_are_compared_exactly_and_type_strictly() -> None:
    value = manifest(
        constraints=(
            IntentConstraint(
                tool_id="text.summarize",
                action_id="summarize",
                allowed_parameter_values={"max_chars": (200,)},
            ),
        )
    )
    assert (
        validate_intent_constraints(
            value,
            tool_id="text.summarize",
            action_id="summarize",
            arguments=SummarizeArguments(text="hello", max_chars=200),
            resource_ids=(),
            destination=None,
        )
        is None
    )
    assert (
        validate_intent_constraints(
            value,
            tool_id="text.summarize",
            action_id="summarize",
            arguments=SummarizeArguments(text="hello", max_chars=201),
            resource_ids=(),
            destination=None,
        )
        is IntentConstraintViolation.parameter_value
    )


def test_usage_tracker_enforces_max_uses_and_expiry() -> None:
    value = manifest(
        constraints=(
            IntentConstraint(
                tool_id="mock_email.read",
                action_id="read",
                allowed_resource_ids=("email-1",),
                max_uses=2,
            ),
        )
    )
    tracker = IntentUsageTracker()
    for _ in range(2):
        assert tracker.reserve(manifest=value, tool_id="mock_email.read", action_id="read", now=NOW)
    assert not tracker.reserve(manifest=value, tool_id="mock_email.read", action_id="read", now=NOW)
    assert not tracker.reserve(
        manifest=value,
        tool_id="mock_email.read",
        action_id="read",
        now=value.expires_at,
    )


def test_usage_tracker_fails_closed_at_capacity() -> None:
    tracker = IntentUsageTracker(max_tracked_manifests=1)
    first = manifest(manifest_id="manifest-1")
    second = manifest(manifest_id="manifest-2")
    assert tracker.reserve(manifest=first, tool_id="mock_email.read", action_id="read", now=NOW)
    assert not tracker.reserve(
        manifest=second, tool_id="mock_email.read", action_id="read", now=NOW
    )


def test_usage_tracker_purges_expired_manifests() -> None:
    tracker = IntentUsageTracker(max_tracked_manifests=1)
    expired = manifest(
        manifest_id="manifest-1",
        expires_at=NOW + timedelta(seconds=1),
    )
    assert tracker.reserve(manifest=expired, tool_id="mock_email.read", action_id="read", now=NOW)
    later = NOW + timedelta(seconds=2)
    fresh = manifest(manifest_id="manifest-2", expires_at=later + timedelta(seconds=10))
    assert tracker.reserve(manifest=fresh, tool_id="mock_email.read", action_id="read", now=later)


def test_relative_dates_resolve_with_daylight_saving_transitions() -> None:
    before_dst = resolve_relative_window(
        scope=RelativeTimeScope.today,
        reference=datetime(2026, 3, 7, 12, 0, tzinfo=UTC),
        timezone_name="America/New_York",
    )
    assert before_dst.start == datetime(2026, 3, 7, 5, 0, tzinfo=UTC)
    assert before_dst.end == datetime(2026, 3, 8, 5, 0, tzinfo=UTC)

    dst_day = resolve_relative_window(
        scope=RelativeTimeScope.today,
        reference=datetime(2026, 3, 8, 12, 0, tzinfo=UTC),
        timezone_name="America/New_York",
    )
    assert dst_day.start == datetime(2026, 3, 8, 5, 0, tzinfo=UTC)
    assert dst_day.end == datetime(2026, 3, 9, 4, 0, tzinfo=UTC)
    assert dst_day.end - dst_day.start == timedelta(hours=23)


def test_this_week_starts_on_monday_in_the_trusted_timezone() -> None:
    window = resolve_relative_window(
        scope=RelativeTimeScope.this_week,
        reference=datetime(2026, 10, 22, 12, 0, tzinfo=UTC),
        timezone_name="Europe/Berlin",
    )
    assert window.start == datetime(2026, 10, 18, 22, 0, tzinfo=UTC)
    assert window.end == datetime(2026, 10, 25, 23, 0, tzinfo=UTC)


def test_relative_dates_require_a_trusted_valid_timezone() -> None:
    with pytest.raises(ValueError):
        resolve_relative_window(
            scope=RelativeTimeScope.today,
            reference=datetime(2026, 10, 19),
            timezone_name="UTC",
        )
    with pytest.raises(ValueError):
        resolve_relative_window(
            scope=RelativeTimeScope.today,
            reference=NOW,
            timezone_name="Not/AZone",
        )
