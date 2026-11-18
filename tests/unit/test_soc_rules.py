"""Deterministic alert-rule evaluator tests (Phase 10).

Each rule fires only on its documented pattern and stays silent on benign or
threshold-boundary evidence. Rules are content-free: they match event types, decision
codes, destinations, and counts — never raw text or payloads.
"""

from __future__ import annotations

from ai_security.soc.config import (
    AlertRule,
    AlertRuleConfig,
    AlertSeverity,
)
from ai_security.soc.rules import (
    EvaluationContext,
    evaluate_broad_resource_access,
    evaluate_burst_reads_across_resources,
    evaluate_repeated_approval_failures,
    evaluate_repeated_blocked_calls,
    evaluate_repeated_external_destination_attempts,
    evaluate_rules,
)


class ListContext:
    """In-memory read-only evaluation context backed by a list of event mappings."""

    def __init__(self, events: list[dict[str, object]]) -> None:
        self._events = events

    def events(self) -> list[dict[str, object]]:
        return list(self._events)


def _event(
    *,
    event_type: str,
    decision: str | None = None,
    tool_id: str | None = None,
    destination: str | None = None,
    principal_subject_id: str | None = "principal-1",
    occurred_at: str = "2026-01-01T12:00:00+00:00",
    sequence_number: int = 1,
) -> dict[str, object]:
    event: dict[str, object] = {
        "event_type": event_type,
        "occurred_at": occurred_at,
        "sequence_number": sequence_number,
        "principal_subject_id": principal_subject_id,
    }
    if decision is not None:
        event["decision"] = decision
    if tool_id is not None:
        event["tool_id"] = tool_id
    if destination is not None:
        event["destination"] = destination
    return event


def _rule(
    rule_id: str,
    kind: str,
    window_seconds: int = 3600,
    threshold: int = 3,
    severity: str = "HIGH",
    enabled: bool = True,
) -> AlertRule:
    return AlertRule(
        rule_id=rule_id,
        kind=kind,
        window_seconds=window_seconds,
        threshold=threshold,
        severity=AlertSeverity(severity),
        enabled=enabled,
        description="test rule",
    )


def _config(*rules: AlertRule) -> AlertRuleConfig:
    return AlertRuleConfig(version="alerts-test-v1", rules=rules)


# -- repeated_blocked_calls --


def test_repeated_blocked_calls_fires_above_threshold() -> None:
    events = [_event(event_type="POLICY_EVALUATED", decision="BLOCK") for _ in range(4)]
    firing = evaluate_repeated_blocked_calls(
        ListContext(events), _rule("blocked-1", "repeated_blocked_calls", threshold=3)
    )
    assert firing is not None
    assert firing.count == 4
    assert firing.rule_id == "blocked-1"
    assert firing.evidence == ("BLOCKED_CALLS_EXCEED_THRESHOLD",)


def test_repeated_blocked_calls_silent_at_or_below_threshold() -> None:
    events = [_event(event_type="POLICY_EVALUATED", decision="BLOCK") for _ in range(3)]
    firing = evaluate_repeated_blocked_calls(
        ListContext(events), _rule("blocked-2", "repeated_blocked_calls", threshold=3)
    )
    assert firing is None


def test_repeated_blocked_calls_ignores_allow_decisions() -> None:
    events = [
        _event(event_type="POLICY_EVALUATED", decision="ALLOW"),
        _event(event_type="POLICY_EVALUATED", decision="ALLOW"),
        _event(event_type="POLICY_EVALUATED", decision="BLOCK"),
    ]
    firing = evaluate_repeated_blocked_calls(
        ListContext(events), _rule("blocked-3", "repeated_blocked_calls", threshold=3)
    )
    assert firing is None


def test_repeated_blocked_calls_empty_is_silent() -> None:
    firing = evaluate_repeated_blocked_calls(
        ListContext([]), _rule("blocked-4", "repeated_blocked_calls", threshold=1)
    )
    assert firing is None


# -- broad_resource_access --


def test_broad_resource_access_fires_above_threshold() -> None:
    events = [
        _event(
            event_type="TOOL_CALL_PROPOSED",
            decision="ALLOW",
            tool_id="tool-a",
            principal_subject_id="principal-1",
        ),
        _event(
            event_type="TOOL_CALL_PROPOSED",
            decision="ALLOW",
            tool_id="tool-b",
            principal_subject_id="principal-1",
        ),
        _event(
            event_type="TOOL_CALL_PROPOSED",
            decision="ALLOW",
            tool_id="tool-c",
            principal_subject_id="principal-1",
        ),
    ]
    firing = evaluate_broad_resource_access(
        ListContext(events), _rule("broad-1", "broad_resource_access", threshold=2)
    )
    assert firing is not None
    assert firing.count == 3
    assert firing.evidence == ("BROAD_RESOURCE_ACCESS",)


def test_broad_resource_access_per_principal() -> None:
    events = [
        _event(
            event_type="TOOL_CALL_PROPOSED",
            decision="ALLOW",
            tool_id="tool-a",
            principal_subject_id="principal-1",
        ),
        _event(
            event_type="TOOL_CALL_PROPOSED",
            decision="ALLOW",
            tool_id="tool-b",
            principal_subject_id="principal-1",
        ),
        _event(
            event_type="TOOL_CALL_PROPOSED",
            decision="ALLOW",
            tool_id="tool-c",
            principal_subject_id="principal-2",
        ),
    ]
    firing = evaluate_broad_resource_access(
        ListContext(events), _rule("broad-2", "broad_resource_access", threshold=3)
    )
    assert firing is None  # principal-1 has 2, principal-2 has 1


# -- burst_reads_across_resources --


def test_burst_reads_fires_above_threshold() -> None:
    events = [
        _event(
            event_type="POLICY_EVALUATED",
            decision="ALLOW",
            tool_id="tool-a",
        ),
        _event(
            event_type="POLICY_EVALUATED",
            decision="ALLOW",
            tool_id="tool-b",
        ),
    ]
    firing = evaluate_burst_reads_across_resources(
        ListContext(events), _rule("burst-1", "burst_reads_across_resources", threshold=2)
    )
    assert firing is not None
    assert firing.count == 2
    assert firing.evidence == ("BURST_READS_ACROSS_RESOURCES",)


def test_burst_reads_ignores_blocked() -> None:
    events = [
        _event(
            event_type="POLICY_EVALUATED",
            decision="BLOCK",
            tool_id="tool-a",
        ),
        _event(
            event_type="POLICY_EVALUATED",
            decision="BLOCK",
            tool_id="tool-b",
        ),
    ]
    firing = evaluate_burst_reads_across_resources(
        ListContext(events), _rule("burst-2", "burst_reads_across_resources", threshold=1)
    )
    assert firing is None


# -- repeated_external_destination_attempts --


def test_external_destination_attempts_fires_above_threshold() -> None:
    events = [
        _event(event_type="EGRESS_INSPECTED", destination="https://example.com"),
        _event(event_type="EGRESS_INSPECTED", destination="https://example.org"),
        _event(event_type="EGRESS_INSPECTED", destination="https://example.net"),
    ]
    firing = evaluate_repeated_external_destination_attempts(
        ListContext(events),
        _rule("ext-1", "repeated_external_destination_attempts", threshold=2),
    )
    assert firing is not None
    assert firing.count == 3
    assert firing.evidence == ("EXTERNAL_DESTINATION_ATTEMPTS_EXCEED_THRESHOLD",)


def test_external_destination_ignores_none() -> None:
    events = [
        _event(event_type="EGRESS_INSPECTED"),
        _event(event_type="EGRESS_INSPECTED"),
    ]
    firing = evaluate_repeated_external_destination_attempts(
        ListContext(events),
        _rule("ext-2", "repeated_external_destination_attempts", threshold=1),
    )
    assert firing is None


# -- repeated_approval_failures --


def test_approval_failures_fires_above_threshold() -> None:
    events = [
        _event(
            event_type="APPROVAL_DECIDED",
            decision="BLOCK",
        ),
        _event(
            event_type="APPROVAL_DECIDED",
            decision="BLOCK",
        ),
        _event(
            event_type="APPROVAL_EXPIRED",
        ),
    ]
    firing = evaluate_repeated_approval_failures(
        ListContext(events),
        _rule("appr-1", "repeated_approval_failures", threshold=2),
    )
    assert firing is not None
    assert firing.count == 3
    assert firing.evidence == ("APPROVAL_FAILURES_EXCEED_THRESHOLD",)


def test_approval_failures_ignores_approved() -> None:
    events = [
        _event(event_type="APPROVAL_DECIDED", decision="ALLOW"),
    ]
    firing = evaluate_repeated_approval_failures(
        ListContext(events),
        _rule("appr-2", "repeated_approval_failures", threshold=1),
    )
    assert firing is None


# -- evaluate_rules (all rules together) --


def test_evaluate_rules_returns_firings_in_config_order() -> None:
    events = [
        _event(event_type="POLICY_EVALUATED", decision="BLOCK"),
        _event(event_type="POLICY_EVALUATED", decision="BLOCK"),
        _event(event_type="POLICY_EVALUATED", decision="BLOCK"),
    ]
    config = _config(
        _rule("r1", "repeated_blocked_calls", threshold=2),
        _rule("r2", "repeated_approval_failures", threshold=1),
    )
    firings = evaluate_rules(ListContext(events), config)
    assert len(firings) == 1
    assert firings[0].rule_id == "r1"


def test_evaluate_rules_disabled_rule_skipped() -> None:
    events = [
        _event(event_type="POLICY_EVALUATED", decision="BLOCK"),
        _event(event_type="POLICY_EVALUATED", decision="BLOCK"),
    ]
    config = _config(
        _rule("r1", "repeated_blocked_calls", threshold=1, enabled=False),
    )
    firings = evaluate_rules(ListContext(events), config)
    assert firings == ()


def test_evaluate_rules_no_firings_when_benign() -> None:
    events = [
        _event(event_type="POLICY_EVALUATED", decision="ALLOW"),
        _event(event_type="TOOL_EXECUTION_COMPLETED"),
    ]
    config = _config(
        _rule("r1", "repeated_blocked_calls", threshold=1),
        _rule("r2", "repeated_approval_failures", threshold=1),
    )
    firings = evaluate_rules(ListContext(events), config)
    assert firings == ()


def test_evaluate_rules_multiple_firings() -> None:
    events = [
        _event(event_type="POLICY_EVALUATED", decision="BLOCK"),
        _event(event_type="POLICY_EVALUATED", decision="BLOCK"),
        _event(event_type="APPROVAL_DECIDED", decision="BLOCK"),
        _event(event_type="APPROVAL_EXPIRED"),
    ]
    config = _config(
        _rule("r1", "repeated_blocked_calls", threshold=1),
        _rule("r2", "repeated_approval_failures", threshold=1),
    )
    firings = evaluate_rules(ListContext(events), config)
    assert len(firings) == 2
    ids = {f.rule_id for f in firings}
    assert ids == {"r1", "r2"}


def test_evaluation_context_is_read_only_protocol() -> None:
    """The EvaluationContext protocol exposes only ``events()`` — no write path."""
    assert hasattr(EvaluationContext, "events")
    # Protocol: structural subtyping; ListContext conforms.
    ctx: EvaluationContext = ListContext([])
    assert ctx.events() == []
