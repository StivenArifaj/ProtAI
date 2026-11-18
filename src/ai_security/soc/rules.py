"""Deterministic alert rule evaluators (blueprint section 17.1).

Each evaluator reads existing audit evidence through ``EvaluationContext`` (read-only,
never writes the production audit path) and returns ``AlertRuleFiring`` objects when a
threshold is exceeded. Rules are content-free: they match on event types, decision
codes, destinations, and counts — never on raw user text, tool output, or exception
messages.

Evaluators are pure functions of the observed events plus the rule config. They have
no tool, policy, approval, or containment authority.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

from ai_security.audit.models import AuditEventType
from ai_security.firewall.decision import FirewallDecision
from ai_security.soc.config import AlertRule, AlertRuleConfig, AlertRuleFiring, AlertRuleKind

#: Maximum events an evaluator may inspect in one run (bounds CPU/memory for
#: attacker-influenced audit volume).
_MAX_EVENTS_PER_EVALUATION = 50_000


@runtime_checkable
class EvaluationContext(Protocol):
    """Read-only view of audit events for alert evaluation.

    Implementations may back this with the PostgreSQL audit chain (read-only query) or
    an in-memory list for tests. The context must never be a write path into the
    production audit chain.
    """

    def events(self) -> list[dict[str, object]]:
        """Return audit events as plain mappings, oldest first.

        Each mapping has at least: ``event_type``, ``decision`` (optional), ``reason``
        (optional), ``tool_id`` (optional), ``action_id`` (optional),
        ``destination`` (optional), ``principal_subject_id`` (optional),
        ``occurred_at`` (ISO-8601 string), and ``sequence_number`` (int).
        """


def _event_time(event: dict[str, object]) -> datetime | None:
    raw = event.get("occurred_at")
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _window_events(context: EvaluationContext, window_seconds: int) -> list[dict[str, object]]:
    """Return events within the trailing window, bounded for safety.

    The window is anchored to the newest event's timestamp (not wall clock), so the
    evaluator is deterministic given the same audit evidence regardless of when it
    runs.
    """
    all_events = context.events()
    if len(all_events) > _MAX_EVENTS_PER_EVALUATION:
        all_events = all_events[-_MAX_EVENTS_PER_EVALUATION:]

    times: list[tuple[datetime | None, dict[str, object]]] = [
        (_event_time(event), event) for event in all_events
    ]
    valid = [(t, e) for t, e in times if t is not None]
    if not valid:
        return []
    newest = max(t for t, _ in valid)
    cutoff = newest - timedelta(seconds=window_seconds)
    return [e for t, e in valid if t is not None and t >= cutoff]


def _count_by_decision(events: list[dict[str, object]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for event in events:
        decision = event.get("decision")
        if isinstance(decision, str):
            counts[decision] += 1
    return counts


def _count_by_event_type(events: list[dict[str, object]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for event in events:
        event_type = event.get("event_type")
        if isinstance(event_type, str):
            counts[event_type] += 1
    return counts


def _destinations(events: list[dict[str, object]]) -> list[str]:
    dests: list[str] = []
    for event in events:
        destination = event.get("destination")
        if isinstance(destination, str) and destination:
            dests.append(destination)
    return dests


def evaluate_repeated_blocked_calls(
    context: EvaluationContext, rule: AlertRule
) -> AlertRuleFiring | None:
    """Fire when blocked calls exceed ``threshold`` within ``window_seconds``.

    Evidence token: ``BLOCKED_CALLS_EXCEED_THRESHOLD``.
    """
    events = _window_events(context, rule.window_seconds)
    blocked = sum(1 for event in events if event.get("decision") == FirewallDecision.block.value)
    if blocked <= rule.threshold:
        return None
    return AlertRuleFiring(
        rule_id=rule.rule_id,
        kind=rule.kind,
        severity=rule.severity,
        count=blocked,
        window_seconds=rule.window_seconds,
        evidence=("BLOCKED_CALLS_EXCEED_THRESHOLD",),
    )


def evaluate_broad_resource_access(
    context: EvaluationContext, rule: AlertRule
) -> AlertRuleFiring | None:
    """Fire when a single principal touches more distinct resources than the threshold
    within the window.

    Evidence token: ``BROAD_RESOURCE_ACCESS``.
    """
    events = _window_events(context, rule.window_seconds)
    resources_by_principal: dict[str, set[str]] = {}
    for event in events:
        principal = event.get("principal_subject_id")
        resource = event.get("tool_id") or event.get("call_id")
        if isinstance(principal, str) and isinstance(resource, str):
            resources_by_principal.setdefault(principal, set()).add(resource)
    max_resources = max((len(s) for s in resources_by_principal.values()), default=0)
    if max_resources < rule.threshold:
        return None
    return AlertRuleFiring(
        rule_id=rule.rule_id,
        kind=rule.kind,
        severity=rule.severity,
        count=max_resources,
        window_seconds=rule.window_seconds,
        evidence=("BROAD_RESOURCE_ACCESS",),
    )


def evaluate_burst_reads_across_resources(
    context: EvaluationContext, rule: AlertRule
) -> AlertRuleFiring | None:
    """Fire when read-tool calls across distinct resources exceed the threshold.

    Evidence token: ``BURST_READS_ACROSS_RESOURCES``.
    """
    events = _window_events(context, rule.window_seconds)
    read_events = [
        e
        for e in events
        if e.get("event_type")
        in (AuditEventType.tool_call_proposed.value, AuditEventType.policy_evaluated.value)
        and e.get("decision") == FirewallDecision.allow.value
    ]
    resources = {e.get("tool_id") for e in read_events if isinstance(e.get("tool_id"), str)}
    if len(resources) < rule.threshold:
        return None
    return AlertRuleFiring(
        rule_id=rule.rule_id,
        kind=rule.kind,
        severity=rule.severity,
        count=len(resources),
        window_seconds=rule.window_seconds,
        evidence=("BURST_READS_ACROSS_RESOURCES",),
    )


def evaluate_repeated_external_destination_attempts(
    context: EvaluationContext, rule: AlertRule
) -> AlertRuleFiring | None:
    """Fire when calls to external destinations exceed the threshold within the window.

    Evidence token: ``EXTERNAL_DESTINATION_ATTEMPTS_EXCEED_THRESHOLD``.
    """
    events = _window_events(context, rule.window_seconds)
    external = sum(
        1
        for event in events
        if isinstance(event.get("destination"), str) and event.get("destination")
    )
    if external < rule.threshold:
        return None
    return AlertRuleFiring(
        rule_id=rule.rule_id,
        kind=rule.kind,
        severity=rule.severity,
        count=external,
        window_seconds=rule.window_seconds,
        evidence=("EXTERNAL_DESTINATION_ATTEMPTS_EXCEED_THRESHOLD",),
    )


def evaluate_repeated_approval_failures(
    context: EvaluationContext, rule: AlertRule
) -> AlertRuleFiring | None:
    """Fire when approval decisions are denied/expired more than the threshold.

    Evidence token: ``APPROVAL_FAILURES_EXCEED_THRESHOLD``.
    """
    events = _window_events(context, rule.window_seconds)
    failures = sum(
        1
        for event in events
        if event.get("event_type") == AuditEventType.approval_decided.value
        and event.get("decision") == FirewallDecision.block.value
    )
    failures += sum(
        1 for event in events if event.get("event_type") == AuditEventType.approval_expired.value
    )
    if failures < rule.threshold:
        return None
    return AlertRuleFiring(
        rule_id=rule.rule_id,
        kind=rule.kind,
        severity=rule.severity,
        count=failures,
        window_seconds=rule.window_seconds,
        evidence=("APPROVAL_FAILURES_EXCEED_THRESHOLD",),
    )


#: Type alias for a single rule evaluator function.
AlertRuleEvaluator = Callable[[EvaluationContext, AlertRule], AlertRuleFiring | None]

_EVALUATORS: dict[str, AlertRuleEvaluator] = {
    AlertRuleKind.repeated_blocked_calls.value: evaluate_repeated_blocked_calls,
    AlertRuleKind.broad_resource_access.value: evaluate_broad_resource_access,
    AlertRuleKind.burst_reads_across_resources.value: evaluate_burst_reads_across_resources,
    AlertRuleKind.repeated_external_destination_attempts.value: (
        evaluate_repeated_external_destination_attempts
    ),
    AlertRuleKind.repeated_approval_failures.value: evaluate_repeated_approval_failures,
}


def evaluate_rules(
    context: EvaluationContext, config: AlertRuleConfig
) -> tuple[AlertRuleFiring, ...]:
    """Evaluate all enabled rules against read-only audit evidence.

    Returns firings in config order. Never writes to the audit path. Never mutates
    ``config`` or ``context``.
    """
    firings: list[AlertRuleFiring] = []
    for rule in config.enabled_rules():
        evaluator = _EVALUATORS.get(rule.kind.value)
        if evaluator is None:
            # Config validation guarantees this cannot happen for enabled rules.
            continue
        firing = evaluator(context, rule)
        if firing is not None:
            firings.append(firing)
    return tuple(firings)


__all__ = [
    "AlertRuleEvaluator",
    "EvaluationContext",
    "evaluate_rules",
    "evaluate_repeated_blocked_calls",
    "evaluate_broad_resource_access",
    "evaluate_burst_reads_across_resources",
    "evaluate_repeated_external_destination_attempts",
    "evaluate_repeated_approval_failures",
]
