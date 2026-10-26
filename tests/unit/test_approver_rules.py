"""Approver-rule parsing and evaluation tests (blueprint section 13.2).

The rule language is intentionally tiny: it can only compare verified principal
attributes and must fail loudly at startup rather than produce an approval that can
never be satisfied.
"""

from __future__ import annotations

import pytest

from ai_security.identity.approver_rules import (
    MAX_RULE_LENGTH,
    ApproverRuleError,
    parse_approver_rule,
)
from ai_security.identity.models import Principal


def _principal(
    subject_id: str = "user-1",
    roles: tuple[str, ...] = ("analyst",),
) -> Principal:
    return Principal(
        subject_id=subject_id,
        roles=roles,
        auth_method="host-hmac",
        issuer="local-dev",
        permissions_context_ref="ctx-1",
    )


def test_role_rule_matches_any_held_role() -> None:
    rule = parse_approver_rule("role:approver")
    assert rule.matches(_principal(roles=("viewer", "approver")))
    assert not rule.matches(_principal(roles=("viewer",)))


def test_principal_rule_matches_only_that_subject() -> None:
    rule = parse_approver_rule("principal:user-2")
    assert rule.matches(_principal(subject_id="user-2", roles=()))
    assert not rule.matches(_principal(subject_id="user-1", roles=("approver",)))


def test_alternatives_are_ored_and_whitespace_is_ignored() -> None:
    rule = parse_approver_rule(" role:ops | principal:user-2 ")
    assert rule.matches(_principal(roles=("ops",)))
    assert rule.matches(_principal(subject_id="user-2", roles=()))
    assert not rule.matches(_principal(subject_id="user-3", roles=("viewer",)))


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "admin",
        "role:",
        ":approver",
        "role:bad role",
        "role:-bad",
        "role:bad-",
        "role:approver|role:approver",
        "principal:user-2|principal:user-2",
        "unknown:value",
        "role:approver|",
        "|role:approver",
        "role:approver| \t |principal:user-2",
        "role:approver:extra",
        "principal:user\x00-2",
    ],
)
def test_rejects_malformed_rules(raw: str) -> None:
    with pytest.raises(ApproverRuleError):
        parse_approver_rule(raw)


def test_rejects_non_string_and_oversized_rules() -> None:
    with pytest.raises(ApproverRuleError):
        parse_approver_rule(None)
    with pytest.raises(ApproverRuleError):
        parse_approver_rule(("role:approver",))
    with pytest.raises(ApproverRuleError, match="at most"):
        parse_approver_rule("role:" + "a" * MAX_RULE_LENGTH)


def test_distinct_alternatives_survive_parsing() -> None:
    rule = parse_approver_rule("role:ops|role:security|principal:user-9")
    assert rule.roles == frozenset({"ops", "security"})
    assert rule.principals == frozenset({"user-9"})


def test_requester_only_principal_rule_is_unsatisfiable_without_self_approval() -> None:
    requester = _principal(subject_id="user-1")
    rule = parse_approver_rule("principal:user-1")
    assert not rule.is_satisfiable_for(requester=requester, self_approval_allowed=False)
    assert rule.is_satisfiable_for(requester=requester, self_approval_allowed=True)


def test_requester_plus_other_principal_remains_satisfiable() -> None:
    requester = _principal(subject_id="user-1")
    rule = parse_approver_rule("principal:user-1|principal:user-2")
    assert rule.is_satisfiable_for(requester=requester, self_approval_allowed=False)


def test_role_rules_remain_satisfiable_even_when_requester_holds_the_role() -> None:
    requester = _principal(subject_id="user-1", roles=("approver",))
    rule = parse_approver_rule("role:approver")
    assert rule.is_satisfiable_for(requester=requester, self_approval_allowed=False)
