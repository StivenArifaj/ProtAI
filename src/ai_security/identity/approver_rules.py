"""Verified-principal approver rules (blueprint section 13.2).

`required_approver_rule` is a small, strictly parsed predicate over attributes of the
verified `Principal` produced by the authorization context. It never accepts a role,
permission, or principal id from model output, a request body, or any other untrusted
field.

V1 grammar (deliberately not a scripting language)::

    rule      := alternative ("|" alternative)*
    alternative := "role:" role-name | "principal:" subject-id

A rule matches when any alternative matches. Role names are limited to the same stable
identifier shape used elsewhere; principal ids are control-free strings (the identity
contract permits up to 256 characters). Whitespace around alternatives is ignored, but
no other syntax is accepted. Malformed rules fail registration at startup rather than
becoming an action that can never be approved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Principal

MAX_RULE_LENGTH = 256
_ROLE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ApproverRuleError(ValueError):
    """The configured approver rule is not valid v1 syntax."""


@dataclass(frozen=True)
class ApproverRule:
    """A parsed approver predicate over verified principal attributes."""

    roles: frozenset[str]
    principals: frozenset[str]

    def matches(self, principal: Principal) -> bool:
        """Whether this verified principal satisfies at least one alternative."""
        if principal.subject_id in self.principals:
            return True
        return any(role in self.roles for role in principal.roles)

    def is_satisfiable_for(
        self,
        *,
        requester: Principal,
        self_approval_allowed: bool,
    ) -> bool:
        """Reject the one rule shape that is provably unsatisfiable before storage.

        A rule listing only the requester as a specific principal can never be approved
        when self-approval is disabled. Role rules are not provably unsatisfiable from
        the requester's attributes alone (another role holder may exist), so they remain
        pending rather than being silently rejected.
        """
        if self_approval_allowed or self.roles:
            return True
        return bool(self.principals - {requester.subject_id})


def parse_approver_rule(raw: object) -> ApproverRule:
    """Parse a `required_approver_rule`; any malformed form raises."""
    if not isinstance(raw, str) or not raw.strip():
        raise ApproverRuleError("required_approver_rule must be a non-empty string")
    if len(raw) > MAX_RULE_LENGTH:
        raise ApproverRuleError(
            f"required_approver_rule must be at most {MAX_RULE_LENGTH} characters"
        )
    if _CONTROL.search(raw):
        raise ApproverRuleError("required_approver_rule must not contain control characters")

    roles: set[str] = set()
    principals: set[str] = set()
    seen: set[tuple[str, str]] = set()
    for raw_alternative in raw.split("|"):
        alternative = raw_alternative.strip()
        if not alternative:
            raise ApproverRuleError("required_approver_rule contains an empty alternative")
        prefix, separator, value = alternative.partition(":")
        if not separator:
            raise ApproverRuleError(
                "required_approver_rule alternatives must use 'role:' or 'principal:'"
            )
        prefix = prefix.strip()
        value = value.strip()
        if prefix == "role":
            if _ROLE.fullmatch(value) is None:
                raise ApproverRuleError(
                    "role alternatives must be 1-128 characters of [A-Za-z0-9._-] "
                    "starting and ending alphanumeric"
                )
            if ("role", value) in seen:
                raise ApproverRuleError("required_approver_rule repeats an alternative")
            seen.add(("role", value))
            roles.add(value)
        elif prefix == "principal":
            if not value or len(value) > 256 or _CONTROL.search(value) or value != value.strip():
                raise ApproverRuleError(
                    "principal alternatives must be 1-256 control-free characters"
                )
            if ("principal", value) in seen:
                raise ApproverRuleError("required_approver_rule repeats an alternative")
            seen.add(("principal", value))
            principals.add(value)
        else:
            raise ApproverRuleError(
                "required_approver_rule alternatives must use 'role:' or 'principal:'"
            )

    return ApproverRule(roles=frozenset(roles), principals=frozenset(principals))


__all__ = [
    "ApproverRule",
    "ApproverRuleError",
    "MAX_RULE_LENGTH",
    "parse_approver_rule",
]
