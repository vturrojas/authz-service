from __future__ import annotations

from typing import Any, Iterable, Mapping, Tuple

from app.domain.policy import Policy, PolicyRule
from app.domain.types import AuthorizationDecision, AuthorizationRequest


ALLOW = "allow"
DENY = "deny"


def evaluate(req: AuthorizationRequest, policy: Policy) -> AuthorizationDecision:
    """
    Deterministic authorization evaluation.

    Semantics:
    - deny-by-default
    - rules are evaluated in listed order
    - if any matching DENY rule exists, decision is DENY (deny overrides allow)
    - otherwise, if at least one matching ALLOW rule exists, decision is ALLOW
    - auditability: return matched rule ids (all matches; deterministic order)
    """
    matched: list[Tuple[str, str]] = []  # (effect, rule_id)

    for rule in policy.rules:
        if _matches(rule, req):
            matched.append((rule.effect, rule.id))

    matched_rule_ids = [rid for _, rid in matched]

    # Explicit deny wins
    if any(effect == DENY for effect, _ in matched):
        return AuthorizationDecision(decision=DENY, reason="explicit_deny", matched_rule_ids=matched_rule_ids)

    if any(effect == ALLOW for effect, _ in matched):
        return AuthorizationDecision(decision=ALLOW, reason="matched_allow", matched_rule_ids=matched_rule_ids)

    return AuthorizationDecision(decision=DENY, reason="deny_by_default", matched_rule_ids=[])


def _matches(rule: PolicyRule, req: AuthorizationRequest) -> bool:
    if rule.effect not in (ALLOW, DENY):
        return False

    if req.action not in rule.actions:
        return False

    if req.resource.type != rule.resource_type:
        return False

    if rule.subject_claims and not _subset_match(rule.subject_claims, req.subject.claims):
        return False

    # req.resource.attrs may be None
    resource_attrs = req.resource.attrs or {}
    if rule.resource_attrs and not _subset_match(rule.resource_attrs, resource_attrs):
        return False

    if rule.context_claims and not _subset_match(rule.context_claims, req.context):
        return False

    return True


def _subset_match(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> bool:
    """
    True if all (k,v) in expected are present in actual with equality.
    Deliberately no wildcards, regex, numeric comparisons, etc. (v0 scope).
    """
    for k, v in expected.items():
        if k not in actual:
            return False
        if actual[k] != v:
            return False
    return True
