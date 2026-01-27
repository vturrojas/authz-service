from app.domain.evaluator import evaluate
from app.domain.policy import Policy, PolicyRule
from app.domain.types import AuthorizationRequest, Resource, Subject


def _req(
    *,
    subject_id="user:1",
    subject_claims=None,
    action="read",
    resource_type="report",
    resource_id="rpt:1",
    resource_attrs=None,
    context=None,
):
    return AuthorizationRequest(
        subject=Subject(id=subject_id, claims=subject_claims or {}),
        action=action,
        resource=Resource(type=resource_type, id=resource_id, attrs=resource_attrs),
        context=context or {},
    )


def test_deny_by_default_when_no_rules_match():
    policy = Policy(id="p1", version="v1", rules=[])
    dec = evaluate(_req(), policy)
    assert dec.decision == "deny"
    assert dec.reason == "deny_by_default"
    assert dec.matched_rule_ids == []


def test_allow_when_allow_rule_matches():
    policy = Policy(
        id="p1",
        version="v1",
        rules=[
            PolicyRule(
                id="r1",
                effect="allow",
                actions=["read"],
                resource_type="report",
                subject_claims={"role": "analyst"},
            )
        ],
    )
    dec = evaluate(_req(subject_claims={"role": "analyst"}), policy)
    assert dec.decision == "allow"
    assert dec.reason == "matched_allow"
    assert dec.matched_rule_ids == ["r1"]


def test_explicit_deny_overrides_allow():
    policy = Policy(
        id="p1",
        version="v1",
        rules=[
            PolicyRule(
                id="allow1",
                effect="allow",
                actions=["read"],
                resource_type="report",
                subject_claims={"role": "analyst"},
            ),
            PolicyRule(
                id="deny1",
                effect="deny",
                actions=["read"],
                resource_type="report",
                subject_claims={"role": "analyst"},
                context_claims={"env": "prod"},
            ),
        ],
    )
    dec = evaluate(_req(subject_claims={"role": "analyst"}, context={"env": "prod"}), policy)
    assert dec.decision == "deny"
    assert dec.reason == "explicit_deny"
    assert dec.matched_rule_ids == ["allow1", "deny1"]


def test_subset_match_resource_attrs():
    policy = Policy(
        id="p1",
        version="v1",
        rules=[
            PolicyRule(
                id="r1",
                effect="allow",
                actions=["read"],
                resource_type="report",
                resource_attrs={"classification": "cui"},
            )
        ],
    )
    dec = evaluate(_req(resource_attrs={"classification": "cui", "owner": "team-a"}), policy)
    assert dec.decision == "allow"
    assert dec.matched_rule_ids == ["r1"]
