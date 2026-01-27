import pytest

from app.domain.policy_loader import PolicyLoadError, load_policy_from_str


def test_load_policy_valid_json():
    raw = """
    {
      "id": "p1",
      "version": "v1",
      "rules": [
        {
          "id": "r1",
          "effect": "allow",
          "actions": ["read"],
          "resource_type": "report",
          "subject_claims": {"role":"analyst"}
        }
      ]
    }
    """
    policy = load_policy_from_str(raw)
    assert policy.id == "p1"
    assert policy.version == "v1"
    assert len(policy.rules) == 1
    assert policy.rules[0].id == "r1"
    assert policy.rules[0].effect == "allow"


def test_load_policy_rejects_extra_fields():
    raw = """
    {
      "id": "p1",
      "version": "v1",
      "rules": [],
      "unexpected": "nope"
    }
    """
    with pytest.raises(PolicyLoadError) as e:
        load_policy_from_str(raw)
    assert "extra" in str(e.value).lower() or "unexpected" in str(e.value).lower()


def test_load_policy_rejects_invalid_effect():
    raw = """
    {
      "id": "p1",
      "version": "v1",
      "rules": [
        {
          "id": "r1",
          "effect": "maybe",
          "actions": ["read"],
          "resource_type": "report"
        }
      ]
    }
    """
    with pytest.raises(PolicyLoadError):
        load_policy_from_str(raw)
