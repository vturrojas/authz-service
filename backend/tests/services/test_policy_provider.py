from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.services.policy_provider import PolicyProviderError, policy_provider_from_env


def test_policy_provider_requires_env_var(monkeypatch):
    monkeypatch.delenv("AUTHZ_POLICY_PATH", raising=False)
    with pytest.raises(PolicyProviderError):
        policy_provider_from_env()


def test_policy_provider_loads_policy(tmp_path: Path, monkeypatch):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        """
        {
          "id": "p1",
          "version": "v1",
          "rules": [
            {
              "id": "r1",
              "effect": "allow",
              "actions": ["read"],
              "resource_type": "report"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    monkeypatch.setenv("AUTHZ_POLICY_PATH", str(policy_file))
    monkeypatch.setenv("AUTHZ_POLICY_RELOAD", "0")

    provider = policy_provider_from_env()
    policy = provider.get()
    assert policy.id == "p1"
    assert policy.version == "v1"
    assert len(policy.rules) == 1
    assert policy.rules[0].id == "r1"
