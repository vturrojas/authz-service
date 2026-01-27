from __future__ import annotations

from pathlib import Path
import json

from fastapi.testclient import TestClient

from app.main import app


def test_authorize_endpoint_allow(tmp_path: Path, monkeypatch):
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
              "resource_type": "report",
              "subject_claims": {"role":"analyst"}
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    monkeypatch.setenv("AUTHZ_POLICY_PATH", str(policy_file))
    monkeypatch.setenv("AUTHZ_POLICY_RELOAD", "0")

    client = TestClient(app)
    r = client.post(
        "/v1/authorize",
        json={
            "subject": {"id": "user:1", "claims": {"role": "analyst"}},
            "action": "read",
            "resource": {"type": "report", "id": "rpt:1", "attrs": {}},
            "context": {"env": "dev"},
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "allow"
    assert body["policy_id"] == "p1"
    assert body["policy_version"] == "v1"
    assert body["matched_rule_ids"] == ["r1"]
    assert "decision_id" in body


def test_authorize_writes_audit_when_enabled(tmp_path: Path, monkeypatch):
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
              "resource_type": "report",
              "subject_claims": {"role":"analyst"}
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    audit_path = tmp_path / "audit.jsonl"

    monkeypatch.setenv("AUTHZ_POLICY_PATH", str(policy_file))
    monkeypatch.setenv("AUTHZ_POLICY_RELOAD", "0")
    monkeypatch.setenv("AUTHZ_AUDIT_PATH", str(audit_path))

    client = TestClient(app)
    r = client.post(
        "/v1/authorize",
        json={
            "subject": {"id": "user:1", "claims": {"role": "analyst"}},
            "action": "read",
            "resource": {"type": "report", "id": "rpt:1", "attrs": {}},
            "context": {"env": "dev"},
        },
    )
    assert r.status_code == 200
    cid = r.headers["X-Correlation-Id"]
    assert audit_path.exists()

    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    obj = json.loads(lines[0])
    assert obj["decision"] == "allow"
    assert obj["policy_id"] == "p1"
    assert obj["correlation_id"] == cid
