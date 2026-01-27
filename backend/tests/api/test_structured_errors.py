import pytest
from fastapi.testclient import TestClient
from app.main import app

def test_policy_unavailable_is_structured(monkeypatch):
    monkeypatch.delenv("AUTHZ_POLICY_PATH", raising=False)
    client = TestClient(app)
    r = client.post(
        "/v1/authorize",
        json={
            "subject": {"id": "user:1", "claims": {}},
            "action": "read",
            "resource": {"type": "report", "id": "r1", "attrs": {}},
            "context": {},
        },
    )
    assert r.status_code == 500
    body = r.json()
    assert "error" in body
    assert body["error"]["code"] == "policy_unavailable"
    assert "correlation_id" in body["error"]
