from fastapi.testclient import TestClient
from app.main import app

def test_correlation_id_is_echoed():
    client = TestClient(app)
    cid = "test-correlation-123"
    r = client.get("/healthz", headers={"X-Correlation-Id": cid})
    assert r.status_code == 200
    assert r.headers.get("X-Correlation-Id") == cid

def test_correlation_id_generated_when_missing():
    client = TestClient(app)
    r = client.get("/healthz")
    assert r.status_code == 200
    assert "X-Correlation-Id" in r.headers
    assert len(r.headers["X-Correlation-Id"]) > 0
