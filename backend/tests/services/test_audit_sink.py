from __future__ import annotations

import json
from pathlib import Path

from app.domain.audit import AuditRecord
from app.services.audit_sink import JsonlAuditSink


def test_jsonl_audit_sink_appends_one_line(tmp_path: Path):
    path = tmp_path / "audit" / "audit.jsonl"
    sink = JsonlAuditSink(path)

    r1 = AuditRecord(
        correlation_id="cid-1",
        decision_id="d1",
        policy_id="p1",
        policy_version="v1",
        subject_id="user:1",
        action="read",
        resource_type="report",
        resource_id="rpt:1",
        decision="allow",
        reason="matched_allow",
        matched_rule_ids=["r1"],
        context={"env": "dev"},
        created_at="2026-01-27T00:00:00Z",
    )
    sink.write(r1)

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    obj = json.loads(lines[0])
    assert obj["decision_id"] == "d1"
    assert obj["decision"] == "allow"
