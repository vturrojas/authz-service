from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.domain.audit import AuditRecord


class AuditSinkError(RuntimeError):
    pass


class JsonlAuditSink:
    """
    Append-only audit sink that writes one JSON object per line.

    v0 intent:
    - deterministic, operator-friendly
    - no background threads
    - easy to swap for DB later
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def write(self, record: AuditRecord) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(asdict(record), separators=(",", ":"), sort_keys=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as e:
            raise AuditSinkError(f"Failed to write audit record to {self.path}") from e


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def audit_sink_from_env() -> Optional[JsonlAuditSink]:
    """
    If AUTHZ_AUDIT_PATH is unset, auditing is disabled (v0 default is explicit via env).
    """
    path = os.getenv("AUTHZ_AUDIT_PATH", "").strip()
    if not path:
        return None
    return JsonlAuditSink(Path(path))
