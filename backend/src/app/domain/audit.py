from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence


@dataclass(frozen=True, slots=True)
class AuditRecord:
    decision_id: str
    policy_id: str
    policy_version: str

    subject_id: str
    action: str
    resource_type: str
    resource_id: Optional[str]

    decision: str  # allow|deny
    reason: str
    matched_rule_ids: Sequence[str]

    context: Mapping[str, Any]
    created_at: str  # RFC3339/ISO timestamp (UTC)

    correlation_id: str
