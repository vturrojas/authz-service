from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence


@dataclass(frozen=True, slots=True)
class Subject:
    """
    A caller identity as seen by this service.

    This is NOT a user directory record. Upstream authentication is assumed.
    """
    id: str
    claims: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class Resource:
    """
    A target of an action. Minimal shape: type is required; id/attrs are optional.
    """
    type: str
    id: Optional[str] = None
    attrs: Mapping[str, Any] = None  # optional bag of attributes


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    subject: Subject
    action: str
    resource: Resource
    context: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    decision: str  # "allow" | "deny"
    reason: str
    matched_rule_ids: Sequence[str]
