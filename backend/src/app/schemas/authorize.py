from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class SubjectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    claims: Dict[str, Any] = Field(default_factory=dict)


class ResourceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str
    id: Optional[str] = None
    attrs: Dict[str, Any] = Field(default_factory=dict)


class AuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: SubjectIn
    action: str
    resource: ResourceIn
    context: Dict[str, Any] = Field(default_factory=dict)


class AuthorizeResponse(BaseModel):
    decision: str  # allow|deny
    reason: str
    decision_id: str
    policy_id: str
    policy_version: str
    matched_rule_ids: list[str]
