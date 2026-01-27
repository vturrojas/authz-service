from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.domain.policy import Policy, PolicyRule


# ----------------------------
# Pydantic models (I/O boundary)
# ----------------------------

class PolicyRuleDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    effect: str = Field(pattern="^(allow|deny)$")
    actions: List[str] = Field(min_length=1)
    resource_type: str

    # Optional constrained predicates (subset equality matches)
    subject_claims: Optional[Dict[str, Any]] = None
    resource_attrs: Optional[Dict[str, Any]] = None
    context_claims: Optional[Dict[str, Any]] = None


class PolicyDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    version: str
    rules: List[PolicyRuleDTO]


# ----------------------------
# Public API
# ----------------------------

class PolicyLoadError(RuntimeError):
    pass


def load_policy_from_str(raw_json: str) -> Policy:
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        raise PolicyLoadError(f"Invalid JSON: {e.msg} at line {e.lineno} col {e.colno}") from e

    return _parse_policy_obj(data)


def load_policy_from_file(path: str | Path) -> Policy:
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise PolicyLoadError(f"Could not read policy file: {p}") from e

    return load_policy_from_str(raw)


# ----------------------------
# Internals
# ----------------------------

def _parse_policy_obj(obj: Mapping[str, Any]) -> Policy:
    try:
        dto = PolicyDTO.model_validate(obj)
    except ValidationError as e:
        # Keep errors readable for humans; no huge dumps
        raise PolicyLoadError(f"Policy validation failed: {e}") from e

    return Policy(
        id=dto.id,
        version=dto.version,
        rules=[
            PolicyRule(
                id=r.id,
                effect=r.effect,
                actions=r.actions,
                resource_type=r.resource_type,
                subject_claims=r.subject_claims,
                resource_attrs=r.resource_attrs,
                context_claims=r.context_claims,
            )
            for r in dto.rules
        ],
    )
