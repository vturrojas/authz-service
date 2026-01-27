from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """
    Deliberately constrained rule model.

    Matching is exact and AND-based:
    - action in actions
    - resource.type matches
    - subject_claims is a subset match of request.subject.claims
    - resource_attrs is a subset match of request.resource.attrs
    - context_claims is a subset match of request.context
    """
    id: str
    effect: str  # "allow" | "deny"
    actions: Sequence[str]
    resource_type: str
    subject_claims: Mapping[str, Any] = None
    resource_attrs: Mapping[str, Any] = None
    context_claims: Mapping[str, Any] = None


@dataclass(frozen=True, slots=True)
class Policy:
    id: str
    version: str
    rules: Sequence[PolicyRule]
