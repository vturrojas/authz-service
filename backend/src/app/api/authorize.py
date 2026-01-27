from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Request

from app.domain.evaluator import evaluate
from app.domain.types import AuthorizationRequest, Resource, Subject
from app.domain.audit import AuditRecord
from app.schemas.authorize import AuthorizeRequest, AuthorizeResponse
from app.services.policy_provider import PolicyProviderError, policy_provider_from_env
from app.services.audit_sink import AuditSinkError, audit_sink_from_env, utc_now_iso
from app.api.errors import error_response

router = APIRouter(tags=["authz"])


@router.post("/v1/authorize", response_model=AuthorizeResponse)
def authorize(request: Request, body: AuthorizeRequest) -> AuthorizeResponse:
    try:
        provider = policy_provider_from_env()
        policy = provider.get()
    except PolicyProviderError as e:
        return error_response(
            request,
            status_code=500,
            code="policy_unavailable",
            message="Active policy could not be loaded.",
            details={"hint": str(e)},
        )

    req = AuthorizationRequest(
        subject=Subject(id=body.subject.id, claims=body.subject.claims),
        action=body.action,
        resource=Resource(type=body.resource.type, id=body.resource.id, attrs=body.resource.attrs),
        context=body.context,
    )

    decision = evaluate(req, policy)
    decision_id = str(uuid.uuid4())

    # Audit (best-effort, but explicit failure mode)
    sink = audit_sink_from_env()
    if sink is not None:
        record = AuditRecord(
            correlation_id=request.state.correlation_id,
            decision_id=decision_id,
            policy_id=policy.id,
            policy_version=policy.version,
            subject_id=req.subject.id,
            action=req.action,
            resource_type=req.resource.type,
            resource_id=req.resource.id,
            decision=decision.decision,
            reason=decision.reason,
            matched_rule_ids=list(decision.matched_rule_ids),
            context=req.context,
            created_at=utc_now_iso(),
        )
        try:
            sink.write(record)
        except AuditSinkError as e:
            return error_response(
                request,
                status_code=500,
                code="audit_write_failed",
                message="Audit write failed.",
                details={"hint": str(e)},
            )

    return AuthorizeResponse(
        decision=decision.decision,
        reason=decision.reason,
        decision_id=decision_id,
        policy_id=policy.id,
        policy_version=policy.version,
        matched_rule_ids=list(decision.matched_rule_ids),
    )
