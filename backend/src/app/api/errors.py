from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from fastapi import Request
from fastapi.responses import JSONResponse


@dataclass(frozen=True, slots=True)
class ErrorBody:
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None


def error_response(request: Request, *, status_code: int, code: str, message: str, details=None) -> JSONResponse:
    cid = getattr(request.state, "correlation_id", None)
    payload: Dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
        }
    }
    if details:
        payload["error"]["details"] = details
    if cid:
        payload["error"]["correlation_id"] = cid
    return JSONResponse(status_code=status_code, content=payload)
