from __future__ import annotations

import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


CORRELATION_HEADER = "X-Correlation-Id"


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    - If client provides X-Correlation-Id, trust it as an opaque string (bounded length).
    - Otherwise generate a UUID4.
    - Store on request.state.correlation_id
    - Echo back on response header.
    """

    def __init__(self, app, max_len: int = 128):
        super().__init__(app)
        self.max_len = max_len

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        raw = request.headers.get(CORRELATION_HEADER)
        if raw:
            cid = raw.strip()[: self.max_len]
        else:
            cid = str(uuid.uuid4())

        request.state.correlation_id = cid
        response = await call_next(request)
        response.headers[CORRELATION_HEADER] = cid
        return response
