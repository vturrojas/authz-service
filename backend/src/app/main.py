from fastapi import FastAPI

from app.api.authorize import router as authorize_router
from app.api.middleware import CorrelationIdMiddleware

app = FastAPI(title="AuthZ Service", version="0.1.0")
app.add_middleware(CorrelationIdMiddleware)

@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}

app.include_router(authorize_router)
