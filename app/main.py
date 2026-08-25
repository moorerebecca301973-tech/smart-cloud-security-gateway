"""
Smart Cloud Security Gateway
============================
A FastAPI reverse proxy that stands in front of your real backend
("your cloud"). Every request must carry an admin-issued API key; the
gateway scores each request's behavior against a trained XGBoost
DoS/DDoS classifier before forwarding it, blocking and alerting on
anything that looks like an attack.

Run with:  uvicorn app.main:app --host 0.0.0.0 --port 8080
See README.md for full setup, deployment, and API documentation.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import db
from .admin import router as admin_router
from .config import settings
from .model_service import get_model_service
from .proxy import close_http_client, gateway_proxy, get_http_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("gateway")

app = FastAPI(
    title="Smart Cloud Security Gateway",
    description="ML-powered reverse proxy that defends a backend against DoS/DDoS traffic.",
    version="1.0.0",
)

# CORS is only relevant to /admin/* - it's what lets a browser-based admin
# portal (e.g. the React app) hosted on a different origin call these
# endpoints with fetch/XHR. The proxied catch-all route doesn't need this;
# normal API clients aren't subject to browser CORS at all.
_admin_origins = [o.strip() for o in settings.admin_portal_origins.split(",") if o.strip()]
if _admin_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_admin_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(admin_router)


@app.on_event("startup")
async def on_startup() -> None:
    db.init_db()
    get_model_service()  # fail fast if the model artifacts are missing/broken
    get_http_client()
    logger.info("Gateway ready. Protecting backend=%s threshold=%.2f", settings.backend_url, settings.attack_threshold)


@app.on_event("shutdown")
async def on_shutdown() -> None:
    await close_http_client()


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "backend": settings.backend_url}


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal gateway error."})


# Catch-all reverse-proxy route. MUST be registered last so /admin/* and
# /health above take precedence.
@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    include_in_schema=False,
)
async def proxy_all(full_path: str, request: Request):
    return await gateway_proxy(request, full_path)
