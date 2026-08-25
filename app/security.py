"""
Auth helpers: API-key validation for client traffic, and a single shared
admin secret for /admin/* endpoints.
"""
from __future__ import annotations

import hmac
import sqlite3
from typing import Optional

from fastapi import Header, HTTPException, Request, status

from . import db
from .config import settings


def extract_api_key(request: Request) -> Optional[str]:
    header_key = request.headers.get("x-api-key")
    if header_key:
        return header_key.strip()
    auth = request.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def validate_api_key(raw_key: str) -> Optional[sqlite3.Row]:
    if not raw_key:
        return None
    return db.lookup_api_key(raw_key)


def require_admin(request: Request, x_admin_token: str = Header(default="")) -> None:
    """Accepts the admin token either as an X-Admin-Token header (used by
    API clients / curl) or a ?token= query parameter (used by the
    browser-facing dashboard, since browsers can't set custom headers on a
    plain navigation)."""
    supplied = x_admin_token or request.query_params.get("token", "")
    if not settings.admin_bootstrap_token or not hmac.compare_digest(
        supplied, settings.admin_bootstrap_token
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid admin token")
