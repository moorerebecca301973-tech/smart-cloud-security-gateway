"""
The core gateway: every request that isn't /admin/* or /health lands here.

Pipeline for each request:
  1. Resolve the client's real IP.
  2. Reject immediately if that IP is on the blocklist.
  3. Validate the caller's API key (issued by an admin via /admin/api-keys).
     Track repeated invalid-key attempts as a brute-force signal.
  4. Feed this request (plus this IP's recent history) into the DoS/DDoS
     model. If it scores as an attack: block the request, blocklist the
     IP, flag/optionally auto-revoke the API key, and alert the admin.
  5. Otherwise forward the request to BACKEND_URL unchanged and relay the
     response back to the caller.
"""
from __future__ import annotations

import logging
import time

import httpx
from fastapi import APIRouter, HTTPException, Request, Response

from . import db
from .alerts import raise_alert
from .config import settings
from .flow_tracker import get_flow_tracker
from .model_service import get_model_service
from .security import extract_api_key, validate_api_key

logger = logging.getLogger("gateway.proxy")
router = APIRouter()

# Headers that must not be blindly forwarded between hops (RFC 7230 6.1 plus
# a couple of proxy-specific ones we set ourselves).
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
}
# The caller's credential for THIS gateway - never forward it on to the
# backend (it's not the backend's auth scheme, and forwarding it would leak
# a live API key to a downstream service unnecessarily).
_STRIP_ON_FORWARD = _HOP_BY_HOP | {"x-api-key", "authorization", "x-internal-service-token"}

_http_client: httpx.AsyncClient | None = None


def get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=settings.upstream_timeout_seconds)
    return _http_client


async def close_http_client() -> None:
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None


def get_client_ip(request: Request) -> str:
    if settings.trust_proxy_headers:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
    return request.client.host if request.client else "unknown"


def _header_bytes(headers: dict) -> int:
    return sum(len(k) + len(v) + 4 for k, v in headers.items())  # +4 for ": " and CRLF


async def gateway_proxy(request: Request, full_path: str) -> Response:
    ip = get_client_ip(request)
    now = time.time()

    # 1. Blocklist check - cheapest, do it first.
    block = db.is_blocked(ip)
    if block is not None:
        db.log_request(ip, None, request.method, full_path, "blocked_ip", None, 403)
        raise HTTPException(status_code=403, detail="Your IP address is blocked.")

    # 2. API key check.
    raw_key = extract_api_key(request)
    key_row = validate_api_key(raw_key) if raw_key else None
    if key_row is None:
        failures = db.record_auth_failure(ip)
        db.log_request(ip, None, request.method, full_path, "unauthorized", None, 401)
        if failures >= settings.auth_failures_before_block:
            db.block_ip(
                ip,
                f"{failures} invalid API key attempts within {settings.auth_failure_window_seconds}s",
                settings.block_duration_seconds,
            )
            await raise_alert(
                severity="high",
                message=f"IP blocked after {failures} failed auth attempts (possible credential stuffing / recon)",
                ip=ip, method=request.method, path=full_path,
            )
        raise HTTPException(status_code=401, detail="Missing or invalid API key.")

    db.touch_api_key(key_row["id"])

    # 3. Read body (bounded) and build a request-size fingerprint.
    body = await request.body()
    if len(body) > settings.max_request_body_bytes:
        db.log_request(ip, key_row["id"], request.method, full_path, "rejected_size", None, 413)
        raise HTTPException(status_code=413, detail="Request body too large.")

    req_headers = dict(request.headers)
    req_header_bytes = _header_bytes(req_headers)
    req_bytes = len(body) + req_header_bytes + len(request.method) + len(str(request.url))

    # 4. Score this request against the DoS/DDoS model.
    tracker = get_flow_tracker()
    features, flow_event = tracker.begin_request(
        ip=ip, method=request.method, path=full_path,
        req_bytes=req_bytes, req_header_bytes=req_header_bytes, has_body=len(body) > 0,
    )

    # 4a. Deterministic rate limit - ALWAYS enforced (not gated by
    # ENFORCEMENT_MODE). "req_count" is this IP's request count within the
    # flow window we just computed; catching raw volumetric floods doesn't
    # need the ML model or any calibration to be trustworthy.
    if settings.rate_limit_enabled and features.get("req_count", 0) > settings.rate_limit_max_requests:
        tracker.mark_blocked(flow_event)
        db.block_ip(
            ip,
            f"Rate limit exceeded: {int(features['req_count'])} requests within "
            f"{settings.flow_window_seconds:.0f}s (cap={settings.rate_limit_max_requests})",
            settings.block_duration_seconds,
        )
        flag_count = db.flag_api_key(key_row["id"])
        db.log_request(ip, key_row["id"], request.method, full_path, "blocked_rate_limit", None, 429, features=features)
        await raise_alert(
            severity="critical",
            message=f"Blocked {ip}: exceeded {settings.rate_limit_max_requests} req/{settings.flow_window_seconds:.0f}s rate limit",
            ip=ip, api_key_id=key_row["id"], method=request.method, path=full_path,
        )
        if settings.auto_revoke_key_after_flags > 0 and flag_count >= settings.auto_revoke_key_after_flags and not key_row["is_admin"]:
            db.revoke_api_key(key_row["id"], reason=f"auto-revoked after {flag_count} attack flags")
            await raise_alert(
                severity="high",
                message=f"API key '{key_row['owner']}' auto-revoked after {flag_count} attack flags",
                ip=ip, api_key_id=key_row["id"],
            )
        raise HTTPException(status_code=429, detail="Rate limit exceeded - too many requests.")

    # 4b. ML scoring - skipped entirely for keys an admin has marked
    # exempt_from_ml (still subject to the blocklist, rate limit, and auth
    # guard above). Exists because a legitimate high-throughput automated
    # client can have machine-precise, uniform request timing that is
    # statistically indistinguishable from a flood on pure behavioral
    # features - the admin who issued the key knows better than the model.
    attack_probability = None
    flagged = False
    if not key_row["exempt_from_ml"]:
        model = get_model_service()
        attack_probability, _ = model.predict(features)
        flagged = model.is_attack(attack_probability)
    enforcing = settings.enforcement_mode.lower() == "enforce" and not key_row["exempt_from_ml"]

    if flagged and enforcing:
        tracker.mark_blocked(flow_event)
        db.block_ip(
            ip,
            f"ML DoS/DDoS detection (p={attack_probability:.4f}) on {request.method} {full_path}",
            settings.block_duration_seconds,
        )
        flag_count = db.flag_api_key(key_row["id"])
        db.log_request(ip, key_row["id"], request.method, full_path, "blocked_ml", attack_probability, 403, features=features)
        await raise_alert(
            severity="critical",
            message=f"Blocked suspected DoS/DDoS traffic from {ip} (probability={attack_probability:.4f})",
            ip=ip, api_key_id=key_row["id"], attack_probability=attack_probability,
            method=request.method, path=full_path,
        )
        if (
            settings.auto_revoke_key_after_flags > 0
            and flag_count >= settings.auto_revoke_key_after_flags
            and not key_row["is_admin"]
        ):
            db.revoke_api_key(key_row["id"], reason=f"auto-revoked after {flag_count} attack flags")
            await raise_alert(
                severity="high",
                message=f"API key '{key_row['owner']}' auto-revoked after {flag_count} attack flags",
                ip=ip, api_key_id=key_row["id"],
            )
        raise HTTPException(
            status_code=403,
            detail="Request blocked: identified as DoS/DDoS traffic by the security model.",
        )

    if flagged and not enforcing:
        # MONITOR mode: surface the finding without touching real traffic,
        # so an admin can calibrate ATTACK_THRESHOLD against real numbers
        # (see /admin/requests) before switching ENFORCEMENT_MODE=enforce.
        await raise_alert(
            severity="warning",
            message=f"[monitor mode] Would have blocked traffic from {ip} (probability={attack_probability:.4f}) - not enforced",
            ip=ip, api_key_id=key_row["id"], attack_probability=attack_probability,
            method=request.method, path=full_path,
        )

    # 5. Clean and forward to the real backend.
    outbound_headers = {
        k: v for k, v in req_headers.items() if k.lower() not in _STRIP_ON_FORWARD
    }
    outbound_headers["x-forwarded-for"] = ip
    outbound_headers["x-forwarded-proto"] = request.url.scheme
    # Identity of the calling client, for the backend's own logging/authz -
    # the raw key itself is never forwarded (see _STRIP_ON_FORWARD above).
    outbound_headers["x-gateway-client-id"] = str(key_row["id"])
    outbound_headers["x-gateway-client-owner"] = key_row["owner"]
    if settings.backend_internal_token:
        outbound_headers["x-internal-service-token"] = settings.backend_internal_token

    target_url = settings.backend_url.rstrip("/") + "/" + full_path.lstrip("/")

    client = get_http_client()
    try:
        upstream_response = await client.request(
            method=request.method,
            url=target_url,
            params=request.query_params,
            headers=outbound_headers,
            content=body,
        )
    except httpx.RequestError as exc:
        tracker.complete_request(flow_event, resp_bytes=0, resp_header_bytes=0, status_code=502)
        db.log_request(ip, key_row["id"], request.method, full_path, "upstream_error", attack_probability, 502)
        logger.error("Upstream request failed: %s", exc)
        raise HTTPException(status_code=502, detail="Upstream service unavailable.") from exc

    resp_body = upstream_response.content
    resp_headers = {
        k: v for k, v in upstream_response.headers.items() if k.lower() not in _HOP_BY_HOP
    }
    tracker.complete_request(
        flow_event,
        resp_bytes=len(resp_body) + _header_bytes(resp_headers),
        resp_header_bytes=_header_bytes(resp_headers),
        status_code=upstream_response.status_code,
    )
    db.log_request(
        ip, key_row["id"], request.method, full_path,
        "flagged_monitor" if flagged else "allowed",
        attack_probability, upstream_response.status_code, features=features,
    )

    return Response(
        content=resp_body,
        status_code=upstream_response.status_code,
        headers=resp_headers,
    )
