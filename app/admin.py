"""
Admin API: issue/revoke client API keys, manage the IP blocklist, and
review alerts/traffic. Every route here requires the X-Admin-Token header
to match ADMIN_BOOTSTRAP_TOKEN (see .env.example).

Also serves a tiny dependency-free HTML dashboard at GET /admin/dashboard
(pass the token as ?token=... since a browser can't easily set a custom
header) for a quick human-readable view.
"""
from __future__ import annotations

import html
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from . import db
from .config import settings
from .model_service import get_model_service
from .security import require_admin

router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])


# --------------------------------------------------------------------------
# API keys
# --------------------------------------------------------------------------

class CreateApiKeyRequest(BaseModel):
    owner: str = Field(..., description="Human-readable label, e.g. an app/team/user name")
    is_admin: bool = False
    exempt_from_ml: bool = Field(
        default=False,
        description=(
            "Skip ML scoring for this key's traffic (still subject to the "
            "deterministic rate limiter, blocklist, and auth guard). Use for "
            "known trusted automated clients - e.g. a legitimate bulk-import "
            "integration - whose precise, machine-regular timing can look "
            "statistically identical to a flood on pure behavioral features."
        ),
    )


@router.post("/api-keys")
def create_api_key(body: CreateApiKeyRequest):
    raw_key, key_id = db.create_api_key(
        owner=body.owner, is_admin=body.is_admin, exempt_from_ml=body.exempt_from_ml
    )
    return {
        "id": key_id,
        "owner": body.owner,
        "api_key": raw_key,
        "exempt_from_ml": body.exempt_from_ml,
        "warning": "This key is shown once and cannot be retrieved again. Store it securely.",
    }


@router.post("/api-keys/{key_id}/ml-exempt")
def set_api_key_ml_exempt(key_id: int, exempt: bool = Query(...)):
    """Toggle ML-exemption on an existing key without reissuing it."""
    ok = db.set_key_ml_exempt(key_id, exempt)
    if not ok:
        raise HTTPException(status_code=404, detail="key not found or revoked")
    return {"id": key_id, "exempt_from_ml": exempt}


@router.get("/api-keys")
def list_api_keys():
    rows = db.list_api_keys()
    return [
        {
            "id": r["id"], "owner": r["owner"], "key_prefix": r["key_prefix"],
            "is_admin": bool(r["is_admin"]), "is_active": bool(r["is_active"]),
            "exempt_from_ml": bool(r["exempt_from_ml"]),
            "created_at": r["created_at"], "last_used_at": r["last_used_at"],
            "request_count": r["request_count"], "flag_count": r["flag_count"],
            "revoked_reason": r["revoked_reason"],
        }
        for r in rows
    ]


@router.delete("/api-keys/{key_id}")
def revoke_api_key(key_id: int):
    ok = db.revoke_api_key(key_id)
    if not ok:
        raise HTTPException(status_code=404, detail="key not found or already revoked")
    return {"revoked": True, "id": key_id}


# --------------------------------------------------------------------------
# Blocklist
# --------------------------------------------------------------------------

class BlockIpRequest(BaseModel):
    ip: str
    reason: str = "manually blocked by admin"
    duration_seconds: Optional[float] = None
    permanent: bool = False


@router.post("/blocklist")
def block_ip(body: BlockIpRequest):
    db.block_ip(body.ip, body.reason, body.duration_seconds, body.permanent)
    return {"blocked": body.ip}


@router.get("/blocklist")
def get_blocklist(active_only: bool = True):
    rows = db.list_blocklist(active_only=active_only)
    return [dict(r) for r in rows]


@router.delete("/blocklist/{ip}")
def unblock_ip(ip: str):
    n = db.unblock_ip(ip)
    if n == 0:
        raise HTTPException(status_code=404, detail="ip not currently blocked")
    return {"unblocked": ip}


# --------------------------------------------------------------------------
# Alerts / traffic / stats
# --------------------------------------------------------------------------

@router.get("/alerts")
def get_alerts(limit: int = Query(default=100, le=1000)):
    return [dict(r) for r in db.list_alerts(limit=limit)]


@router.get("/requests")
def get_requests(limit: int = Query(default=100, le=1000)):
    return [dict(r) for r in db.list_recent_requests(limit=limit)]


class LabelRequest(BaseModel):
    request_log_id: int
    label: str = Field(..., description="'benign' or 'attack'")


@router.post("/requests/label")
def label_request(body: LabelRequest):
    """Mark a historical request as ground-truth benign or attack traffic.
    Labeled rows (with their stored feature vector) become training data
    for train/export_labeled_data.py + train/train_model.py, so the model
    can be retrained on your real traffic instead of only synthetic data."""
    label_map = {"benign": 0, "attack": 1}
    if body.label not in label_map:
        raise HTTPException(status_code=422, detail="label must be 'benign' or 'attack'")
    ok = db.label_request(body.request_log_id, label_map[body.label])
    if not ok:
        raise HTTPException(
            status_code=404,
            detail="request not found, or it has no stored feature vector (only ML-scored requests can be labeled)",
        )
    return {"labeled": body.request_log_id, "label": body.label}


@router.get("/requests/labeled")
def get_labeled_requests():
    return [dict(r) for r in db.list_labeled_requests()]


@router.get("/stats")
def get_stats():
    stats = db.stats_summary()
    stats["enforcement_mode"] = settings.enforcement_mode
    stats["attack_threshold"] = settings.attack_threshold
    return stats


# --------------------------------------------------------------------------
# Model calibration helper
# --------------------------------------------------------------------------

class ScoreRequest(BaseModel):
    features: dict[str, float] = Field(
        default_factory=dict,
        description="Any subset of the 77 training feature names; anything omitted defaults to 0.",
    )


@router.post("/model/score")
def score_features(body: ScoreRequest):
    """Score an arbitrary feature vector against the model directly,
    bypassing the live flow tracker. Useful for calibrating
    ATTACK_THRESHOLD against known benign/attack traffic samples (e.g.
    replayed from a pcap or CICFlowMeter CSV) before switching
    ENFORCEMENT_MODE=enforce."""
    model = get_model_service()
    probability, _ = model.predict(body.features)
    return {
        "attack_probability": probability,
        "would_block_at_current_threshold": probability >= settings.attack_threshold,
        "current_threshold": settings.attack_threshold,
        "feature_names_expected": model.feature_names,
    }


# --------------------------------------------------------------------------
# Minimal HTML dashboard (no template engine dependency)
# --------------------------------------------------------------------------

def _esc(v) -> str:
    return html.escape(str(v)) if v is not None else ""


def _render_dashboard() -> str:
    stats = db.stats_summary()
    alerts = db.list_alerts(limit=25)
    blocks = db.list_blocklist(active_only=True)
    keys = db.list_api_keys()

    def stat_card(label: str, value) -> str:
        return f'<div class="card"><div class="v">{_esc(value)}</div><div class="l">{_esc(label)}</div></div>'

    stat_cards = "".join([
        stat_card("Active API keys", stats["active_api_keys"]),
        stat_card("Blocked IPs (active)", stats["active_blocked_ips"]),
        stat_card("Allowed / last hour", stats["requests_allowed_last_hour"]),
        stat_card("Blocked / last hour", stats["requests_blocked_last_hour"]),
        stat_card("Alerts / last hour", stats["alerts_last_hour"]),
    ])

    alert_rows = "".join(
        f"<tr><td>{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(a['ts']))}</td>"
        f"<td>{_esc(a['severity'])}</td><td>{_esc(a['ip'])}</td>"
        f"<td>{_esc(round(a['attack_probability'], 4) if a['attack_probability'] is not None else '')}</td>"
        f"<td>{_esc(a['message'])}</td></tr>"
        for a in alerts
    ) or '<tr><td colspan="5">No alerts yet.</td></tr>'

    block_rows = "".join(
        f"<tr><td>{_esc(b['ip'])}</td><td>{_esc(b['reason'])}</td>"
        f"<td>{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(b['blocked_at']))}</td>"
        f"<td>{'permanent' if b['permanent'] else time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(b['expires_at'])) if b['expires_at'] else ''}</td></tr>"
        for b in blocks
    ) or '<tr><td colspan="4">No IPs currently blocked.</td></tr>'

    key_rows = "".join(
        f"<tr><td>{k['id']}</td><td>{_esc(k['owner'])}</td><td>{_esc(k['key_prefix'])}…</td>"
        f"<td>{'yes' if k['is_active'] else 'revoked'}</td><td>{k['request_count']}</td>"
        f"<td>{k['flag_count']}</td></tr>"
        for k in keys
    ) or '<tr><td colspan="6">No API keys issued yet.</td></tr>'

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Smart Cloud Security - Admin</title>
<meta http-equiv="refresh" content="15">
<style>
body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0b1220; color:#e6ecf5; margin:0; padding:24px; }}
h1 {{ font-size:20px; margin-bottom:4px; }}
.sub {{ color:#8a97ab; margin-bottom:20px; font-size:13px; }}
.cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:28px; }}
.card {{ background:#131c2e; border:1px solid #22314a; border-radius:10px; padding:14px 18px; min-width:150px; }}
.card .v {{ font-size:24px; font-weight:600; }}
.card .l {{ font-size:12px; color:#8a97ab; margin-top:4px; }}
h2 {{ font-size:15px; margin-top:32px; color:#cfd8e6; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; background:#131c2e; border-radius:8px; overflow:hidden; }}
th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #22314a; }}
th {{ color:#8a97ab; font-weight:500; }}
tr:last-child td {{ border-bottom:none; }}
</style></head>
<body>
<h1>Smart Cloud Security &mdash; Admin Dashboard</h1>
<div class="sub">Auto-refreshes every 15s. Backend: {_esc(settings.backend_url)} &middot; Threshold: {settings.attack_threshold} &middot; Mode: <b style="color:{'#4ade80' if settings.enforcement_mode=='enforce' else '#facc15'}">{_esc(settings.enforcement_mode.upper())}</b>{' (not blocking - see README calibration section)' if settings.enforcement_mode != 'enforce' else ''}</div>
<div class="cards">{stat_cards}</div>
<h2>Recent alerts</h2>
<table><tr><th>Time</th><th>Severity</th><th>IP</th><th>Attack prob.</th><th>Message</th></tr>{alert_rows}</table>
<h2>Active blocklist</h2>
<table><tr><th>IP</th><th>Reason</th><th>Blocked at</th><th>Expires</th></tr>{block_rows}</table>
<h2>API keys</h2>
<table><tr><th>ID</th><th>Owner</th><th>Prefix</th><th>Active</th><th>Requests</th><th>Flags</th></tr>{key_rows}</table>
</body></html>"""


@router.get("/dashboard")
def dashboard():
    from fastapi.responses import HTMLResponse
    return HTMLResponse(_render_dashboard())
