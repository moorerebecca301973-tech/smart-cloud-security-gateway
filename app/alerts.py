"""
Admin alerting. Every alert is always written to the database (visible via
GET /admin/alerts and the dashboard); if a webhook URL and/or SMTP
credentials are configured in .env, the same alert is also pushed out
in near-real-time.
"""
from __future__ import annotations

import asyncio
import logging
import smtplib
from email.message import EmailMessage
from typing import Optional

import httpx

from . import db
from .config import settings

logger = logging.getLogger("gateway.alerts")


async def raise_alert(
    severity: str,
    message: str,
    ip: Optional[str] = None,
    api_key_id: Optional[int] = None,
    attack_probability: Optional[float] = None,
    method: Optional[str] = None,
    path: Optional[str] = None,
) -> None:
    alert = db.insert_alert(
        ip=ip, api_key_id=api_key_id, severity=severity, message=message,
        attack_probability=attack_probability, method=method, path=path,
    )
    logger.warning("ALERT[%s] %s (ip=%s prob=%s)", severity, message, ip, attack_probability)

    # Fire-and-forget the external notifications so a slow webhook/SMTP
    # server never delays the request that's actively being blocked.
    asyncio.create_task(_dispatch_webhook(alert))
    asyncio.create_task(_dispatch_email(alert))


async def _dispatch_webhook(alert: dict) -> None:
    if not settings.alert_webhook_url:
        return
    payload = {
        "text": (
            f":rotating_light: [{alert['severity'].upper()}] {alert['message']}\n"
            f"ip={alert.get('ip')} prob={alert.get('attack_probability')} "
            f"{alert.get('method') or ''} {alert.get('path') or ''}"
        ),
        **alert,
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(settings.alert_webhook_url, json=payload)
    except Exception:
        logger.exception("Failed to deliver alert webhook")


async def _dispatch_email(alert: dict) -> None:
    if not (settings.smtp_host and settings.alert_email_to and settings.alert_email_from):
        return
    try:
        await asyncio.to_thread(_send_email_sync, alert)
    except Exception:
        logger.exception("Failed to deliver alert email")


def _send_email_sync(alert: dict) -> None:
    msg = EmailMessage()
    msg["Subject"] = f"[Smart Cloud Security] {alert['severity'].upper()}: {alert['message']}"
    msg["From"] = settings.alert_email_from
    msg["To"] = settings.alert_email_to
    body = "\n".join(f"{k}: {v}" for k, v in alert.items())
    msg.set_content(body)

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        if settings.smtp_use_tls:
            smtp.starttls()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(msg)
