"""
Central configuration for the gateway, loaded from environment variables
(and a local .env file during development). See .env.example for the full
list of knobs and what each one does.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Upstream ("your cloud")
    backend_url: str = "http://localhost:9000"
    # Optional shared secret attached as X-Internal-Service-Token on every
    # forwarded request. Set this when the backend is itself a service that
    # should only be reachable through this gateway (e.g. the file storage
    # service) and enforces the same token on its side. Leave blank if the
    # backend doesn't use this (nothing is sent).
    backend_internal_token: str = ""

    # Admin
    admin_bootstrap_token: str = "change-me-to-a-long-random-secret"
    # Comma-separated list of origins allowed to call /admin/* from a
    # browser (e.g. the React admin portal's dev server or its deployed
    # origin). Only affects /admin/* CORS - the proxied catch-all route is
    # unaffected since normal API clients don't rely on browser CORS.
    # Example: "http://localhost:5173,https://admin.example.com"
    admin_portal_origins: str = "http://localhost:5173"

    # Model
    model_dir: str = "models"
    attack_threshold: float = 0.5

    # "monitor": score every request, log/alert on high-probability ones, but
    #            always forward - use this to observe real attack_probability
    #            values (via /admin/requests) and pick a sensible threshold.
    # "enforce": actually block + blocklist + alert once attack_probability
    #            crosses attack_threshold.
    # Defaults to "enforce" because the bundled model (train/train_model.py)
    # was retrained on an L7-native feature set and validated against a
    # battery of held-out edge cases (see README "Model provenance") - but
    # it is still trained on synthetic archetypes, not your real traffic.
    # Drop to "monitor" if you want to watch attack_probability on your own
    # traffic before trusting it to block anything.
    enforcement_mode: str = "enforce"

    # Blocking behaviour
    block_duration_seconds: int = 3600
    auto_revoke_key_after_flags: int = 5
    auth_failures_before_block: int = 20
    auth_failure_window_seconds: int = 60

    # Flow window
    flow_window_seconds: float = 60.0
    flow_idle_gap_seconds: float = 1.0
    flow_max_events_per_ip: int = 500

    # Deterministic rate limiter - a request-volume cap per source IP over
    # the same flow window, independent of the ML model. This is the
    # reliable first line of defense: it ALWAYS enforces (regardless of
    # ENFORCEMENT_MODE) because "too many requests too fast" needs no model
    # calibration to be a correct call. The ML layer on top of this is for
    # catching attack *shape* (not just volume) once you've calibrated it.
    rate_limit_enabled: bool = True
    rate_limit_max_requests: int = 300

    # Client IP resolution
    trust_proxy_headers: bool = False

    # Storage
    db_path: str = "data/gateway.db"

    # Upstream behaviour
    upstream_timeout_seconds: float = 30.0
    max_request_body_bytes: int = 10 * 1024 * 1024

    # Alerting
    alert_webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    alert_email_from: str = ""
    alert_email_to: str = ""


settings = Settings()
