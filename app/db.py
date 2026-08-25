"""
Lightweight SQLite storage for API keys, the IP blocklist, alerts, and a
rolling request log. SQLite is used so the whole gateway runs with zero
external services out of the box; swap this module for a Postgres-backed
one if you need multi-instance / high-throughput deployment.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

from .config import settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT UNIQUE NOT NULL,
    key_prefix TEXT NOT NULL,
    owner TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    exempt_from_ml INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    revoked_at REAL,
    revoked_reason TEXT,
    last_used_at REAL,
    request_count INTEGER NOT NULL DEFAULT 0,
    flag_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS blocklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    reason TEXT NOT NULL,
    blocked_at REAL NOT NULL,
    expires_at REAL,
    permanent INTEGER NOT NULL DEFAULT 0,
    unblocked_at REAL,
    UNIQUE(ip, unblocked_at)
);
CREATE INDEX IF NOT EXISTS idx_blocklist_ip ON blocklist(ip);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    ip TEXT,
    api_key_id INTEGER,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    attack_probability REAL,
    method TEXT,
    path TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS request_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    ip TEXT NOT NULL,
    api_key_id INTEGER,
    method TEXT,
    path TEXT,
    action TEXT NOT NULL,      -- allowed | blocked_ml | blocked_ip | blocked_key | unauthorized
    attack_probability REAL,
    status_code INTEGER,
    features_json TEXT         -- the exact feature vector scored, for later retraining
);
CREATE INDEX IF NOT EXISTS idx_request_log_ts ON request_log(ts);
CREATE INDEX IF NOT EXISTS idx_request_log_ip ON request_log(ip);

CREATE TABLE IF NOT EXISTS auth_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    ip TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_failures_ip_ts ON auth_failures(ip, ts);

-- Admin-supplied ground-truth labels on historical requests, used to build
-- a real-traffic training set (see train/export_labeled_data.py).
CREATE TABLE IF NOT EXISTS request_labels (
    request_log_id INTEGER PRIMARY KEY REFERENCES request_log(id),
    label INTEGER NOT NULL,     -- 0 = benign, 1 = attack
    labeled_at REAL NOT NULL,
    labeled_by TEXT
);
"""


def _connect() -> sqlite3.Connection:
    Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(_SCHEMA)
        _migrate(conn)


def _migrate(conn: sqlite3.Connection) -> None:
    """Additive, idempotent column migrations for DBs created by an older
    version of this schema (CREATE TABLE IF NOT EXISTS won't add columns to
    an existing table)."""
    existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(api_keys)")}
    if "exempt_from_ml" not in existing_cols:
        conn.execute("ALTER TABLE api_keys ADD COLUMN exempt_from_ml INTEGER NOT NULL DEFAULT 0")
    existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(request_log)")}
    if "features_json" not in existing_cols:
        conn.execute("ALTER TABLE request_log ADD COLUMN features_json TEXT")


# --------------------------------------------------------------------------
# API keys
# --------------------------------------------------------------------------

def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def create_api_key(owner: str, is_admin: bool = False, exempt_from_ml: bool = False) -> tuple[str, int]:
    """Create a new API key. Returns (raw_key, key_id). The raw key is shown
    to the caller ONCE - only its hash is stored."""
    raw_key = "cg_" + secrets.token_urlsafe(32)
    key_hash = _hash_key(raw_key)
    prefix = raw_key[:10]
    now = time.time()
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO api_keys (key_hash, key_prefix, owner, is_admin, exempt_from_ml, is_active, created_at)
               VALUES (?, ?, ?, ?, ?, 1, ?)""",
            (key_hash, prefix, owner, int(is_admin), int(exempt_from_ml), now),
        )
        key_id = cur.lastrowid
    return raw_key, key_id


def set_key_ml_exempt(key_id: int, exempt: bool) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE api_keys SET exempt_from_ml = ? WHERE id = ? AND is_active = 1",
            (int(exempt), key_id),
        )
    return cur.rowcount > 0


def lookup_api_key(raw_key: str) -> Optional[sqlite3.Row]:
    key_hash = _hash_key(raw_key)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1", (key_hash,)
        ).fetchone()
    return row


def touch_api_key(key_id: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE api_keys SET last_used_at = ?, request_count = request_count + 1 WHERE id = ?",
            (time.time(), key_id),
        )


def flag_api_key(key_id: int) -> int:
    """Increment the flag counter for a key (called when a request from this
    key is blocked as an attack). Returns the new flag count."""
    with get_conn() as conn:
        conn.execute("UPDATE api_keys SET flag_count = flag_count + 1 WHERE id = ?", (key_id,))
        row = conn.execute("SELECT flag_count FROM api_keys WHERE id = ?", (key_id,)).fetchone()
    return row["flag_count"] if row else 0


def revoke_api_key(key_id: int, reason: str = "revoked by admin") -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE api_keys SET is_active = 0, revoked_at = ?, revoked_reason = ? WHERE id = ? AND is_active = 1",
            (time.time(), reason, key_id),
        )
    return cur.rowcount > 0


def list_api_keys() -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC").fetchall()


# --------------------------------------------------------------------------
# Blocklist
# --------------------------------------------------------------------------

def block_ip(ip: str, reason: str, duration_seconds: Optional[float], permanent: bool = False) -> None:
    now = time.time()
    expires_at = None if permanent or duration_seconds is None else now + duration_seconds
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO blocklist (ip, reason, blocked_at, expires_at, permanent)
               VALUES (?, ?, ?, ?, ?)""",
            (ip, reason, now, expires_at, int(permanent)),
        )


def is_blocked(ip: str) -> Optional[sqlite3.Row]:
    now = time.time()
    with get_conn() as conn:
        row = conn.execute(
            """SELECT * FROM blocklist
               WHERE ip = ? AND unblocked_at IS NULL
                 AND (permanent = 1 OR expires_at > ?)
               ORDER BY blocked_at DESC LIMIT 1""",
            (ip, now),
        ).fetchone()
    return row


def unblock_ip(ip: str) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE blocklist SET unblocked_at = ? WHERE ip = ? AND unblocked_at IS NULL",
            (time.time(), ip),
        )
    return cur.rowcount


def list_blocklist(active_only: bool = True) -> list[sqlite3.Row]:
    now = time.time()
    with get_conn() as conn:
        if active_only:
            return conn.execute(
                """SELECT * FROM blocklist
                   WHERE unblocked_at IS NULL AND (permanent = 1 OR expires_at > ?)
                   ORDER BY blocked_at DESC""",
                (now,),
            ).fetchall()
        return conn.execute("SELECT * FROM blocklist ORDER BY blocked_at DESC LIMIT 500").fetchall()


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------

def insert_alert(
    ip: Optional[str],
    api_key_id: Optional[int],
    severity: str,
    message: str,
    attack_probability: Optional[float] = None,
    method: Optional[str] = None,
    path: Optional[str] = None,
) -> dict[str, Any]:
    now = time.time()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO alerts (ts, ip, api_key_id, severity, message, attack_probability, method, path)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (now, ip, api_key_id, severity, message, attack_probability, method, path),
        )
    return {
        "ts": now, "ip": ip, "api_key_id": api_key_id, "severity": severity,
        "message": message, "attack_probability": attack_probability,
        "method": method, "path": path,
    }


def list_alerts(limit: int = 100) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()


# --------------------------------------------------------------------------
# Request log
# --------------------------------------------------------------------------

def log_request(
    ip: str,
    api_key_id: Optional[int],
    method: str,
    path: str,
    action: str,
    attack_probability: Optional[float],
    status_code: int,
    features: Optional[dict[str, float]] = None,
) -> int:
    import json as _json
    features_json = _json.dumps(features) if features is not None else None
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO request_log (ts, ip, api_key_id, method, path, action, attack_probability, status_code, features_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (time.time(), ip, api_key_id, method, path, action, attack_probability, status_code, features_json),
        )
        # Cheap retention: keep the table from growing unbounded. Rows with
        # a human label are kept regardless, since those are valuable
        # training data.
        conn.execute(
            """DELETE FROM request_log WHERE id NOT IN (
                   SELECT id FROM request_log ORDER BY id DESC LIMIT 50000
               ) AND id NOT IN (SELECT request_log_id FROM request_labels)"""
        )
        return cur.lastrowid


def list_recent_requests(limit: int = 100) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM request_log ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()


def stats_summary() -> dict[str, Any]:
    now = time.time()
    with get_conn() as conn:
        total_keys = conn.execute("SELECT COUNT(*) c FROM api_keys WHERE is_active = 1").fetchone()["c"]
        active_blocks = conn.execute(
            "SELECT COUNT(*) c FROM blocklist WHERE unblocked_at IS NULL AND (permanent = 1 OR expires_at > ?)",
            (now,),
        ).fetchone()["c"]
        last_hour = now - 3600
        allowed = conn.execute(
            "SELECT COUNT(*) c FROM request_log WHERE action = 'allowed' AND ts > ?", (last_hour,)
        ).fetchone()["c"]
        blocked = conn.execute(
            "SELECT COUNT(*) c FROM request_log WHERE action != 'allowed' AND ts > ?", (last_hour,)
        ).fetchone()["c"]
        alerts_last_hour = conn.execute(
            "SELECT COUNT(*) c FROM alerts WHERE ts > ?", (last_hour,)
        ).fetchone()["c"]
    return {
        "active_api_keys": total_keys,
        "active_blocked_ips": active_blocks,
        "requests_allowed_last_hour": allowed,
        "requests_blocked_last_hour": blocked,
        "alerts_last_hour": alerts_last_hour,
    }


# --------------------------------------------------------------------------
# Auth-failure brute-force guard
# --------------------------------------------------------------------------

def record_auth_failure(ip: str) -> int:
    """Record a failed-API-key attempt from an IP and return how many
    failures that IP has racked up within the configured window."""
    now = time.time()
    window_start = now - settings.auth_failure_window_seconds
    with get_conn() as conn:
        conn.execute("INSERT INTO auth_failures (ts, ip) VALUES (?, ?)", (now, ip))
        conn.execute("DELETE FROM auth_failures WHERE ts < ?", (now - 3600,))
        row = conn.execute(
            "SELECT COUNT(*) c FROM auth_failures WHERE ip = ? AND ts > ?", (ip, window_start)
        ).fetchone()
    return row["c"]


# --------------------------------------------------------------------------
# Ground-truth labeling (feeds train/export_labeled_data.py)
# --------------------------------------------------------------------------

def label_request(request_log_id: int, label: int, labeled_by: str = "admin") -> bool:
    """label: 0 = benign, 1 = attack. Requires the row to have a stored
    feature vector (i.e. it went through the ML scoring path)."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT features_json FROM request_log WHERE id = ?", (request_log_id,)
        ).fetchone()
        if row is None or row["features_json"] is None:
            return False
        conn.execute(
            """INSERT INTO request_labels (request_log_id, label, labeled_at, labeled_by)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(request_log_id) DO UPDATE SET label=excluded.label,
                   labeled_at=excluded.labeled_at, labeled_by=excluded.labeled_by""",
            (request_log_id, label, time.time(), labeled_by),
        )
    return True


def list_labeled_requests() -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """SELECT rl.id, rl.ts, rl.ip, rl.method, rl.path, rl.features_json,
                      lb.label, lb.labeled_at, lb.labeled_by
               FROM request_labels lb JOIN request_log rl ON rl.id = lb.request_log_id
               ORDER BY lb.labeled_at DESC"""
        ).fetchall()
