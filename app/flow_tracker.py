"""
Per-client-IP sliding-window flow tracker + L7-native feature extraction.

HISTORY / WHY THIS SCHEMA
--------------------------
The first version of this gateway fed the model a set of features shaped
to *look like* CICFlowMeter's packet-capture columns (Flow Duration, TCP
flag counts, TCP window sizes, ...), because that's what the bundled model
was trained on. Testing that against the real model showed the mapping
doesn't work: a reverse proxy never sees individual TCP packets or flags,
so the approximated vector didn't land in the region of feature space the
model actually learned a boundary around - controlled testing found the
model gave a 0.0 attack probability to every one of 200 simulated
flood-shaped sessions, while flagging some ordinary browsing sessions.

This version instead defines a small, purpose-built feature set made only
of things an HTTP reverse proxy can genuinely observe well: request rate,
timing regularity, path repetition, error rate, method mix, and payload
size statistics over a sliding per-IP window. `train/train_model.py`
trains the model on THIS SAME extraction function (imported directly, not
reimplemented), so there is no train/serve mismatch this time - whatever
the model learned on is exactly what it's scored on in production.

IMPORTANT CAVEAT: the training data behind the bundled model is
*synthetic* (see train/generate_synthetic_traffic.py) - realistic
archetypes of benign and attack sessions, not traffic captured from your
actual deployment. That's a reasonable bootstrap, but your real users and
real attackers won't match my synthetic archetypes perfectly. Once this
gateway has been live for a while, use `POST /admin/requests/label` to
label real historical requests and `train/export_labeled_data.py` to pull
them out, then re-run `train/train_model.py --data <export>.csv` to
retrain on real traffic. Treat the bundled model as a calibrated starting
point, not a finished product.
"""
from __future__ import annotations

import statistics
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Optional

from .config import settings


@dataclass
class _Event:
    ts: float
    method: str
    path: str
    fwd_bytes: float           # request size (headers + body) in bytes
    fwd_header_bytes: float
    has_body: bool
    bwd_bytes: Optional[float] = None    # filled in once the response is known
    bwd_header_bytes: float = 0.0
    status_code: Optional[int] = None    # filled in once the response is known


# The ordered list of feature names this tracker produces. Keep this in
# sync with models/feature_names.json - model_service.py trusts that file
# as the source of truth for column order, but this list is what
# train/train_model.py uses to build training vectors, so it must match.
FEATURE_NAMES: list[str] = [
    "req_count", "window_seconds", "req_rate",
    "iat_mean", "iat_std", "iat_cv", "iat_min", "iat_max",
    "fwd_bytes_mean", "fwd_bytes_std",
    "bwd_bytes_mean", "bwd_bytes_std",
    "header_bytes_mean", "has_body_ratio",
    "unique_paths", "unique_path_ratio", "top_path_share",
    "get_ratio", "post_ratio", "other_method_ratio",
    "error_ratio", "active_time_ratio",
    "avg_bytes_per_request", "max_req_per_second",
]


def _mean(values: list[float]) -> float:
    return float(statistics.fmean(values)) if values else 0.0


def _std(values: list[float]) -> float:
    return float(statistics.pstdev(values)) if len(values) > 1 else 0.0


def compute_features_from_events(events: list[_Event], now: float, idle_gap_seconds: float) -> dict[str, float]:
    """Pure function: turns a list of _Event (already trimmed to the
    window you care about, oldest first) into the feature dict the model
    consumes. Used identically by the live tracker and by the training
    script, so training and serving can never drift apart."""
    if not events:
        return {name: 0.0 for name in FEATURE_NAMES}

    timestamps = [e.ts for e in events]
    req_count = float(len(events))
    window_seconds = max(timestamps[-1] - timestamps[0], 0.0)
    req_rate = req_count / max(window_seconds, 1e-6) if len(events) > 1 else 0.0

    if len(timestamps) >= 2:
        diffs = [b - a for a, b in zip(timestamps, timestamps[1:])]
        iat_mean, iat_std = _mean(diffs), _std(diffs)
        iat_cv = (iat_std / iat_mean) if iat_mean > 1e-9 else 0.0
        iat_min, iat_max = min(diffs), max(diffs)
    else:
        diffs = []
        iat_mean = iat_std = iat_cv = iat_min = iat_max = 0.0

    fwd_sizes = [e.fwd_bytes for e in events]
    header_sizes = [e.fwd_header_bytes for e in events]
    completed = [e for e in events if e.bwd_bytes is not None]
    bwd_sizes = [e.bwd_bytes for e in completed]  # type: ignore[misc]

    has_body_ratio = sum(1 for e in events if e.has_body) / req_count

    paths = [e.path for e in events]
    path_counts = Counter(paths)
    unique_paths = float(len(path_counts))
    unique_path_ratio = unique_paths / req_count
    top_path_share = max(path_counts.values()) / req_count if path_counts else 0.0

    methods = [e.method.upper() for e in events]
    get_ratio = methods.count("GET") / req_count
    post_ratio = methods.count("POST") / req_count
    other_method_ratio = max(0.0, 1.0 - get_ratio - post_ratio)

    completed_with_status = [e for e in completed if e.status_code is not None]
    error_ratio = (
        sum(1 for e in completed_with_status if e.status_code >= 400) / len(completed_with_status)
        if completed_with_status else 0.0
    )

    # Fraction of the window spent in "active" bursts (gaps <= idle_gap_seconds)
    # vs idle gaps between bursts - floods tend toward 1.0 (constant activity),
    # human sessions have long idle stretches pulling this down.
    if len(diffs) > 0:
        active_time = sum(d for d in diffs if d <= idle_gap_seconds)
        active_time_ratio = active_time / window_seconds if window_seconds > 1e-9 else 1.0
    else:
        active_time_ratio = 0.0

    total_bytes = sum(fwd_sizes) + sum(bwd_sizes)
    avg_bytes_per_request = total_bytes / req_count

    # Densest 1-second sub-window - catches short violent bursts even when
    # the overall window's average rate looks moderate.
    max_req_per_second = 1.0
    if len(timestamps) > 1:
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > 1.0:
                left += 1
            max_req_per_second = max(max_req_per_second, right - left + 1)

    return {
        "req_count": req_count,
        "window_seconds": window_seconds,
        "req_rate": req_rate,
        "iat_mean": iat_mean,
        "iat_std": iat_std,
        "iat_cv": iat_cv,
        "iat_min": iat_min,
        "iat_max": iat_max,
        "fwd_bytes_mean": _mean(fwd_sizes),
        "fwd_bytes_std": _std(fwd_sizes),
        "bwd_bytes_mean": _mean(bwd_sizes),
        "bwd_bytes_std": _std(bwd_sizes),
        "header_bytes_mean": _mean(header_sizes),
        "has_body_ratio": has_body_ratio,
        "unique_paths": unique_paths,
        "unique_path_ratio": unique_path_ratio,
        "top_path_share": top_path_share,
        "get_ratio": get_ratio,
        "post_ratio": post_ratio,
        "other_method_ratio": other_method_ratio,
        "error_ratio": error_ratio,
        "active_time_ratio": active_time_ratio,
        "avg_bytes_per_request": avg_bytes_per_request,
        "max_req_per_second": float(max_req_per_second),
    }


class FlowTracker:
    """Per-source-IP sliding window of recent HTTP request/response events,
    used to derive the live feature vector for the DoS/DDoS model."""

    def __init__(
        self,
        window_seconds: float = 60.0,
        idle_gap_seconds: float = 1.0,
        max_events_per_ip: int = 500,
    ):
        self.window_seconds = window_seconds
        self.idle_gap_seconds = idle_gap_seconds
        self.max_events_per_ip = max_events_per_ip
        self._events: dict[str, Deque[_Event]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _evict_expired(self, ip: str, now: float) -> None:
        events = self._events[ip]
        cutoff = now - self.window_seconds
        while events and events[0].ts < cutoff:
            events.popleft()
        while len(events) > self.max_events_per_ip:
            events.popleft()

    def begin_request(
        self, ip: str, method: str, path: str,
        req_bytes: float, req_header_bytes: float, has_body: bool,
    ) -> tuple[dict[str, float], _Event]:
        """Record the arrival of a new request and compute a feature vector
        from this IP's flow history *including* this request. Returns the
        feature dict plus a handle to update once the response is known."""
        now = time.time()
        with self._lock:
            self._evict_expired(ip, now)
            event = _Event(
                ts=now, method=method, path=path,
                fwd_bytes=req_bytes, fwd_header_bytes=req_header_bytes, has_body=has_body,
            )
            self._events[ip].append(event)
            features = compute_features_from_events(list(self._events[ip]), now, self.idle_gap_seconds)
        return features, event

    def complete_request(
        self, event: _Event, resp_bytes: float, resp_header_bytes: float, status_code: int,
    ) -> None:
        with self._lock:
            event.bwd_bytes = resp_bytes
            event.bwd_header_bytes = resp_header_bytes
            event.status_code = status_code

    def mark_blocked(self, event: _Event) -> None:
        """Called when a request is blocked before reaching the backend, so
        it doesn't linger with bwd_bytes=None forever."""
        with self._lock:
            event.bwd_bytes = 0.0
            event.bwd_header_bytes = 0.0
            event.status_code = 403


_tracker: FlowTracker | None = None


def get_flow_tracker() -> FlowTracker:
    global _tracker
    if _tracker is None:
        _tracker = FlowTracker(
            window_seconds=settings.flow_window_seconds,
            idle_gap_seconds=settings.flow_idle_gap_seconds,
            max_events_per_ip=settings.flow_max_events_per_ip,
        )
    return _tracker
