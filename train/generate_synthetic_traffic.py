"""
Generates labeled synthetic HTTP-traffic sessions for bootstrapping the L7
DoS/DDoS classifier, using the SAME `_Event` shape and feature extractor
(`compute_features_from_events`) the live gateway uses - so a model trained
on this data sees exactly the same kind of vector in production.

This is a reasonable way to get a calibrated starting model, but it is
still synthetic: these archetypes are my best modeling of what benign and
attack traffic tends to look like at the HTTP layer, not traffic observed
from your actual deployment. Once the gateway has run for a while, label
real requests via POST /admin/requests/label and retrain on that instead
(or blended with this synthetic set) using train_model.py --data.
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.flow_tracker import _Event  # noqa: E402

BENIGN_PATHS = [
    "/", "/home", "/products", "/products/123", "/products/456", "/cart",
    "/checkout", "/account", "/account/orders", "/search", "/api/v1/user",
    "/api/v1/notifications", "/static/app.js", "/static/style.css", "/favicon.ico",
]
LOGIN_PATH = "/api/v1/auth/login"


def _make_events(timings: list[float], sizes: list[tuple[float, float, bool]],
                  paths: list[str], methods: list[str], statuses: list[int]) -> list[_Event]:
    events = []
    t = 1_700_000_000.0
    for i, gap in enumerate(timings):
        t += gap
        req_bytes, resp_bytes, has_body = sizes[i]
        ev = _Event(
            ts=t, method=methods[i], path=paths[i],
            fwd_bytes=req_bytes, fwd_header_bytes=req_bytes * 0.35, has_body=has_body,
            bwd_bytes=resp_bytes, bwd_header_bytes=resp_bytes * 0.15, status_code=statuses[i],
        )
        events.append(ev)
    return events


def _jittered(n: int, lo: float, hi: float) -> list[float]:
    return [0.0] + [random.uniform(lo, hi) for _ in range(n - 1)]


# ---------------------------------------------------------------------------
# Benign archetypes
# ---------------------------------------------------------------------------

def gen_casual_browsing(rng: random.Random) -> list[_Event]:
    n = rng.randint(2, 20)
    timings = [0.0] + [rng.uniform(0.4, 9.0) for _ in range(n - 1)]
    paths = [rng.choice(BENIGN_PATHS) for _ in range(n)]
    methods = [rng.choices(["GET", "POST"], weights=[0.9, 0.1])[0] for _ in range(n)]
    sizes = []
    for m in methods:
        req = rng.uniform(250, 2000) if m == "GET" else rng.uniform(300, 4000)
        resp = rng.uniform(400, 60000)
        sizes.append((req, resp, m == "POST" and rng.random() < 0.8))
    statuses = [200 if rng.random() > 0.03 else rng.choice([404, 500]) for _ in range(n)]
    return _make_events(timings, sizes, paths, methods, statuses)


def gen_api_polling(rng: random.Random) -> list[_Event]:
    n = rng.randint(3, 12)
    path = rng.choice(["/api/v1/status", "/api/v1/notifications", "/api/v1/inbox"])
    timings = [0.0] + [rng.uniform(4.0, 30.0) for _ in range(n - 1)]
    paths = [path] * n
    methods = ["GET"] * n
    sizes = [(rng.uniform(150, 400), rng.uniform(200, 3000), False) for _ in range(n)]
    statuses = [200] * n
    return _make_events(timings, sizes, paths, methods, statuses)


def gen_mobile_sync(rng: random.Random) -> list[_Event]:
    """A mobile app doing periodic background syncs: short bursts of a few
    requests, separated by long idle gaps while the app is backgrounded."""
    bursts = rng.randint(2, 4)
    sync_paths = ["/sync/photos", "/sync/contacts", "/sync/messages", "/sync/settings"]
    return _gen_bursty(rng, bursts, sync_paths, min_burst=3, max_burst=10)


def _gen_bursty(rng: random.Random, bursts: int, paths_pool: list[str], min_burst: int, max_burst: int) -> list[_Event]:
    timings, sizes, paths, methods, statuses = [], [], [], [], []
    first = True
    for b in range(bursts):
        n = rng.randint(min_burst, max_burst)
        for i in range(n):
            if first:
                timings.append(0.0)
                first = False
            elif i == 0:
                timings.append(rng.uniform(8, 45))  # idle gap between bursts
            else:
                timings.append(rng.uniform(0.05, 0.5))
            paths.append(rng.choice(paths_pool))
            methods.append(rng.choice(["GET", "POST"]))
            req = rng.uniform(300, 5000)
            resp = rng.uniform(300, 20000)
            sizes.append((req, resp, True))
            statuses.append(200)
    return _make_events(timings, sizes, paths, methods, statuses)


def gen_file_download(rng: random.Random) -> list[_Event]:
    n = rng.randint(1, 3)
    timings = [0.0] + [rng.uniform(1, 5) for _ in range(n - 1)]
    paths = ["/downloads/report.pdf"] * n
    methods = ["GET"] * n
    sizes = [(rng.uniform(200, 500), rng.uniform(100_000, 5_000_000), False) for _ in range(n)]
    statuses = [200] * n
    return _make_events(timings, sizes, paths, methods, statuses)


def gen_legit_bulk_client(rng: random.Random) -> list[_Event]:
    """A legitimate integration partner doing a batch import - deliberately
    hard: high volume and repetitive like an attack, but at a moderate,
    human-provisioned rate with realistic error/retry behavior."""
    n = rng.randint(80, 250)
    timings = [0.0] + [rng.uniform(0.08, 0.5) for _ in range(n - 1)]
    paths = [f"/api/v1/import/batch/{rng.randint(1, 9999)}" for _ in range(n)]
    methods = ["POST"] * n
    sizes = [(rng.uniform(800, 6000), rng.uniform(200, 2000), True) for _ in range(n)]
    statuses = [200 if rng.random() > 0.06 else rng.choice([409, 422, 500]) for _ in range(n)]
    return _make_events(timings, sizes, paths, methods, statuses)


def gen_page_load_burst(rng: random.Random) -> list[_Event]:
    """A browser loading a page and its assets: a SHORT burst of many
    near-simultaneous requests to DIFFERENT static paths, then (usually)
    quiet. High instantaneous rate, but small absolute request count and a
    tiny total window - the key differences from a real flood, which
    sustains high volume over a much longer window."""
    n = rng.randint(8, 35)
    asset_paths = [f"/static/{p}" for p in
                   ["app.js", "vendor.js", "style.css", "logo.png", "hero.jpg", "icons.svg",
                    "font.woff2", "analytics.js", "banner.png", "spinner.gif"]]
    timings = [0.0] + [rng.uniform(0.002, 0.03) for _ in range(n - 1)]
    paths = [rng.choice(asset_paths) + (f"?v={rng.randint(1,999)}" if rng.random() < 0.3 else "") for _ in range(n)]
    methods = ["GET"] * n
    sizes = [(rng.uniform(150, 400), rng.uniform(1000, 90000), False) for _ in range(n)]
    statuses = [200 if rng.random() > 0.05 else 304 for _ in range(n)]
    events = _make_events(timings, sizes, paths, methods, statuses)
    # Occasionally a second, smaller burst a bit later (e.g. a lazy-loaded
    # section), then nothing - still nowhere near sustained flood volume.
    if rng.random() < 0.4:
        n2 = rng.randint(3, 10)
        t2 = [rng.uniform(1.0, 6.0)] + [rng.uniform(0.002, 0.03) for _ in range(n2 - 1)]
        p2 = [rng.choice(asset_paths) for _ in range(n2)]
        m2 = ["GET"] * n2
        s2 = [(rng.uniform(150, 400), rng.uniform(1000, 20000), False) for _ in range(n2)]
        st2 = [200] * n2
        more = _make_events(t2, s2, p2, m2, st2)
        # shift timestamps to continue after the first burst
        offset = events[-1].ts
        for e in more:
            e.ts += offset
        events += more
    return events


def gen_dashboard_poller(rng: random.Random) -> list[_Event]:
    """A legitimate dashboard/app polling a FIXED small set of known
    endpoints repeatedly and fairly quickly (e.g. every 1-3s) - unlike a
    scraper, it never enumerates new/sequential resources."""
    n = rng.randint(30, 150)
    widget_paths = [f"/api/v1/widgets/{name}" for name in
                    ["revenue", "traffic", "errors", "latency", "users_online", "queue_depth"]]
    timings = [0.0] + [rng.uniform(0.8, 3.0) for _ in range(n - 1)]
    paths = [rng.choice(widget_paths) for _ in range(n)]
    methods = ["GET"] * n
    sizes = [(rng.uniform(150, 350), rng.uniform(200, 4000), False) for _ in range(n)]
    statuses = [200] * n
    return _make_events(timings, sizes, paths, methods, statuses)


def gen_user_file_upload(rng: random.Random) -> list[_Event]:
    """A human uploading one or a few large files (photos, documents) at a
    normal human pace - large bodies, but low count and no mechanical
    timing regularity, unlike gen_large_payload_flood."""
    n = rng.randint(1, 5)
    timings = [0.0] + [rng.uniform(2.0, 20.0) for _ in range(n - 1)]
    paths = ["/api/v1/upload"] * n
    methods = ["POST"] * n
    sizes = [(rng.uniform(20_000, 250_000), rng.uniform(150, 600), True) for _ in range(n)]
    statuses = [200] * n
    return _make_events(timings, sizes, paths, methods, statuses)


def gen_health_check(rng: random.Random) -> list[_Event]:
    """Load-balancer / uptime-monitor / k8s-probe traffic: tiny request AND
    response bodies, a single fixed path, very regular clock-driven timing
    (often MORE regular than a human), sustained indefinitely, and a clean
    200 every time. Easy to mistake for a slow attack probe on rate/timing
    alone - error_ratio staying at 0 is what should tell them apart."""
    n = rng.randint(10, 200)
    path = rng.choice(["/health", "/healthz", "/ping", "/status", "/livez", "/readyz"])
    interval = rng.choice([1.0, 2.0, 5.0, 10.0, 15.0, 30.0])
    timings = [0.0] + [max(0.05, rng.gauss(interval, interval * 0.03)) for _ in range(n - 1)]
    paths = [path] * n
    methods = ["GET"] * n
    sizes = [(rng.uniform(40, 90), rng.uniform(10, 60), False) for _ in range(n)]
    statuses = [200] * n
    return _make_events(timings, sizes, paths, methods, statuses)


def gen_normal_login(rng: random.Random) -> list[_Event]:
    """A single real user logging in - the single most common one-shot
    legitimate action on almost any web app. Usually succeeds first try;
    sometimes a typo means 1-2 failed attempts before success. Must be
    represented explicitly, or the model has no counterexample to the
    attack archetypes that also hit /auth/login and learns "any POST to a
    login path" is suspicious - which would false-positive on real users
    constantly, including from a single isolated request with no history."""
    n = rng.choice([1, 1, 1, 2, 3])
    timings = [0.0] + [rng.uniform(2.0, 12.0) for _ in range(n - 1)]
    paths = [LOGIN_PATH] * n
    methods = ["POST"] * n
    sizes = [(rng.uniform(80, 200), rng.uniform(50, 300), True) for _ in range(n)]
    statuses = ([401] * (n - 1) + [200]) if n > 1 else [200]
    return _make_events(timings, sizes, paths, methods, statuses)


BENIGN_GENERATORS = [
    gen_casual_browsing, gen_api_polling, gen_mobile_sync, gen_file_download,
    gen_legit_bulk_client, gen_page_load_burst, gen_dashboard_poller, gen_user_file_upload,
    gen_health_check, gen_normal_login,
]


# ---------------------------------------------------------------------------
# Attack archetypes
# ---------------------------------------------------------------------------

def gen_http_flood(rng: random.Random) -> list[_Event]:
    n = rng.randint(150, 5000)
    path = rng.choice(["/", "/api/v1/user", "/search"])
    timings = [0.0] + [max(0.0, rng.gauss(0.003, 0.001)) for _ in range(n - 1)]
    paths = [path] * n
    methods = ["GET"] * n
    base = rng.uniform(40, 150)
    sizes = [(base + rng.uniform(-5, 5), rng.uniform(0, 60), False) for _ in range(n)]
    statuses = [200 if rng.random() > 0.3 else 503 for _ in range(n)]
    return _make_events(timings, sizes, paths, methods, statuses)


def gen_credential_stuffing(rng: random.Random) -> list[_Event]:
    n = rng.randint(100, 2000)
    timings = [0.0] + [max(0.0, rng.gauss(0.02, 0.008)) for _ in range(n - 1)]
    paths = [LOGIN_PATH] * n
    methods = ["POST"] * n
    sizes = [(rng.uniform(60, 140), rng.uniform(30, 90), True) for _ in range(n)]
    statuses = [401 if rng.random() > 0.02 else 200 for _ in range(n)]
    return _make_events(timings, sizes, paths, methods, statuses)


def gen_scraper_burst(rng: random.Random) -> list[_Event]:
    n = rng.randint(200, 3000)
    timings = [0.0] + [max(0.0, rng.gauss(0.01, 0.004)) for _ in range(n - 1)]
    paths = [f"/products/{i}" for i in range(n)]
    methods = ["GET"] * n
    sizes = [(rng.uniform(150, 300), rng.uniform(500, 3000), False) for _ in range(n)]
    statuses = [200] * n
    return _make_events(timings, sizes, paths, methods, statuses)


def gen_boundary_flood(rng: random.Random) -> list[_Event]:
    """Stays just under a typical deterministic rate-limit cap (~a few
    hundred req/window) but is otherwise clearly mechanical: near-zero
    jitter, single endpoint, uniform tiny payloads. This is the case the
    rate limiter alone would miss - the ML layer needs to catch it."""
    n = rng.randint(60, 280)
    path = rng.choice(BENIGN_PATHS)
    timings = [0.0] + [max(0.0, rng.gauss(0.15, 0.02)) for _ in range(n - 1)]
    paths = [path] * n
    methods = ["GET"] * n
    base = rng.uniform(60, 200)
    sizes = [(base + rng.uniform(-3, 3), rng.uniform(100, 400), False) for _ in range(n)]
    statuses = [200] * n
    return _make_events(timings, sizes, paths, methods, statuses)


def gen_vuln_scan(rng: random.Random) -> list[_Event]:
    n = rng.randint(100, 1500)
    scan_paths = ["/admin", "/.env", "/wp-login.php", "/.git/config", "/phpmyadmin",
                  "/api/v1/../../etc/passwd", "/config.php", "/backup.zip"]
    timings = [0.0] + [max(0.0, rng.gauss(0.03, 0.015)) for _ in range(n - 1)]
    paths = [rng.choice(scan_paths) for _ in range(n)]
    methods = ["GET"] * n
    sizes = [(rng.uniform(80, 200), rng.uniform(0, 500), False) for _ in range(n)]
    statuses = [404 if rng.random() > 0.05 else 200 for _ in range(n)]
    return _make_events(timings, sizes, paths, methods, statuses)


def gen_slow_credential_stuffing(rng: random.Random) -> list[_Event]:
    """Throttled attack traffic: an attacker deliberately staying under any
    rate limit (1 attempt every ~1.5-4s) but sustaining it for a long
    session with a high failure rate on a single auth endpoint - volume
    and timing alone won't catch this, error_ratio + path repetition must."""
    n = rng.randint(60, 400)
    timings = [0.0] + [rng.uniform(1.2, 4.0) for _ in range(n - 1)]
    paths = [LOGIN_PATH] * n
    methods = ["POST"] * n
    sizes = [(rng.uniform(70, 130), rng.uniform(40, 90), True) for _ in range(n)]
    statuses = [401 if rng.random() > 0.03 else 200 for _ in range(n)]
    return _make_events(timings, sizes, paths, methods, statuses)


def gen_slow_vuln_scan(rng: random.Random) -> list[_Event]:
    """A throttled vulnerability/path scanner: one probe every couple of
    seconds against a rotating set of sensitive/nonexistent paths."""
    n = rng.randint(50, 300)
    scan_paths = ["/admin", "/.env", "/wp-login.php", "/.git/config", "/phpmyadmin",
                  "/config.php", "/backup.zip", "/.aws/credentials", "/server-status"]
    timings = [0.0] + [rng.uniform(1.0, 3.5) for _ in range(n - 1)]
    paths = [rng.choice(scan_paths) for _ in range(n)]
    methods = ["GET"] * n
    sizes = [(rng.uniform(80, 200), rng.uniform(0, 500), False) for _ in range(n)]
    statuses = [404 if rng.random() > 0.05 else 200 for _ in range(n)]
    return _make_events(timings, sizes, paths, methods, statuses)


def gen_large_payload_flood(rng: random.Random) -> list[_Event]:
    """A volumetric flood using LARGE bodies instead of tiny ones (e.g.
    repeated big file/image uploads meant to exhaust bandwidth/disk) -
    exists so the model can't shortcut to "small request = attack, big
    request = benign"; size alone must not be the deciding signal."""
    n = rng.randint(150, 1200)
    timings = [0.0] + [max(0.0, rng.gauss(0.01, 0.004)) for _ in range(n - 1)]
    path = rng.choice(["/api/v1/upload", "/api/v1/media", "/api/v1/import"])
    paths = [path] * n
    methods = ["POST"] * n
    size = rng.uniform(20_000, 200_000)
    sizes = [(size + rng.uniform(-500, 500), rng.uniform(20, 200), True) for _ in range(n)]
    statuses = [503 if rng.random() < 0.35 else 200 for _ in range(n)]
    return _make_events(timings, sizes, paths, methods, statuses)


ATTACK_GENERATORS = [
    gen_http_flood, gen_credential_stuffing, gen_scraper_burst, gen_boundary_flood, gen_vuln_scan,
    gen_slow_credential_stuffing, gen_slow_vuln_scan, gen_large_payload_flood,
]


def generate_dataset(rng: random.Random, n_per_generator: int) -> list[tuple[list[_Event], int]]:
    """Returns [(events, label), ...] - label 0 = benign, 1 = attack."""
    out: list[tuple[list[_Event], int]] = []
    for gen in BENIGN_GENERATORS:
        for _ in range(n_per_generator):
            out.append((gen(rng), 0))
    for gen in ATTACK_GENERATORS:
        for _ in range(n_per_generator):
            out.append((gen(rng), 1))
    rng.shuffle(out)
    return out
