# Smart Cloud Security Gateway

A FastAPI reverse proxy that sits between your users and your real backend
("your cloud"). Every request must carry an API key that you (the admin)
issue; the gateway scores each request's behavior with a trained XGBoost
DoS/DDoS classifier and a deterministic rate limiter, blocks anything that
looks like an attack, blocklists the sender's IP, and alerts you - and
otherwise forwards the request through unchanged and returns the real
response to the user.

```
        ┌──────────┐        ┌─────────────────────────────┐        ┌───────────┐
 user → │  API key │  ───▶  │   Smart Cloud Security       │  ───▶  │ your cloud│
        └──────────┘        │   Gateway (this project)     │        │ (backend) │
                             │  - blocklist check           │        └───────────┘
                             │  - API key check              │
                             │  - rate limit (deterministic) │
                             │  - ML DoS/DDoS scoring        │
                             │  - forward + relay response   │
                             └───────────────┬───────────────┘
                                              │ blocked/flagged
                                              ▼
                                     admin alerts + dashboard
```

## What's in this package

```
app/
  main.py           FastAPI app, wiring, startup/shutdown
  proxy.py           the core gateway pipeline (auth → blocklist → rate
                      limit → ML scoring → forward)
  flow_tracker.py     per-IP sliding-window feature extraction (read the
                      docstring - explains why the feature set looks the
                      way it does)
  model_service.py    loads dos_ddos_xgboost.json + scaler.pkl + feature order
  admin.py            admin API + a small built-in HTML dashboard
  alerts.py           alert dispatch (DB + optional webhook/email)
  security.py         API key + admin token checks
  db.py               SQLite storage (api keys, blocklist, alerts, request log)
  config.py           settings, all overridable via .env
models/                the ACTIVE model: dos_ddos_xgboost.json + scaler.pkl +
                        feature_names.json, trained by train/train_model.py
  _legacy_packet_capture_model/  your originally-uploaded model, trained on
                        CSE-CIC-IDS2018 packet-capture features - kept for
                        reference, not loaded by the app. See "Model
                        provenance" below for why it was replaced.
train/
  generate_synthetic_traffic.py  labeled benign/attack session archetypes
  train_model.py                  trains + evaluates + saves the model
  export_labeled_data.py          pulls admin-labeled real traffic into a
                                   CSV for retraining on your own data
tests/
  dummy_backend.py     a stand-in "cloud" for local testing
  smoke_test.py         end-to-end test against the REAL model artifacts
.env.example           every setting, documented
Dockerfile / docker-compose.yml
```

## Quick start (local, no Docker)

```bash
cd ddos_gateway
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env: set BACKEND_URL to your real service, and set
# ADMIN_BOOTSTRAP_TOKEN to a long random secret:
python3 -c "import secrets; print(secrets.token_urlsafe(48))"

uvicorn app.main:app --host 0.0.0.0 --port 8080
```

To try it against the included dummy backend instead of your real cloud:

```bash
# terminal 1
uvicorn tests.dummy_backend:app --port 9000
# terminal 2 (.env: BACKEND_URL=http://localhost:9000)
uvicorn app.main:app --port 8080
```

Then create your first API key and try it:

```bash
curl -X POST http://localhost:8080/admin/api-keys \
  -H "X-Admin-Token: <your ADMIN_BOOTSTRAP_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"owner": "my-web-app"}'
# -> {"id":1,"owner":"my-web-app","api_key":"cg_...", "warning": "shown once"}

curl http://localhost:8080/orders/123 -H "X-API-Key: cg_..."
```

Open the dashboard in a browser: `http://localhost:8080/admin/dashboard?token=<your ADMIN_BOOTSTRAP_TOKEN>`

## Admin portal (React)

The read-only HTML dashboard above is fine for a quick look, but day-to-day
admin work — creating/revoking keys, managing the blocklist, labeling
requests, calibrating the model — is better done from the companion React
app in `admin_portal/` (sibling package to this one, not inside `app/`).

```bash
cd admin_portal
npm install
npm run dev        # http://localhost:5173
```

It signs in with the same `ADMIN_BOOTSTRAP_TOKEN` and talks straight to
this gateway's `/admin/*` API from the browser, so CORS has to be opened
up for its origin - already defaulted in `.env.example`:

```bash
ADMIN_PORTAL_ORIGINS=http://localhost:5173
```

Add its real deployed origin here too once you host `admin_portal`
somewhere other than your laptop. See `admin_portal/README.md` for the
full page-by-page rundown and production build/deploy instructions.

## Quick start (Docker)

```bash
cp .env.example .env   # fill in BACKEND_URL and ADMIN_BOOTSTRAP_TOKEN
docker compose up --build
```

## Using the companion File Storage Service as the backend

The `file_storage_service` project (delivered alongside this one) is a
ready-made destination: a service for storing user-uploaded images,
videos, and documents (Word/Excel/PowerPoint/PDF/etc), built specifically
to sit behind this gateway rather than be reachable directly. To wire them
together:

```bash
BACKEND_URL=http://<file-service-host>:9100
BACKEND_INTERNAL_TOKEN=<same value as the file service's INTERNAL_SERVICE_TOKEN>
```

Once set, end users hit this gateway's `/files` endpoints exactly like any
other route - the gateway authenticates them, screens for DoS/DDoS, and
forwards clean requests to the file service, attaching
`X-Internal-Service-Token` (proving the request came through the gateway)
and `X-Gateway-Client-Id`/`X-Gateway-Client-Owner` (so uploads are
attributed to the right caller without the file service ever seeing their
API key). See that project's own README for its full API and file-type/
size limits.

## Run the smoke test

Exercises the whole pipeline against your **real** model artifacts, with a
mocked backend: key creation, benign pass-through, a low-volume stealth
attack caught by the ML layer specifically, a high-volume ML-exempt burst
caught by the rate limiter, auth-brute-force blocking, labeling, the
calibration endpoint, and the dashboard.

```bash
pip install respx   # test-only dependency, not needed in production
python3 -m tests.smoke_test
```

## Retraining the model

```bash
# Retrain on synthetic archetypes only (what shipped in models/):
python3 -m train.train_model

# After the gateway has run for a while and you've labeled some real
# requests via POST /admin/requests/label:
python3 -m train.export_labeled_data --out real_traffic.csv
python3 -m train.train_model --data real_traffic.csv          # blended
python3 -m train.train_model --data real_traffic.csv --real-only  # real data only
```

Each run backs up whatever was previously in `models/` into
`models/_previous_model/` first, prints accuracy/precision/recall/F1 and a
confusion matrix on a held-out split, and overwrites `models/*` with the
new model. Restart the gateway (or redeploy) to pick it up.

---

## How requests are handled

1. **Blocklist check.** If the caller's IP is currently blocked, reject
   immediately with 403 - cheapest check, done first.
2. **API key check.** Missing/invalid key → 401. Repeated invalid attempts
   from the same IP within `AUTH_FAILURE_WINDOW_SECONDS` (default: 20 within
   60s) auto-block that IP - this guards against credential stuffing and
   key-guessing, and it **always enforces**, regardless of `ENFORCEMENT_MODE`.
3. **Deterministic rate limit.** If an IP sends more than
   `RATE_LIMIT_MAX_REQUESTS` requests within `FLOW_WINDOW_SECONDS`, it's
   blocked immediately (429) - this **always enforces** too. This is your
   reliable, no-calibration-needed defense against raw volumetric floods.
4. **ML DoS/DDoS scoring.** Skipped entirely for keys marked
   `exempt_from_ml`. Otherwise the request (plus this IP's recent behavior)
   is turned into a feature vector and scored by the trained model. What
   happens next depends on `ENFORCEMENT_MODE` - see "Model provenance" below.
5. **Forward.** If nothing above blocked it, the request goes to
   `BACKEND_URL` unchanged (method, path, query, body, headers minus
   hop-by-hop ones) and the real response is relayed back to the caller.
   The caller's own `X-API-Key`/`Authorization` header is stripped before
   forwarding (it's the gateway's credential, not the backend's) and
   replaced with `X-Gateway-Client-Id` / `X-Gateway-Client-Owner` so your
   backend can still see who made the call without ever seeing the raw key.

Every request is logged (`/admin/requests`); every block/flag raises an
alert (`/admin/alerts`, plus a webhook/email if configured).

## Model provenance - read this before you trust the ML layer

**The model that shipped in `_legacy_packet_capture_model/` doesn't work for
this gateway, and here's the honest reason why.** It was trained on
CSE-CIC-IDS2018, where every feature (`Flow Duration`, TCP flag counts, TCP
window sizes, per-packet timing) comes from CICFlowMeter watching raw
*packet captures*. A FastAPI reverse proxy operates at the HTTP layer - it
never sees individual TCP packets, flags, or window sizes. Testing that
model against an HTTP-layer approximation of its features found the
relationship between "more/faster requests" and `attack_probability` was
**not reliably monotonic**: 200 simulated flood sessions scored 0.0 attack
probability across the board, while some simulated flood-shaped sessions
scored high but so did ordinary browsing. It wasn't usable as a live
detector, no matter what threshold was picked.

**So the model was retrained from scratch on a feature set actually
designed for what an HTTP proxy can observe.** `app/flow_tracker.py`
computes 24 features per client IP over a sliding window - request rate,
timing regularity (`iat_cv`), path repetition (`top_path_share`,
`unique_path_ratio`), error rate, method mix, and payload size statistics
- and `train/train_model.py` trains directly on the output of that same
function (imported, not reimplemented), so there is no train/serve
mismatch this time: whatever the model learned on is exactly what it's
scored on in production.

**The training data is synthetic** - `train/generate_synthetic_traffic.py`
generates labeled sessions from 16 archetypes (9 benign: casual browsing,
API polling, mobile sync bursts, file downloads, a legit bulk-import
client, browser page-load asset bursts, a dashboard polling fixed
endpoints, a user uploading large files, health-check/uptime-monitor
traffic, and normal one-shot logins; 7 attack: HTTP floods, credential
stuffing (fast and throttled/slow), scraper bursts, a rate-limit-boundary
flood, vulnerability scanning (fast and throttled), and large-payload
floods). This isn't traffic captured from your actual deployment - it's my
best modeling of what these patterns look like behaviorally. During
development it was stress-tested against edge cases it wasn't trained on
(a browser loading 25 page assets at once, a k8s health check, a single
login attempt, a legitimate high-volume bulk client) specifically to find
and fix false-positive/false-negative gaps before shipping - three separate
rounds of "test against real edge cases → find a gap → add the missing
archetype → retrain" - but no synthetic dataset covers everything your
real users and real attackers will do.

**A structural limit worth naming directly:** a legitimate high-throughput
automated client (a batch job firing requests on a precise interval) can
be statistically indistinguishable from a flood using only timing/volume/
size features - both are mechanically regular. No amount of retraining
fully solves this with behavioral features alone, because in the extreme
case there may genuinely be no difference to see. The practical fix is
`POST /admin/api-keys {"exempt_from_ml": true}`: mark specific keys you
issue to trusted, known clients as exempt from ML scoring. They still go
through the blocklist, the deterministic rate limiter, and the
auth-failure guard - just not the model. You know which of your API
consumers are trusted automation and which aren't; the model can't.

**What this means practically:**

- `ENFORCEMENT_MODE=enforce` is the default (the model has been calibrated
  and edge-case-tested, unlike the original). If this gateway protects
  something business-critical, consider running `monitor` mode first
  anyway and watching `attack_probability` in `GET /admin/requests` against
  your real traffic before trusting it to block anything - that costs you
  nothing but a few days.
- The deterministic **rate limiter** (`RATE_LIMIT_MAX_REQUESTS`) still
  matters even with a good model: it's what catches high-volume traffic
  from `exempt_from_ml` keys, and it needs no calibration to be correct.
- **Keep improving it with real traffic.** `POST /admin/requests/label`
  marks a historical request (with its stored feature vector) as
  ground-truth benign or attack; `python3 -m train.export_labeled_data`
  pulls all labeled rows into a CSV; `python3 -m train.train_model --data
  export.csv` retrains blended with (or instead of, via `--real-only`) the
  synthetic set. The more real traffic you label, the less this model
  depends on my synthetic archetypes matching your actual users and
  attackers.
- `POST /admin/model/score {"features": {...}}` scores a hand-built
  feature vector directly against the model - useful for testing specific
  scenarios without generating live traffic.

## Admin API reference

All `/admin/*` routes require `X-Admin-Token: <ADMIN_BOOTSTRAP_TOKEN>`
(or `?token=...` for the dashboard, since browsers can't set custom
headers on a plain navigation).

| Method & path | What it does |
|---|---|
| `POST /admin/api-keys` `{"owner", "exempt_from_ml"?}` | Issue a new client API key (shown once) |
| `GET /admin/api-keys` | List keys (owner, status, usage, flag count - not the raw key) |
| `DELETE /admin/api-keys/{id}` | Revoke a key |
| `POST /admin/api-keys/{id}/ml-exempt?exempt=true` | Toggle ML exemption on an existing key |
| `POST /admin/blocklist` `{"ip", "reason", "duration_seconds"?, "permanent"?}` | Manually block an IP |
| `GET /admin/blocklist` | List active blocks |
| `DELETE /admin/blocklist/{ip}` | Unblock an IP |
| `GET /admin/alerts?limit=100` | Recent alerts |
| `GET /admin/requests?limit=100` | Recent request log (incl. `attack_probability`) |
| `POST /admin/requests/label` `{"request_log_id", "label"}` | Mark a request ground-truth benign/attack, for retraining |
| `GET /admin/requests/labeled` | List labeled requests |
| `GET /admin/stats` | Summary counters + current mode/threshold |
| `POST /admin/model/score` `{"features": {...}}` | Score a feature vector directly - for calibration |
| `GET /admin/dashboard?token=...` | Human-readable HTML dashboard |

Client-facing routes (everything else) require `X-API-Key: <key>` (or
`Authorization: Bearer <key>`).

## Key settings (see `.env.example` for the full list)

| Setting | Purpose |
|---|---|
| `BACKEND_URL` | Your real service - all clean traffic is forwarded here |
| `ADMIN_BOOTSTRAP_TOKEN` | Secret for all `/admin/*` routes - rotate periodically |
| `ENFORCEMENT_MODE` | `enforce` (default) or `monitor` for the ML layer |
| `ATTACK_THRESHOLD` | Probability cutoff for the ML layer (default 0.5) |
| `RATE_LIMIT_MAX_REQUESTS` / `FLOW_WINDOW_SECONDS` | Deterministic rate limit |
| `BLOCK_DURATION_SECONDS` | How long an IP stays blocked |
| `AUTO_REVOKE_KEY_AFTER_FLAGS` | Auto-revoke a key after N attack flags |
| `TRUST_PROXY_HEADERS` | Only enable if a trusted LB/CDN sets `X-Forwarded-For` in front of you - otherwise clients can spoof their IP and dodge blocking |
| `ALERT_WEBHOOK_URL` | Slack-compatible webhook (or any URL accepting a JSON POST) |
| `SMTP_*` / `ALERT_EMAIL_*` | Email alerts |

## Operational notes

- **Storage** is SQLite (`DB_PATH`, WAL mode) - zero external dependencies,
  fine for a single instance. For multi-instance/high-throughput
  deployment, swap `app/db.py` for a Postgres-backed version (the function
  signatures are the small surface you'd need to reimplement).
- **State is per-process.** The flow tracker and rate limiter track
  per-IP behavior in memory; running multiple gateway replicas without a
  shared store means each replica has its own view of a given IP's recent
  traffic. For a single-instance deployment (or one behind a
  session-sticky/IP-sticky LB) this is fine as-is.
- **`TRUST_PROXY_HEADERS`** matters a lot: if you put this gateway behind
  your own load balancer/CDN, turn it on so real client IPs are used for
  blocking (not the LB's IP). If you leave it off while behind a proxy,
  every client will appear to share the LB's IP - blocking one attacker
  would block everyone.
- **API keys** are shown once at creation time; only a SHA-256 hash is
  stored. If a key is lost, revoke it and issue a new one.
- **Retention**: the request log is capped at the last 50,000 rows to
  keep the DB bounded; alerts and the blocklist are not auto-pruned.
