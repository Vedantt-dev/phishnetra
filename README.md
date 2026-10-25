# PhishNetra

**A Multi-Layered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and
Browser-Level Threat Mitigation.**

PhishNetra verifies every page a user navigates to — *never trust, always verify* — using four
independent detection layers, fuses their evidence in a zero-trust policy engine, and enforces
the decision directly in the browser: blocking, restricting credential entry, or warning, with a
human-readable explanation of why.

```
Chrome extension ──► FastAPI detection API ──► L1 Reputation & threat intel
 (enforcement)          (policy engine)        L2 URL ML ensemble (char n-grams + lexical)
     ▲                       │                 L3 DOM ML model (PhiUSIIL HTML features)
     └── ALLOW / WARN / RESTRICT / BLOCK ◄──── L4 Brand impersonation (homoglyph, typosquat, content)
                              │
                     React admin console (live feed, explainability, trends)
```

## Live demo

| | |
|---|---|
| Admin console | **https://phishnetra-seven.vercel.app/dashboard/** (click *Run demo scans*) |
| Demo phishing pages | https://phishnetra-seven.vercel.app/demo/ |
| API docs | https://phishnetra-seven.vercel.app/docs |
| Extension download | https://phishnetra-seven.vercel.app/phishnetra-extension.zip ([install steps](docs/PUBLISHING.md#a-load-unpacked-judges--testers-no-review)) |

The extension talks to the hosted API by default, so nothing needs to run locally. Every push to `main`
redeploys automatically. On Vercel the scan log lives in per-instance temporary storage, so the dashboard
starts empty after a cold start; set `PHISHNETRA_DB` to a Postgres URL for durable history.

See **[docs/architecture.md](docs/architecture.md)** for diagrams and design, and
**[docs/evaluation.md](docs/evaluation.md)** for methodology and results.

## Features

- **Two-stage real-time detection** — URL verified before the page loads; page structure and
  content verified after it renders (including late-rendered SPA login forms).
- **Four detection layers** — threat-intel/WHOIS/TLS reputation, URL ensemble ML, DOM random
  forest, brand-impersonation engine (homoglyphs, typosquats, combosquats, content claims, favicon pHash).
- **Zero-trust policy engine** — weighted fusion, decisive-evidence escalation, corroboration,
  expiring trust, credential least-privilege (`RESTRICT`), all tunable in `backend/config.yaml`.
- **Browser-level mitigation** — interstitial block page, zero-latency `declarativeNetRequest`
  blocklist, password-field lock with capture-phase submit interception, Shadow-DOM warning banner.
- **Fail-safe** — offline heuristics in the extension if the API is down; broken layers are
  excluded rather than crashing the scan.
- **Explainable** — every verdict carries per-layer scores, weights, contributions and reasons.
- **Admin console** — live WebSocket feed, verdict trends, layer averages, impersonated brands,
  manual URL scanning, false-positive/negative feedback loop.
- **Research tooling** — dataset download, training, CV, ROC/confusion plots, layer ablation study.

## Quick start

Requirements: Python 3.9+, Node 18+, Google Chrome.

```bash
# 1. Backend
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt

# 2. Dashboard (optional — a built copy is served by the backend at /dashboard)
cd dashboard && npm install && npm run build && cd ..

# 3. Run the API (http://localhost:8000 — dashboard at /dashboard/, API docs at /docs)
./scripts/start_backend.sh
```

Bundled models (trained on the synthetic seed set) are in `backend/models/`, so everything works
immediately. Train on real data for meaningful accuracy — see [Training](#training--evaluation).

### Load the Chrome extension

1. Open `chrome://extensions`, enable **Developer mode**.
2. **Load unpacked** → select the `extension/` folder.
3. Accept the data disclosure on the welcome tab, then pin PhishNetra; the popup shows API status
   (green dot) and the verdict for the current tab.
4. It uses the hosted API by default; to use your local server, open the popup → Settings → API URL
   `http://localhost:8000`.

Publishing to the Chrome Web Store / Edge Add-ons: see **[docs/PUBLISHING.md](docs/PUBLISHING.md)**.

### Try it (safe local demo pages)

Open <https://phishnetra-seven.vercel.app/demo/> (or <http://localhost:8000/demo/>) with the extension loaded:

| Page | Expected |
|---|---|
| `benign-blog.html` | ✓ ALLOW |
| `phish-login.html` (cloned "PayPal" login) | ✕ BLOCK — impersonates PayPal |
| `phish-wallet.html` (fake MetaMask recovery) | ✕ BLOCK — impersonates MetaMask |
| `http://paypa1-secure-login.xyz/verify/account` | ✕ blocked at the URL stage, before load |

Stop the backend and revisit the typosquat URL: the offline heuristics still block it.
Switch the popup to monitor mode to log without enforcing.

## Training & evaluation

```bash
python ml/download_datasets.py --phiusiil              # UCI PhiUSIIL (~55 MB)
python ml/download_datasets.py --tranco --openphish    # optional: larger allowlist, live feed
python ml/train_url_model.py --data phiusiil --cv      # L2 → backend/models/url_model.joblib
python ml/train_dom_model.py --data phiusiil           # L3 → backend/models/dom_model.joblib
python ml/evaluate.py --data phiusiil --sample 20000   # layer ablation through the policy engine
```

Reports (JSON metrics + ROC/confusion-matrix PNGs) are written to `ml/reports/`. Restart the API
to load new models. `python ml/generate_seed.py` regenerates the bundled synthetic seed data.

## API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/scan` | URL-stage scan `{url}` |
| `POST` | `/api/v1/scan/dom` | DOM-stage scan `{url, title, text, favicon_url, features}` |
| `GET` | `/api/v1/scans` | Scan history (`limit`, `verdict`, `q`) |
| `GET` | `/api/v1/scans/{id}` | One scan with full layer breakdown |
| `GET` | `/api/v1/stats` | Aggregates for the dashboard (`days`) |
| `GET` | `/api/v1/blocklist` | Domains synced into the extension's DNR rules |
| `POST` | `/api/v1/feedback` | `{url, label: phishing|legitimate}` → updates block/allow lists |
| `POST` | `/api/v1/override` | Log a user proceeding past a warning |
| `GET` | `/api/v1/models` | Loaded model metadata and test metrics |
| `WS` | `/api/v1/ws/live` | Live scan stream |
| `GET` | `/health` | Liveness + model status |

Interactive docs: <http://localhost:8000/docs>.

## Configuration

`backend/config.yaml` — layer weights, WARN/RESTRICT/BLOCK thresholds, escalation and
corroboration rules, cache TTL, WHOIS/TLS budgets, OpenPhish feed refresh, suspicious TLDs.
Environment: `PHISHNETRA_OFFLINE=1` (no network lookups), `PHISHNETRA_DB`, `PHISHNETRA_STATE_DIR`,
`PHISHNETRA_CONFIG`.

## Tests

```bash
cd backend && ../.venv/bin/python -m pytest
```

Covers feature extraction, homoglyph/typosquat/combosquat detection, reputation, every policy rule,
and an end-to-end API flow (scan → cache → DOM scan → override → feedback → blocklist → stats).

## Project structure

```
backend/    FastAPI service: app/{layers,features,api}, policy engine, models, data, tests
ml/         dataset download, seed generation, training, ablation evaluation, reports/
extension/  Chrome MV3 extension: service worker, content script, popup, blocked page
dashboard/  React + TypeScript + Tailwind + Recharts admin console
demo/       safe local phishing / benign test pages
docs/       architecture and evaluation write-ups
```

## Ethics & safety

Demo phishing pages are local, never submit data, and are clearly marked. Only use PhishNetra to
analyse URLs and sites you are authorised to test.
