# PhishNetra Architecture

PhishNetra is a **multi-layered, AI-driven, zero-trust** phishing defence. It verifies every
top-level navigation in the browser before trusting it, fuses evidence from four independent
detection layers into one explainable risk score, and enforces the result at browser level.

## 1. System overview

```mermaid
flowchart LR
  subgraph Browser["Chrome (MV3 extension)"]
    NAV["webNavigation.onBeforeNavigate"] --> BG["Service worker<br/>policy enforcement point"]
    CS["Content script<br/>DOM feature extractor"] --> BG
    DNR["declarativeNetRequest<br/>blocklist rules"]
    OFF["Offline heuristics<br/>(fail-safe fallback)"] -.-> BG
    BG --> UI["Blocked page · Warn banner ·<br/>Credential guard · Popup"]
  end
  subgraph API["FastAPI detection service"]
    SC["Scanner<br/>(cache, fail-safe layers)"] --> L1["L1 Reputation & threat intel"]
    SC --> L2["L2 URL ML ensemble"]
    SC --> L3["L3 DOM ML model"]
    SC --> L4["L4 Brand impersonation"]
    L1 & L2 & L3 & L4 --> PE["Zero-trust policy engine"]
    PE --> DB[("SQLite<br/>scan log")]
    PE --> WS["WebSocket live feed"]
  end
  BG -- "POST /scan · /scan/dom" --> SC
  BG -- "GET /blocklist (30 min)" --> DNR
  WS --> DASH["React admin console"]
  DB --> DASH
```

## 2. Two-stage verification of a navigation

```mermaid
sequenceDiagram
  participant U as User
  participant SW as Extension service worker
  participant API as PhishNetra API
  participant P as Page (content script)
  U->>SW: navigates to URL
  Note over SW: blocklisted domain? → DNR redirect, 0 ms
  SW->>API: POST /api/v1/scan (URL stage, 1.2 s budget)
  API-->>SW: risk, verdict, reasons, layer scores
  alt verdict = BLOCK
    SW->>U: redirect to blocked.html (interstitial)
  else API unreachable
    SW->>SW: offline lexical + typosquat heuristics
  end
  P->>SW: DOM features (forms, password fields, links…)
  SW->>API: POST /api/v1/scan/dom (DOM stage)
  API-->>SW: refined verdict
  SW->>P: WARN → banner · RESTRICT → lock password fields · BLOCK → interstitial
```

**Stage 1 (pre-navigation)** uses only what is known from the URL: reputation, lexical ML and
brand typosquatting. **Stage 2 (post-load)** adds page structure (Layer 3) and page-content
impersonation (title/text claims a brand that does not own the domain). Single-page apps that
render the login form late trigger one re-scan when a password field appears.

## 3. Detection layers

| Layer | Input | Technique | Output examples |
|---|---|---|---|
| **L1 Reputation & intel** (`backend/app/layers/reputation.py`) | domain | Allowlist (Tranco), blocklist (OpenPhish + user reports), WHOIS age, TLS verification, TLD reputation, free-hosting detection | "Domain registered only 4 days ago" |
| **L2 URL ML** (`url_model.py`) | URL string | Soft-voting ensemble: char 3–5-gram TF-IDF + 33 lexical features → logistic regression; lexical features → histogram gradient boosting | "URL classifier rates this 93 % likely phishing" |
| **L3 DOM ML** (`dom_model.py`) | 25 PhiUSIIL HTML features from the live DOM | Random forest | "Password form submits credentials to a different domain" |
| **L4 Brand impersonation** (`brand.py`) | host, title, text, favicon | Homoglyph skeletons (TR39 subset + leetspeak), Levenshtein typosquatting, combosquatting, content brand claims, favicon pHash | "Homoglyph spoof of PayPal: 'pаypal' imitates 'paypal'" |

Every layer returns a `LayerResult(score 0–100 | None, reasons, details)`. A layer that crashes
or has nothing to judge returns `None` and is excluded from the weights (fail-safe, not fail-open).

## 4. Zero-trust policy engine (`backend/app/policy.py`)

```mermaid
flowchart TD
  A["Layer scores"] --> B["Weighted average over available layers<br/>(weights renormalised)"]
  B --> C{"Decisive layer ≥ 90?<br/>(reputation / brand only)"}
  C -- yes --> C1["risk ≥ that score"]
  C -- no --> D
  C1 --> D{"Any layer ≥ 80?"}
  D -- yes --> D1["risk ≥ WARN threshold"]
  D -- no --> E
  D1 --> E{"Strong layer ≥ 70 plus<br/>another layer ≥ 30?"}
  E -- yes --> E1["risk ≥ strong score (+5 per extra strong layer)"]
  E -- no --> F
  E1 --> F{"Decision"}
  F -->|"blocklisted or risk ≥ 75"| BLOCK
  F -->|"password form, unverified, risk ≥ 45"| RESTRICT
  F -->|"risk ≥ 30"| WARN
  F -->|otherwise| ALLOW
```

Zero-trust principles applied:

* **Never trust, always verify** — every top-level navigation is scored; unknown domains start
  with baseline risk 15, not 0.
* **Least privilege for credentials** — on an unverified domain with a password form, risk ≥ 45
  puts the page in `RESTRICT`: password inputs are locked and form submission is intercepted in
  the capture phase until the user explicitly confirms.
* **Trust expires** — verdicts are cached for 15 minutes only; user overrides last 30 minutes and
  are logged for audit.
* **Evidence-proportional enforcement** — statistical ML layers alone can WARN but cannot BLOCK;
  blocking needs decisive evidence (blocklist, brand spoof) or corroboration between layers.
* **Degrade safely** — if the API is unreachable, the extension falls back to offline heuristics
  instead of failing open.

All weights and thresholds live in `backend/config.yaml` for experimentation.

## 5. Browser-level mitigation

| Verdict | Mechanism |
|---|---|
| `BLOCK` | `chrome.tabs.update` to an interstitial with risk, reasons and layer breakdown; blocklisted domains are redirected by `declarativeNetRequest` before any request is sent |
| `RESTRICT` | Content script locks `input[type=password]`, intercepts `focusin`/`submit` in the capture phase, shows a confirm dialog |
| `WARN` | Shadow-DOM banner (page CSS can't hide it) with reasons and report / mark-safe buttons |
| `ALLOW` | Badge ✓ |

User feedback (`Report phishing` / `It's safe`) updates the blocklist/allowlist immediately and is
stored for future retraining.
