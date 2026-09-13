# 🦋 Monarch Security Engine — How It Works

A plain-language tour of what this application **is**, **how it works internally**, and **how to build & run it**.
For module-level diagrams see [ARCHITECTURE.md](ARCHITECTURE.md). For click-by-click usage see [USAGE_GUIDE.md](USAGE_GUIDE.md).

---

## 1. What is Monarch?

Monarch is a **self-hosted, browser-based security auditing platform** for web applications and networks.
You give it a URL or an IP range, and it:

1. **Crawls** the target (with `fetch` or a real headless browser via Playwright) while recording every network request, cookie and header — like an automated DevTools.
2. **Runs 60+ security checks** over that recording: security headers, cookie flags, JWT handling, CORS, DOM-XSS sinks, exposed `.env`/`.git`/backup files, WordPress & admin-panel exposure, API security, transport issues.
3. **Fingerprints the tech stack**, audits SEO, probes admin endpoints, and computes a weighted security score (A–F).
4. **Explains everything**: each finding comes with severity, evidence and concrete remediation — plus an **AI-generated executive summary and prioritized fix plan** (OpenRouter, OpenAI, Claude, Gemini, a local Ollama model, or a built-in offline analyst).
5. **Keeps watching**: uptime monitors poll your sites and raise notifications when they go DOWN, run SLOW, or recover. A page-speed analyzer measures real DNS/TCP/TLS/TTFB timings and audits page weight.
6. **Exports** the result as Markdown, standalone HTML, JSON, or SARIF (GitHub Code Scanning compatible).

It is **defensive-only and passive by design**: it never exploits, never injects payloads beyond a harmless CORS preflight, and refuses private-range targets unless you explicitly allow them.

### Who is it for?

- Developers who want a security check before shipping.
- Security teams auditing systems they own.
- Home-lab / network operators mapping devices and watching services.
- Anyone who wants AI-assisted, plain-language explanations of what's wrong and how to fix it.

---

## 2. The big picture

```
   You (browser)
       │  http://localhost:3000
       ▼
┌─────────────────────────────┐
│  Node.js server (Express)   │  ← serves the UI (Vite build), the REST API,
│  + WebSocket + SSE          │    and pushes live events
└──────────┬──────────────────┘
           │
   ┌───────┴────────┬─────────────────┬──────────────┐
   ▼                ▼                 ▼              ▼
 Crawler      Security checks    Side tools     Background
 (fetch /     (60+ rules +       (TLS, recon,   (uptime monitors,
 Playwright)  scoring)           speed, net,    notifications)
                                 loadtest, DB)
           │
           ▼
   AI remediation (cloud APIs or your local Ollama — optional)
```

Everything runs on **one Node.js process** with only three runtime dependencies (`express`, `ws`, `cheerio`) and stores state as JSON files in `reports/` — no database to install.

---

## 3. How a scan works, step by step

1. **You submit a target** from the top bar (`POST /api/scans`). A rate limiter (10/min) and a concurrency cap (default 3) protect the server.
2. **Safety gate** (`engine/safety.js`): the URL is normalized and, unless `ALLOW_PRIVATE_TARGETS=true`, private/loopback addresses are refused — so a public deployment can't be abused as an SSRF proxy.
3. **Crawl** (`engine/crawler.js`): the chosen engine fetches up to `MAX_PAGES` pages, following same-origin links, and records every request/response (URL, method, status, type, size, timing) plus cookies and tech-stack clues.
4. **Checks** (`engine/checks/*`): pure functions analyze the crawl result + network log and return findings — each with a stable id, severity, description, evidence and remediation.
5. **Score** (`engine/checks/index.js`): findings are weighted into a 0–100 score and A–F grade.
6. **AI plan** (`ai/insights.js`, optional): findings are compacted into a prompt and sent to your configured provider. The model must answer with a JSON remediation plan; Monarch parses it deterministically and **falls back to a built-in rule-based analyst** if the provider fails or is not configured.
7. **Persist & stream**: the report is written to `reports/<uuid>.json` while progress events stream to the UI over Server-Sent Events; the sidebar history and exports (MD/HTML/JSON/SARIF) are generated from the same report.

Everything you see in the Scanner tabs (Findings, AI Plan, Network, Cookies, Inventory) and the Dashboard / WP-Admin / Tech Stack / SEO tabs is derived from that one report.

---

## 4. How the AI providers work

Monarch treats AI as **optional plumbing behind one interface** (`generateInsights`):

| Provider | Where it runs | Needs | Config |
|---|---|---|---|
| OpenRouter | Cloud | API key | `OPENROUTER_API_KEY` |
| OpenAI | Cloud | API key | `OPENAI_API_KEY` |
| Anthropic | Cloud | API key | `ANTHROPIC_API_KEY` |
| Gemini | Cloud | API key | `GEMINI_API_KEY` |
| **Ollama** | **Your machine / LAN** | **nothing** | `OLLAMA_BASE_URL`, `OLLAMA_MODEL` |
| none (heuristic) | In-process | nothing | — |

Selection order at startup: the `AI_PROVIDER` env var wins; otherwise the first configured key wins; `OLLAMA_BASE_URL` alone selects Ollama. You can also switch provider at runtime from the UI (AI pill) — that choice lives in the session and overrides env for subsequent scans.

**Ollama specifics**: Monarch calls your server's native `/api/chat` endpoint with `format: json` (constraining the model to a JSON object) and `temperature 0.2` for deterministic output. Base URLs are normalized — `localhost:11434`, `192.168.1.20:11434`, `https://ollama.mycompany.com` all work; only `http(s)` schemes are accepted. Because the model runs locally, **scan data never leaves your machine**, which makes Ollama the right choice for internal systems with strict data-handling rules.

---

## 5. How monitoring & notifications work

1. You create a monitor (URL + interval + expected status + keyword + notification preference).
2. `modules/monitor.js` schedules a timer per monitor and probes the URL with `fetch` (12s timeout), classifying each check as **up** / **degraded** (>1500 ms) / **down**.
3. Last 60 checkpoints are kept per monitor for the sparkline and uptime %.
4. When a check matches your `notifyOn` policy (`all` / `changes` / `down` / `none`), the monitor calls `notificationService.notifyMonitorStatus()`:
   - the alert is **persisted** to `reports/notifications.json` (7-day retention, max 250),
   - **broadcast** over the WebSocket `notification` channel,
   - rendered by the browser as an unread badge on the 🔔 bell, a dropdown entry, a toast, and (if permitted) a **native browser notification**.
5. Monitor state changes also stream on the `monitor_update` channel, so open cards refresh live.

---

## 6. How the page-speed analyzer works

`modules/speed.js` performs 1–3 timed runs against the target:

- **Raw-socket phase timing** — it connects with `net.Socket`/`tls.connect` to measure DNS lookup, TCP connect and TLS handshake separately.
- **Full fetch** — measures TTFB and content download, captures the body and headers.
- **Audits** — missing compression, no `Cache-Control`, render-blocking `<head>` stylesheets, synchronous head scripts, oversized inline JS, images without `loading="lazy"` or dimensions, legacy image formats, HTTP/1.1.
- **Scoring** — TTFB (35%), total time (25%), page size (25%), audits (15%) → 0–100 score + grade + plain-language advice.

The best (fastest) successful run is reported, so transient network noise doesn't punish the target.

---

## 7. Building & running

### Prerequisites
- **Node.js ≥ 20** (no native modules, no database)
- Optional: Playwright browser for the JS-rendered crawler (`npx playwright install chromium`)
- Optional: [Ollama](https://ollama.com) for local AI
- Optional: Python / Go runtimes for the power-up microservices

### Build & start

```bash
git clone https://github.com/mahmud-r-farhan/Monarch-Security-Engine.git
cd Monarch-Security-Engine
npm install          # install express, ws, cheerio + dev tooling
npm run build        # Vite: bundles src/frontend → dist/ (the production UI)
npm start            # node src/server.js → http://localhost:3000
```

That's the whole pipeline: **TypeScript frontend → Vite bundle → static files served by Express**. The server detects which UI to serve automatically: `dist/` (built) → `src/frontend` (dev, unminified) → `public/` (legacy fallback that asks you to build).

### Configuration

Copy `.env.example` → `.env` and set what you need (all optional):

- `PORT` — dashboard port (3000)
- `AI_PROVIDER` — `openrouter | openai | anthropic | gemini | ollama | none`
- `OLLAMA_BASE_URL` / `OLLAMA_MODEL` — local AI endpoint + model
- `CRAWLER` — `fetch` or `playwright`; `MAX_PAGES`, `MAX_CONCURRENT_SCANS`, `SCAN_TTL_HOURS`
- `ALLOW_PRIVATE_TARGETS` — keep `true` for local lab use, **set `false` when exposing the dashboard beyond localhost**

### Development loop

```bash
npm run dev          # server with --watch (auto-restart on change)
npm run build        # rebuild the frontend after editing src/frontend/**
npm test             # 34 unit & integration tests (node --test)
npm run typecheck    # tsc --noEmit over the frontend TypeScript
npm run app          # build + start in one command
```

### Practice target

```bash
npm run demo:target  # intentionally vulnerable app on http://localhost:4000
```
Scan `http://localhost:4000` to see every feature light up safely.

### Docker

```bash
docker build -t monarch:local .
docker run -p 3000:3000 monarch:local
```

### Deployment notes

- The app is a single process with in-memory state + JSON files; scale by running one instance per host (put `reports/` on persistent storage you control).
- If you expose it beyond localhost: reverse proxy with TLS + authentication, set `ALLOW_PRIVATE_TARGETS=false`, and treat `reports/` as sensitive (see [SECURITY.md](../SECURITY.md)).
- Prometheus metrics are at `/api/metrics`; the live API catalog at `/api/docs`.

---

## 8. Where the data lives

| Path | Content | Lifecycle |
|---|---|---|
| `reports/<scan-uuid>.json` | Full scan reports | Deleted on scan delete; TTL cleanup (default 24h) |
| `reports/monitors.json` | Monitor definitions + last 60 checkpoints each | Until you delete the monitor |
| `reports/notifications.json` | Notification history | Auto-pruned after 7 days (max 250) |
| `dist/` | Built frontend bundle | Regenerated by `npm run build` |

All of it is plain JSON in your working directory — back it up, inspect it, or wipe it freely.

---

## 9. Extending Monarch

- **New security check** → add `engine/checks/<name>.js`, register it in `checks/index.js`, add a test. ([CONTRIBUTING.md](../CONTRIBUTING.md))
- **New AI provider** → add a branch in `callProvider` (`ai/insights.js`), a `DEFAULT_MODEL` entry, and a UI option in the AI modal. Follow the Ollama pattern: normalize any user URL, parse JSON strictly, fall back to heuristics on failure.
- **New side tool** → service in `modules/`, router in `routes/tools.js`, one component per tab in `frontend/components/`.
- **New user-facing event** → emit through `notificationService.notify()` so it lands in the bell, toasts, and WebSocket in one step.
