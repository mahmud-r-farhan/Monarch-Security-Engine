# Monarch Security Engine v2.1 — Usage Guide

## Quick Start

1. **Install**
```bash
npm install
npm run build
npm start
# Open http://localhost:3000
```

2. **First Scan**
- Enter target URL (e.g. `https://example.com` or `http://localhost:4000`)
- Choose engine: `fetch` (fast, zero-dep) or `playwright` (headless browser, needs `npx playwright install`)
- Set max pages (1-200)
- Click **Scan**
- Watch live progress via SSE

## Understanding Results

### Grade
- **A (90-100)**: Hardened
- **B (70-89)**: Good, minor issues
- **C (40-69)**: Needs hardening
- **D (20-39)**: Multiple high issues
- **F (0-19)**: Critical exposure

### Severity
- **Critical**: Immediate exploitation risk (e.g. exposed .env, JWT alg=none)
- **High**: Significant risk (e.g. missing HSTS, CORS wildcard)
- **Medium**: Defense-in-depth (e.g. missing CSP nonce, weak SameSite)
- **Low/Info**: Hardening suggestions

### Views

#### Scanner
- **Findings**: All vulnerabilities with remediation
- **AI Plan**: Executive summary, attack narrative, prioritized action plan (needs OpenRouter key or offline heuristic)
- **Network**: DevTools-style log of all requests (method, status, size, timing)
- **Cookies**: HttpOnly, Secure, SameSite audit
- **Inventory**: External origins discovered

#### Dashboard
- Severity distribution, category breakdown, posture metrics

#### WP & Admin
- WordPress detection, XML-RPC exposure, author enumeration, exposed admin panels

#### Tech Stack
- Fingerprinted frameworks (React, Next, Vue, WordPress, Express, etc.)
- Rate limiting detection (RFC RateLimit headers)

#### SEO & AIO
- Title, meta description, canonical, heading hierarchy, OpenGraph, JSON-LD, image alt audit

#### TLS & Headers (v2)
- **TLS Analyzer**: Paste `example.com` → certificate chain, expiry days, protocol (TLS 1.2/1.3), cipher, grade A-F, findings
- **Security Headers**: Paste `https://example.com` → checks HSTS, CSP, X-Frame-Options, etc., grade & score

#### Recon (v2)
- **Subdomains**: Enter `example.com` → CT logs (crt.sh) + common subdomain DNS brute-force
- **Sitemap/Robots**: Enter `https://example.com` → parse sitemap.xml URLs, analyze robots.txt disallows for sensitive paths

#### Network
- Select subnet (auto-detected), choose Fast/Full/Custom mode
- ICMP sweep + ARP table + TCP/UDP port mapping + OUI vendor lookup
- Export CSV/JSON

#### Monitor
- Add URL, interval (15s-5m), expected status, keyword
- **Notifications (NEW v2.1)**: choose when to be alerted per monitor:
  - **All events** — every DOWN / SLOW / recovery check
  - **Only status changes** — alert only when the site state flips
  - **Only when down** — alert on outages
  - **Never** — silent monitoring
- Live sparkline, uptime %, WebSocket push
- **Pause/Resume (NEW v2.1)**: use the ⏸️/▶️ button to suspend a monitor without deleting it

#### Page Speed (NEW v2.1)
- Enter a URL and run 1-3 timed requests
- **Connection waterfall**: DNS lookup → TCP connect → TLS handshake → server TTFB → content download, with color-coded bars
- **Metrics**: TTFB, total load, page size, compression (gzip/brotli), HTTP protocol version, status code
- **Audits**: missing compression, no Cache-Control, render-blocking CSS, synchronous head scripts, oversized inline JS, images missing lazy-loading or dimensions, legacy image formats, HTTP/1.1
- **Score**: weighted 0-100 with A-F grade (TTFB 35%, total 25%, size 25%, audits 15%)
- **Advice**: prioritized fix suggestions (CDN, compression, HTTP/2, streaming, …)

#### Notification Center (NEW v2.1)
- **🔔 Bell icon** in the topbar shows an unread badge
- Dropdown lists the latest alerts with severity icons (🔴 down, 🟠 slow, 🟢 live/recovered) and relative timestamps
- Clicking an alert marks it read and jumps to the Monitor view
- **Mark all read** / **Clear** actions in the dropdown header
- Toasts pop immediately for live feedback; native browser notifications fire if permission is granted
- Alerts persist for 7 days (max 250) and survive server restarts

#### Load Test
- Set URL, method, concurrency (1-100), total (5-2000)
- Optional security probes: CSRF, SQLi, XSS, rate-limit burst
- Live RPS, p50/p95/p99

#### Inspector
- **HTTP**: Craft request with Bearer/Basic/API-Key auth, custom headers/body
- **SSH**: Banner grab, OS hint, latency

#### Databases
- Test PostgreSQL, MySQL, MongoDB, Redis, MSSQL handshakes
- Stress test 30 concurrent connections

## AI Configuration

1. Click **AI: OpenRouter** pill in topbar
2. Choose provider:
   - **OpenRouter** (recommended): Multi-model, get key at openrouter.ai, model `openai/gpt-4o-mini` (fast + cheap; ~$0.001 per scan)
   - **OpenAI**: `gpt-4o-mini`
   - **Anthropic**: `claude-3-5-haiku-latest`
   - **Gemini**: `gemini-1.5-flash`
   - **Ollama** (NEW): Local / self-hosted models — **no API key needed**, see below
   - **Offline**: No key, heuristic rules
3. Paste API key (stored in session only, never persisted to disk)
4. Save

### Ollama (local / self-hosted AI)

Run the AI analysis fully offline with your own models:

```bash
# 1. Install Ollama (https://ollama.com) and pull a model
ollama pull llama3.2          # default; qwen2.5:7b, mistral, gemma2 also work well

# 2. Serve (listens on http://localhost:11434 by default)
ollama serve

# 3. Point Monarch at it — either via env before starting:
OLLAMA_BASE_URL=http://localhost:11434 OLLAMA_MODEL=llama3.2 npm start
# …or at runtime in the UI: AI pill → Provider "Ollama (Local)" → server URL + model → Save
```

- **Server URL** accepts `localhost:11434`, `http://192.168.1.20:11434`, `https://ollama.mycompany.com` — scheme and `/api` suffixes are normalized automatically; `http(s)` only
- Choose any model you have pulled (`ollama list`); larger models (7B+) give noticeably better remediation plans
- All data stays on your machine — ideal for scanning internal systems where nothing may leave the network
- Monarch talks to Ollama's native `/api/chat` with `format: json`, so the remediation plan is parsed deterministically; if the model misbehaves, the offline heuristic analyst takes over automatically
- Works with Ollama behind a reverse proxy or on another machine — the URL is fully configurable

### AI provider health check (NEW)

The AI modal has a **🔌 Test Connection** button that probes the provider with the values currently in the form — *before* saving. It tells you:

- **Reachable / key valid**, with latency and how many models are available
- **Ollama**: the list of installed models (so you can paste the exact name into the model field), or a hint like "Start it with: `ollama serve`" if the server is down
- **Cloud providers**: whether the key was accepted (401/403 → key rejected, 429 → quota exhausted)

Same check over the API:

```bash
# Probe the active provider
curl http://localhost:3000/api/ai/health

# Probe everything (status board)
curl "http://localhost:3000/api/ai/health?all=1"

# Probe one provider (fresh, skipping the 30s cache)
curl "http://localhost:3000/api/ai/health?provider=ollama&fresh=1"

# Test an unsaved config (what the modal's Test Connection button does)
curl -X POST http://localhost:3000/api/ai/health -H "content-type: application/json" \
  -d '{"provider":"ollama","baseUrl":"http://localhost:11434"}'
```

## Exports

In scan view, after completion:
- **MD**: Markdown report for docs
- **HTML**: Standalone self-contained printable report
- **JSON**: Raw machine-readable
- **SARIF**: GitHub Code Scanning compatible → upload via `github/codeql-action/upload-sarif`

## CLI

```bash
node src/cli.js https://example.com --max-pages 50 --engine fetch --out ./reports
node src/cli.js http://localhost:4000 --no-ai --out audit
```

Exit codes: 0=clean, 1=low/med, 2=high/critical, 3=error

## API Examples

```bash
# Start scan
curl -X POST http://localhost:3000/api/scans -H "content-type: application/json" -d '{"target":"https://example.com","maxPages":10}'

# Stream events
curl http://localhost:3000/api/scans/<id>/events

# Get report
curl http://localhost:3000/api/scans/<id> | jq

# TLS analyze
curl -X POST http://localhost:3000/api/tls/analyze -H "content-type: application/json" -d '{"target":"example.com"}'

# Subdomain enum
curl -X POST http://localhost:3000/api/recon/subdomains -H "content-type: application/json" -d '{"domain":"example.com"}'

# Page speed analysis (NEW v2.1)
curl -X POST http://localhost:3000/api/speed/analyze -H "content-type: application/json" -d '{"target":"https://example.com","runs":2}'

# Quick live/down probe (NEW v2.1)
curl -X POST http://localhost:3000/api/speed/status -H "content-type: application/json" -d '{"target":"https://example.com"}'

# Create a monitor with notification preference (NEW v2.1)
curl -X POST http://localhost:3000/api/monitors -H "content-type: application/json" \
  -d '{"name":"Prod API","url":"https://api.example.com/health","intervalSeconds":60,"notifyOn":"down"}'

# Point AI at a local Ollama server (NEW)
curl -X POST http://localhost:3000/api/config -H "content-type: application/json" \
  -d '{"provider":"ollama","model":"llama3.2","baseUrl":"http://localhost:11434"}'

# Check AI provider health (NEW)
curl "http://localhost:3000/api/ai/health?all=1"

# List notifications / unread count (NEW v2.1)
curl "http://localhost:3000/api/notifications?limit=20"
curl http://localhost:3000/api/notifications/unread-count

# Mark one / all read, clear all (NEW v2.1)
curl -X POST http://localhost:3000/api/notifications/<id>/read
curl -X POST http://localhost:3000/api/notifications/read-all
curl -X DELETE http://localhost:3000/api/notifications

# Pause / resume a monitor (NEW v2.1)
curl -X POST http://localhost:3000/api/monitors/<id>/toggle

# Prometheus metrics (includes unread notification gauge)
curl http://localhost:3000/api/metrics
```

### WebSocket channels

Subscribe to `ws://localhost:3000/ws` and send `{"action":"subscribe","channel":"all"}`:

| Channel | Payload | Description |
|---|---|---|
| `monitor_update` | monitor object | Emitted on every check |
| `notification` (NEW v2.1) | notification object | Monitor DOWN/SLOW/LIVE alerts |

## Power-Ups

```bash
# Python (advanced secrets)
pip install requests
python3 services/python/advanced_scanner.py --server --port 5001

# Go (fast port scan)
go run services/go/main.go -server -port 5002

# Node will auto-detect if running
curl http://localhost:3000/api/health
# Should show power-up status in future
```

## Troubleshooting

- **Build required page**: Run `npm run build`
- **Playwright not found**: `npx playwright install chromium` or use fetch engine
- **Private target blocked**: Set `ALLOW_PRIVATE_TARGETS=true` (default true)
- **Rate limited**: Wait 1 min (scan limiter 10/min)
- **No findings**: Check if target is reachable, try fetch engine first
- **AI not working**: Check key in UI config, or use offline mode
- **No notifications arriving** (NEW v2.1): ensure the monitor is active (not paused), the notification preference is not "Never", and the WS indicator shows connected — check `monarch_notifications_unread` in `/api/metrics`
- **Browser notifications not showing**: allow notifications for the site in your browser settings; the app asks permission on first click

## Security Best Practices

- Only scan own systems or with explicit permission
- Use offline heuristic for sensitive internal apps (no data leaves)
- API keys stored in sessionStorage only (cleared on tab close)
- Reports stored in `reports/` — clean periodically or set `SCAN_TTL_HOURS`
- Monitor URLs and status history are stored in `reports/monitors.json`; notification history in `reports/notifications.json` — treat both as sensitive (they reveal internal hostnames)
- Run behind reverse proxy with TLS in production
- Set `ALLOW_PRIVATE_TARGETS=false` for public deployments
