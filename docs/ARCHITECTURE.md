# Monarch Security Engine v2.1 — Architecture

This document maps every module, its dependencies, and the data flow through the system.
It is the reference for the rules in [CONTRIBUTING.md](../CONTRIBUTING.md) — new code must fit this shape.

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Browser (SPA)                              │
│     Vite build: src/frontend (TS)  ──▶  dist/ (static assets)       │
│     REST /api/*  +  WebSocket /ws                                   │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│                    src/server.js  (slim orchestrator)               │
│  security headers · CORS · static serving · /api/health · /api/...  │
│  mounts route modules ──▶ starts background services                │
└───┬──────────────────┬──────────────────┬───────────────────────────┘
    │                  │                  │
┌───▼─────────┐ ┌──────▼───────┐ ┌────────▼────────┐
│ routes/     │ │ routes/      │ │ routes/         │
│ scans.js    │ │ monitors.js  │ │ tools.js        │
└───┬─────────┘ └──────┬───────┘ └────────┬────────┘
    │                  │                  │
┌───▼──────────────────────────────────────────────────────────────┐
│           engine/ · modules/ · scanRegistry · ai/ · report/       │
│                      (services & business logic)                  │
└───────────────────────────────────────────────────────────────────┘
```

---

## Backend Module Dependency Diagram

```
                            src/server.js
                                 │
        ┌────────────────────────┼─────────────────────────┐
        │ mounts                 │ mounts                  │ mounts
        ▼                        ▼                         ▼
  routes/scans.js          routes/monitors.js         routes/tools.js
        │                        │                         │
        │                        ├── modules/monitor.js    │
        │                        │    └──▶ modules/notifications.js
        │                        ├── modules/notifications.js
        │                        │                         │
        │                        │                         ├── modules/loadtest.js
        │                        │                         ├── modules/netdiscovery.js
        │                        │                         │    └──▶ modules/oui.js
        │                        │                         ├── modules/speed.js
        │                        │                         ├── modules/tls.js
        │                        │                         ├── modules/subdomain.js
        │                        │                         ├── modules/poking.js
        │                        │                         ├── modules/database.js
        │                        │                         │
        ├── engine/scanner.js    │                         └── middleware/rateLimiter.js
        │    ├── engine/crawler.js ──▶ engine/safety.js   (also: server.js, routes/scans.js)
        │    ├── engine/network.js  (NetworkLog)
        │    ├── engine/checks/index.js
        │    │    ├── checks/headers.js
        │    │    ├── checks/cookies.js
        │    │    ├── checks/clientside.js
        │    │    ├── checks/exposure.js
        │    │    ├── checks/infoleak.js
        │    │    ├── checks/jwt.js
        │    │    └── checks/transport.js
        │    ├── checks/techstack.js
        │    ├── checks/seo.js
        │    ├── checks/apisecurity.js
        │    ├── checks/wpadmin.js
        │    └── ai/insights.js
        │
        ├── scanRegistry.js
        ├── report/markdown.js ◀── report/html.js
        ├── report/sarif.js
        └── middleware/rateLimiter.js

  Background services initialized in server.js:
      wsServer (modules/ws.js)          ◀── broadcasts: monitor_update, notification
      monitorService (modules/monitor.js)
      notificationService (modules/notifications.js)
      scanRegistry.startTtlCleanup()

  External runtime dependencies (only 3): express, ws, cheerio
  Optional power-ups (auto-detected at runtime): services/python, services/go
  Programmatic consumers: src/index.js re-exports the engine + report surface
```

### Layering rules

```
routes/*  ──▶  modules/*  ──▶  (node built-ins only)
    │              │
    │              └──▶ engine/*  ──▶ ai/* (optional, degrades to heuristics)
    ├──▶ scanRegistry.js
    └──▶ report/*       (markdown, html, sarif — no outbound network)

Server.js never imports modules/* business logic directly except
monitorService / notificationService / wsServer for boot-time init.
```

| Rule | Reason |
|---|---|
| `routes/` never call each other | Keeps routers independently testable |
| `modules/` never import `routes/` or `server.js` | Prevents circular imports |
| `engine/` stays dependency-free (except cheerio) | Scanner works in CLI, server, and tests alike |
| All user-facing events flow through `notificationService.notify()` | Single notification pipeline (persist + WS + listeners) |
| Persistence lives in `reports/*.json` | Zero database dependency; `monitors.json`, `notifications.json`, `<scan-uuid>.json` |

---

## Backend Module Reference

| Module | Responsibility | Key exports |
|---|---|---|
| `server.js` | Boot, security headers, CORS, static files, health/config/docs endpoints, mounts routers, starts services | — |
| `scanRegistry.js` | In-memory scan registry + disk persistence + TTL cleanup, concurrency counter | `scanRegistry` |
| `routes/scans.js` | Start/stream/list/export/delete scans | `router` |
| `routes/monitors.js` | Monitor CRUD + check/toggle, notification REST (list/read/clear) | `router` |
| `routes/tools.js` | Page speed, TLS, recon, load test, netdiscovery, poke, db routes | `router` |
| `engine/scanner.js` | Orchestrates crawl → checks → score → AI insights, emits progress events | `runScan`, `summarizeScan` |
| `engine/crawler.js` | Fetch & Playwright crawlers, DevTools-style network log capture | `crawl` |
| `engine/network.js` | Request log with severity/cap handling | `NetworkLog` |
| `engine/safety.js` | Target normalization + private-range SSRF gate (`ALLOW_PRIVATE_TARGETS`) | `normalizeTarget`, `assertTargetAllowed`, `isPrivateIp` |
| `engine/checks/*` | 60+ security checks (headers, cookies, JWT, DOM-XSS, exposure, transport, infoleak) + techstack/seo/apisecurity/wpadmin | `runChecks`, `scoreFindings`, per-check fns |
| `modules/monitor.js` | Uptime polling with interval timers, history (60 pts), status transitions, per-monitor `notifyOn` preference | `monitorService` |
| `modules/notifications.js` | Persistent notification hub: create/list/read/clear, WS broadcast, 7-day retention, 250-item cap | `notificationService` |
| `modules/speed.js` | Page speed analyzer: raw-socket DNS/TCP/TLS phases, TTFB, audits (compression, caching, render-blocking, images), 0–100 score | `analyzePageSpeed`, `quickStatusCheck` |
| `modules/loadtest.js` | Concurrency load runner with p50/p95/p99 + security probes | `LoadTestRunner` |
| `modules/netdiscovery.js` | ARP, ICMP sweep, TCP/UDP port scan, CIDR/range expansion | `runNetworkDiscovery`, `scanHostPorts`, … |
| `modules/oui.js` | MAC vendor (OUI) database lookup | `resolveVendor`, `normalizeMac` |
| `modules/tls.js` | Certificate chain analysis, protocol/cipher grading, security-header audit | `analyzeTLS`, `checkSecurityHeaders` |
| `modules/subdomain.js` | CT log (crt.sh) enumeration, DNS brute, sitemap/robots parsing | `enumerateSubdomains`, `parseSitemap`, `analyzeRobotsTxt` |
| `modules/poking.js` | HTTP inspector + SSH banner grab | `pokeHttp`, `pokeSsh` |
| `modules/database.js` | Wire-protocol handshakes (postgres/mysql/mongo/redis/mssql) + stress test | `testDbConnection`, `runDbLoadTest` |
| `modules/ws.js` | WebSocket server: subscriptions, heartbeat, broadcast | `wsServer` |
| `modules/powerup.js` | Optional bridge to Python/Go microservices; graceful degradation when offline | `checkPowerUpServices` |
| `middleware/rateLimiter.js` | In-memory sliding-window limiter (scan 10/min, api 120/min, discovery 20/min) | `scanLimiter`, `apiLimiter`, `discoveryLimiter` |
| `ai/insights.js` | AI remediation via OpenRouter/OpenAI/Anthropic/Gemini (plain fetch) with deterministic heuristic fallback | `generateInsights`, `detectProvider`, `DEFAULT_MODEL` |
| `report/*.js` | Export renderers: markdown, standalone HTML, SARIF 2.1.0 | `renderMarkdown`, `renderHtml`, `renderSarif` |
| `env.js` | `.env` loader | `loadEnv` |
| `index.js` | Programmatic API surface for library consumers | re-exports `runScan`, checks, crawl, AI, report renderers |
| `cli.js` | Headless scan runner with exit codes | — |

---

## Data Flow

### 1. Security scan
```
POST /api/scans
  → routes/scans.js (scanLimiter, concurrency check via scanRegistry)
    → engine/scanner.js runScan()
        → engine/safety.js normalizeTarget
        → engine/crawler.js crawl()          (fetch or playwright)
        → engine/network.js NetworkLog       (per-request events → SSE)
        → engine/checks/* + techstack/seo/apisecurity/wpadmin
        → scoreFindings() → ai/insights.js generateInsights()
    → scanRegistry.persist() → reports/<uuid>.json
    ← 202 { id }  ·  progress via GET /api/scans/:id/events (SSE)
```

### 2. Uptime monitoring → notifications
```
server.js boot
  → monitorService.init(broadcast)      loads reports/monitors.json, schedules timers
  → notificationService.init(broadcast) loads reports/notifications.json

every intervalSeconds per monitor:
  modules/monitor.js checkMonitor()
    → fetch probe → checkpoint {status: up|down|degraded, latencyMs, statusCode}
    → status transition? → per-monitor notifyOn policy
        → notificationService.notifyMonitorStatus()
            → persist to reports/notifications.json
            → wsServer.broadcast('notification', …)   ──▶ browser bell badge + toast
                                                              + native browser notification
    → wsServer.broadcast('monitor_update', …)         ──▶ monitor card live refresh
```

### 3. Page speed analysis
```
POST /api/speed/analyze
  → routes/tools.js
    → modules/speed.js analyzePageSpeed()
        → raw net.Socket + tls.connect  → dns/tcp/tls phase timings
        → fetch()                       → ttfb, download, size, headers, html
        → audits (compression, caching, blocking CSS/JS, images)
        → weighted score → grade → advice
    ← JSON {metrics, phases, audits, score, grade, advice}
```

### 4. WebSocket events
```
/ws  (modules/ws.js — subscribe/heartbeat)
  channels: monitor_update, notification (+ scan lifecycle via SSE, not WS)
```

---

## Frontend Architecture

```
src/frontend/
├── index.html          SPA shell — topbar (scan form, AI pill, 🔔 bell), nav tabs, views
├── main.ts             Orchestrator: setup*, navigation, WebSocket client, window.* handlers
├── state.ts            Single mutable AppState store
├── types.ts            Shared TypeScript interfaces (ScanReport, UptimeMonitor, AppState, …)
├── utils.ts            $, $$, toast, escapeHtml, formatBytes
└── components/         One file per tab
    ├── scanner.ts      Scan form, findings, network log, cookies, inventory, AI plan
    ├── dashboard.ts    Severity distribution, category breakdown
    ├── modals.ts       AI config, monitor modal, dev modal wiring
    ├── monitors.ts     Monitor cards + notifyOn badge + pause/resume
    ├── notifications.ts  Bell dropdown, unread badge, WS handler, browser notifications
    ├── speedtest.ts    Speed form + waterfall/metrics/audits rendering
    ├── tlsrecon.ts     TLS analyzer, headers audit, subdomains, sitemap/robots
    ├── netdiscovery.ts Subnet scan UI, device table, CSV/JSON export
    ├── loadtester.ts   Load test form + live metrics
    ├── inspector.ts    HTTP request builder + SSH tester
    └── dbtester.ts     Database handshake tester
```

### Frontend dependency rules

```
main.ts ──▶ components/* ──▶ { utils.ts, state.ts, types.ts }

- components never import each other (one exception: scanner.ts → dashboard.ts)
- state.ts imports types only; no DOM access outside components
- Vite bundles: index.html + main.ts → dist/ (vanilla TS, no framework)
```

### Frontend ↔ Backend contract
```
REST:  fetch('/api/…') same-origin — no client-side routing, view switching is state-based
WS:    ws(s)://host/ws  → subscribe 'all' → handles monitor_update + notification channels
SSE:   EventSource-style manual parsing for scan progress and load test streams
```

---

## Build & Runtime Topology

```
npm run build      vite build  src/frontend → dist/
npm start          node src/server.js
                   ├── serves dist/ (falls back to src/frontend in dev, then public/)
                   ├── REST API under /api  (rate limited)
                   ├── WebSocket at /ws
                   └── background timers: monitor intervals, scan TTL cleanup (1h)
reports/           <scan-uuid>.json · monitors.json · notifications.json  (auto-created)
```

## Testing Topology

```
test/
├── checks.test.js            engine checks fixtures
├── netdiscovery.test.js      network expansion, ARP parsing, real socket probes
├── v2_modules.test.js        OUI, monitor stats, techstack, seo, apisecurity, wpadmin
└── notifications-speed.test.js   notification lifecycle, notifyOn policy, speed analyzer

Run: npm test (node --test) · Typecheck: npm run typecheck (tsc --noEmit)
```
