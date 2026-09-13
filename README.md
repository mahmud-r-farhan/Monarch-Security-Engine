# 🦋 Monarch Security Engine v2

### Professional Web Vulnerability Scanner, Attack Surface Mapper & Network Defense Platform

**Crawl → Record DevTools traffic → Detect 60+ vulns → Fingerprint tech stack → Audit TLS/SSL & headers → Enumerate subdomains → Discover LAN devices → Load test → Get AI remediation → Export SARIF/Markdown/HTML**

[![CI](https://github.com/mahmud-r-farhan/Monarch-Security-Engine/actions/workflows/ci.yml/badge.svg)](https://github.com/mahmud-r-farhan/Monarch-Security-Engine/actions/workflows/ci.yml)
[![Security](https://github.com/mahmud-r-farhan/Monarch-Security-Engine/actions/workflows/security.yml/badge.svg)](https://github.com/mahmud-r-farhan/Monarch-Security-Engine/actions/workflows/security.yml)
[![Docker](https://github.com/mahmud-r-farhan/Monarch-Security-Engine/actions/workflows/docker.yml/badge.svg)](https://github.com/mahmud-r-farhan/Monarch-Security-Engine/actions/workflows/docker.yml)
![Node](https://img.shields.io/badge/node-%3E%3D20-339933?logo=node.js&logoColor=white)
![Version](https://img.shields.io/badge/version-2.0.0-4f7cff)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Zero native deps](https://img.shields.io/badge/native%20deps-0-success)

</div>




---

[![image.png](https://i.postimg.cc/jjxtb6d3/image.png)](https://postimg.cc/k2pkNbSW)
> ⚠️ **Defensive Only** — Monarch is for **educational use, defensive research, and auditing systems you own or are explicitly authorised to test**. Scanning third-party targets without permission is illegal. Passive by design, but you remain responsible for where you point it.

---

## ✨ What's New in v2.0

- **🎨 Professional UI Overhaul** — Dark, modern, glass-morphism design system with Inter + JetBrains Mono, responsive, accessible
- **🔐 TLS & Security Headers Analyzer** — Certificate chain, expiry, weak ciphers, grade (A-F), HSTS/CSP audit
- **🧭 Recon & Asset Discovery** — Subdomain enumeration via CT logs + DNS, sitemap parsing, robots.txt analysis
- **📄 SARIF Export** — GitHub Code Scanning compatible (`report.sarif`)
- **🛡️ Hardened Security** — Fixed CSP `frame-ancestors *` bug → `none`, `X-Frame-Options: DENY`, rate limiting (scan 10/min, API 120/min, discovery 20/min), input validation, TTL cleanup
- **🐍 Python & Go Power-Ups** — Optional microservices for high-entropy secret detection & ultra-fast port scanning
- **⚡ Crawler Fix** — Previously returned dummy `score 100` for SEO/techstack — now stores real HTML (500k truncated)
- **📊 Prometheus Metrics** — `/api/metrics` endpoint
- **📚 API Docs** — `/api/docs` endpoint listing all routes
- **🐳 Production Docker** — Multi-stage build, healthcheck, non-root user

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/mahmud-r-farhan/Monarch-Security-Engine.git
cd Monarch-Security-Engine
npm install
```

### 2. Build Frontend

```bash
npm run build
```

### 3. Launch

```bash
npm start
# 🦋 Monarch v2 → http://localhost:3000
```

### 4. Practice Target (Vulnerable Demo)

```bash
# Terminal 2
npm run demo:target
# → http://localhost:4000 (intentionally vulnerable)
```

Scan `http://localhost:4000` in Monarch to see findings.

---

## 🐳 Docker

```bash
docker build -t monarch:local .
docker run -p 3000:3000 monarch:local

# Or via GHCR
docker pull ghcr.io/mahmud-r-farhan/monarch-security-engine:latest
docker run -p 3000:3000 ghcr.io/mahmud-r-farhan/monarch-security-engine:latest
```

---

## 🧩 Power-Up Services (Optional)

Monarch core works 100% without them. Enable for enhanced scanning:

### Python — Advanced Secret Detection

```bash
pip install requests
python3 services/python/advanced_scanner.py --server --port 5001
# Then set PYTHON_SERVICE_URL=http://localhost:5001
```

Detects high-entropy tokens, AWS/GitHub/Stripe keys, vulnerable libs (jQuery <3.5, Lodash <4.17.21).

### Go — Ultra-Fast Port Scanner

```bash
go run services/go/main.go -server -port 5002
# Then set GO_SERVICE_URL=http://localhost:5002
```

1000 ports in ~2-5s with banner grabbing, CIDR expansion.

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health, version, AI provider, ws clients |
| `GET` | `/api/metrics` | Prometheus metrics |
| `GET` | `/api/docs` | List all API endpoints |
| `GET` | `/api/config` | AI provider config |
| `POST` | `/api/config` | Set AI provider/key/model |
| `POST` | `/api/scans` | Start scan (rate-limited) |
| `GET` | `/api/scans` | List scans |
| `GET` | `/api/scans/:id` | Full report JSON |
| `GET` | `/api/scans/:id/events` | SSE progress stream |
| `GET` | `/api/scans/:id/report.:fmt` | Export `md, html, json, sarif` |
| `DELETE` | `/api/scans/:id` | Delete scan |
| `GET` | `/api/monitors` | List uptime monitors |
| `POST` | `/api/monitors` | Create monitor |
| `POST` | `/api/monitors/:id/check` | Trigger check |
| `DELETE` | `/api/monitors/:id` | Delete monitor |
| `POST` | `/api/loadtest/run` | Load test with SSE |
| `GET` | `/api/netdiscovery/interfaces` | Local interfaces |
| `GET` | `/api/netdiscovery/arp` | ARP table |
| `POST` | `/api/netdiscovery/scan` | LAN discovery (rate-limited) |
| `POST` | `/api/netdiscovery/scan-host` | Single host port scan |
| `POST` | `/api/poke` | HTTP inspector |
| `POST` | `/api/poke/ssh` | SSH banner grab |
| `POST` | `/api/db/test` | DB handshake |
| `POST` | `/api/db/stress` | DB stress test |
| `POST` | `/api/tls/analyze` | TLS/SSL cert analysis |
| `POST` | `/api/tls/headers` | Security headers audit |
| `POST` | `/api/recon/subdomains` | Subdomain enum (CT + DNS) |
| `POST` | `/api/recon/sitemap` | Sitemap parser |
| `POST` | `/api/recon/robots` | Robots.txt analyzer |
| `WS` | `/ws` | WebSocket live updates |

---

## 🛡️ Security Checks (60+)

- **Headers**: CSP (unsafe-inline, nonce, wildcards), HSTS, X-Frame-Options, COOP/COEP/CORP, Permissions-Policy, Referrer-Policy
- **Cookies**: HttpOnly, Secure, SameSite, __Host/__Secure prefix, expiration
- **JWT**: alg=none, weak secrets, expiration, storage in localStorage
- **CORS**: Wildcard origin with credentials, overly permissive
- **DOM-XSS**: Sink detection (innerHTML, eval, document.write)
- **Exposure**: .env, .git, backup files, source maps, verbose errors
- **TLS**: Certificate expiry, chain issues, weak protocols (TLS 1.0/1.1), weak ciphers
- **WP/Admin**: Exposed admin panels, XML-RPC, user enumeration

---

## ⚙️ Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | Dashboard port |
| `AI_PROVIDER` | `openrouter` | `openrouter, openai, anthropic, gemini, none` |
| `OPENROUTER_API_KEY` | — | OpenRouter key |
| `OPENROUTER_MODEL` | `deepseek/deepseek-r1-distill-qwen-7b` | Model |
| `CRAWLER` | `fetch` | `fetch` or `playwright` |
| `MAX_PAGES` | `25` | Max pages per crawl |
| `MAX_CONCURRENT_SCANS` | `3` | Concurrent scan limit |
| `SCAN_TTL_HOURS` | `24` | Auto-cleanup after hours |
| `PYTHON_SERVICE_URL` | `http://localhost:5001` | Python power-up URL |
| `GO_SERVICE_URL` | `http://localhost:5002` | Go power-up URL |
| `ALLOW_PRIVATE_TARGETS` | `true` | Allow RFC1918 scanning |

---

## 🧪 Testing

```bash
npm test              # 18+ unit & integration tests
npm run typecheck     # TypeScript check
```

---

## 📁 Project Structure

```
src/
├── frontend/          # TypeScript + Vite (source)
│   ├── index.html     # SPA shell (modern v2 UI)
│   ├── main.ts        # Orchestrator
│   ├── styles.css     # Design system v2
│   └── types.ts
├── engine/            # Crawler, scanner, scoring
├── modules/           # Net discovery, monitor, loadtest, TLS, recon, powerup
├── middleware/        # Rate limiting
├── ai/                # OpenRouter, OpenAI, Anthropic, Gemini, heuristic
├── report/            # Markdown, HTML, SARIF
├── server.js          # Express + WS v2 hardened
└── env.js
services/
├── python/            # High-entropy secret detection
└── go/                # Ultra-fast port scanner
demo/
├── target.js          # Vulnerable demo app
public/                # Legacy fallback (build required notice)
dist/                  # Built frontend (Vite output)
reports/               # Scan reports
.github/workflows/    # CI, security, docker, release
```

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## 🔒 Security Policy

See [SECURITY.md](SECURITY.md)

---

## 📜 License

[Apache-2.0](LICENSE) © 2026 [Mahmud Rahman](https://github.com/mahmud-r-farhan)
