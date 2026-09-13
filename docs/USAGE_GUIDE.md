# Monarch Security Engine v2 — Usage Guide

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

#### TLS & Headers (NEW v2)
- **TLS Analyzer**: Paste `example.com` → certificate chain, expiry days, protocol (TLS 1.2/1.3), cipher, grade A-F, findings
- **Security Headers**: Paste `https://example.com` → checks HSTS, CSP, X-Frame-Options, etc., grade & score

#### Recon (NEW v2)
- **Subdomains**: Enter `example.com` → CT logs (crt.sh) + common subdomain DNS brute-force
- **Sitemap/Robots**: Enter `https://example.com` → parse sitemap.xml URLs, analyze robots.txt disallows for sensitive paths

#### Network
- Select subnet (auto-detected), choose Fast/Full/Custom mode
- ICMP sweep + ARP table + TCP/UDP port mapping + OUI vendor lookup
- Export CSV/JSON

#### Monitor
- Add URL, interval (15s-5m), expected status, keyword
- Live sparkline, uptime %, WebSocket push

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
   - **OpenRouter** (recommended): Multi-model, get key at openrouter.ai, model `deepseek/deepseek-r1-distill-qwen-7b` (free)
   - **OpenAI**: `gpt-4o-mini`
   - **Anthropic**: `claude-3-5-haiku-latest`
   - **Gemini**: `gemini-1.5-flash`
   - **Offline**: No key, heuristic rules
3. Paste API key (stored in session only, never persisted to disk)
4. Save

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

# Prometheus metrics
curl http://localhost:3000/api/metrics
```

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

## Security Best Practices

- Only scan own systems or with explicit permission
- Use offline heuristic for sensitive internal apps (no data leaves)
- API keys stored in sessionStorage only (cleared on tab close)
- Reports stored in `reports/` — clean periodically or set `SCAN_TTL_HOURS`
- Run behind reverse proxy with TLS in production
- Set `ALLOW_PRIVATE_TARGETS=false` for public deployments
