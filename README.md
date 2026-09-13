<div align="center">

# 🦋 Monarch Security Engine

### Automated Web Vulnerability Scanner & Network Analyzer (AI-Powered)

**Crawl a site → record every request like a DevTools Network tab → run 60+ passive security checks → get an AI-written, prioritised remediation plan → export Markdown / HTML (PDF) / JSON.**

[![CI](https://github.com/mahmud-r-farhan/Monarch-Security-Engine/actions/workflows/ci.yml/badge.svg)](https://github.com/mahmud-r-farhan/Monarch-Security-Engine/actions/workflows/ci.yml)
![Node](https://img.shields.io/badge/node-%3E%3D20-339933?logo=node.js&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)
![Zero native deps](https://img.shields.io/badge/native%20deps-0-success)

</div>

---

> ⚠️ **Disclaimer** — Monarch is strictly for **educational use, defensive research, and auditing applications you own or are explicitly authorised to test**. Scanning third-party targets without permission is illegal. The scanner is passive by design (no exploitation, no payload injection), but you remain responsible for where you point it.

---

## ✨ What it does

| Stage | What happens |
|---|---|
| **1 · Crawl** | Follows same-origin links (bounded), collects scripts, styles, frames, forms and cookies. Two engines: a zero-dependency `fetch` engine (default) and an optional headless-Chromium engine via Playwright that also captures runtime `localStorage`/`sessionStorage` and console errors. |
| **2 · Network Inspector** | Every request/response is recorded DevTools-style — method, status, type, size, TTFB/total timing, redirect chain, full request & response headers — and **streamed live to the dashboard** over Server-Sent Events, complete with a waterfall column. |
| **3 · Security checks** | 7 analyzers, 60+ distinct findings (see below), each with severity, CWE/OWASP mapping, evidence, and a copy-pasteable remediation. |
| **4 · Score & grade** | 0–100 score with A–F grade using severity-weighted diminishing penalties. |
| **5 · AI Insights** | Findings + traffic summary are handed to an LLM (OpenAI / Anthropic / Gemini — plain `fetch`, no SDKs) which returns a risk level, executive summary, attack narrative, root causes, ≤7-step prioritised action plan and quick wins. A deterministic rules-based analyst runs when no key is configured or the provider fails, so a report is **always** produced. |
| **6 · Reports** | Markdown, self-contained print-ready HTML (→ PDF via browser print), and raw JSON. |

### Checks performed

<details>
<summary><b>Headers</b> — CSP, HSTS, clickjacking, MIME sniffing, Referrer/Permissions/COOP, consistency</summary>

- Missing CSP / report-only-only CSP / meta-only CSP
- CSP weaknesses: `unsafe-inline`, `unsafe-eval`, wildcard & scheme-only sources, missing `object-src`, `base-uri`, `frame-ancestors`
- Missing/weak HSTS (`max-age` < 180 d, no `includeSubDomains`)
- No clickjacking protection, obsolete `ALLOW-FROM`
- Missing `X-Content-Type-Options`, `Referrer-Policy` (or permissive), `Permissions-Policy`, `Cross-Origin-Opener-Policy`
- Legacy `X-XSS-Protection: 1` without `mode=block`
- Cacheable documents that set cookies
- CSP applied inconsistently across pages
</details>

<details>
<summary><b>Cookies & sessions</b></summary>

- Missing `HttpOnly`, `Secure`, `SameSite` (severity escalates for session-like names)
- `SameSite=None`, over-broad `Domain`, long-lived session cookies, JWTs inside cookies
</details>

<details>
<summary><b>JWT analysis</b> — discovered in cookies, Authorization headers, scripts, Web Storage</summary>

- `alg=none` / unsigned tokens · symmetric HS* algorithms · `jku`/`x5u` header injection vectors
- Missing `exp`, excessive TTL, expired tokens lying around
- Sensitive PII claims, privileged role claims
- Tokens hard-coded in JavaScript or persisted in `localStorage`/`sessionStorage`
</details>

<details>
<summary><b>Transport & CORS</b></summary>

- Plaintext HTTP, HTTPS→HTTP downgrade redirects, long redirect chains
- Active vs passive mixed content
- CORS: wildcard, reflected `Origin`, reflected `Origin` **with credentials**
</details>

<details>
<summary><b>Client-side heuristics</b></summary>

- Token-like values written to Web Storage
- DOM-XSS patterns: URL-controlled sources (`location.hash/search`, `document.referrer`, `window.name`) near sinks (`innerHTML`, `document.write`, `insertAdjacentHTML`, `eval`, `new Function`)
- `postMessage` listeners without origin validation
- Secrets in JS: AWS keys, Stripe, GitHub, Slack, Google API keys, private-key blocks, generic `api_key=…`
- Forms: credentials over HTTP, login via GET, POST forms without CSRF tokens
- Third-party scripts without Subresource Integrity, excessive third-party origins, inline event handlers
</details>

<details>
<summary><b>Exposure & information leakage</b></summary>

- Signature-verified probes for `/.env`, `/.git/HEAD`, `/.git/config`, `phpinfo.php`, `server-status`, `.DS_Store`, `backup.zip`, `config.json` (SPA catch-all 200s are ignored)
- Public OpenAPI/Swagger docs, GraphQL endpoints, reachable admin panels, sensitive paths in `robots.txt`, missing `security.txt`
- Version disclosure (`Server`, `X-Powered-By`, `X-AspNet-Version`, …), stack traces, source maps, directory listings, 5xx during crawl
</details>

---

## 🚀 Quick start

```bash
git clone https://github.com/mahmud-r-farhan/Monarch-Security-Engine.git
cd Monarch-Security-Engine
npm install
cp .env.example .env          # optional: add an AI key here
npm start                     # dashboard → http://localhost:3000
```

Need a target you're allowed to break? Start the bundled **intentionally vulnerable demo app** in a second terminal and scan `http://localhost:4000`:

```bash
npm run demo:target
```

It ships with an `alg=none` JWT, reflected-origin CORS with credentials, an exposed `.env`, AWS/Stripe keys in a bundle, DOM-XSS sinks, insecure cookies and more — you should see ~45 findings and a grade **F**.

### Optional: real-browser engine

```bash
npm install playwright
npx playwright install chromium
CRAWLER=playwright npm start   # or pick "browser (Playwright)" in the UI
```

The browser engine captures XHR/fetch traffic triggered by JavaScript, runtime Web Storage contents and console errors. Monarch falls back to the `fetch` engine automatically if Chromium isn't available.

### Enable AI insights

Set **one** of these in `.env` — the provider is auto-detected:

```ini
OPENAI_API_KEY=sk-...        # gpt-4o-mini by default
ANTHROPIC_API_KEY=sk-ant-... # claude-3-5-haiku by default
GEMINI_API_KEY=AIza...       # gemini-1.5-flash by default
AI_MODEL=                    # optional override
```

---

## 🖥️ Dashboard

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ 🦋 Monarch   [ https://target.example      ] [fetch ▾] [25] [Scan]  online  │
├──────────────┬───────────────────────────────────────────────────────────────┤
│ Scan history │  F  https://target.example/     5 pages · 24 req · 6.4 KB     │
│  F target…   │     ████████████████████████████████ completed in 0.2s        │
│  B shop…     │     critical 8 · high 7 · medium 14 · low 9 · info 8          │
│  A docs…     │     [HTML / PDF] [Markdown] [JSON]                            │
│              ├───────────────────────────────────────────────────────────────┤
│              │  Findings 46 │ AI Insights │ Network 24 │ Cookies │ Inventory │
│              ├───────────────────────────────────────────────────────────────┤
│              │  CRITICAL  JWT uses alg=none / unsigned            jwt CWE-347│
│              │  CRITICAL  CORS reflects arbitrary Origin with credentials    │
│              │  HIGH      Content-Security-Policy header is missing          │
│              │  …                                                            │
└──────────────┴───────────────────────────────────────────────────────────────┘
```

- **Findings** — filter by severity chip or free text; expand for location, evidence, remediation snippet, CWE/OWASP and references.
- **AI Insights** — risk level, executive summary, attack path, root causes, numbered action plan with effort estimates and linked finding IDs.
- **Network** — DevTools-style table with status colouring, type filters, waterfall bars and a click-to-open header inspector.
- **Cookies & Storage / Inventory** — cookie flag matrix, runtime storage (browser engine), pages, forms, scripts + SRI status, third-party origins, probe results, CORS probe.

Findings and network rows appear **while the scan is running**; the page URL carries the scan ID (`/#<id>`) so results are shareable within your team.

---

## ⌨️ CLI

```bash
npx monarch https://target.example --pages 30 --out ./audit
```

```
  › [crawl]   Fetching https://target.example/
  › [probe]   Probing /.env
  🟥 CRITICAL Environment file (.env) is publicly accessible
  🟧 HIGH     Content-Security-Policy header is missing
  …
  Target   https://target.example/
  Score    31/100  (grade F)  risk: critical
  Findings 23  →  critical 1 · high 4 · medium 8 · low 6 · info 4
  Crawl    12 pages · 61 requests · 4.8s · engine=fetch
```

| Option | Description |
|---|---|
| `--pages <n>` | Max pages to crawl (default 25) |
| `--engine fetch\|playwright` | Crawler engine |
| `--no-ai` | Skip AI stage |
| `--out <dir>` | Write `report.json`, `report.md`, `report.html` |
| `--format summary\|md\|json` | What to print to stdout |
| `--quiet` | Suppress progress |

Exit code is **2** if critical findings exist, **1** for high, **0** otherwise — drop it straight into CI:

```yaml
- run: npx monarch https://staging.example --no-ai --quiet --out audit
- uses: actions/upload-artifact@v4
  with: { name: security-audit, path: audit }
```

---

## 🔌 REST API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Version, AI provider, crawler, running scans |
| `POST` | `/api/scans` | Body `{ target, maxPages?, engine?, ai? }` → `202 { id }` |
| `GET` | `/api/scans/:id/events` | **SSE** stream: `status`, `network`, `finding`, `done`, `error`, `closed` (replays buffered events on connect) |
| `GET` | `/api/scans` | Scan history (in-memory + `reports/*.json`) |
| `GET` | `/api/scans/:id` | Full scan document |
| `GET` | `/api/scans/:id/report.md\|html\|json` | Exports |
| `DELETE` | `/api/scans/:id` | Remove a scan |

### Programmatic use

```js
import { runScan, renderMarkdown } from 'monarch-security-engine';

const scan = await runScan('https://target.example', {
  maxPages: 10,
  onEvent: e => e.type === 'finding' && console.log(e.finding.severity, e.finding.title),
});
console.log(scan.score);          // { score: 62, grade: 'C', counts: {...} }
console.log(scan.insights.actionPlan);
await fs.writeFile('audit.md', renderMarkdown(scan));
```

---

## 🏗️ Architecture

```
src/
├─ server.js               Express API + SSE + static dashboard
├─ cli.js                  CI-friendly command line
├─ index.js                Library entry point
├─ engine/
│  ├─ scanner.js           Orchestrator: crawl → checks → score → AI, emits lifecycle events
│  ├─ crawler.js           fetch engine + optional Playwright engine, probes, CORS probe
│  ├─ network.js           DevTools-style NetworkLog with subscribers
│  ├─ safety.js            URL normalisation, private-IP guard
│  └─ checks/              headers · cookies · jwt · transport · clientside · exposure · infoleak
├─ ai/insights.js          OpenAI / Anthropic / Gemini adapters + deterministic fallback analyst
└─ report/                 markdown.js · html.js
public/                    Dashboard (vanilla JS, no build step)
demo/target.js             Intentionally vulnerable practice app
test/                      node:test suite
```

Every check is a pure function `(crawlResult) → Finding[]`, so adding one is a single file plus a line in `checks/index.js`:

```js
export function myCheck(ctx) {
  return ctx.pages
    .filter(p => !p.headers['x-my-header'])
    .map(p => ({ id: 'missing-my-header', severity: 'low', category: 'headers', location: p.finalUrl,
                 title: 'X-My-Header missing', description: '…', remediation: '…', cwe: 'CWE-16' }));
}
```

---

## ⚙️ Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Dashboard port |
| `CRAWLER` | `fetch` | `fetch` or `playwright` |
| `MAX_PAGES` | `25` | Crawl budget per scan |
| `REQUEST_TIMEOUT_MS` | `10000` | Per-request timeout |
| `MAX_CONCURRENT_SCANS` | `2` | Server-side concurrency cap |
| `ALLOW_PRIVATE_TARGETS` | `true` | Set `false` when exposing the dashboard to block scans of loopback/RFC-1918 hosts (SSRF guard) |
| `REPORT_DIR` | `./reports` | Where scan JSON is persisted |
| `AI_PROVIDER` | auto | Force `openai` / `anthropic` / `gemini` / `none` |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` | — | Enables LLM insights |
| `AI_MODEL` | per-provider default | Model override |

### Docker

```bash
docker build -t monarch .
docker run -p 3000:3000 --env-file .env monarch
```

---

## 🧪 Development

```bash
npm test          # node:test unit suite (checks, parsers, scoring, AI fallback, safety)
npm run dev       # server with --watch
```

## 🗺️ Roadmap

- [ ] Authenticated crawls (cookie / header injection, login recorder)
- [ ] Diff two scans and fail CI on regressions
- [ ] TLS/certificate analysis (protocol versions, cipher suites, expiry)
- [ ] Scheduled re-scans & webhook notifications
- [ ] SARIF export for GitHub Code Scanning

## 📜 License

MIT © [Mahmud R. Farhan](https://github.com/mahmud-r-farhan) — see [LICENSE](LICENSE).
