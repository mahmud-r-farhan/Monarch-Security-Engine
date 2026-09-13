import express from 'express';
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runScan, summarizeScan } from './engine/scanner.js';
import { renderMarkdown } from './report/markdown.js';
import { renderHtml } from './report/html.js';
import { renderSarif } from './report/sarif.js';
import { detectProvider, DEFAULT_MODEL } from './ai/insights.js';
import { loadEnv } from './env.js';

import { wsServer } from './modules/ws.js';
import { monitorService } from './modules/monitor.js';
import { LoadTestRunner } from './modules/loadtest.js';
import { getLocalInterfaces, getArpTable, runNetworkDiscovery, scanHostPorts, getDefaultRoute } from './modules/netdiscovery.js';
import { pokeHttp, pokeSsh } from './modules/poking.js';
import { testDbConnection, runDbLoadTest } from './modules/database.js';
import { analyzeTLS, checkSecurityHeaders } from './modules/tls.js';
import { enumerateSubdomains, parseSitemap, analyzeRobotsTxt } from './modules/subdomain.js';
import { scanLimiter, apiLimiter, discoveryLimiter } from './middleware/rateLimiter.js';

loadEnv();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const REPORT_DIR = path.resolve(process.env.REPORT_DIR || path.join(__dirname, '..', 'reports'));
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT_SCANS || 3);
const SCAN_TTL_MS = Number(process.env.SCAN_TTL_HOURS || 24) * 60 * 60 * 1000;

const app = express();
const server = http.createServer(app);

// Trust proxy for correct IP in rate limiter
app.set('trust proxy', 1);

// Attach WebSocket server
wsServer.attach(server);

// Initialize background monitor service with WebSocket broadcast
monitorService.init((channel, data) => wsServer.broadcast(channel, data)).catch(err => {
  console.error('[Monitor] Init error:', err.message);
});

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

// Security headers - hardened
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'X-DNS-Prefetch-Control': 'off',
    // Fixed CSP: frame-ancestors none, no unsafe-inline where possible
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'", // unsafe-inline needed for inline event handlers in legacy fallback
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com data:",
      "img-src 'self' data: https: blob:",
      "connect-src 'self' ws: wss: https://api.github.com https://crt.sh",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests",
    ].join('; '),
  });
  next();
});

// CORS for API (allow same-origin and dev)
app.use('/api', (req, res, next) => {
  const origin = req.headers.origin;
  // Allow same-origin or localhost dev
  if (!origin || origin.includes('localhost') || origin.includes('127.0.0.1')) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

app.use('/api/', apiLimiter);

// Serve frontend: dist (built) > src/frontend (dev) > public (legacy fallback)
const distPath = path.join(__dirname, '..', 'dist');
const publicPath = path.join(__dirname, '..', 'public');
const frontendSrcPath = path.join(__dirname, 'frontend');
let staticDir = publicPath;
if (fsSync.existsSync(path.join(distPath, 'index.html'))) staticDir = distPath;
else if (fsSync.existsSync(path.join(frontendSrcPath, 'index.html'))) staticDir = frontendSrcPath;

app.use(express.static(staticDir, {
  maxAge: staticDir === distPath ? '1h' : '0',
  etag: true,
  lastModified: true,
}));

// In-memory scan registry backed by JSON files on disk.
const scans = new Map(); // id -> { status, events: [], scan?, error?, listeners:Set, createdAt }
let running = 0;

// Runtime in-memory AI configuration
let runtimeAiConfig = null;

function getReportFilePath(id) {
  if (!/^[0-9a-f-]{36}$/.test(id)) return null;
  const baseDir = path.resolve(REPORT_DIR);
  const filePath = path.resolve(baseDir, `${id}.json`);
  if (!filePath.startsWith(baseDir + path.sep)) return null;
  return filePath;
}

async function persist(scan) {
  await fs.mkdir(REPORT_DIR, { recursive: true });
  const filePath = getReportFilePath(scan.id);
  if (!filePath) return;
  await fs.writeFile(filePath, JSON.stringify(scan));
}

async function loadFromDisk(id) {
  const filePath = getReportFilePath(id);
  if (!filePath) return null;
  try {
    return JSON.parse(await fs.readFile(filePath, 'utf8'));
  } catch {
    return null;
  }
}

async function getScan(id) {
  const rec = scans.get(id);
  if (rec?.scan) return rec.scan;
  return loadFromDisk(id);
}

// Periodic cleanup of old scans
setInterval(async () => {
  const now = Date.now();
  for (const [id, rec] of scans) {
    if (now - rec.createdAt > SCAN_TTL_MS && rec.status !== 'running') {
      scans.delete(id);
    }
  }
  try {
    const files = await fs.readdir(REPORT_DIR);
    for (const f of files) {
      if (!f.endsWith('.json') || f.includes('monitors')) continue;
      const fp = path.join(REPORT_DIR, f);
      const stat = await fs.stat(fp).catch(() => null);
      if (stat && now - stat.mtimeMs > SCAN_TTL_MS) {
        await fs.unlink(fp).catch(() => {});
      }
    }
  } catch {}
}, 60 * 60 * 1000).unref();

/* ------------------------------------------------------------------ */
/* Config & Health Endpoints                                          */
/* ------------------------------------------------------------------ */

app.get('/api/health', (req, res) => {
  const activeProvider = runtimeAiConfig?.provider || detectProvider();
  const hasKey = Boolean(
    runtimeAiConfig?.apiKey ||
    process.env.OPENROUTER_API_KEY ||
    process.env.OPENAI_API_KEY ||
    process.env.ANTHROPIC_API_KEY ||
    process.env.GEMINI_API_KEY
  );

  res.json({
    ok: true,
    version: '2.0.0',
    name: 'Monarch Security Engine',
    ai: activeProvider,
    aiConfigured: hasKey,
    crawler: process.env.CRAWLER || 'fetch',
    running,
    maxConcurrent: MAX_CONCURRENT,
    wsClients: wsServer.getClientCount(),
    monitorsActive: monitorService.getMonitors().filter(m => m.active).length,
    uptime: process.uptime(),
    reportsDir: REPORT_DIR,
    staticDir: staticDir.includes('dist') ? 'dist (built)' : 'public (fallback)',
  });
});

app.get('/api/metrics', (req, res) => {
  // Simple Prometheus-style metrics
  const mem = process.memoryUsage();
  const metrics = [
    `# HELP monarch_scans_running Current running scans`,
    `# TYPE monarch_scans_running gauge`,
    `monarch_scans_running ${running}`,
    `# HELP monarch_scans_total Total scans in memory`,
    `# TYPE monarch_scans_total gauge`,
    `monarch_scans_total ${scans.size}`,
    `# HELP monarch_ws_clients WebSocket clients`,
    `# TYPE monarch_ws_clients gauge`,
    `monarch_ws_clients ${wsServer.getClientCount()}`,
    `# HELP monarch_monitors_active Active monitors`,
    `# TYPE monarch_monitors_active gauge`,
    `monarch_monitors_active ${monitorService.getMonitors().filter(m => m.active).length}`,
    `# HELP monarch_memory_heap_used Heap used bytes`,
    `# TYPE monarch_memory_heap_used gauge`,
    `monarch_memory_heap_used ${mem.heapUsed}`,
    `# HELP monarch_uptime_seconds Process uptime`,
    `# TYPE monarch_uptime_seconds counter`,
    `monarch_uptime_seconds ${process.uptime()}`,
  ].join('\n');
  res.type('text/plain').send(metrics);
});

app.get('/api/docs', (req, res) => {
  res.json({
    name: 'Monarch Security Engine API',
    version: '2.0.0',
    endpoints: [
      { method: 'GET', path: '/api/health', description: 'Service health and status' },
      { method: 'GET', path: '/api/metrics', description: 'Prometheus metrics' },
      { method: 'GET', path: '/api/config', description: 'AI provider config' },
      { method: 'POST', path: '/api/config', description: 'Set AI config' },
      { method: 'POST', path: '/api/scans', description: 'Start security scan', rateLimited: true },
      { method: 'GET', path: '/api/scans', description: 'List recent scans' },
      { method: 'GET', path: '/api/scans/:id', description: 'Get scan report' },
      { method: 'GET', path: '/api/scans/:id/events', description: 'SSE stream of scan progress' },
      { method: 'GET', path: '/api/scans/:id/report.:fmt', description: 'Export md, html, json, sarif' },
      { method: 'DELETE', path: '/api/scans/:id', description: 'Delete scan' },
      { method: 'GET', path: '/api/monitors', description: 'List uptime monitors' },
      { method: 'POST', path: '/api/monitors', description: 'Create monitor' },
      { method: 'POST', path: '/api/monitors/:id/check', description: 'Trigger monitor check' },
      { method: 'DELETE', path: '/api/monitors/:id', description: 'Delete monitor' },
      { method: 'POST', path: '/api/loadtest/run', description: 'Run load test with SSE' },
      { method: 'GET', path: '/api/netdiscovery/interfaces', description: 'Local interfaces' },
      { method: 'POST', path: '/api/netdiscovery/scan', description: 'Network discovery', rateLimited: true },
      { method: 'POST', path: '/api/netdiscovery/scan-host', description: 'Port scan single host' },
      { method: 'POST', path: '/api/poke', description: 'HTTP inspector' },
      { method: 'POST', path: '/api/poke/ssh', description: 'SSH banner grab' },
      { method: 'POST', path: '/api/db/test', description: 'DB connection test' },
      { method: 'POST', path: '/api/db/stress', description: 'DB stress test' },
      { method: 'POST', path: '/api/tls/analyze', description: 'TLS/SSL analysis' },
      { method: 'POST', path: '/api/tls/headers', description: 'Security headers check' },
      { method: 'POST', path: '/api/recon/subdomains', description: 'Subdomain enumeration' },
      { method: 'POST', path: '/api/recon/sitemap', description: 'Sitemap parser' },
      { method: 'POST', path: '/api/recon/robots', description: 'Robots.txt analyzer' },
    ],
  });
});

app.get('/api/config', (req, res) => {
  const provider = runtimeAiConfig?.provider || detectProvider();
  const hasKey = Boolean(
    runtimeAiConfig?.apiKey ||
    process.env.OPENROUTER_API_KEY ||
    process.env.OPENAI_API_KEY ||
    process.env.ANTHROPIC_API_KEY ||
    process.env.GEMINI_API_KEY
  );

  res.json({
    provider,
    model: runtimeAiConfig?.model || process.env.AI_MODEL || DEFAULT_MODEL[provider] || '',
    hasApiKey: hasKey,
    availableProviders: [
      { id: 'openrouter', name: 'OpenRouter (Default / Multi-Model)', defaultModel: DEFAULT_MODEL.openrouter },
      { id: 'openai', name: 'OpenAI (GPT-4o, GPT-4o-mini)', defaultModel: DEFAULT_MODEL.openai },
      { id: 'anthropic', name: 'Anthropic (Claude 3.5 Sonnet / Haiku)', defaultModel: DEFAULT_MODEL.anthropic },
      { id: 'gemini', name: 'Google Gemini (Gemini 1.5 Flash)', defaultModel: DEFAULT_MODEL.gemini },
      { id: 'none', name: 'Deterministic Heuristic (Offline / No Key)', defaultModel: 'monarch-rules-v1' },
    ],
  });
});

app.post('/api/config', (req, res) => {
  const { provider, apiKey, model } = req.body || {};
  if (provider && !['openrouter', 'openai', 'anthropic', 'gemini', 'none'].includes(provider)) {
    return res.status(400).json({ error: 'Invalid provider' });
  }
  runtimeAiConfig = {
    provider: provider || 'openrouter',
    apiKey: apiKey || '',
    model: model || DEFAULT_MODEL[provider] || '',
  };
  res.json({
    ok: true,
    message: 'AI Configuration updated in session',
    provider: runtimeAiConfig.provider,
    model: runtimeAiConfig.model,
    hasApiKey: Boolean(runtimeAiConfig.apiKey),
  });
});

/* ------------------------------------------------------------------ */
/* Security Scans Endpoints                                           */
/* ------------------------------------------------------------------ */

app.post('/api/scans', scanLimiter, async (req, res) => {
  const { target, maxPages, engine, ai, aiConfig } = req.body || {};
  if (!target) return res.status(400).json({ error: 'target is required' });
  if (typeof target !== 'string' || target.length > 2048) return res.status(400).json({ error: 'Invalid target length' });
  if (running >= MAX_CONCURRENT) return res.status(429).json({ error: `Too many concurrent scans (max ${MAX_CONCURRENT}); try again shortly.` });

  const rec = { status: 'running', events: [], listeners: new Set(), createdAt: Date.now(), target };
  let id = null;

  const onEvent = ev => {
    if (ev.type === 'status' && ev.stage === 'init' && !id) {
      id = ev.message.match(/Scan ([0-9a-f-]{36})/)?.[1];
      if (id) scans.set(id, rec);
    }
    rec.events.push(ev);
    // Keep only last 500 events to prevent memory bloat
    if (rec.events.length > 500) rec.events.shift();
    for (const l of rec.listeners) l(ev);
  };

  running++;

  const p = runScan(target, {
    maxPages: clamp(Number(maxPages) || undefined, 1, 200),
    engine: engine === 'playwright' ? 'playwright' : engine === 'fetch' ? 'fetch' : undefined,
    ai: ai !== false,
    aiConfig: aiConfig || runtimeAiConfig,
    onEvent,
  })
    .then(async scan => {
      rec.status = 'done';
      rec.scan = scan;
      await persist(scan).catch(() => {});
    })
    .catch(err => {
      rec.status = 'error';
      rec.error = err.message;
    })
    .finally(() => {
      running--;
      for (const l of rec.listeners) l({ type: 'closed' });
    });

  await Promise.race([p, new Promise(r => setTimeout(r, 80))]);

  if (!id) return res.status(500).json({ error: rec.error || 'failed to start scan' });
  res.status(202).json({ id, status: rec.status, error: rec.error });
});

app.get('/api/scans/:id/events', (req, res) => {
  if (!/^[0-9a-f-]{36}$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid scan ID format' });
  const rec = scans.get(req.params.id);
  if (!rec) return res.status(404).json({ error: 'scan not found (or server restarted)' });

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();

  const send = ev => res.write(`event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`);
  rec.events.forEach(send);

  if (rec.status !== 'running') {
    send({ type: 'closed', status: rec.status, error: rec.error });
    return res.end();
  }

  const listener = ev => {
    send(ev);
    if (ev.type === 'closed') res.end();
  };

  rec.listeners.add(listener);
  const ping = setInterval(() => res.write(': ping\n\n'), 15000);
  req.on('close', () => {
    rec.listeners.delete(listener);
    clearInterval(ping);
  });
});

app.get('/api/scans', async (req, res) => {
  const list = [];
  for (const [id, rec] of scans) {
    list.push(rec.scan ? summarizeScan(rec.scan) : { id, target: rec.target, status: rec.status, error: rec.error, startedAt: new Date(rec.createdAt).toISOString() });
  }
  try {
    const files = (await fs.readdir(REPORT_DIR)).filter(f => f.endsWith('.json') && !f.includes('monitors'));
    for (const f of files) {
      const id = f.slice(0, -5);
      if (!scans.has(id)) {
        const s = await loadFromDisk(id);
        if (s) list.push(summarizeScan(s));
      }
    }
  } catch {}
  list.sort((a, b) => (b.startedAt || '').localeCompare(a.startedAt || ''));
  res.json(list.slice(0, 100));
});

app.get('/api/scans/:id', async (req, res) => {
  if (!/^[0-9a-f-]{36}$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid scan ID' });
  const scan = await getScan(req.params.id);
  if (scan) return res.json(scan);
  const rec = scans.get(req.params.id);
  if (rec) return res.json({ id: req.params.id, status: rec.status, error: rec.error });
  res.status(404).json({ error: 'not found' });
});

app.get('/api/scans/:id/report.:fmt', async (req, res) => {
  if (!/^[0-9a-f-]{36}$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid scan ID' });
  const scan = await getScan(req.params.id);
  if (!scan) return res.status(404).json({ error: 'not found' });

  let host = 'target';
  try { host = new URL(scan.target).host.replace(/[^a-z0-9.-]/gi, '_'); } catch {}
  const name = `monarch-${host}-${scan.id.slice(0, 8)}`;

  if (req.params.fmt === 'md') return res.type('text/markdown').attachment(`${name}.md`).send(renderMarkdown(scan));
  if (req.params.fmt === 'html') return res.type('text/html').send(renderHtml(scan));
  if (req.params.fmt === 'json') return res.attachment(`${name}.json`).json(scan);
  if (req.params.fmt === 'sarif') return res.type('application/json').attachment(`${name}.sarif.json`).json(renderSarif(scan));

  res.status(400).json({ error: 'format must be md, html, json, or sarif' });
});

app.delete('/api/scans/:id', async (req, res) => {
  if (!/^[0-9a-f-]{36}$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid scan ID' });
  scans.delete(req.params.id);
  await fs.unlink(path.join(REPORT_DIR, `${req.params.id}.json`)).catch(() => {});
  res.status(204).end();
});

/* ------------------------------------------------------------------ */
/* Uptime Monitoring Endpoints                                        */
/* ------------------------------------------------------------------ */

app.get('/api/monitors', (req, res) => {
  res.json(monitorService.getMonitors());
});

app.post('/api/monitors', async (req, res) => {
  try {
    const monitor = await monitorService.createMonitor(req.body || {});
    res.status(201).json(monitor);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/monitors/:id', (req, res) => {
  const m = monitorService.getMonitor(req.params.id);
  if (!m) return res.status(404).json({ error: 'monitor not found' });
  res.json(m);
});

app.post('/api/monitors/:id/check', async (req, res) => {
  const updated = await monitorService.checkMonitor(req.params.id);
  if (!updated) return res.status(404).json({ error: 'monitor not found' });
  res.json(updated);
});

app.post('/api/monitors/:id/toggle', async (req, res) => {
  const updated = await monitorService.toggleMonitor(req.params.id);
  if (!updated) return res.status(404).json({ error: 'monitor not found' });
  res.json(updated);
});

app.delete('/api/monitors/:id', async (req, res) => {
  const deleted = await monitorService.deleteMonitor(req.params.id);
  if (!deleted) return res.status(404).json({ error: 'monitor not found' });
  res.status(204).end();
});

/* ------------------------------------------------------------------ */
/* HTTP Load Testing Endpoints                                        */
/* ------------------------------------------------------------------ */

app.post('/api/loadtest/run', async (req, res) => {
  const { url, method, headers, body, concurrency, totalRequests, timeoutMs, securityProbes } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url is required' });
  if (typeof url !== 'string' || url.length > 2048) return res.status(400).json({ error: 'Invalid URL' });

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();

  const runner = new LoadTestRunner({
    url,
    method,
    headers,
    body,
    concurrency,
    totalRequests,
    timeoutMs,
    securityProbes,
  });

  req.on('close', () => runner.abort());

  try {
    const summary = await runner.run(progress => {
      res.write(`event: progress\ndata: ${JSON.stringify(progress)}\n\n`);
    });
    res.write(`event: done\ndata: ${JSON.stringify(summary)}\n\n`);
    res.end();
  } catch (err) {
    res.write(`event: error\ndata: ${JSON.stringify({ error: err.message })}\n\n`);
    res.end();
  }
});

/* ------------------------------------------------------------------ */
/* Network Discovery Endpoints                                        */
/* ------------------------------------------------------------------ */

app.get('/api/netdiscovery/interfaces', async (req, res) => {
  const ifaces = getLocalInterfaces();
  const route = await getDefaultRoute();
  res.json({ interfaces: ifaces, gateway: route.gateway, ifaceIp: route.ifaceIp });
});

app.get('/api/netdiscovery/arp', async (req, res) => {
  const devices = await getArpTable();
  res.json(devices);
});

app.post('/api/netdiscovery/scan-host', async (req, res) => {
  const { host, tcpPorts, udpPorts, timeoutMs } = req.body || {};
  if (!host) return res.status(400).json({ error: 'host is required' });
  if (typeof host !== 'string' || host.length > 256) return res.status(400).json({ error: 'Invalid host' });
  try {
    const openPorts = await scanHostPorts(host, tcpPorts, udpPorts, timeoutMs);
    res.json({ host, openPorts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/netdiscovery/scan', discoveryLimiter, async (req, res) => {
  const { subnet, mode, customTcp, customUdp, pingTimeout, portTimeout } = req.body || {};

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();

  try {
    const result = await runNetworkDiscovery({
      subnet,
      mode,
      customTcp,
      customUdp,
      pingTimeout,
      portTimeout,
      onEvent: ev => {
        res.write(`event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`);
      },
    });
    res.write(`event: done\ndata: ${JSON.stringify(result)}\n\n`);
    res.end();
  } catch (err) {
    res.write(`event: error\ndata: ${JSON.stringify({ error: err.message })}\n\n`);
    res.end();
  }
});

/* ------------------------------------------------------------------ */
/* HTTP Inspector & SSH Poke Endpoints                                */
/* ------------------------------------------------------------------ */

app.post('/api/poke', async (req, res) => {
  try {
    const result = await pokeHttp(req.body || {});
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/poke/ssh', async (req, res) => {
  try {
    const result = await pokeSsh(req.body || {});
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/* ------------------------------------------------------------------ */
/* Database Tester Endpoints                                          */
/* ------------------------------------------------------------------ */

app.post('/api/db/test', async (req, res) => {
  try {
    const result = await testDbConnection(req.body || {});
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/db/stress', async (req, res) => {
  try {
    const result = await runDbLoadTest(req.body || {});
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/* ------------------------------------------------------------------ */
/* TLS/SSL Analyzer Endpoints (New)                                   */
/* ------------------------------------------------------------------ */

app.post('/api/tls/analyze', async (req, res) => {
  const { target, timeoutMs } = req.body || {};
  if (!target) return res.status(400).json({ error: 'target is required' });
  try {
    const result = await analyzeTLS(target, { timeoutMs });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/tls/headers', async (req, res) => {
  const { url, timeoutMs } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url is required' });
  try {
    const result = await checkSecurityHeaders(url, { timeoutMs });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/* ------------------------------------------------------------------ */
/* Recon & Asset Discovery Endpoints (New)                            */
/* ------------------------------------------------------------------ */

app.post('/api/recon/subdomains', async (req, res) => {
  const { domain, concurrency, includeCommon } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'domain is required' });
  try {
    const result = await enumerateSubdomains(domain, { concurrency, includeCommon });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/recon/sitemap', async (req, res) => {
  const { target } = req.body || {};
  if (!target) return res.status(400).json({ error: 'target is required' });
  try {
    const result = await parseSitemap(target);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/recon/robots', async (req, res) => {
  const { target } = req.body || {};
  if (!target) return res.status(400).json({ error: 'target is required' });
  try {
    const result = await analyzeRobotsTxt(target);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/* ------------------------------------------------------------------ */
/* Frontend fallback (SPA)                                            */
/* ------------------------------------------------------------------ */

app.get('*', (req, res) => {
  // If API route not matched, serve index.html for SPA routing
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  res.sendFile(path.join(staticDir, 'index.html'));
});

/* ------------------------------------------------------------------ */
/* Global Error Handler & Listener                                    */
/* ------------------------------------------------------------------ */

app.use((err, req, res, next) => {
  console.error('[Error] %s %s: %s', req.method, req.path, err.message);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

function clamp(n, lo, hi) {
  return n == null ? undefined : Math.min(hi, Math.max(lo, n));
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  🦋  Monarch Security Engine v2.0  →  http://0.0.0.0:${PORT}`);
  console.log(`      AI default: ${detectProvider()}   crawler: ${process.env.CRAWLER || 'fetch'}   reports: ${REPORT_DIR}`);
  console.log(`      Static: ${staticDir}   Max concurrent: ${MAX_CONCURRENT}\n`);
});
