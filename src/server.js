import express from 'express';
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runScan, summarizeScan } from './engine/scanner.js';
import { renderMarkdown } from './report/markdown.js';
import { renderHtml } from './report/html.js';
import { detectProvider, DEFAULT_MODEL } from './ai/insights.js';
import { loadEnv } from './env.js';

import { wsServer } from './modules/ws.js';
import { monitorService } from './modules/monitor.js';
import { LoadTestRunner } from './modules/loadtest.js';
import { getLocalInterfaces, getArpTable, runNetworkDiscovery, scanHostPorts } from './modules/netdiscovery.js';
import { pokeHttp, pokeSsh } from './modules/poking.js';
import { testDbConnection, runDbLoadTest } from './modules/database.js';

loadEnv();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const REPORT_DIR = path.resolve(process.env.REPORT_DIR || path.join(__dirname, '..', 'reports'));
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT_SCANS || 2);

const app = express();
const server = http.createServer(app);

// Attach WebSocket server
wsServer.attach(server);

// Initialize background monitor service with WebSocket broadcast
monitorService.init((channel, data) => wsServer.broadcast(channel, data)).catch(err => {
  console.error('[Monitor] Init error:', err.message);
});

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use((_, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'self'; frame-ancestors *",
  });
  next();
});

// Serve frontend (dist if built with Vite, otherwise fallback to public)
const staticDir = fsSync.existsSync(path.join(__dirname, '..', 'dist', 'index.html'))
  ? path.join(__dirname, '..', 'dist')
  : path.join(__dirname, '..', 'public');
app.use(express.static(staticDir));

/** In-memory scan registry backed by JSON files on disk. */
const scans = new Map(); // id -> { status, events: [], scan?, error?, listeners:Set }
let running = 0;

/** Runtime in-memory AI configuration set via UI without editing .env */
let runtimeAiConfig = null;

async function persist(scan) {
  await fs.mkdir(REPORT_DIR, { recursive: true });
  await fs.writeFile(path.join(REPORT_DIR, `${scan.id}.json`), JSON.stringify(scan));
}
async function loadFromDisk(id) {
  if (!/^[0-9a-f-]{36}$/.test(id)) return null;
  try { return JSON.parse(await fs.readFile(path.join(REPORT_DIR, `${id}.json`), 'utf8')); } catch { return null; }
}
async function getScan(id) {
  const rec = scans.get(id);
  if (rec?.scan) return rec.scan;
  return loadFromDisk(id);
}

/* ------------------------------------------------------------------ */
/* Config & Health Endpoints                                          */
/* ------------------------------------------------------------------ */

app.get('/api/health', (_, res) => {
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
    version: 'active',
    ai: activeProvider,
    aiConfigured: hasKey,
    crawler: process.env.CRAWLER || 'fetch',
    running,
    wsClients: wsServer.getClientCount(),
    monitorsActive: monitorService.getMonitors().filter(m => m.active).length,
  });
});

app.get('/api/config', (_, res) => {
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

app.post('/api/scans', async (req, res) => {
  const { target, maxPages, engine, ai, aiConfig } = req.body || {};
  if (!target) return res.status(400).json({ error: 'target is required' });
  if (running >= MAX_CONCURRENT) return res.status(429).json({ error: `Too many concurrent scans (max ${MAX_CONCURRENT}); try again shortly.` });
  const rec = { status: 'running', events: [], listeners: new Set(), createdAt: Date.now(), target };
  let id = null;
  const onEvent = ev => {
    if (ev.type === 'status' && ev.stage === 'init' && !id) {
      id = ev.message.match(/Scan ([0-9a-f-]{36})/)?.[1];
      scans.set(id, rec);
    }
    rec.events.push(ev);
    for (const l of rec.listeners) l(ev);
  };
  running++;
  const p = runScan(target, {
    maxPages: clamp(Number(maxPages) || undefined, 1, 100),
    engine: engine === 'playwright' ? 'playwright' : engine === 'fetch' ? 'fetch' : undefined,
    ai: ai !== false,
    aiConfig: aiConfig || runtimeAiConfig,
    onEvent,
  }).then(async scan => { rec.status = 'done'; rec.scan = scan; await persist(scan).catch(() => {}); })
    .catch(err => { rec.status = 'error'; rec.error = err.message; })
    .finally(() => { running--; for (const l of rec.listeners) l({ type: 'closed' }); });

  await Promise.race([p, new Promise(r => setTimeout(r, 50))]);
  if (!id) return res.status(500).json({ error: rec.error || 'failed to start scan' });
  res.status(202).json({ id, status: rec.status, error: rec.error });
});

app.get('/api/scans/:id/events', (req, res) => {
  const rec = scans.get(req.params.id);
  if (!rec) return res.status(404).json({ error: 'scan not found (or server restarted)' });
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.flushHeaders();
  const send = ev => res.write(`event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`);
  rec.events.forEach(send);
  if (rec.status !== 'running') { send({ type: 'closed', status: rec.status, error: rec.error }); return res.end(); }
  const listener = ev => { send(ev); if (ev.type === 'closed') res.end(); };
  rec.listeners.add(listener);
  const ping = setInterval(() => res.write(': ping\n\n'), 15000);
  req.on('close', () => { rec.listeners.delete(listener); clearInterval(ping); });
});

app.get('/api/scans', async (_, res) => {
  const list = [];
  for (const [id, rec] of scans) list.push(rec.scan ? summarizeScan(rec.scan) : { id, target: rec.target, status: rec.status, error: rec.error, startedAt: new Date(rec.createdAt).toISOString() });
  try {
    const files = (await fs.readdir(REPORT_DIR)).filter(f => f.endsWith('.json') && !f.includes('monitors'));
    for (const f of files) { const id = f.slice(0, -5); if (!scans.has(id)) { const s = await loadFromDisk(id); if (s) list.push(summarizeScan(s)); } }
  } catch { /* no reports dir yet */ }
  list.sort((a, b) => (b.startedAt || '').localeCompare(a.startedAt || ''));
  res.json(list.slice(0, 100));
});

app.get('/api/scans/:id', async (req, res) => {
  const scan = await getScan(req.params.id);
  if (scan) return res.json(scan);
  const rec = scans.get(req.params.id);
  if (rec) return res.json({ id: req.params.id, status: rec.status, error: rec.error });
  res.status(404).json({ error: 'not found' });
});

app.get('/api/scans/:id/report.:fmt', async (req, res) => {
  const scan = await getScan(req.params.id);
  if (!scan) return res.status(404).json({ error: 'not found' });
  const name = `monarch-${new URL(scan.target).host}-${scan.id.slice(0, 8)}`;
  if (req.params.fmt === 'md') return res.type('text/markdown').attachment(`${name}.md`).send(renderMarkdown(scan));
  if (req.params.fmt === 'html') return res.type('html').send(renderHtml(scan));
  if (req.params.fmt === 'json') return res.attachment(`${name}.json`).json(scan);
  res.status(400).json({ error: 'format must be md, html or json' });
});

app.delete('/api/scans/:id', async (req, res) => {
  scans.delete(req.params.id);
  if (/^[0-9a-f-]{36}$/.test(req.params.id)) await fs.unlink(path.join(REPORT_DIR, `${req.params.id}.json`)).catch(() => {});
  res.status(204).end();
});

/* ------------------------------------------------------------------ */
/* Uptime Monitoring Endpoints                                        */
/* ------------------------------------------------------------------ */

app.get('/api/monitors', (_, res) => {
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

  // Stream progress via SSE
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
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

app.get('/api/netdiscovery/interfaces', (_, res) => {
  res.json(getLocalInterfaces());
});

app.get('/api/netdiscovery/arp', async (_, res) => {
  const devices = await getArpTable();
  res.json(devices);
});

app.post('/api/netdiscovery/scan-host', async (req, res) => {
  const { host, ports, timeoutMs } = req.body || {};
  if (!host) return res.status(400).json({ error: 'host is required' });
  try {
    const openPorts = await scanHostPorts(host, ports, timeoutMs);
    res.json({ host, openPorts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/netdiscovery/scan', async (req, res) => {
  const { subnet, ports } = req.body || {};

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();

  try {
    const result = await runNetworkDiscovery({
      subnet,
      ports,
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
/* Global Error Handler & Listener                                    */
/* ------------------------------------------------------------------ */

app.use((err, _req, res, _next) => res.status(500).json({ error: err.message }));

function clamp(n, lo, hi) { return n == null ? undefined : Math.min(hi, Math.max(lo, n)); }

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  🦋  Monarch Security Engine  →  http://0.0.0.0:${PORT}`);
  console.log(`      AI default: ${detectProvider()}   crawler: ${process.env.CRAWLER || 'fetch'}   reports: ${REPORT_DIR}\n`);
});
