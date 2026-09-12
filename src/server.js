import express from 'express';
import path from 'node:path';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { runScan, summarizeScan } from './engine/scanner.js';
import { renderMarkdown } from './report/markdown.js';
import { renderHtml } from './report/html.js';
import { detectProvider } from './ai/insights.js';
import { loadEnv } from './env.js';

loadEnv();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const REPORT_DIR = path.resolve(process.env.REPORT_DIR || path.join(__dirname, '..', 'reports'));
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT_SCANS || 2);

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));
app.use((_, res, next) => {
  // Practise what we preach.
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors *",
  });
  next();
});
app.use(express.static(path.join(__dirname, '..', 'public')));

/** In-memory scan registry backed by JSON files on disk. */
const scans = new Map(); // id -> { status, events: [], scan?, error?, listeners:Set }
let running = 0;

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

app.get('/api/health', (_, res) => res.json({ ok: true, version: '0.1.0', ai: detectProvider(), crawler: process.env.CRAWLER || 'fetch', running }));

app.post('/api/scans', async (req, res) => {
  const { target, maxPages, engine, ai } = req.body || {};
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
    onEvent,
  }).then(async scan => { rec.status = 'done'; rec.scan = scan; await persist(scan).catch(() => {}); })
    .catch(err => { rec.status = 'error'; rec.error = err.message; })
    .finally(() => { running--; for (const l of rec.listeners) l({ type: 'closed' }); });
  // Wait until the init event has assigned an id (synchronous inside runScan before first await).
  await Promise.race([p, new Promise(r => setTimeout(r, 50))]);
  if (!id) return res.status(500).json({ error: rec.error || 'failed to start scan' });
  res.status(202).json({ id, status: rec.status, error: rec.error });
});

/** Server-Sent Events: replays buffered events, then streams live. */
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
    const files = (await fs.readdir(REPORT_DIR)).filter(f => f.endsWith('.json'));
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

app.use((err, _req, res, _next) => res.status(500).json({ error: err.message }));

function clamp(n, lo, hi) { return n == null ? undefined : Math.min(hi, Math.max(lo, n)); }

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  🦋  Monarch Security Engine  →  http://0.0.0.0:${PORT}`);
  console.log(`      AI provider: ${detectProvider()}   crawler: ${process.env.CRAWLER || 'fetch'}   reports: ${REPORT_DIR}\n`);
});
