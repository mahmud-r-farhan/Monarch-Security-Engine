import { Router } from 'express';
import { runScan, summarizeScan } from '../engine/scanner.js';
import { renderMarkdown } from '../report/markdown.js';
import { renderHtml } from '../report/html.js';
import { renderSarif } from '../report/sarif.js';
import { scanLimiter, apiLimiter } from '../middleware/rateLimiter.js';
import { scanRegistry } from '../scanRegistry.js';

/**
 * Scan routes — start, stream, list, fetch, export and delete scans.
 */
const router = Router();
const { scans, maxConcurrent: MAX_CONCURRENT } = scanRegistry;

function clamp(n, lo, hi) {
  return n == null ? undefined : Math.min(hi, Math.max(lo, n));
}

router.post('/scans', scanLimiter, async (req, res) => {
  const { target, maxPages, engine, ai, aiConfig } = req.body || {};
  if (!target) return res.status(400).json({ error: 'target is required' });
  if (typeof target !== 'string' || target.length > 2048) return res.status(400).json({ error: 'Invalid target length' });
  if (scanRegistry.running >= MAX_CONCURRENT) {
    return res.status(429).json({ error: `Too many concurrent scans (max ${MAX_CONCURRENT}); try again shortly.` });
  }

  const rec = scanRegistry.createRecord(target);
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

  scanRegistry.running++;

  const p = runScan(target, {
    maxPages: clamp(Number(maxPages) || undefined, 1, 200),
    engine: engine === 'playwright' ? 'playwright' : engine === 'fetch' ? 'fetch' : undefined,
    ai: ai !== false,
    aiConfig: aiConfig || req.app.locals.runtimeAiConfig,
    onEvent,
  })
    .then(async scan => {
      rec.status = 'done';
      rec.scan = scan;
      await scanRegistry.persist(scan).catch(() => {});
    })
    .catch(err => {
      rec.status = 'error';
      rec.error = err.message;
    })
    .finally(() => {
      scanRegistry.running--;
      for (const l of rec.listeners) l({ type: 'closed' });
    });

  await Promise.race([p, new Promise(r => setTimeout(r, 80))]);

  if (!id) return res.status(500).json({ error: rec.error || 'failed to start scan' });
  res.status(202).json({ id, status: rec.status, error: rec.error });
});

router.get('/scans/:id/events', (req, res) => {
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

router.get('/scans', async (req, res) => {
  const list = [];
  for (const [id, rec] of scans) {
    list.push(rec.scan ? summarizeScan(rec.scan) : { id, target: rec.target, status: rec.status, error: rec.error, startedAt: new Date(rec.createdAt).toISOString() });
  }
  try {
    const { readdir } = await import('node:fs/promises');
    const files = (await readdir(scanRegistry.reportDir)).filter(f => f.endsWith('.json') && !f.includes('monitors') && !f.includes('notifications'));
    for (const f of files) {
      const id = f.slice(0, -5);
      if (!scans.has(id)) {
        const s = await scanRegistry.loadFromDisk(id);
        if (s) list.push(summarizeScan(s));
      }
    }
  } catch {}
  list.sort((a, b) => (b.startedAt || '').localeCompare(a.startedAt || ''));
  res.json(list.slice(0, 100));
});

router.get('/scans/:id', async (req, res) => {
  if (!/^[0-9a-f-]{36}$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid scan ID' });
  const scan = await scanRegistry.getScan(req.params.id);
  if (scan) return res.json(scan);
  const rec = scans.get(req.params.id);
  if (rec) return res.json({ id: req.params.id, status: rec.status, error: rec.error });
  res.status(404).json({ error: 'not found' });
});

router.get('/scans/:id/report.:fmt', async (req, res) => {
  if (!/^[0-9a-f-]{36}$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid scan ID' });
  const scan = await scanRegistry.getScan(req.params.id);
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

router.delete('/scans/:id', async (req, res) => {
  if (!/^[0-9a-f-]{36}$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid scan ID' });
  scans.delete(req.params.id);
  const { unlink } = await import('node:fs/promises');
  const reportPath = scanRegistry.getReportFilePath(req.params.id);
  if (reportPath) await unlink(reportPath).catch(() => {});
  res.status(204).end();
});

export default router;
