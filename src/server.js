import express from 'express';
import http from 'node:http';
import path from 'node:path';
import fsSync from 'node:fs';
import { fileURLToPath } from 'node:url';
import { detectProvider } from './ai/insights.js';
import { DEFAULT_MODEL, PROVIDERS, PROVIDER_INFO, normalizeOllamaBaseUrl } from './ai/registry.js';
import { loadEnv } from './env.js';

import { wsServer } from './modules/ws.js';
import { monitorService } from './modules/monitor.js';
import { notificationService } from './modules/notifications.js';
import { scanRegistry } from './scanRegistry.js';
import { resetAiHealthCache as aiHealthCacheReset } from './ai/health.js';
import { apiLimiter } from './middleware/rateLimiter.js';

import scanRoutes from './routes/scans.js';
import monitorRoutes from './routes/monitors.js';
import toolRoutes from './routes/tools.js';
import aiRoutes from './routes/ai.js';

loadEnv();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);

const app = express();
const server = http.createServer(app);

// Trust proxy for correct IP in rate limiter
app.set('trust proxy', 1);

// Attach WebSocket server
wsServer.attach(server);

// Initialize background services with WebSocket broadcast
const broadcast = (channel, data) => wsServer.broadcast(channel, data);
monitorService.init(broadcast).catch(err => {
  console.error('[Monitor] Init error:', err.message);
});
notificationService.init(broadcast).catch(err => {
  console.error('[Notifications] Init error:', err.message);
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

// Runtime AI configuration lives on app.locals so route modules can read it.
// baseUrl holds the Ollama endpoint when the ollama provider is selected.
app.locals.runtimeAiConfig = null;
app.locals.ollamaBaseUrl = normalizeOllamaBaseUrl(process.env.OLLAMA_BASE_URL || process.env.OLLAMA_HOST || '');

/* ------------------------------------------------------------------ */
/* Config & Health Endpoints                                          */
/* ------------------------------------------------------------------ */

function aiKeyConfigured() {
  return Boolean(
    app.locals.runtimeAiConfig?.apiKey ||
    process.env.OPENROUTER_API_KEY ||
    process.env.OPENAI_API_KEY ||
    process.env.ANTHROPIC_API_KEY ||
    process.env.GEMINI_API_KEY
  );
}

app.get('/api/health', (req, res) => {
  const activeProvider = app.locals.runtimeAiConfig?.provider || detectProvider();
  res.json({
    ok: true,
    version: '2.1.0',
    name: 'Monarch Security Engine',
    ai: activeProvider,
    aiConfigured: aiKeyConfigured(),
    crawler: process.env.CRAWLER || 'fetch',
    running: scanRegistry.running,
    maxConcurrent: scanRegistry.maxConcurrent,
    wsClients: wsServer.getClientCount(),
    monitorsActive: monitorService.getMonitors().filter(m => m.active).length,
    unreadNotifications: notificationService.unreadCount(),
    uptime: process.uptime(),
    reportsDir: scanRegistry.reportDir,
    staticDir: staticDir.includes('dist') ? 'dist (built)' : 'public (fallback)',
  });
});

app.get('/api/metrics', (req, res) => {
  // Simple Prometheus-style metrics
  const mem = process.memoryUsage();
  const metrics = [
    `# HELP monarch_scans_running Current running scans`,
    `# TYPE monarch_scans_running gauge`,
    `monarch_scans_running ${scanRegistry.running}`,
    `# HELP monarch_scans_total Total scans in memory`,
    `# TYPE monarch_scans_total gauge`,
    `monarch_scans_total ${scanRegistry.scans.size}`,
    `# HELP monarch_ws_clients WebSocket clients`,
    `# TYPE monarch_ws_clients gauge`,
    `monarch_ws_clients ${wsServer.getClientCount()}`,
    `# HELP monarch_monitors_active Active monitors`,
    `# TYPE monarch_monitors_active gauge`,
    `monarch_monitors_active ${monitorService.getMonitors().filter(m => m.active).length}`,
    `# HELP monarch_notifications_unread Unread notifications`,
    `# TYPE monarch_notifications_unread gauge`,
    `monarch_notifications_unread ${notificationService.unreadCount()}`,
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
    version: '2.1.0',
    endpoints: [
      { method: 'GET', path: '/api/health', description: 'Service health and status' },
      { method: 'GET', path: '/api/metrics', description: 'Prometheus metrics' },
      { method: 'GET', path: '/api/config', description: 'AI provider config' },
      { method: 'POST', path: '/api/config', description: 'Set AI config' },
      { method: 'GET', path: '/api/ai/health', description: 'Probe active AI provider (?all=1 for every provider, ?provider=x for one, ?fresh=1 to skip cache)' },
      { method: 'POST', path: '/api/ai/health', description: 'Probe a not-yet-saved AI config before saving' },
      { method: 'GET', path: '/api/ai/providers', description: 'List AI providers and default models' },
      { method: 'POST', path: '/api/scans', description: 'Start security scan', rateLimited: true },
      { method: 'GET', path: '/api/scans', description: 'List recent scans' },
      { method: 'GET', path: '/api/scans/:id', description: 'Get scan report' },
      { method: 'GET', path: '/api/scans/:id/events', description: 'SSE stream of scan progress' },
      { method: 'GET', path: '/api/scans/:id/report.:fmt', description: 'Export md, html, json, sarif' },
      { method: 'DELETE', path: '/api/scans/:id', description: 'Delete scan' },
      { method: 'GET', path: '/api/monitors', description: 'List uptime monitors' },
      { method: 'POST', path: '/api/monitors', description: 'Create monitor (supports notifyOn preference)' },
      { method: 'POST', path: '/api/monitors/:id/check', description: 'Trigger monitor check' },
      { method: 'POST', path: '/api/monitors/:id/toggle', description: 'Pause/resume monitor' },
      { method: 'DELETE', path: '/api/monitors/:id', description: 'Delete monitor' },
      { method: 'GET', path: '/api/notifications', description: 'List notifications (?limit=&unread=1)' },
      { method: 'GET', path: '/api/notifications/unread-count', description: 'Unread notification count' },
      { method: 'POST', path: '/api/notifications/:id/read', description: 'Mark notification read' },
      { method: 'POST', path: '/api/notifications/read-all', description: 'Mark all notifications read' },
      { method: 'DELETE', path: '/api/notifications/:id', description: 'Delete notification' },
      { method: 'DELETE', path: '/api/notifications', description: 'Clear all notifications' },
      { method: 'POST', path: '/api/speed/analyze', description: 'Full page speed analysis (DNS/TCP/TLS/TTFB, audits, score)' },
      { method: 'POST', path: '/api/speed/status', description: 'Quick live/down status probe' },
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
  const provider = app.locals.runtimeAiConfig?.provider || detectProvider();
  res.json({
    provider,
    model: app.locals.runtimeAiConfig?.model || process.env.AI_MODEL || DEFAULT_MODEL[provider] || '',
    hasApiKey: aiKeyConfigured(),
    baseUrl: app.locals.ollamaBaseUrl || process.env.OLLAMA_BASE_URL || '',
    availableProviders: PROVIDER_INFO,
  });
});

app.post('/api/config', (req, res) => {
  const { provider, apiKey, model, baseUrl } = req.body || {};
  if (provider && !PROVIDERS.includes(provider)) {
    return res.status(400).json({ error: 'Invalid provider' });
  }
  let ollamaBaseUrl = app.locals.ollamaBaseUrl;
  if (provider === 'ollama' && baseUrl) {
    try { ollamaBaseUrl = normalizeOllamaBaseUrl(baseUrl); } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  }
  app.locals.runtimeAiConfig = {
    provider: provider || 'openrouter',
    apiKey: apiKey || '',
    model: model || DEFAULT_MODEL[provider] || '',
  };
  if (provider === 'ollama') app.locals.ollamaBaseUrl = ollamaBaseUrl;
  // Invalidate cached AI health so the next probe reflects the new config
  if (typeof aiHealthCacheReset === 'function') aiHealthCacheReset();
  res.json({
    ok: true,
    message: 'AI Configuration updated in session',
    provider: app.locals.runtimeAiConfig.provider,
    model: app.locals.runtimeAiConfig.model,
    hasApiKey: Boolean(app.locals.runtimeAiConfig.apiKey),
    baseUrl: provider === 'ollama' ? app.locals.ollamaBaseUrl : undefined,
  });
});

/* ------------------------------------------------------------------ */
/* Modular route components                                           */
/* ------------------------------------------------------------------ */

app.use('/api', scanRoutes);     // /api/scans…
app.use('/api', monitorRoutes);  // /api/monitors… + /api/notifications…
app.use('/api', toolRoutes);     // /api/speed…, /api/tls…, /api/recon…, etc.
app.use('/api', aiRoutes);       // /api/ai/health…, /api/ai/providers

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

// Periodic cleanup of old scans (memory + disk)
scanRegistry.startTtlCleanup();

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  🦋  Monarch Security Engine v2.1  →  http://0.0.0.0:${PORT}`);
  console.log(`      AI default: ${detectProvider()}   crawler: ${process.env.CRAWLER || 'fetch'}   reports: ${scanRegistry.reportDir}`);
  console.log(`      Static: ${staticDir}   Max concurrent: ${scanRegistry.maxConcurrent}\n`);
});
