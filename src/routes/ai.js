import { Router } from 'express';
import { checkProvider, checkActiveProvider, checkAllProviders } from '../ai/health.js';
import { PROVIDER_INFO, PROVIDERS } from '../ai/registry.js';
import { getJson } from '../ai/providers/http.js';

/**
 * AI routes — provider metadata, health checks and live model listings.
 *
 * GET  /api/ai/health            → probe the currently-active provider
 * GET  /api/ai/health?all=1      → probe every provider (status board)
 * GET  /api/ai/health?provider=x → probe one provider
 * GET  /api/ai/health?deep=1     → also run a tiny chat completion to validate the model
 * POST /api/ai/health            → same as GET but body may carry {provider,baseUrl,apiKey,model,deep}
 *                                  so the UI can test a *not-yet-saved* configuration.
 * GET  /api/ai/providers         → provider metadata + curated model suggestions
 * POST /api/ai/models            → live model ids for a provider {provider, apiKey?}
 *                                  (openrouter needs no key; others use the posted or saved key)
 */
const router = Router();

function pickConfig(req) {
  // Runtime config saved via /api/config lives on app.locals
  const saved = req.app.locals.runtimeAiConfig || null;
  // A POST may carry values for a *not-yet-saved* config to test without saving
  const body = req.method === 'POST' ? (req.body || {}) : {};
  const overrides = {};
  if (body.provider) overrides.provider = body.provider;
  if (body.baseUrl) overrides.baseUrl = body.baseUrl;
  if (body.apiKey) overrides.apiKey = body.apiKey;
  if (body.model) overrides.model = body.model;
  if (body.timeoutMs) overrides.timeoutMs = body.timeoutMs;
  const hasOverrides = Object.keys(overrides).length > 0;
  const aiConfig = hasOverrides ? { ...(saved || {}), ...overrides } : saved;
  const fresh = req.query.fresh === '1' || body.fresh === true;
  const deep = req.query.deep === '1' || body.deep === true;
  return { aiConfig, fresh, deep, hasOverrides };
}

router.get('/ai/health', async (req, res) => {
  try {
    if (req.query.all === '1') {
      return res.json(await checkAllProviders({ aiConfig: req.app.locals.runtimeAiConfig || null, fresh: req.query.fresh === '1' }));
    }
    const provider = req.query.provider;
    if (provider && !PROVIDERS.includes(provider)) {
      return res.status(400).json({ error: 'Invalid provider' });
    }
    if (provider) {
      return res.json(await checkProvider(provider, { aiConfig: req.app.locals.runtimeAiConfig || null, fresh: req.query.fresh === '1', deep: req.query.deep === '1' }));
    }
    res.json(await checkActiveProvider({ aiConfig: req.app.locals.runtimeAiConfig || null, fresh: req.query.fresh === '1', deep: req.query.deep === '1' }));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/ai/health', async (req, res) => {
  try {
    const { aiConfig, fresh, deep, hasOverrides } = pickConfig(req);
    const provider = aiConfig?.provider;
    if (provider && !PROVIDERS.includes(provider)) {
      return res.status(400).json({ error: 'Invalid provider' });
    }
    // An explicit (possibly unsaved) config — or an explicit override — probes that provider
    if ((hasOverrides && provider) || (provider && provider !== 'none')) {
      return res.json(await checkProvider(provider, { aiConfig, fresh: fresh || hasOverrides, deep }));
    }
    res.json(await checkActiveProvider({ aiConfig, fresh, deep }));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/ai/providers', (req, res) => {
  res.json(PROVIDER_INFO);
});

/** Live model ids for the UI datalist. OpenRouter's catalog is public. */
router.post('/ai/models', async (req, res) => {
  const { provider, apiKey, baseUrl } = req.body || {};
  if (!provider || !PROVIDERS.includes(provider)) {
    return res.status(400).json({ error: 'Invalid provider' });
  }
  if (provider === 'none' || provider === 'ollama') {
    return res.status(400).json({ error: `Live listing not available for ${provider} — use the suggestions instead` });
  }
  const saved = req.app.locals.runtimeAiConfig;
  const key = apiKey || saved?.apiKey || '';
  const customBase = (baseUrl || saved?.baseUrl || process.env.OPENAI_COMPATIBLE_BASE_URL || 'http://localhost:1234/v1').replace(/\/+$/, '');
  const endpoints = {
    openrouter: { url: 'https://openrouter.ai/api/v1/models', headers: { 'HTTP-Referer': 'https://github.com/mahmud-r-farhan/Monarch-Security-Engine' } },
    openai: { url: 'https://api.openai.com/v1/models', headers: {} },
    anthropic: { url: 'https://api.anthropic.com/v1/models', headers: { 'anthropic-version': '2023-06-01' } },
    gemini: { url: 'https://generativelanguage.googleapis.com/v1beta/models', headers: {} },
    'openai-compatible': { url: `${customBase}/models`, headers: {} },
  };
  const ep = endpoints[provider];
  const url = provider === 'gemini' && key ? `${ep.url}?key=${encodeURIComponent(key)}` : ep.url;
  try {
    const json = await getJson(url, {
      headers: { ...ep.headers, ...(key && provider !== 'gemini' ? { authorization: `Bearer ${key}` } : {}) },
      timeoutMs: 10_000,
    });
    const raw = Array.isArray(json?.data) ? json.data : Array.isArray(json?.models) ? json.models : [];
    const ids = raw.map(m => m.id || m.name).filter(Boolean).sort();
    res.json({ ok: true, provider, count: ids.length, models: ids.slice(0, 300) });
  } catch (err) {
    res.json({ ok: false, provider, error: err.message, models: [] });
  }
});

export default router;
