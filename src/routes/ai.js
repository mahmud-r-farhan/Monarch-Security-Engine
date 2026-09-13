import { Router } from 'express';
import { checkProvider, checkActiveProvider, checkAllProviders } from '../ai/health.js';
import { PROVIDER_INFO, PROVIDERS } from '../ai/registry.js';

/**
 * AI routes — provider metadata and health checks.
 *
 * GET /api/ai/health            → probe the currently-active provider
 * GET /api/ai/health?all=1      → probe every provider (status board)
 * GET /api/ai/health?provider=x → probe one provider
 * POST /api/ai/health           → same as GET but body may carry {provider,baseUrl,apiKey,model}
 *                                 so the UI can test a *not-yet-saved* configuration.
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
  const hasOverrides = Object.keys(overrides).length > 0;
  const aiConfig = hasOverrides ? { ...(saved || {}), ...overrides } : saved;
  const fresh = req.query.fresh === '1' || body.fresh === true;
  return { aiConfig, fresh, hasOverrides };
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
      return res.json(await checkProvider(provider, { aiConfig: req.app.locals.runtimeAiConfig || null, fresh: req.query.fresh === '1' }));
    }
    res.json(await checkActiveProvider({ aiConfig: req.app.locals.runtimeAiConfig || null, fresh: req.query.fresh === '1' }));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/ai/health', async (req, res) => {
  try {
    const { aiConfig, fresh, hasOverrides } = pickConfig(req);
    const provider = aiConfig?.provider;
    if (provider && !PROVIDERS.includes(provider)) {
      return res.status(400).json({ error: 'Invalid provider' });
    }
    // An explicit (possibly unsaved) config — or an explicit override — probes that provider
    if ((hasOverrides && provider) || (provider && provider !== 'none')) {
      return res.json(await checkProvider(provider, { aiConfig, fresh: fresh || hasOverrides }));
    }
    res.json(await checkActiveProvider({ aiConfig, fresh }));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/ai/providers', (req, res) => {
  res.json(PROVIDER_INFO);
});

export default router;
