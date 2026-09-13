import { providers } from './providers/index.js';
import { resolveProviderConfig, detectProvider, PROVIDER_ENV } from './registry.js';
import { getJson } from './providers/http.js';

const HEALTH_TTL_MS = 30_000; // cache successful/failed probes for 30s
let cache = { at: 0, byProvider: new Map() };

/**
 * Probe one provider's endpoint. Never throws — returns a status object.
 * - cloud key providers: GET the models endpoint (cheap, validates key + reachability)
 * - ollama: GET /api/tags (lists installed models)
 * - none: trivially healthy
 */
export async function checkProvider(provider, { env = process.env, aiConfig = null, fetchImpl = fetch, fresh = false } = {}) {
  if (!fresh) {
    const hit = cache.byProvider.get(provider);
    if (hit && Date.now() - hit.checkedAt < HEALTH_TTL_MS) return hit;
  }

  const status = await probe(provider, { env, aiConfig, fetchImpl });
  status.checkedAt = Date.now();
  cache.byProvider.set(provider, status);
  return status;
}

async function probe(provider, { env, aiConfig, fetchImpl }) {
  const cfg = resolveProviderConfig({ provider, ...(aiConfig || {}) }, env);

  if (provider === 'none') {
    return { provider, ok: true, latencyMs: 0, detail: 'Offline heuristic analyst — always available' };
  }

  const client = providers[provider];
  if (!client) return { provider, ok: false, latencyMs: 0, error: `Unknown provider "${provider}"` };

  const started = Date.now();
  try {
    if (provider === 'ollama') {
      const models = await client.listModels({ baseUrl: cfg.baseUrl, fetchImpl });
      const names = models.map(m => m.name || m.model).filter(Boolean);
      return {
        provider,
        ok: true,
        latencyMs: Date.now() - started,
        baseUrl: cfg.baseUrl,
        models: names.slice(0, 25),
        detail: names.length ? `Reachable — ${names.length} model(s) installed` : 'Reachable — no models pulled yet (run: ollama pull llama3.2)',
      };
    }

    // Cloud providers: hit their models listing endpoint with the configured key.
    const key = cfg.apiKey;
    if (!key) return { provider, ok: false, latencyMs: 0, error: 'No API key configured' };

    const endpoints = {
      openrouter: { url: 'https://openrouter.ai/api/v1/models', headers: { authorization: `Bearer ${key}`, 'HTTP-Referer': 'https://github.com/mahmud-r-farhan/Monarch-Security-Engine' } },
      openai: { url: 'https://api.openai.com/v1/models', headers: { authorization: `Bearer ${key}` } },
      anthropic: { url: 'https://api.anthropic.com/v1/models', headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01' } },
      gemini: { url: `https://generativelanguage.googleapis.com/v1beta/models?key=${key}`, headers: {} },
    };
    const ep = endpoints[provider];
    const json = await getJson(ep.url, { headers: ep.headers, timeoutMs: 8000, fetchImpl });
    const count = Array.isArray(json?.data) ? json.data.length : Array.isArray(json?.models) ? json.models.length : null;
    return {
      provider,
      ok: true,
      latencyMs: Date.now() - started,
      detail: count != null ? `Reachable — ${count} model(s) available` : 'Reachable',
    };
  } catch (err) {
    const msg = String(err.message || err);
    return {
      provider,
      ok: false,
      latencyMs: Date.now() - started,
      baseUrl: cfg.baseUrl || undefined,
      error: /aborted|timeout/i.test(msg) ? `Timed out after 8s` : msg,
      hint: hintFor(provider, msg),
    };
  }
}

function hintFor(provider, msg) {
  if (provider === 'ollama') {
    if (/ECONNREFUSED|fetch failed|ENOTFOUND/i.test(msg)) return 'Is the server running? Start it with: ollama serve';
    return 'Verify OLLAMA_BASE_URL and that the server is reachable from Monarch.';
  }
  if (/HTTP 401|HTTP 403|invalid.*key|unauthorized/i.test(msg)) return 'API key rejected — check the key and its billing/quota status.';
  if (/HTTP 429/.test(msg)) return 'Rate limited — the key is valid but quota is exhausted right now.';
  if (/ENOTFOUND|ECONNREFUSED|fetch failed|timeout/i.test(msg)) return 'Network problem reaching the provider endpoint.';
  return null;
}

/** Probe the currently-active provider (env + optional runtime override). */
export async function checkActiveProvider({ env = process.env, aiConfig = null, fetchImpl = fetch, fresh = false } = {}) {
  const provider = aiConfig?.provider && aiConfig.provider !== 'auto' ? aiConfig.provider : detectProvider(env);
  return checkProvider(provider, { env, aiConfig, fetchImpl, fresh });
}

/** Probe every registered provider in parallel — powers the full status board. */
export async function checkAllProviders({ env = process.env, aiConfig = null, fetchImpl = fetch, fresh = false } = {}) {
  const jobs = ['openrouter', 'openai', 'anthropic', 'gemini', 'ollama', 'none'].map(p => checkProvider(p, { env, aiConfig, fetchImpl, fresh }));
  const results = await Promise.all(jobs);
  return {
    active: aiConfig?.provider && aiConfig.provider !== 'auto' ? aiConfig.provider : detectProvider(env),
    providers: results,
    checkedAt: Date.now(),
  };
}

/** Drop the health cache (called when the runtime AI config changes). */
export function resetAiHealthCache() {
  cache = { at: 0, byProvider: new Map() };
}

// Re-exported for callers that want to build per-provider probes without import churn.
export { PROVIDER_ENV };
