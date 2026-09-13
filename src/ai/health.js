import { providers } from './providers/index.js';
import { resolveProviderConfig, detectProvider, PROVIDER_ENV } from './registry.js';
import { getJson } from './providers/http.js';

const HEALTH_TTL_MS = 30_000; // cache successful/failed probes for 30s
let cache = { at: 0, byProvider: new Map() };

/**
 * Probe one provider's endpoint. Never throws — returns a status object.
 * - cloud key providers: GET the models endpoint (cheap, validates key + reachability)
 *   with `deep: true` it ALSO runs a tiny chat completion to validate the
 *   configured model end-to-end (same path a scan will take).
 * - ollama: GET /api/tags (lists installed models)
 * - none: trivially healthy
 */
export async function checkProvider(provider, { env = process.env, aiConfig = null, fetchImpl = fetch, fresh = false, deep = false } = {}) {
  const cacheKey = deep ? `${provider}::deep` : provider;
  if (!fresh) {
    const hit = cache.byProvider.get(cacheKey);
    if (hit && Date.now() - hit.checkedAt < HEALTH_TTL_MS) return hit;
  }

  const status = await probe(provider, { env, aiConfig, fetchImpl, deep });
  status.checkedAt = Date.now();
  cache.byProvider.set(cacheKey, status);
  return status;
}

async function probe(provider, { env, aiConfig, fetchImpl, deep }) {
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
      const modelOk = !cfg.model || names.some(n => n === cfg.model || n.startsWith(cfg.model + ':'));
      const base = {
        provider,
        ok: true,
        latencyMs: Date.now() - started,
        baseUrl: cfg.baseUrl,
        models: names.slice(0, 25),
        model: cfg.model,
        modelExists: modelOk || undefined,
        detail: names.length ? `Reachable — ${names.length} model(s) installed` : 'Reachable — no models pulled yet (run: ollama pull llama3.2)',
        hint: names.length && !modelOk ? `Model "${cfg.model}" is not pulled yet — run: ollama pull ${cfg.model}` : undefined,
      };
      if (names.length && !modelOk) base.ok = false;
      if (!deep) return base;

      // Deep check: prove the pulled model actually answers a chat request.
      const chatStarted = Date.now();
      await client.chat({
        baseUrl: cfg.baseUrl,
        model: cfg.model,
        system: 'You are a connectivity probe. Reply with the JSON object {"ok":true} and nothing else.',
        prompt: 'ping',
        fetchImpl,
        timeoutMs: 30_000,
      });
      base.chat = { ok: true, latencyMs: Date.now() - chatStarted };
      base.detail += ` · model "${cfg.model}" responded in ${base.chat.latencyMs}ms`;
      return base;
    }

    // Cloud & custom OpenAI-compatible providers: hit their models listing endpoint
    const key = cfg.apiKey;
    if (provider !== 'openai-compatible' && !key) {
      return { provider, ok: false, latencyMs: 0, error: 'No API key configured', hint: `Add a ${PROVIDER_ENV[provider]?.key || 'n'} API key or pick another provider.` };
    }

    let targetBase = cfg.baseUrl || 'https://api.openai.com/v1';
    while (typeof targetBase === 'string' && targetBase.endsWith('/')) {
      targetBase = targetBase.slice(0, -1);
    }

    const endpoints = {
      openrouter: { url: 'https://openrouter.ai/api/v1/models', headers: { authorization: `Bearer ${key}`, 'HTTP-Referer': 'https://github.com/mahmud-r-farhan/Monarch-Security-Engine' } },
      'openai-compatible': { url: `${targetBase}/models`, headers: key ? { authorization: `Bearer ${key}` } : {} },
      openai: { url: 'https://api.openai.com/v1/models', headers: { authorization: `Bearer ${key}` } },
      anthropic: { url: 'https://api.anthropic.com/v1/models', headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01' } },
      gemini: { url: `https://generativelanguage.googleapis.com/v1beta/models?key=${key}`, headers: {} },
    };
    const ep = endpoints[provider];
    const json = await getJson(ep.url, { headers: ep.headers, timeoutMs: 8000, fetchImpl });
    const list = Array.isArray(json?.data) ? json.data : Array.isArray(json?.models) ? json.models : null;
    const count = list ? list.length : null;

    // Validate the configured model id against the live catalog where possible.
    let modelExists = null;
    if (list && cfg.model) {
      modelExists = list.some(m => (m.id || m.name) === cfg.model);
    }

    const base = {
      provider,
      ok: true,
      latencyMs: Date.now() - started,
      model: cfg.model || undefined,
      detail: count != null ? `Reachable — ${count} model(s) available` : 'Reachable',
      hint: modelExists === false
        ? `Model "${cfg.model}" is not in ${provider}'s catalog — check the exact id (openrouter.ai/models).`
        : undefined,
    };
    if (modelExists === false) base.ok = false; // catalog lookup is authoritative for openrouter/openai/gemini

    if (!deep) return base;

    // Deep check: run a minimal chat completion — validates model + key + JSON path.
    const chatStarted = Date.now();
    const reply = await client.chat({
      apiKey: key,
      baseUrl: cfg.baseUrl,
      model: cfg.model,
      system: 'You are a connectivity probe. Reply with the JSON object {"ok":true} and nothing else.',
      prompt: 'ping',
      fetchImpl,
      timeoutMs: 30_000,
    });
    base.chat = { ok: true, latencyMs: Date.now() - chatStarted, responded: Boolean(reply) };
    base.latencyMs = Date.now() - started;
    base.detail = `${base.detail} · model "${cfg.model}" responded in ${base.chat.latencyMs}ms`;
    return base;
  } catch (err) {
    const msg = String(err.message || err);
    return {
      provider,
      ok: false,
      latencyMs: Date.now() - started,
      baseUrl: cfg.baseUrl || undefined,
      model: cfg.model || undefined,
      error: /timed out|aborted|timeout/i.test(msg) ? `Timed out` : msg,
      hint: hintFor(provider, msg),
    };
  }
}

function hintFor(provider, msg) {
  if (provider === 'ollama') {
    if (/ECONNREFUSED|fetch failed|ENOTFOUND/i.test(msg)) return 'Is the server running? Start it with: ollama serve';
    return 'Verify OLLAMA_BASE_URL and that the server is reachable from Monarch.';
  }
  if (/HTTP 401|HTTP 403|invalid.*key|unauthorized|No auth credentials/i.test(msg)) return 'API key rejected — check the key and its billing/quota status.';
  if (/HTTP 402|insufficient|credits/i.test(msg)) return 'The key is valid but the account is out of credits — top up or switch to a :free model.';
  if (/HTTP 404|No endpoints found|not a valid model/i.test(msg)) return `Model not found — verify the exact model id at ${provider === 'openrouter' ? 'openrouter.ai/models' : 'the provider\'s model list'}.`;
  if (/HTTP 429/.test(msg)) return 'Rate limited — the key is valid but quota is exhausted right now. Free tiers allow ~20 requests/min.';
  if (/timed out|AI_TIMEOUT/i.test(msg)) return 'The model was too slow to respond. Reasoning models (e.g. deepseek-r1-*) often exceed timeouts — switch to a fast model like openai/gpt-4o-mini, or raise AI_TIMEOUT_MS.';
  if (/response_format|json_object/i.test(msg)) return 'This model does not support JSON mode — Monarch will retry without it automatically.';
  if (/ENOTFOUND|ECONNREFUSED|fetch failed|timeout/i.test(msg)) return 'Network problem reaching the provider endpoint.';
  return null;
}

/** Probe the currently-active provider (env + optional runtime override). */
export async function checkActiveProvider({ env = process.env, aiConfig = null, fetchImpl = fetch, fresh = false, deep = false } = {}) {
  const provider = aiConfig?.provider && aiConfig.provider !== 'auto' ? aiConfig.provider : detectProvider(env);
  return checkProvider(provider, { env, aiConfig, fetchImpl, fresh, deep });
}

/** Probe every registered provider in parallel — powers the full status board. */
export async function checkAllProviders({ env = process.env, aiConfig = null, fetchImpl = fetch, fresh = false } = {}) {
  const jobs = ['openrouter', 'openai-compatible', 'openai', 'anthropic', 'gemini', 'ollama', 'none'].map(p => checkProvider(p, { env, aiConfig, fetchImpl, fresh }));
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
