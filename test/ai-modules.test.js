import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateInsights, heuristicInsights, detectProvider, parseModelJson, normalizeOllamaBaseUrl } from '../src/ai/insights.js';
import { resolveProviderConfig, DEFAULT_MODEL, PROVIDERS, PROVIDER_INFO, clampTimeoutMs } from '../src/ai/registry.js';
import { checkProvider, checkAllProviders, resetAiHealthCache } from '../src/ai/health.js';
import { providers } from '../src/ai/providers/index.js';
import { buildPrompt, SYSTEM } from '../src/ai/prompt.js';
import { mergeAiConfig } from '../src/routes/scans.js';

test('AI facade re-exports stay importable from ai/insights.js', () => {
  assert.equal(typeof generateInsights, 'function');
  assert.equal(typeof heuristicInsights, 'function');
  assert.equal(typeof detectProvider, 'function');
  assert.equal(typeof parseModelJson, 'function');
  assert.equal(typeof normalizeOllamaBaseUrl, 'function');
  assert.ok(Array.isArray(PROVIDERS) && PROVIDERS.includes('ollama'));
  assert.equal(DEFAULT_MODEL.ollama, 'llama3.2');
});

test('provider registry exposes a client for every non-none provider id', () => {
  for (const id of PROVIDERS.filter(p => p !== 'none')) {
    assert.ok(providers[id], `missing client for ${id}`);
    assert.equal(typeof providers[id].chat, 'function', `${id}.chat missing`);
  }
  assert.equal(typeof providers.ollama.listModels, 'function');
});

test('PROVIDER_INFO matches PROVIDERS ids', () => {
  assert.deepEqual(PROVIDER_INFO.map(p => p.id).sort(), [...PROVIDERS].sort());
});

test('resolveProviderConfig merges env, runtime override and per-provider keys', () => {
  const env = { OPENROUTER_API_KEY: 'sk-or-x', AI_MODEL: 'm1' };
  const cfg = resolveProviderConfig(null, env);
  assert.equal(cfg.provider, 'openrouter');
  assert.equal(cfg.model, 'm1');
  assert.equal(cfg.apiKey, 'sk-or-x');

  // Runtime override switches provider and injects the key into the right slot
  const cfg2 = resolveProviderConfig({ provider: 'anthropic', apiKey: 'ak-x', model: 'claude-x' }, {});
  assert.equal(cfg2.provider, 'anthropic');
  assert.equal(cfg2.model, 'claude-x');
  assert.equal(cfg2.apiKey, 'ak-x');
  assert.equal(cfg2.baseUrl, null);

  // Ollama gets a normalized baseUrl; OLLAMA_MODEL wins over AI_MODEL for ollama
  const cfg3 = resolveProviderConfig({ provider: 'ollama', baseUrl: 'myhost:11434/api' }, { OLLAMA_MODEL: 'qwen2.5:7b' });
  assert.equal(cfg3.provider, 'ollama');
  assert.equal(cfg3.baseUrl, 'http://myhost:11434');
  assert.equal(cfg3.model, 'qwen2.5:7b');

  // None → no key
  const cfg4 = resolveProviderConfig({ provider: 'none' }, {});
  assert.equal(cfg4.apiKey, '');
});

test('generateInsights falls back to heuristic when the provider fails', async () => {
  const scan = minimalScan();
  const out = await generateInsights(scan, {
    env: {},
    aiConfig: { provider: 'openrouter', apiKey: 'bad-key' },
    fetchImpl: async () => ({ ok: false, status: 401, text: async () => 'unauthorized', json: async () => ({}) }),
  });
  assert.equal(out.provider, 'heuristic');
  assert.match(out.warning, /openrouter.*failed/i);
  assert.ok(out.actionPlan.length >= 0);
});

test('generateInsights routes to the ollama client and parses strict JSON', async () => {
  const scan = minimalScan();
  const calls = [];
  const fetchImpl = async (url, opts) => {
    calls.push({ url, body: JSON.parse(opts.body) });
    return {
      ok: true,
      json: async () => ({ message: { content: JSON.stringify({ riskLevel: 'low', executiveSummary: 'ok', rootCauses: [], actionPlan: [], quickWins: [], attackNarrative: '' }) } }),
    };
  };
  const out = await generateInsights(scan, {
    env: {},
    aiConfig: { provider: 'ollama', baseUrl: 'localhost:11434', model: 'llama3.2' },
    fetchImpl,
  });
  assert.equal(out.provider, 'ollama');
  assert.equal(out.riskLevel, 'low');
  assert.equal(calls.length, 1);
  assert.ok(calls[0].url.endsWith('/api/chat'));
  assert.equal(calls[0].body.format, 'json');
  assert.equal(calls[0].body.model, 'llama3.2');
});

test('parseModelJson repairs smart quotes and trailing commas', () => {
  assert.equal(parseModelJson('{“a”:1,}').a, 1);
  assert.equal(parseModelJson('{"a":"x", "b":[1,2,]}').b.length, 2);
});

test('prompt builder compacts findings and includes the target', () => {
  const scan = minimalScan();
  const prompt = buildPrompt(scan);
  assert.ok(prompt.includes('https://target.example'));
  assert.ok(prompt.includes('test-finding'));
  assert.ok(SYSTEM.includes('Respond ONLY with a JSON object'));
});

test('health check: none is trivially healthy, ollama lists models, failures carry hints', async () => {
  resetAiHealthCache();
  const none = await checkProvider('none', { fresh: true });
  assert.equal(none.ok, true);

  const ollama = await checkProvider('ollama', {
    fresh: true,
    aiConfig: { provider: 'ollama', baseUrl: 'http://localhost:59999' },
  });
  assert.equal(ollama.ok, false);
  assert.ok(ollama.hint, 'expected an actionable hint for refused connection');

  const all = await checkAllProviders({ fresh: true });
  assert.equal(all.providers.length, 7);
  assert.ok(all.providers.every(p => 'ok' in p && 'checkedAt' in p));
});

function minimalScan() {
  const finding = {
    id: 'test-finding',
    category: 'headers',
    severity: 'medium',
    title: 'Test finding',
    description: 'd',
    remediation: 'r',
  };
  return {
    target: 'https://target.example',
    crawl: { engine: 'fetch', pages: [{ url: 'https://target.example' }], cookies: [], externalOrigins: [] },
    findings: [finding],
    score: { score: 80, grade: 'B', counts: { critical: 0, high: 0, medium: 1, low: 0, info: 0 } },
    networkSummary: { requests: 1 },
  };
}

/* ------------------------------------------------------------------ */
/* Regression tests for the OpenRouter timeout / abort failure          */
/* ------------------------------------------------------------------ */

test('default OpenRouter model is a fast non-reasoning model', () => {
  assert.equal(DEFAULT_MODEL.openrouter, 'openai/gpt-4o-mini');
  // The old default was a reasoning model that routinely missed the 60s deadline
  assert.ok(!/r1|reasoning|qwq|o1/i.test(DEFAULT_MODEL.openrouter));
});

function abortingFetch() {
  return async () => {
    const err = new Error('This operation was aborted');
    err.name = 'AbortError';
    throw err;
  };
}

test('an aborted request yields a friendly timeout warning and hint (not "This operation was aborted")', async () => {
  const out = await generateInsights(minimalScan(), {
    env: {},
    aiConfig: { provider: 'openrouter', apiKey: 'sk-or-test', model: 'openai/gpt-4o-mini' },
    fetchImpl: abortingFetch(),
  });
  assert.equal(out.provider, 'heuristic');
  assert.match(out.warning, /openrouter.*failed/i);
  assert.match(out.warning, /timed out/i);
  assert.doesNotMatch(out.warning, /This operation was aborted/i);
  assert.match(out.hint, /too slow|AI_TIMEOUT_MS/i);
});

test('the timeout is user-configurable and clamped to 30s–600s', () => {
  assert.equal(clampTimeoutMs(95_000), 95_000);
  assert.equal(clampTimeoutMs(1_000), 30_000);
  assert.equal(clampTimeoutMs(999_999_999), 600_000);
  assert.equal(clampTimeoutMs('nonsense'), 120_000);
  const cfg = resolveProviderConfig({ provider: 'openrouter', apiKey: 'k', timeoutMs: 95_000 }, {});
  assert.equal(cfg.timeoutMs, 95_000);
});

test('transient server errors are retried and recover', async () => {
  let calls = 0;
  const fetchImpl = async (url, opts) => {
    calls++;
    if (calls === 1) return { ok: false, status: 500, text: async () => 'upstream overloaded', json: async () => ({}) };
    return {
      ok: true,
      json: async () => ({ choices: [{ message: { content: JSON.stringify({ riskLevel: 'low', executiveSummary: 'ok', rootCauses: [], actionPlan: [], quickWins: [], attackNarrative: '' }) } }] }),
    };
  };
  const out = await generateInsights(minimalScan(), {
    env: {},
    aiConfig: { provider: 'openrouter', apiKey: 'k', model: 'openai/gpt-4o-mini' },
    fetchImpl,
  });
  assert.equal(out.provider, 'openrouter');
  assert.equal(out.riskLevel, 'low');
  assert.equal(calls, 2);
});

test('auth errors fail fast (no retry) and keep the actionable hint', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; return { ok: false, status: 401, text: async () => 'No auth credentials', json: async () => ({}) }; };
  const out = await generateInsights(minimalScan(), {
    env: {},
    aiConfig: { provider: 'openrouter', apiKey: 'bad', model: 'openai/gpt-4o-mini' },
    fetchImpl,
  });
  assert.equal(out.provider, 'heuristic');
  assert.equal(calls, 1);
  assert.match(out.hint, /key/i);
});

test('models that reject JSON mode are retried without response_format', async () => {
  const bodies = [];
  const fetchImpl = async (url, opts) => {
    bodies.push(JSON.parse(opts.body));
    if (bodies.length === 1) {
      return { ok: false, status: 400, text: async () => JSON.stringify({ error: { message: 'response_format is not supported by this model' } }), json: async () => ({}) };
    }
    return {
      ok: true,
      json: async () => ({ choices: [{ message: { content: JSON.stringify({ riskLevel: 'low', executiveSummary: 'ok', rootCauses: [], actionPlan: [], quickWins: [], attackNarrative: '' }) } }] }),
    };
  };
  const out = await generateInsights(minimalScan(), {
    env: {},
    aiConfig: { provider: 'openrouter', apiKey: 'k', model: 'some/free-model' },
    fetchImpl,
  });
  assert.equal(out.provider, 'openrouter');
  assert.equal(bodies.length, 2);
  assert.equal(bodies[0].response_format.type, 'json_object');
  assert.equal(bodies[1].response_format, undefined);
});

test('reasoning-model <think> blocks are stripped before JSON parsing', () => {
  assert.equal(parseModelJson('<think>let me reason about this...</think>{"a":1}').a, 1);
  assert.equal(parseModelJson('Sure! ```json\n{"b":2}\n```').b, 2);
  assert.equal(parseModelJson('{"riskLevel":"low"}').riskLevel, 'low');
});

test('chat requests carry a max_tokens cap so slow models cannot run away', async () => {
  const bodies = [];
  const fetchImpl = async (url, opts) => {
    bodies.push(JSON.parse(opts.body));
    return {
      ok: true,
      json: async () => ({ choices: [{ message: { content: JSON.stringify({ riskLevel: 'low', executiveSummary: 'ok', rootCauses: [], actionPlan: [], quickWins: [], attackNarrative: '' }) } }] }),
    };
  };
  await generateInsights(minimalScan(), {
    env: {},
    aiConfig: { provider: 'openrouter', apiKey: 'k', model: 'openai/gpt-4o-mini' },
    fetchImpl,
  });
  assert.ok(bodies[0].max_tokens >= 1000 && bodies[0].max_tokens <= 8000);
});

test('deep health check validates the key AND runs a real model completion', async () => {
  resetAiHealthCache();
  const calls = [];
  const fetchImpl = async (url, opts = {}) => {
    calls.push({ url: String(url), method: opts.method || 'GET', body: opts.body ? JSON.parse(opts.body) : null });
    if (opts.method === 'POST') {
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: '{"ok":true}' } }] }),
      };
    }
    return {
      ok: true,
      json: async () => ({ data: [{ id: 'openai/gpt-4o-mini' }, { id: 'meta-llama/llama-3.3-70b-instruct' }] }),
    };
  };
  const ok = await checkProvider('openrouter', {
    fresh: true,
    deep: true,
    aiConfig: { provider: 'openrouter', apiKey: 'k', model: 'openai/gpt-4o-mini' },
    fetchImpl,
  });
  assert.equal(ok.ok, true);
  assert.equal(ok.chat.ok, true);
  assert.match(ok.detail, /responded/);
  assert.equal(calls.filter(c => c.method === 'POST').length, 1);

  // An unknown model id is caught during the catalog check — before wasting a chat call
  const bad = await checkProvider('openrouter', {
    fresh: true,
    aiConfig: { provider: 'openrouter', apiKey: 'k', model: 'nope/does-not-exist' },
    fetchImpl,
  });
  assert.equal(bad.ok, false);
  assert.match(bad.hint, /not in openrouter's catalog|exact id/i);
});

test('an empty client-side API key does not shadow the server-saved one', () => {
  const saved = { provider: 'openrouter', apiKey: 'sk-or-saved', model: 'openai/gpt-4o-mini', timeoutMs: 120000 };
  // What the browser sends after a refresh: provider+model from sessionStorage, no key
  const client = { provider: 'openrouter', apiKey: '', model: 'openai/gpt-4o-mini' };
  const merged = mergeAiConfig(saved, client);
  assert.equal(merged.apiKey, 'sk-or-saved');
  assert.equal(merged.provider, 'openrouter');

  // A fresh client key wins over the saved one
  const merged2 = mergeAiConfig(saved, { apiKey: 'sk-or-new' });
  assert.equal(merged2.apiKey, 'sk-or-new');

  // No saved config, empty client → null
  assert.equal(mergeAiConfig(null, { apiKey: '' }), null);
});
