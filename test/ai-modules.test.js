import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateInsights, heuristicInsights, detectProvider, parseModelJson, normalizeOllamaBaseUrl } from '../src/ai/insights.js';
import { resolveProviderConfig, DEFAULT_MODEL, PROVIDERS, PROVIDER_INFO } from '../src/ai/registry.js';
import { checkProvider, checkAllProviders, resetAiHealthCache } from '../src/ai/health.js';
import { providers } from '../src/ai/providers/index.js';
import { buildPrompt, SYSTEM } from '../src/ai/prompt.js';

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
  assert.equal(all.providers.length, 6);
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
