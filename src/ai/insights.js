/**
 * AI Insights — slim facade.
 *
 * The heavy lifting lives in focused modules:
 *   registry.js   provider ids, defaults, env detection, URL normalization
 *   prompt.js     system prompt + scan→prompt builder
 *   parse.js      tolerant JSON parsing of model output
 *   heuristic.js  offline rule-based analyst (fallback)
 *   providers/*   one HTTP client per provider
 *   health.js     provider reachability/health probes
 *
 * This file keeps the historical import surface stable (`ai/insights.js`) for
 * server.js, the programmatic API (index.js), tests and docs.
 */

import { providers } from './providers/index.js';
import { resolveProviderConfig, detectProvider, DEFAULT_MODEL } from './registry.js';
import { SYSTEM, buildPrompt } from './prompt.js';
import { parseModelJson } from './parse.js';
import { heuristicInsights } from './heuristic.js';

export { detectProvider, DEFAULT_MODEL, PROVIDERS, normalizeOllamaBaseUrl } from './registry.js';
export { heuristicInsights } from './heuristic.js';
export { parseModelJson } from './parse.js';

/**
 * Generate insights for a scan report.
 * Order of operations: resolve provider → build prompt → call provider →
 * parse strictly → fall back to the heuristic analyst on any failure.
 * The fallback carries a `warning` (what failed) and a `hint` (what to try)
 * so UIs can explain the degradation instead of surfacing a raw stack message.
 */
export async function generateInsights(scan, { env = process.env, fetchImpl = fetch, aiConfig = null } = {}) {
  const cfg = resolveProviderConfig(aiConfig, env);
  const prompt = buildPrompt(scan);

  if (cfg.provider === 'none') {
    return { provider: 'heuristic', model: 'monarch-rules-v1', ...heuristicInsights(scan) };
  }

  try {
    const client = providers[cfg.provider];
    if (!client) throw new Error(`Unknown AI provider "${cfg.provider}"`);

    const text = await client.chat({
      apiKey: cfg.apiKey,
      baseUrl: cfg.baseUrl,
      model: cfg.model,
      system: SYSTEM,
      prompt,
      fetchImpl,
      timeoutMs: cfg.timeoutMs,
    });
    const parsed = parseModelJson(text);
    if (!parsed) throw new Error('Model returned non-JSON output');
    return { provider: cfg.provider, model: cfg.model, ...parsed };
  } catch (err) {
    const fallback = heuristicInsights(scan);
    return {
      provider: 'heuristic',
      model: 'monarch-rules-v1',
      warning: `AI provider "${cfg.provider}" failed: ${explain(err, cfg)}. Showing rules-based analysis.`,
      hint: hintFor(err, cfg),
      ...fallback,
    };
  }
}

/** Replace opaque transport errors (e.g. Node's "This operation was aborted") with human wording. */
function explain(err, cfg) {
  const msg = String(err?.message || err);
  if (err?.code === 'AI_TIMEOUT' || /this operation was aborted/i.test(msg)) {
    return `request timed out after ${Math.round((cfg.timeoutMs || 120_000) / 1000)}s`;
  }
  return msg;
}

/** Actionable next step for the most common failure modes. */
function hintFor(err, cfg) {
  const msg = String(err?.message || err);
  if (err?.code === 'AI_TIMEOUT' || /this operation was aborted|timed out/i.test(msg)) {
    return `The model "${cfg.model}" was too slow. Reasoning models (deepseek-r1-*, o1, …) emit long chain-of-thought and often miss deadlines — switch to a fast model (e.g. ${cfg.provider === 'openrouter' ? 'openai/gpt-4o-mini on OpenRouter' : 'a non-reasoning model'}) or raise AI_TIMEOUT_MS.`;
  }
  if (/HTTP 401|HTTP 403|No auth credentials/i.test(msg)) return 'The API key was rejected — re-check it in AI Provider Configuration (a page refresh clears session-stored keys).';
  if (/HTTP 402|insufficient|credits/i.test(msg)) return 'Out of credits — top up the provider account or switch to a :free model.';
  if (/HTTP 404|No endpoints found/i.test(msg)) return `Model "${cfg.model}" was not found — verify the exact id in AI Provider Configuration.`;
  if (/HTTP 429/i.test(msg)) return 'Rate limited — wait a moment or switch model/provider. Free tiers are limited to ~20 requests/min.';
  if (/fetch failed|ENOTFOUND|ECONNREFUSED|network/i.test(msg)) return 'Monarch could not reach the provider endpoint — check the network/proxy, or run the Test Connection probe in AI Provider Configuration.';
  if (/non-JSON/i.test(msg)) return 'The model ignored the JSON contract — pick a stronger instruction-following model.';
  return null;
}
