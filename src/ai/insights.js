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
    });
    const parsed = parseModelJson(text);
    if (!parsed) throw new Error('Model returned non-JSON output');
    return { provider: cfg.provider, model: cfg.model, ...parsed };
  } catch (err) {
    const fallback = heuristicInsights(scan);
    return {
      provider: 'heuristic',
      model: 'monarch-rules-v1',
      warning: `AI provider "${cfg.provider}" failed: ${err.message}. Showing rules-based analysis.`,
      ...fallback,
    };
  }
}
