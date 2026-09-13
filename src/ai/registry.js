/**
 * AI provider registry — ids, defaults, environment detection and URL helpers.
 * Provider *clients* live in ./providers/*; this module is pure metadata/logic.
 */

export const DEFAULT_MODEL = {
  openrouter: 'deepseek/deepseek-r1-distill-qwen-7b',
  openai: 'gpt-4o-mini',
  anthropic: 'claude-3-5-haiku-latest',
  gemini: 'gemini-1.5-flash',
  ollama: 'llama3.2',
  none: 'monarch-rules-v1',
};

/** Valid provider ids — shared by server config endpoint and callers. */
export const PROVIDERS = ['openrouter', 'openai', 'anthropic', 'gemini', 'ollama', 'none'];

/**
 * Which env vars configure each provider (used by detection and the health check).
 */
export const PROVIDER_ENV = {
  openrouter: { key: 'OPENROUTER_API_KEY' },
  openai: { key: 'OPENAI_API_KEY' },
  anthropic: { key: 'ANTHROPIC_API_KEY' },
  gemini: { key: 'GEMINI_API_KEY' },
  ollama: { url: 'OLLAMA_BASE_URL', altUrl: 'OLLAMA_HOST', model: 'OLLAMA_MODEL' },
};

/** UI display metadata for the config endpoint / modal. */
export const PROVIDER_INFO = [
  { id: 'openrouter', name: 'OpenRouter (Default / Multi-Model)', defaultModel: DEFAULT_MODEL.openrouter },
  { id: 'openai', name: 'OpenAI (GPT-4o, GPT-4o-mini)', defaultModel: DEFAULT_MODEL.openai },
  { id: 'anthropic', name: 'Anthropic (Claude 3.5 Sonnet / Haiku)', defaultModel: DEFAULT_MODEL.anthropic },
  { id: 'gemini', name: 'Google Gemini (Gemini 1.5 Flash)', defaultModel: DEFAULT_MODEL.gemini },
  { id: 'ollama', name: 'Ollama (Local / Self-hosted)', defaultModel: DEFAULT_MODEL.ollama },
  { id: 'none', name: 'Deterministic Heuristic (Offline / No Key)', defaultModel: DEFAULT_MODEL.none },
];

/**
 * Pick the active provider from env:
 * 1. explicit AI_PROVIDER wins (except 'auto'),
 * 2. else the first configured cloud key,
 * 3. else Ollama if a base URL is set,
 * 4. else the offline heuristic.
 */
export function detectProvider(env = process.env) {
  const forced = (env.AI_PROVIDER || '').toLowerCase();
  if (forced && forced !== 'auto') return forced;
  if (env.OPENROUTER_API_KEY) return 'openrouter';
  if (env.ANTHROPIC_API_KEY) return 'anthropic';
  if (env.OPENAI_API_KEY) return 'openai';
  if (env.GEMINI_API_KEY) return 'gemini';
  if (env.OLLAMA_BASE_URL || env.OLLAMA_HOST) return 'ollama';
  return 'none';
}

/**
 * Normalize an Ollama base URL from user/env input.
 * Accepts: http://localhost:11434, localhost:11434, 127.0.0.1:11434, ollama.mynet:11434/api
 * Only http/https schemes are allowed; /api and /v1 suffixes are stripped.
 */
export function normalizeOllamaBaseUrl(input) {
  let raw = String(input || '').trim();
  if (!raw) return 'http://localhost:11434';
  // If the user supplied an explicit scheme, respect it; otherwise default to http://
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
  let u;
  try {
    u = new URL(hasScheme ? raw : 'http://' + raw);
  } catch {
    throw new Error(`Invalid Ollama base URL: ${input}`);
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error(`Ollama base URL must use http:// or https:// — got: ${input}`);
  }
  if (!u.hostname) {
    throw new Error(`Ollama base URL is missing a hostname: ${input}`);
  }
  u.pathname = u.pathname.replace(/\/(api|v1)\/?$/i, '');
  u.search = '';
  u.hash = '';
  return u.origin + (u.pathname === '/' ? '' : u.pathname.replace(/\/$/, ''));
}

/**
 * Resolve the effective provider config from env + optional runtime override.
 * Returns { provider, model, apiKey, baseUrl }.
 */
export function resolveProviderConfig(aiConfig = null, env = process.env) {
  const effective = { ...env };
  if (aiConfig) {
    if (aiConfig.provider && aiConfig.provider !== 'auto') effective.AI_PROVIDER = aiConfig.provider;
    if (aiConfig.apiKey) {
      effective.AI_API_KEY = aiConfig.apiKey;
      const p = effective.AI_PROVIDER || 'openrouter';
      const keyVar = PROVIDER_ENV[p]?.key;
      if (keyVar) effective[keyVar] = aiConfig.apiKey;
    }
    if (aiConfig.model) effective.AI_MODEL = aiConfig.model;
    if (aiConfig.baseUrl) effective.OLLAMA_BASE_URL = aiConfig.baseUrl;
  }

  const provider = detectProvider(effective);
  const model = effective.AI_MODEL || effective[PROVIDER_ENV[provider]?.model || ''] || DEFAULT_MODEL[provider] || '';
  const apiKey = provider === 'none' ? '' : effective[PROVIDER_ENV[provider]?.key || ''] || effective.AI_API_KEY || '';
  const baseUrl = provider === 'ollama'
    ? normalizeOllamaBaseUrl(effective.OLLAMA_BASE_URL || effective.OLLAMA_HOST || '')
    : null;

  return { provider, model, apiKey, baseUrl };
}
