/**
 * AI provider registry — ids, defaults, environment detection and URL helpers.
 * Provider *clients* live in ./providers/*; this module is pure metadata/logic.
 */

export const DEFAULT_MODEL = {
  // A fast, non-reasoning, JSON-mode-capable model. Reasoning models
  // (DeepSeek-R1 distills etc.) regularly exceed request timeouts while
  // emitting chain-of-thought — they are poor defaults for one-shot JSON.
  openrouter: 'openai/gpt-4o-mini',
  openai: 'gpt-4o-mini',
  anthropic: 'claude-3-5-haiku-latest',
  gemini: 'gemini-1.5-flash',
  ollama: 'llama3.2',
  none: 'monarch-rules-v1',
};

/** Valid provider ids — shared by server config endpoint and callers. */
export const PROVIDERS = ['openrouter', 'openai', 'anthropic', 'gemini', 'ollama', 'none'];

/**
 * Which env vars configure each provider.
 * `model` is optional per provider (falls back to AI_MODEL, then DEFAULT_MODEL).
 */
export const PROVIDER_ENV = {
  openrouter: { key: 'OPENROUTER_API_KEY', model: 'OPENROUTER_MODEL' },
  openai: { key: 'OPENAI_API_KEY', model: 'OPENAI_MODEL' },
  anthropic: { key: 'ANTHROPIC_API_KEY', model: 'ANTHROPIC_MODEL' },
  gemini: { key: 'GEMINI_API_KEY', model: 'GEMINI_MODEL' },
  ollama: { url: 'OLLAMA_BASE_URL', altUrl: 'OLLAMA_HOST', model: 'OLLAMA_MODEL' },
};

/** Curated, known-good model suggestions per provider (UI datalist). */
export const SUGGESTED_MODELS = {
  openrouter: [
    'openai/gpt-4o-mini',
    'openai/gpt-4.1-mini',
    'google/gemini-2.0-flash-001',
    'anthropic/claude-3.5-haiku',
    'meta-llama/llama-3.3-70b-instruct',
    'meta-llama/llama-3.3-70b-instruct:free',
    'deepseek/deepseek-chat-v3-0324:free',
    'mistralai/mistral-nemo:free',
  ],
  openai: ['gpt-4o-mini', 'gpt-4.1-mini', 'gpt-4o', 'gpt-4.1', 'o4-mini'],
  anthropic: ['claude-3-5-haiku-latest', 'claude-3-5-sonnet-latest', 'claude-sonnet-4-20250514', 'claude-opus-4-20250514'],
  gemini: ['gemini-1.5-flash', 'gemini-1.5-pro', 'gemini-2.0-flash', 'gemini-2.5-flash'],
  ollama: ['llama3.2', 'llama3.1', 'qwen2.5:7b', 'mistral', 'phi3.5'],
  none: ['monarch-rules-v1'],
};

/** UI display metadata for the config endpoint / modal. */
export const PROVIDER_INFO = [
  { id: 'openrouter', name: 'OpenRouter (Default / Multi-Model)', defaultModel: DEFAULT_MODEL.openrouter, models: SUGGESTED_MODELS.openrouter },
  { id: 'openai', name: 'OpenAI (GPT-4o, GPT-4o-mini)', defaultModel: DEFAULT_MODEL.openai, models: SUGGESTED_MODELS.openai },
  { id: 'anthropic', name: 'Anthropic (Claude 3.5 Sonnet / Haiku)', defaultModel: DEFAULT_MODEL.anthropic, models: SUGGESTED_MODELS.anthropic },
  { id: 'gemini', name: 'Google Gemini (Gemini 1.5 Flash)', defaultModel: DEFAULT_MODEL.gemini, models: SUGGESTED_MODELS.gemini },
  { id: 'ollama', name: 'Ollama (Local / Self-hosted)', defaultModel: DEFAULT_MODEL.ollama, models: SUGGESTED_MODELS.ollama },
  { id: 'none', name: 'Deterministic Heuristic (Offline / No Key)', defaultModel: DEFAULT_MODEL.none, models: SUGGESTED_MODELS.none },
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
 * Returns { provider, model, apiKey, baseUrl, timeoutMs }.
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
    if (aiConfig.timeoutMs) effective.AI_TIMEOUT_MS = String(aiConfig.timeoutMs);
  }

  const provider = detectProvider(effective);
  const model = effective.AI_MODEL
    || effective[PROVIDER_ENV[provider]?.model || '']
    || DEFAULT_MODEL[provider]
    || '';
  const apiKey = provider === 'none' ? '' : effective[PROVIDER_ENV[provider]?.key || ''] || effective.AI_API_KEY || '';
  const baseUrl = provider === 'ollama'
    ? normalizeOllamaBaseUrl(effective.OLLAMA_BASE_URL || effective.OLLAMA_HOST || '')
    : null;

  const timeoutMs = clampTimeoutMs(effective.AI_TIMEOUT_MS);

  return { provider, model, apiKey, baseUrl, timeoutMs };
}

/** 30s … 10min; invalid values fall back to 120s. */
export function clampTimeoutMs(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return 120_000;
  return Math.min(600_000, Math.max(30_000, Math.round(n)));
}
