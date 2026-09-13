import { openrouter } from './openrouter.js';
import { openaiCompatible } from './openaiCompatibleProvider.js';
import { openai } from './openai.js';
import { anthropic } from './anthropic.js';
import { gemini } from './gemini.js';
import { ollama } from './ollama.js';

/**
 * Provider registry — the single place that maps a provider id to its client.
 * Each client implements:
 *   chat({ apiKey?, baseUrl?, model, system, prompt, fetchImpl }) -> Promise<string>
 * and optionally:
 *   listModels({...}) -> Promise<any[]>   (used by the health check)
 */
export const providers = {
  openrouter,
  'openai-compatible': openaiCompatible,
  openai,
  anthropic,
  gemini,
  ollama,
};
