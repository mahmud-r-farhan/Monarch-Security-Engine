import { postJson, getJson } from './http.js';
import { normalizeOllamaBaseUrl } from '../registry.js';

/**
 * Ollama — local / self-hosted provider.
 * Uses the native /api/chat endpoint with `format: 'json'` so the model is
 * constrained to emit a single JSON object (no response_format support needed).
 */
export const ollama = {
  id: 'ollama',

  async chat({ baseUrl, model, system, prompt, fetchImpl }) {
    const base = normalizeOllamaBaseUrl(baseUrl);
    const { json } = await postJson(`${base}/api/chat`, {
      body: {
        model,
        stream: false,
        format: 'json', // constrain output to a JSON object
        options: { temperature: 0.2, num_ctx: 8192 },
        messages: [{ role: 'system', content: system }, { role: 'user', content: prompt }],
      },
      fetchImpl,
    });
    return json.message?.content || '';
  },

  /** List models installed on the Ollama server (used by the health check). */
  async listModels({ baseUrl, fetchImpl }) {
    const base = normalizeOllamaBaseUrl(baseUrl);
    const json = await getJson(`${base}/api/tags`, { fetchImpl });
    return Array.isArray(json?.models) ? json.models : [];
  },
};
