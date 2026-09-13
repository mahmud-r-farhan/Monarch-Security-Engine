import { postJson, chatBody } from './http.js';

/**
 * OpenAI-compatible chat-completions client.
 * Shared by the `openai` provider and `openrouter` (which is OpenAI-wire-compatible
 * but adds attribution headers and its own base URL).
 *
 * Robustness:
 * - Bounded transient retries (timeouts, 429, 5xx) happen inside postJson.
 * - If the model/endpoint rejects `response_format: json_object` (not all
 *   OpenRouter models support it), the call is retried once without it — the
 *   prompt already demands strict JSON and parse.js tolerates prose/fences.
 */

const RESPONSE_FORMAT_ERR = /response_format|json_object|json mode|structured output|unsupported parameter|not supported/i;

export async function openAiChat({
  baseUrl, apiKey, model, system, prompt,
  extraHeaders = {}, fetchImpl, timeoutMs, maxTokens = 3000, retries = 2,
}) {
  const call = async (jsonMode) => {
    const { json } = await postJson(`${baseUrl}/chat/completions`, {
      headers: { authorization: `Bearer ${apiKey}`, ...extraHeaders },
      body: chatBody({ model, system, prompt, jsonMode, maxTokens }),
      fetchImpl,
      timeoutMs,
      retries: jsonMode ? retries : 0, // fallback attempt: single shot
    });
    return json.choices?.[0]?.message?.content || '';
  };

  try {
    return await call(true);
  } catch (err) {
    // Some models (e.g. certain reasoning / free-tier models) reject JSON mode.
    if (RESPONSE_FORMAT_ERR.test(String(err?.message || ''))) return call(false);
    throw err;
  }
}

/** List models from an OpenAI-compatible endpoint (used by health checks). */
export async function openAiListModels({ baseUrl, apiKey, extraHeaders = {}, fetchImpl, timeoutMs = 8000 }) {
  const { res, json } = await (async () => {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const res = await fetch(`${baseUrl}/models`, {
        headers: { authorization: `Bearer ${apiKey}`, ...extraHeaders },
        signal: ac.signal,
      });
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        const err = new Error(`HTTP ${res.status}${text ? `: ${String(text).slice(0, 200)}` : ''}`);
        err.status = res.status;
        throw err;
      }
      return { res, json: await res.json() };
    } finally {
      clearTimeout(timer);
    }
  })();
  return json;
}
