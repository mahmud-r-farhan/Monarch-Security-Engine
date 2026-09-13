import { postJson, chatBody } from './http.js';

/**
 * OpenAI-compatible chat-completions client.
 * Shared by the `openai` provider and `openrouter` (which is OpenAI-wire-compatible
 * but adds attribution headers and its own base URL).
 */

export async function openAiChat({ baseUrl, apiKey, model, system, prompt, extraHeaders = {}, fetchImpl }) {
  const { json } = await postJson(`${baseUrl}/chat/completions`, {
    headers: { authorization: `Bearer ${apiKey}`, ...extraHeaders },
    body: chatBody({ model, system, prompt }),
    fetchImpl,
  });
  return json.choices?.[0]?.message?.content || '';
}

/** List models from an OpenAI-compatible endpoint (used by health checks). */
export async function openAiListModels({ baseUrl, apiKey, extraHeaders = {}, fetchImpl }) {
  const res = await fetch(`${baseUrl}/models`, { headers: { authorization: `Bearer ${apiKey}`, ...extraHeaders } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
