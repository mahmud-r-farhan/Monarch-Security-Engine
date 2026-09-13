/**
 * Shared HTTP helpers for AI provider clients.
 * All providers use plain fetch (no SDKs) with a uniform timeout + error shape.
 */

export const AI_TIMEOUT_MS = Number(process.env.AI_TIMEOUT_MS || 60_000);

/** JSON POST with timeout. Returns parsed JSON or throws an Error with provider context. */
export async function postJson(url, { headers = {}, body, timeoutMs = AI_TIMEOUT_MS, fetchImpl = fetch } = {}) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      method: 'POST',
      signal: ac.signal,
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
    });
    return { res, json: await parseOk(res, url) };
  } finally {
    clearTimeout(timer);
  }
}

/** GET with timeout, parsed JSON, strict ok-check. */
export async function getJson(url, { headers = {}, timeoutMs = AI_TIMEOUT_MS, fetchImpl = fetch } = {}) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { method: 'GET', signal: ac.signal, headers });
    return await parseOk(res, url);
  } finally {
    clearTimeout(timer);
  }
}

async function parseOk(res, url) {
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status} from ${hostOf(url)}: ${truncate(text, 200)}`);
  }
  return res.json();
}

/** Standard chat message shape used by OpenAI-compatible providers. */
export function chatBody({ model, system, prompt, temperature = 0.2, jsonMode = true, extra = {} }) {
  return {
    model,
    temperature,
    ...(jsonMode ? { response_format: { type: 'json_object' } } : {}),
    messages: [{ role: 'system', content: system }, { role: 'user', content: prompt }],
    ...extra,
  };
}

function hostOf(u) { try { return new URL(u).host; } catch { return u; } }
function truncate(s, n) { s = String(s ?? ''); return s.length > n ? s.slice(0, n) + '…' : s; }
