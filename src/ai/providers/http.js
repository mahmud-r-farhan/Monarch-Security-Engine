/**
 * Shared HTTP helpers for AI provider clients.
 * All providers use plain fetch (no SDKs) with a uniform timeout, bounded
 * retries for transient failures, and a consistent error shape.
 *
 * Notes on the abort path: Node's fetch rejects with `AbortError: This
 * operation was aborted` when the timeout AbortController fires. That message
 * is opaque to users, so it is translated into an explicit, actionable
 * timeout error (AI_TIMEOUT) before it escapes this module.
 */

export const AI_TIMEOUT_MS = clampTimeout(
  Number(process.env.AI_TIMEOUT_MS || 120_000) || 120_000
);

/** Hard bounds for any AI request timeout (30s … 10min). */
export function clampTimeout(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return 120_000;
  return Math.min(600_000, Math.max(30_000, Math.round(n)));
}

/**
 * JSON POST with timeout + bounded retries.
 * Retries (with exponential backoff) only transient failures:
 * timeouts, HTTP 408/429/5xx, and network-level errors. 4xx client errors
 * (bad key, bad model, bad request) fail fast — retrying cannot fix them.
 * Honors the `Retry-After` header on 429 responses.
 */
export async function postJson(url, {
  headers = {},
  body,
  timeoutMs = AI_TIMEOUT_MS,
  fetchImpl = fetch,
  retries = 0,
  onRetry = null,
  retryDelayMs = null,
} = {}) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (attempt > 0) {
      const delay = retryDelayMs ?? backoffDelayMs(attempt, lastErr);
      if (onRetry) onRetry(attempt, lastErr, delay);
      await sleep(delay);
    }
    try {
      return await postJsonOnce(url, { headers, body, timeoutMs, fetchImpl });
    } catch (err) {
      lastErr = err;
      if (!isTransientAiError(err) || attempt === retries) throw err;
    }
  }
  throw lastErr; // unreachable — kept for exhaustiveness
}

async function postJsonOnce(url, { headers, body, timeoutMs, fetchImpl }) {
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
  } catch (err) {
    throw translateAbort(err, timeoutMs);
  } finally {
    clearTimeout(timer);
  }
}

/** GET with timeout, parsed JSON, strict ok-check. */
export async function getJson(url, { headers = {}, timeoutMs = 8000, fetchImpl = fetch } = {}) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { method: 'GET', signal: ac.signal, headers });
    return await parseOk(res, url);
  } catch (err) {
    throw translateAbort(err, timeoutMs);
  } finally {
    clearTimeout(timer);
  }
}

async function parseOk(res, url) {
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw await aiHttpError(res, url, text);
  }
  return res.json();
}

/** Build the richest error we can from a provider error response. */
async function aiHttpError(res, url, text) {
  const status = res.status;
  // Retry-After (seconds or HTTP-date) is surfaced for the backoff planner.
  const retryAfter = Number(res.headers?.get?.('retry-after'));
  let detail = truncate(text, 300);
  try {
    const j = JSON.parse(text);
    const msg = j?.error?.message || j?.error?.metadata?.raw || j?.message;
    if (msg) detail = truncate(String(msg), 300);
  } catch { /* plain text body */ }
  const err = new Error(`HTTP ${status} from ${hostOf(url)}: ${detail}`);
  err.status = status;
  if (Number.isFinite(retryAfter) && retryAfter > 0) err.retryAfterMs = Math.min(retryAfter * 1000, 30_000);
  return err;
}

/**
 * Translate a bare AbortError into an explicit, actionable timeout error.
 * AbortSignal triggered by the timeout fires `AbortError: This operation was
 * aborted` (Node ≥18) — the exact string users reported seeing.
 */
export function translateAbort(err, timeoutMs) {
  if (err && (err.name === 'AbortError' || err.code === 'ABORT_ERR' || /this operation was aborted/i.test(String(err.message || '')))) {
    const e = new Error(`AI request timed out after ${Math.round((timeoutMs || 0) / 1000)}s — the model did not respond in time`);
    e.code = 'AI_TIMEOUT';
    e.cause = err;
    return e;
  }
  return err;
}

/** Errors worth retrying: timeouts, 408/429/5xx, network hiccups. */
export function isTransientAiError(err) {
  if (!err) return false;
  if (err.code === 'AI_TIMEOUT') return true;
  if (err.status === 408 || err.status === 429 || (err.status >= 500 && err.status <= 599)) return true;
  if (/fetch failed|network|ECONNRESET|ECONNREFUSED|ENOTFOUND|ETIMEDOUT|EAI_AGAIN|socket hang up|terminated/i.test(String(err.message || err.cause?.message || ''))) return true;
  return false;
}

/** Exponential backoff with a cap; a provider-supplied Retry-After wins. */
function backoffDelayMs(attempt, err) {
  if (err?.retryAfterMs) return err.retryAfterMs;
  return Math.min(1000 * 2 ** (attempt - 1), 8000);
}

/** Standard chat message shape used by OpenAI-compatible providers. */
export function chatBody({ model, system, prompt, temperature = 0.2, jsonMode = true, maxTokens = 3000, extra = {} }) {
  return {
    model,
    temperature,
    ...(jsonMode ? { response_format: { type: 'json_object' } } : {}),
    ...(maxTokens ? { max_tokens: maxTokens } : {}),
    messages: [{ role: 'system', content: system }, { role: 'user', content: prompt }],
    ...extra,
  };
}

function hostOf(u) { try { return new URL(u).host; } catch { return u; } }
function truncate(s, n) { s = String(s ?? ''); return s.length > n ? s.slice(0, n) + '…' : s; }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
