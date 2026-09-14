/**
 * NetworkLog — DevTools-style capture of every request/response the engine observes.
 * Each entry mirrors the shape of a Chrome Network panel row so the dashboard can render
 * it 1:1 and the checks/AI layer can reason over the full lifecycle.
 */
export class NetworkLog {
  constructor() {
    this.entries = [];
    this._seq = 0;
    this._listeners = new Set();
  }

  /** Subscribe to new entries (used for SSE streaming). Returns an unsubscribe fn. */
  onEntry(fn) {
    this._listeners.add(fn);
    return () => this._listeners.delete(fn);
  }

  start({ url, method = 'GET', headers = {}, initiator = 'crawler', type = 'document' }) {
    const entry = {
      id: ++this._seq,
      url,
      method,
      type,
      initiator,
      startedAt: Date.now(),
      request: { headers: normalizeHeaders(headers) },
      response: null,
      timing: { total: null, ttfb: null },
      size: null,
      status: null,
      statusText: null,
      mimeType: null,
      error: null,
      redirectedFrom: null,
    };
    this.entries.push(entry);
    return entry;
  }

  finish(entry, { status, statusText, headers, body, redirectedFrom = null, ttfb = null }) {
    entry.status = status;
    entry.statusText = statusText || '';
    const bodyStr = typeof body === 'string' ? body : (Buffer.isBuffer(body) ? body.toString('utf8') : (body ? String(body) : null));
    entry.response = {
      headers: normalizeHeaders(headers),
      body: bodyStr ? (bodyStr.length > 500000 ? bodyStr.slice(0, 500000) : bodyStr) : null,
    };
    entry.mimeType = (entry.response.headers['content-type'] || '').split(';')[0].trim() || null;
    entry.size = body ? Buffer.byteLength(body) : 0;
    entry.timing.total = Date.now() - entry.startedAt;
    entry.timing.ttfb = ttfb;
    entry.redirectedFrom = redirectedFrom;
    this._emit(entry);
    return entry;
  }

  fail(entry, err) {
    entry.error = err?.message || String(err);
    entry.timing.total = Date.now() - entry.startedAt;
    this._emit(entry);
    return entry;
  }

  _emit(entry) {
    for (const fn of this._listeners) {
      try { fn(entry); } catch { /* listener errors never break the scan */ }
    }
  }

  toJSON() {
    return this.entries;
  }

  summary() {
    const byStatus = {};
    const byType = {};
    let bytes = 0;
    for (const e of this.entries) {
      const bucket = e.error ? 'failed' : `${Math.floor((e.status || 0) / 100)}xx`;
      byStatus[bucket] = (byStatus[bucket] || 0) + 1;
      byType[e.type] = (byType[e.type] || 0) + 1;
      bytes += e.size || 0;
    }
    return { requests: this.entries.length, bytes, byStatus, byType };
  }
}

export function normalizeHeaders(headers) {
  const out = {};
  if (!headers) return out;
  if (typeof headers.forEach === 'function' && !Array.isArray(headers)) {
    headers.forEach((v, k) => { out[k.toLowerCase()] = v; });
    return out;
  }
  for (const [k, v] of Object.entries(headers)) {
    out[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
  }
  return out;
}
