import * as cheerio from 'cheerio';
import { assertTargetAllowed } from './safety.js';

export const USER_AGENT = 'MonarchSecurityEngine/0.1 (+https://github.com/mahmud-r-farhan/Monarch-Security-Engine; authorized-audit)';

const PROBE_PATHS = [
  { path: '/robots.txt', kind: 'info' },
  { path: '/sitemap.xml', kind: 'info' },
  { path: '/.well-known/security.txt', kind: 'info' },
  { path: '/.env', kind: 'sensitive' },
  { path: '/.git/HEAD', kind: 'sensitive' },
  { path: '/.git/config', kind: 'sensitive' },
  { path: '/server-status', kind: 'sensitive' },
  { path: '/phpinfo.php', kind: 'sensitive' },
  { path: '/.DS_Store', kind: 'sensitive' },
  { path: '/backup.zip', kind: 'sensitive' },
  { path: '/config.json', kind: 'sensitive' },
  { path: '/swagger.json', kind: 'info' },
  { path: '/openapi.json', kind: 'info' },
  { path: '/api', kind: 'info' },
  { path: '/admin', kind: 'info' },
  { path: '/graphql', kind: 'info' },
];

/**
 * Crawl a target and populate the network log + page inventory.
 */
export async function crawl(target, { log, maxPages = 25, timeoutMs = 10000, engine = 'fetch', onProgress = () => {} }) {
  const origin = new URL(target).origin;
  await assertTargetAllowed(target);

  if (engine === 'playwright') {
    const pw = await tryPlaywright();
    if (pw) {
      try {
        return await crawlWithPlaywright(pw, target, { log, maxPages, timeoutMs, onProgress, origin });
      } catch (err) {
        onProgress({ stage: 'crawl', level: 'warn', message: `Playwright engine failed (${err.message}) — falling back to fetch engine` });
      }
    } else {
      onProgress({ stage: 'crawl', level: 'warn', message: 'Playwright/Chromium not installed — falling back to fetch engine' });
    }
  }
  return crawlWithFetch(target, { log, maxPages, timeoutMs, onProgress, origin });
}

/* ------------------------------------------------------------------ */
/* fetch engine (default — zero native deps)                           */
/* ------------------------------------------------------------------ */
async function crawlWithFetch(target, { log, maxPages, timeoutMs, onProgress, origin }) {
  const queue = [target];
  const seen = new Set([normalize(target)]);
  const pages = [];
  const assets = new Map();
  const forms = [];
  const cookies = new Map();
  const inlineScripts = [];
  const externalOrigins = new Set();

  while (queue.length && pages.length < maxPages) {
    const url = queue.shift();
    onProgress({ stage: 'crawl', message: `Fetching ${url}`, pages: pages.length });
    const res = await fetchLogged(url, { log, timeoutMs, type: 'document' });
    if (!res) continue;

    collectCookies(res.headers, url, cookies);
    const page = {
      url,
      finalUrl: res.finalUrl,
      status: res.status,
      headers: res.headers,
      contentType: res.headers['content-type'] || '',
      title: null,
      links: [],
      scripts: [],
      mixedContent: [],
      redirectChain: res.redirectChain,
      hasInlineEventHandlers: false,
      metaCsp: null,
    };

    if (/text\/html/i.test(page.contentType) && res.body) {
      const $ = cheerio.load(res.body);
      page.title = $('title').first().text().trim() || null;
      page.metaCsp = $('meta[http-equiv="Content-Security-Policy"]').attr('content') || null;
      page.hasInlineEventHandlers = /\son(click|load|error|mouseover|submit)\s*=/i.test(res.body);

      $('a[href]').each((_, el) => {
        const abs = absolutize($(el).attr('href'), res.finalUrl);
        if (!abs) return;
        page.links.push(abs);
        if (abs.startsWith(origin) && !seen.has(normalize(abs)) && isCrawlable(abs)) {
          seen.add(normalize(abs));
          queue.push(abs);
        }
      });

      $('script').each((_, el) => {
        const src = $(el).attr('src');
        if (src) {
          const abs = absolutize(src, res.finalUrl);
          if (!abs) return;
          page.scripts.push(abs);
          if (!assets.has(abs)) assets.set(abs, { url: abs, type: 'script', integrity: $(el).attr('integrity') || null, crossorigin: $(el).attr('crossorigin') || null, foundOn: url });
          if (!abs.startsWith(origin)) externalOrigins.add(new URL(abs).origin);
          if (abs.startsWith('http://') && res.finalUrl.startsWith('https://')) page.mixedContent.push(abs);
        } else {
          const code = $(el).html() || '';
          if (code.trim()) inlineScripts.push({ page: url, code: code.slice(0, 20000) });
        }
      });

      $('link[rel="stylesheet"][href], img[src], iframe[src]').each((_, el) => {
        const raw = $(el).attr('href') || $(el).attr('src');
        const abs = absolutize(raw, res.finalUrl);
        if (!abs) return;
        const tag = el.tagName.toLowerCase();
        const type = tag === 'link' ? 'stylesheet' : tag === 'img' ? 'image' : 'iframe';
        if (!assets.has(abs)) assets.set(abs, { url: abs, type, integrity: $(el).attr('integrity') || null, crossorigin: null, foundOn: url });
        if (!abs.startsWith(origin)) externalOrigins.add(new URL(abs).origin);
        if (abs.startsWith('http://') && res.finalUrl.startsWith('https://')) page.mixedContent.push(abs);
      });

      $('form').each((_, el) => {
        const action = absolutize($(el).attr('action') || res.finalUrl, res.finalUrl);
        const inputs = [];
        $(el).find('input, textarea, select').each((_, inp) => {
          inputs.push({ name: $(inp).attr('name') || null, type: ($(inp).attr('type') || 'text').toLowerCase(), autocomplete: $(inp).attr('autocomplete') || null });
        });
        forms.push({
          page: url,
          action,
          method: ($(el).attr('method') || 'GET').toUpperCase(),
          inputs,
          hasCsrfToken: inputs.some(i => /csrf|xsrf|_token|authenticity/i.test(i.name || '')),
          hasPassword: inputs.some(i => i.type === 'password'),
        });
      });
    }
    pages.push(page);
  }

  // Fetch a bounded set of scripts so JWT/secret/storage heuristics can inspect them.
  const scriptAssets = [...assets.values()].filter(a => a.type === 'script').slice(0, 15);
  const scriptBodies = [];
  for (const a of scriptAssets) {
    onProgress({ stage: 'assets', message: `Fetching asset ${a.url}` });
    const res = await fetchLogged(a.url, { log, timeoutMs, type: 'script' });
    if (res?.body) scriptBodies.push({ url: a.url, code: res.body.slice(0, 200000), headers: res.headers });
    collectCookies(res?.headers, a.url, cookies);
  }

  // Well-known & sensitive-file probes.
  const probes = [];
  for (const p of PROBE_PATHS) {
    const url = origin + p.path;
    if (seen.has(normalize(url))) continue;
    onProgress({ stage: 'probe', message: `Probing ${p.path}` });
    const res = await fetchLogged(url, { log, timeoutMs, type: 'probe', method: 'GET', maxBody: 4096 });
    if (!res) continue;
    probes.push({ path: p.path, kind: p.kind, status: res.status, contentType: res.headers['content-type'] || '', snippet: (res.body || '').slice(0, 300), finalUrl: res.finalUrl });
  }

  // OPTIONS / CORS preflight probe against the root.
  const cors = await corsProbe(origin, { log, timeoutMs });

  return {
    engine: 'fetch',
    origin,
    pages,
    assets: [...assets.values()],
    forms,
    cookies: [...cookies.values()],
    inlineScripts,
    scriptBodies,
    externalOrigins: [...externalOrigins],
    probes,
    cors,
    storage: null, // only available with the browser engine
    consoleErrors: [],
  };
}

async function corsProbe(origin, { log, timeoutMs }) {
  const evil = 'https://evil.example';
  const res = await fetchLogged(origin + '/', {
    log, timeoutMs, type: 'cors-probe',
    headers: { Origin: evil, 'Access-Control-Request-Method': 'GET' },
    maxBody: 0,
  });
  if (!res) return null;
  return {
    requestedOrigin: evil,
    allowOrigin: res.headers['access-control-allow-origin'] || null,
    allowCredentials: res.headers['access-control-allow-credentials'] || null,
  };
}

export async function fetchLogged(url, { log, timeoutMs, type = 'document', method = 'GET', headers = {}, maxBody = 2_000_000 }) {
  const reqHeaders = { 'user-agent': USER_AGENT, accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8', ...headers };
  const redirectChain = [];
  let current = url;
  for (let hop = 0; hop < 6; hop++) {
    const entry = log.start({ url: current, method, headers: reqHeaders, type, initiator: hop ? 'redirect' : 'crawler' });
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const t0 = Date.now();
      const res = await fetch(current, { method, headers: reqHeaders, redirect: 'manual', signal: ac.signal });
      const ttfb = Date.now() - t0;
      let body = '';
      if (maxBody > 0) {
        const buf = Buffer.from(await res.arrayBuffer());
        body = buf.subarray(0, maxBody).toString('utf8');
        log.finish(entry, { status: res.status, statusText: res.statusText, headers: rawHeaders(res.headers), body: buf, ttfb, redirectedFrom: redirectChain.at(-1) || null });
      } else {
        await res.arrayBuffer().catch(() => {});
        log.finish(entry, { status: res.status, statusText: res.statusText, headers: rawHeaders(res.headers), body: null, ttfb, redirectedFrom: redirectChain.at(-1) || null });
      }
      const h = rawHeaders(res.headers);
      if ([301, 302, 303, 307, 308].includes(res.status) && h.location) {
        redirectChain.push(current);
        current = new URL(h.location, current).href;
        continue;
      }
      return { status: res.status, headers: h, body, finalUrl: current, redirectChain };
    } catch (err) {
      log.fail(entry, err.name === 'AbortError' ? new Error(`timeout after ${timeoutMs}ms`) : err);
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
  return null;
}

/** Preserve multiple Set-Cookie headers (undici exposes getSetCookie). */
function rawHeaders(h) {
  const out = {};
  h.forEach((v, k) => { out[k.toLowerCase()] = v; });
  if (typeof h.getSetCookie === 'function') {
    const sc = h.getSetCookie();
    if (sc.length) out['set-cookie'] = sc;
  }
  return out;
}

function collectCookies(headers, url, cookies) {
  if (!headers) return;
  const raw = headers['set-cookie'];
  if (!raw) return;
  const list = Array.isArray(raw) ? raw : [raw];
  for (const line of list) {
    const c = parseSetCookie(line, url);
    if (c) cookies.set(`${c.name}@${c.domain || new URL(url).hostname}`, c);
  }
}

export function parseSetCookie(line, setBy) {
  const parts = line.split(';').map(s => s.trim()).filter(Boolean);
  if (!parts.length) return null;
  const eq = parts[0].indexOf('=');
  if (eq < 0) return null;
  const c = { name: parts[0].slice(0, eq).trim(), value: parts[0].slice(eq + 1), secure: false, httpOnly: false, sameSite: null, domain: null, path: '/', expires: null, maxAge: null, setBy };
  for (const attr of parts.slice(1)) {
    const [k, ...v] = attr.split('=');
    const key = k.trim().toLowerCase();
    const val = v.join('=').trim();
    if (key === 'secure') c.secure = true;
    else if (key === 'httponly') c.httpOnly = true;
    else if (key === 'samesite') c.sameSite = val;
    else if (key === 'domain') c.domain = val;
    else if (key === 'path') c.path = val;
    else if (key === 'expires') c.expires = val;
    else if (key === 'max-age') c.maxAge = Number(val);
  }
  return c;
}

/* ------------------------------------------------------------------ */
/* Playwright engine (optional — real browser, full traffic + storage) */
/* ------------------------------------------------------------------ */
async function tryPlaywright() {
  try {
    const mod = await import('playwright');
    return mod.chromium;
  } catch {
    return null;
  }
}

async function crawlWithPlaywright(chromium, target, { log, maxPages, timeoutMs, onProgress, origin }) {
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  const context = await browser.newContext({ userAgent: USER_AGENT, ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const inflight = new Map();
  const consoleErrors = [];

  page.on('request', req => {
    const entry = log.start({ url: req.url(), method: req.method(), headers: req.headers(), type: req.resourceType(), initiator: 'browser' });
    inflight.set(req, entry);
  });
  page.on('response', async res => {
    const entry = inflight.get(res.request());
    if (!entry) return;
    let body = null;
    try { body = await res.body(); } catch { /* opaque / redirect */ }
    log.finish(entry, { status: res.status(), statusText: res.statusText(), headers: res.headers(), body });
  });
  page.on('requestfailed', req => { const e = inflight.get(req); if (e) log.fail(e, new Error(req.failure()?.errorText || 'failed')); });
  page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

  const queue = [target];
  const seen = new Set([normalize(target)]);
  const pages = [];
  const forms = [];
  const inlineScripts = [];
  const assets = new Map();
  let storage = { localStorage: {}, sessionStorage: {} };

  while (queue.length && pages.length < maxPages) {
    const url = queue.shift();
    onProgress({ stage: 'crawl', message: `Rendering ${url}`, pages: pages.length });
    let resp;
    try { resp = await page.goto(url, { waitUntil: 'networkidle', timeout: timeoutMs }); } catch (err) { onProgress({ stage: 'crawl', level: 'warn', message: `Failed ${url}: ${err.message}` }); continue; }
    const html = await page.content();
    const $ = cheerio.load(html);
    const info = await page.evaluate(() => ({
      links: [...document.querySelectorAll('a[href]')].map(a => a.href),
      scripts: [...document.querySelectorAll('script[src]')].map(s => ({ src: s.src, integrity: s.integrity || null, crossorigin: s.crossOrigin || null })),
      inline: [...document.querySelectorAll('script:not([src])')].map(s => s.textContent.slice(0, 20000)),
      forms: [...document.querySelectorAll('form')].map(f => ({
        action: f.action, method: (f.method || 'GET').toUpperCase(),
        inputs: [...f.querySelectorAll('input,textarea,select')].map(i => ({ name: i.name || null, type: (i.type || 'text').toLowerCase(), autocomplete: i.getAttribute('autocomplete') })),
      })),
      localStorage: Object.fromEntries(Object.keys(localStorage).map(k => [k, String(localStorage.getItem(k)).slice(0, 500)])),
      sessionStorage: Object.fromEntries(Object.keys(sessionStorage).map(k => [k, String(sessionStorage.getItem(k)).slice(0, 500)])),
    }));
    Object.assign(storage.localStorage, info.localStorage);
    Object.assign(storage.sessionStorage, info.sessionStorage);
    for (const s of info.scripts) if (!assets.has(s.src)) assets.set(s.src, { url: s.src, type: 'script', integrity: s.integrity, crossorigin: s.crossorigin, foundOn: url });
    info.inline.forEach(code => code.trim() && inlineScripts.push({ page: url, code }));
    info.forms.forEach(f => forms.push({ page: url, ...f, hasCsrfToken: f.inputs.some(i => /csrf|xsrf|_token|authenticity/i.test(i.name || '')), hasPassword: f.inputs.some(i => i.type === 'password') }));
    for (const l of info.links) if (l.startsWith(origin) && !seen.has(normalize(l)) && isCrawlable(l)) { seen.add(normalize(l)); queue.push(l); }

    pages.push({
      url, finalUrl: page.url(), status: resp?.status() ?? null, headers: resp ? await resp.allHeaders() : {},
      contentType: resp ? (await resp.allHeaders())['content-type'] || '' : '', title: await page.title(),
      links: info.links, scripts: info.scripts.map(s => s.src),
      mixedContent: page.url().startsWith('https://') ? [...info.scripts.map(s => s.src), ...info.links].filter(u => u.startsWith('http://')) : [],
      redirectChain: [], hasInlineEventHandlers: /\son(click|load|error|mouseover|submit)\s*=/i.test(html),
      metaCsp: $('meta[http-equiv="Content-Security-Policy"]').attr('content') || null,
    });
  }

  const cookies = (await context.cookies()).map(c => ({ name: c.name, value: c.value, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite, domain: c.domain, path: c.path, expires: c.expires > 0 ? new Date(c.expires * 1000).toUTCString() : null, maxAge: null, setBy: origin }));
  await browser.close();

  // Reuse fetch-based helpers for scripts/probes/cors (consistent output shape).
  const scriptBodies = [];
  for (const a of [...assets.values()].filter(a => a.type === 'script').slice(0, 15)) {
    const res = await fetchLogged(a.url, { log, timeoutMs, type: 'script' });
    if (res?.body) scriptBodies.push({ url: a.url, code: res.body.slice(0, 200000), headers: res.headers });
  }
  const probes = [];
  for (const p of PROBE_PATHS) {
    const res = await fetchLogged(origin + p.path, { log, timeoutMs, type: 'probe', maxBody: 4096 });
    if (res) probes.push({ path: p.path, kind: p.kind, status: res.status, contentType: res.headers['content-type'] || '', snippet: (res.body || '').slice(0, 300), finalUrl: res.finalUrl });
  }
  const cors = await corsProbe(origin, { log, timeoutMs });
  const externalOrigins = [...new Set([...assets.values()].map(a => new URL(a.url).origin).filter(o => o !== origin))];

  return { engine: 'playwright', origin, pages, assets: [...assets.values()], forms, cookies, inlineScripts, scriptBodies, externalOrigins, probes, cors, storage, consoleErrors };
}

/* ------------------------------------------------------------------ */
function absolutize(href, base) {
  if (!href) return null;
  try {
    const u = new URL(href, base);
    if (!/^https?:$/.test(u.protocol)) return null;
    u.hash = '';
    return u.href;
  } catch { return null; }
}
function normalize(u) { try { const x = new URL(u); x.hash = ''; return x.href.replace(/\/$/, ''); } catch { return u; } }
function isCrawlable(u) { return !/\.(png|jpe?g|gif|svg|webp|ico|css|js|pdf|zip|gz|mp4|mp3|woff2?|ttf|eot)(\?|$)/i.test(u) && !/\/(logout|signout|delete)\b/i.test(u); }
