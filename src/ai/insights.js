/**
 * AI Insights Engine.
 * Digests findings + network summary into an executive summary, prioritized action plan and
 * remediation snippets. Supports OpenAI, Anthropic and Gemini via plain fetch (no SDKs).
 * Falls back to a deterministic, rules-based "analyst" so the product always produces a report.
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

export async function generateInsights(scan, { env = process.env, fetchImpl = fetch, aiConfig = null } = {}) {
  const effectiveEnv = { ...env };
  if (aiConfig) {
    if (aiConfig.provider && aiConfig.provider !== 'auto') effectiveEnv.AI_PROVIDER = aiConfig.provider;
    if (aiConfig.apiKey) {
      effectiveEnv.AI_API_KEY = aiConfig.apiKey;
      const p = effectiveEnv.AI_PROVIDER || 'openrouter';
      if (p === 'openrouter') effectiveEnv.OPENROUTER_API_KEY = aiConfig.apiKey;
      else if (p === 'openai') effectiveEnv.OPENAI_API_KEY = aiConfig.apiKey;
      else if (p === 'anthropic') effectiveEnv.ANTHROPIC_API_KEY = aiConfig.apiKey;
      else if (p === 'gemini') effectiveEnv.GEMINI_API_KEY = aiConfig.apiKey;
    }
    if (aiConfig.model) effectiveEnv.AI_MODEL = aiConfig.model;
    if (aiConfig.baseUrl) effectiveEnv.OLLAMA_BASE_URL = aiConfig.baseUrl;
  }

  const provider = detectProvider(effectiveEnv);
  const prompt = buildPrompt(scan);
  if (provider === 'none') return { provider: 'heuristic', model: 'monarch-rules-v1', ...heuristicInsights(scan) };
  try {
    const text = await callProvider(provider, prompt, effectiveEnv, fetchImpl);
    const parsed = parseModelJson(text);
    if (!parsed) throw new Error('Model returned non-JSON output');
    return { provider, model: effectiveEnv.AI_MODEL || DEFAULT_MODEL[provider], ...parsed };
  } catch (err) {
    const fallback = heuristicInsights(scan);
    return { provider: 'heuristic', model: 'monarch-rules-v1', warning: `AI provider "${provider}" failed: ${err.message}. Showing rules-based analysis.`, ...fallback };
  }
}

export const DEFAULT_MODEL = {
  openrouter: 'deepseek/deepseek-r1-distill-qwen-7b',
  openai: 'gpt-4o-mini',
  anthropic: 'claude-3-5-haiku-latest',
  gemini: 'gemini-1.5-flash',
  ollama: 'llama3.2',
};

/** Valid provider ids — shared by server config endpoint and callers. */
export const PROVIDERS = ['openrouter', 'openai', 'anthropic', 'gemini', 'ollama', 'none'];

/**
 * Normalize an Ollama base URL from user/env input.
 * Accepts: http://localhost:11434, localhost:11434, 127.0.0.1:11434, ollama.mynet:11434/api
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
  // strip /api or /v1 suffixes — they are added by the client
  u.pathname = u.pathname.replace(/\/(api|v1)\/?$/i, '');
  u.search = '';
  u.hash = '';
  return u.origin + (u.pathname === '/' ? '' : u.pathname.replace(/\/$/, ''));
}

const SYSTEM = `You are Monarch, a senior application-security analyst producing a defensive audit for the owner of the scanned application.
Respond ONLY with a JSON object of this exact shape:
{
  "riskLevel": "critical|high|medium|low|minimal",
  "executiveSummary": "3-5 sentences for a non-technical stakeholder",
  "rootCauses": ["short root-cause statements"],
  "actionPlan": [{"priority": 1, "title": "...", "why": "...", "how": "concrete config/code snippet or steps", "effort": "low|medium|high", "findingIds": ["..."]}],
  "quickWins": ["one-line items fixable in under an hour"],
  "attackNarrative": "2-4 sentences describing how an attacker would realistically chain the top findings"
}
Be specific, cite finding ids, never invent findings not in the input, and keep the action plan to at most 7 items.`;

function buildPrompt(scan) {
  const compact = scan.findings.map(f => ({ id: f.id, severity: f.severity, title: f.title, location: f.location, evidence: truncate(JSON.stringify(f.evidence), 300) }));
  return `Target: ${scan.target}\nEngine: ${scan.crawl.engine}\nPages crawled: ${scan.crawl.pages.length}\nNetwork: ${JSON.stringify(scan.networkSummary)}\nScore: ${scan.score.score}/100 (${scan.score.grade})\nThird-party origins: ${scan.crawl.externalOrigins.slice(0, 15).join(', ') || 'none'}\nCookies: ${scan.crawl.cookies.map(c => `${c.name}[${c.httpOnly ? 'HttpOnly' : ''}${c.secure ? ' Secure' : ''}${c.sameSite ? ' SameSite=' + c.sameSite : ''}]`).join(', ') || 'none'}\n\nFindings (${compact.length}):\n${JSON.stringify(compact, null, 1)}`;
}

async function callProvider(provider, prompt, env, fetchImpl) {
  const model = env.AI_MODEL || DEFAULT_MODEL[provider];
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 60_000);
  try {
    if (provider === 'openrouter') {
      const apiKey = env.OPENROUTER_API_KEY || env.AI_API_KEY;
      const r = await fetchImpl('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        signal: ac.signal,
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${apiKey}`,
          'HTTP-Referer': 'https://github.com/mahmud-r-farhan/Monarch-Security-Engine',
          'X-Title': 'Monarch Security Engine',
        },
        body: JSON.stringify({
          model,
          temperature: 0.2,
          response_format: { type: 'json_object' },
          messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: prompt }],
        }),
      });
      const j = await ok(r);
      return j.choices?.[0]?.message?.content || '';
    }
    if (provider === 'openai') {
      const apiKey = env.OPENAI_API_KEY || env.AI_API_KEY;
      const r = await fetchImpl('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        signal: ac.signal,
        headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({ model, temperature: 0.2, response_format: { type: 'json_object' }, messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: prompt }] }),
      });
      const j = await ok(r);
      return j.choices?.[0]?.message?.content || '';
    }
    if (provider === 'anthropic') {
      const apiKey = env.ANTHROPIC_API_KEY || env.AI_API_KEY;
      const r = await fetchImpl('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        signal: ac.signal,
        headers: { 'content-type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model, max_tokens: 2500, temperature: 0.2, system: SYSTEM, messages: [{ role: 'user', content: prompt }] }),
      });
      const j = await ok(r);
      return j.content?.map(c => c.text || '').join('') || '';
    }
    if (provider === 'gemini') {
      const apiKey = env.GEMINI_API_KEY || env.AI_API_KEY;
      const r = await fetchImpl(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`, {
        method: 'POST',
        signal: ac.signal,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: SYSTEM }] },
          contents: [{ role: 'user', parts: [{ text: prompt }] }],
          generationConfig: { temperature: 0.2, responseMimeType: 'application/json' },
        }),
      });
      const j = await ok(r);
      return j.candidates?.[0]?.content?.parts?.map(p => p.text).join('') || '';
    }
    if (provider === 'ollama') {
      const base = normalizeOllamaBaseUrl(env.OLLAMA_BASE_URL || env.OLLAMA_HOST || 'http://localhost:11434');
      const omodel = env.OLLAMA_MODEL || model;
      const r = await fetchImpl(`${base}/api/chat`, {
        method: 'POST',
        signal: ac.signal,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          model: omodel,
          stream: false,
          format: 'json', // constrain output to a JSON object
          options: { temperature: 0.2, num_ctx: 8192 },
          messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: prompt }],
        }),
      });
      const j = await ok(r);
      return j.message?.content || '';
    }
    throw new Error(`Unknown AI provider "${provider}"`);
  } finally { clearTimeout(timer); }
}

async function ok(r) {
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${truncate(await r.text(), 200)}`);
  return r.json();
}

export function parseModelJson(text) {
  if (!text) return null;
  const cleaned = text.replace(/^```(json)?/m, '').replace(/```$/m, '').trim();
  try { return JSON.parse(cleaned); } catch { /* try to locate object */ }
  const m = cleaned.match(/\{[\s\S]*\}/);
  if (!m) return null;
  try { return JSON.parse(m[0]); } catch { return null; }
}

/* ------------------------------------------------------------------ */
/* Deterministic analyst — used offline or when the provider fails.   */
/* ------------------------------------------------------------------ */
export function heuristicInsights(scan) {
  const f = scan.findings;
  const by = sev => f.filter(x => x.severity === sev);
  const counts = scan.score.counts;
  const riskLevel = by('critical').length ? 'critical' : by('high').length ? 'high' : by('medium').length ? 'medium' : by('low').length ? 'low' : 'minimal';
  const host = safeHost(scan.target);

  const executiveSummary = [
    `${host} scored ${scan.score.score}/100 (grade ${scan.score.grade}) across ${scan.crawl.pages.length} crawled page(s) and ${scan.networkSummary.requests} observed requests.`,
    counts.critical ? `${counts.critical} critical issue(s) require immediate attention because they enable direct compromise (e.g. ${by('critical')[0].title.toLowerCase()}).` : 'No critical issues were detected.',
    counts.high ? `${counts.high} high-severity weakness(es) materially increase the chance that a single bug such as XSS turns into account takeover.` : '',
    counts.medium || counts.low ? `The remaining ${(counts.medium || 0) + (counts.low || 0)} medium/low items are defence-in-depth gaps that are cheap to close.` : '',
    'Most items can be fixed at the web-server or edge layer without application changes.',
  ].filter(Boolean).join(' ');

  const groups = groupBy(f, x => x.category);
  const rootCauses = [];
  if (groups.headers?.length >= 3) rootCauses.push('Security headers are not applied centrally (edge/web-server), leaving browser-side defences unconfigured.');
  if (groups.cookies?.length) rootCauses.push('Session cookies are issued without hardening attributes, indicating framework defaults were not reviewed.');
  if (groups.jwt?.length) rootCauses.push('Token handling favours convenience (long-lived, client-accessible tokens) over least-exposure.');
  if (groups.client?.length) rootCauses.push('Client-side code trusts URL/third-party input and stores secrets in reachable locations.');
  if (groups.transport?.length) rootCauses.push('Transport security is not enforced end-to-end (HTTP reachability, mixed content or permissive CORS).');
  if (groups.exposure?.length) rootCauses.push('Deployment artefacts (dot-files, backups, configs) are inside the public web root.');
  if (groups.infoleak?.length) rootCauses.push('Verbose server configuration discloses stack details useful for targeted exploitation.');
  if (!rootCauses.length) rootCauses.push('Overall posture is sound; remaining items are hygiene improvements.');

  const plan = [];
  const push = (title, why, how, effort, ids) => { if (ids.length) plan.push({ priority: plan.length + 1, title, why, how, effort, findingIds: ids }); };
  const ids = (...prefixes) => f.filter(x => prefixes.some(p => x.id.startsWith(p))).map(x => x.id);

  push('Remove exposed secrets & artefacts, rotate credentials', 'Direct leakage of credentials or source is the fastest path to full compromise.', 'Delete the files from the web root, add deny rules for dot-files/archives, rotate every credential found, and audit logs for prior access.', 'medium', [...new Set(ids('exposed-', 'secret-', 'jwt-hardcoded'))]);
  push('Enforce HTTPS everywhere', 'Plaintext transport exposes every credential and cookie to network attackers.', 'Redirect 80→443 with 301, fix insecure form actions and sub-resources, then add HSTS with max-age=31536000; includeSubDomains.', 'medium', [...new Set(ids('no-https', 'https-downgrade', 'mixed-content', 'password-form-insecure', 'missing-hsts', 'weak-hsts'))]);
  push('Lock down CORS', 'Reflected origins with credentials let any site act as the logged-in user.', 'Compare Origin against an explicit allow-list and never pair a reflected origin with Access-Control-Allow-Credentials: true.', 'low', ids('cors-'));
  push('Harden session cookies', 'A missing HttpOnly/Secure/SameSite flag turns any XSS or network position into session theft.', 'Set-Cookie: __Host-session=…; Path=/; Secure; HttpOnly; SameSite=Lax — most frameworks expose this as a one-line config.', 'low', ids('cookie-'));
  push('Fix JWT handling', 'Unsigned/long-lived tokens or tokens in Web Storage make forgery and theft trivial.', 'Pin RS256/ES256, reject alg=none, set exp ≤ 15 min, keep PII out of claims, and move tokens from localStorage to HttpOnly cookies.', 'medium', ids('jwt-', 'token-in-web-storage', 'runtime-token'));
  push('Deploy a Content-Security-Policy', 'CSP is the single most effective mitigation against XSS, which is the pivot for most of the other findings.', "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'. Roll out with Content-Security-Policy-Report-Only first.", 'high', ids('missing-csp', 'csp-', 'inconsistent-csp', 'dom-xss', 'eval-usage', 'inline-event'));
  push('Add remaining defence-in-depth headers', 'Cheap protection against clickjacking, MIME sniffing and referrer leaks.', 'X-Frame-Options: DENY · X-Content-Type-Options: nosniff · Referrer-Policy: strict-origin-when-cross-origin · Permissions-Policy: camera=(), microphone=(), geolocation=() · Cross-Origin-Opener-Policy: same-origin', 'low', ids('missing-clickjacking', 'missing-xcto', 'missing-referrer', 'weak-referrer', 'missing-permissions', 'missing-coop', 'obsolete-xfo', 'xss-auditor'));
  push('Protect the supply chain', 'A compromised CDN script runs with your users\' full privileges.', 'Add integrity + crossorigin attributes to third-party scripts or self-host them; reduce the number of third-party origins.', 'low', ids('missing-sri', 'many-third-parties'));
  push('Reduce information disclosure', 'Version banners and stack traces help attackers pick working exploits.', 'server_tokens off; remove X-Powered-By; disable debug pages; stop shipping source maps.', 'low', ids('version-disclosure', 'stack-trace', 'source-map', 'directory-listing', 'server-errors'));
  push('Add CSRF protections', 'State-changing forms can be triggered from attacker pages.', 'Use synchronizer tokens or SameSite=Lax cookies with Origin verification on every mutating endpoint.', 'medium', ids('form-no-csrf', 'cookie-samesite-none'));

  const quickWins = [];
  if (ids('missing-xcto').length) quickWins.push('Add X-Content-Type-Options: nosniff');
  if (ids('missing-referrer').length) quickWins.push('Add Referrer-Policy: strict-origin-when-cross-origin');
  if (ids('missing-clickjacking').length) quickWins.push('Add X-Frame-Options: DENY');
  if (ids('version-disclosure-x-powered-by').length) quickWins.push('Remove the X-Powered-By header');
  if (ids('cookie-no-httponly', 'cookie-no-secure', 'cookie-no-samesite').length) quickWins.push('Enable HttpOnly/Secure/SameSite on all cookies in framework session config');
  if (ids('no-security-txt').length) quickWins.push('Publish /.well-known/security.txt');
  if (ids('missing-hsts').length) quickWins.push('Add Strict-Transport-Security: max-age=31536000; includeSubDomains');

  const top = f.slice(0, 3).map(x => x.title.toLowerCase());
  const attackNarrative = top.length
    ? `An attacker would start with ${top[0]}${top[1] ? `, combine it with ${top[1]}` : ''}${top[2] ? ` and leverage ${top[2]}` : ''} to escalate from a single foothold to session or data compromise. Closing the top three findings breaks this chain.`
    : 'No practical attack chain was identified from the observed surface.';

  return { riskLevel, executiveSummary, rootCauses, actionPlan: plan.slice(0, 7), quickWins, attackNarrative };
}

function groupBy(arr, fn) { const o = {}; for (const x of arr) (o[fn(x)] ||= []).push(x); return o; }
function truncate(s, n) { s = String(s ?? ''); return s.length > n ? s.slice(0, n) + '…' : s; }
function safeHost(u) { try { return new URL(u).host; } catch { return u; } }
