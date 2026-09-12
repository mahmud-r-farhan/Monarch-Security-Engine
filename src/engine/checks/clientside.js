/**
 * Client-side heuristics: XSS sinks, insecure storage usage, CSRF readiness, SRI, third-party scripts, secrets in JS.
 */
const STORAGE_TOKEN_RE = /(localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*['"`]([^'"`]*(token|jwt|auth|session|secret|api[_-]?key|password)[^'"`]*)['"`]/gi;
const DOM_SINK_RE = /\.(innerHTML|outerHTML)\s*=|document\.write(ln)?\s*\(|insertAdjacentHTML\s*\(|\beval\s*\(|new\s+Function\s*\(/g;
const URL_SOURCE_RE = /location\.(hash|search|href)|document\.URL|document\.referrer|window\.name/g;
const POSTMESSAGE_RE = /addEventListener\s*\(\s*['"]message['"]/g;
const SECRET_PATTERNS = [
  { name: 'AWS Access Key', re: /\bAKIA[0-9A-Z]{16}\b/g, severity: 'critical' },
  { name: 'Google API Key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: 'medium' },
  { name: 'Stripe Secret Key', re: /\bsk_(live|test)_[0-9a-zA-Z]{20,}\b/g, severity: 'critical' },
  { name: 'GitHub Token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, severity: 'critical' },
  { name: 'Slack Token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, severity: 'high' },
  { name: 'Private Key Block', re: /-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'Generic secret assignment', re: /\b(api[_-]?key|secret|password|passwd|client_secret)\b\s*[:=]\s*['"][A-Za-z0-9_\-\/+=]{12,}['"]/gi, severity: 'medium' },
];

export function clientSideCheck(ctx) {
  const findings = [];
  const scripts = [
    ...ctx.inlineScripts.map(s => ({ where: `inline script on ${s.page}`, code: s.code })),
    ...ctx.scriptBodies.map(s => ({ where: s.url, code: s.code })),
  ];

  for (const s of scripts) {
    // Insecure storage of tokens
    for (const m of s.code.matchAll(STORAGE_TOKEN_RE)) {
      findings.push({ id: 'token-in-web-storage', severity: 'high', category: 'client', location: s.where, title: `Token-like value written to ${m[1]} ("${m[2]}")`, description: 'Web Storage is readable by any JavaScript on the origin. Auth material stored there is exfiltrated by a single XSS bug and (for localStorage) persists indefinitely.', evidence: snippet(s.code, m.index), remediation: 'Store session material in HttpOnly cookies. If you must use a bearer token from JS, keep it in memory, use a short expiry and rotate via a refresh cookie.', cwe: 'CWE-922', owasp: 'A07:2021 Identification and Authentication Failures', references: ['https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage'] });
    }
    // DOM XSS: source + sink in same script
    const sinks = [...s.code.matchAll(DOM_SINK_RE)];
    const sources = [...s.code.matchAll(URL_SOURCE_RE)];
    if (sinks.length && sources.length) {
      findings.push({ id: 'dom-xss-pattern', severity: 'medium', category: 'client', location: s.where, title: `Potential DOM XSS: URL-controlled source flows near ${uniq(sinks.map(x => x[0].replace(/\s*[=(].*/, '')))} sink(s)`, description: `Script reads attacker-controllable data (${uniq(sources.map(x => x[0]))}) and uses dangerous DOM sinks. If the data reaches the sink unescaped, arbitrary script executes.`, evidence: snippet(s.code, sinks[0].index), remediation: 'Use textContent / safe DOM APIs instead of innerHTML; sanitize with DOMPurify when HTML is unavoidable; adopt Trusted Types (`require-trusted-types-for \'script\'`).', cwe: 'CWE-79', owasp: 'A03:2021 Injection', references: ['https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html'] });
    } else if (sinks.some(x => /eval|Function/.test(x[0]))) {
      findings.push({ id: 'eval-usage', severity: 'low', category: 'client', location: s.where, title: 'eval() / new Function() usage detected', description: 'Dynamic code evaluation widens the XSS attack surface and prevents a strict CSP.', evidence: snippet(s.code, sinks.find(x => /eval|Function/.test(x[0])).index), remediation: 'Replace with JSON.parse or explicit logic; remove the need for unsafe-eval.', cwe: 'CWE-95' });
    }
    // postMessage without origin check
    for (const m of s.code.matchAll(POSTMESSAGE_RE)) {
      const window = s.code.slice(m.index, m.index + 600);
      if (!/\.origin\s*(===|==|!==|!=)|origin\s*\)/.test(window)) {
        findings.push({ id: 'postmessage-no-origin-check', severity: 'medium', category: 'client', location: s.where, title: 'postMessage listener without origin validation', description: 'A "message" handler processes data without checking event.origin, so any page that can obtain a window reference can inject data.', evidence: snippet(s.code, m.index), remediation: 'Verify `event.origin` against an exact allow-list before acting on the message.', cwe: 'CWE-346', references: ['https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns'] });
        break;
      }
    }
    // Secrets
    for (const p of SECRET_PATTERNS) {
      const m = p.re.exec(s.code);
      p.re.lastIndex = 0;
      if (m) findings.push({ id: `secret-${p.name.toLowerCase().replace(/\s+/g, '-')}`, severity: p.severity, category: 'client', location: s.where, title: `${p.name} exposed in client-side code`, description: 'Credentials shipped to the browser are public. Anyone can extract and abuse them against the associated service.', evidence: redact(m[0]), remediation: 'Revoke and rotate the credential immediately; move the call behind a server-side endpoint that holds the secret.', cwe: 'CWE-798', owasp: 'A02:2021 Cryptographic Failures' });
    }
  }

  // Runtime storage (playwright engine)
  if (ctx.storage) {
    for (const area of ['localStorage', 'sessionStorage']) {
      for (const [k, v] of Object.entries(ctx.storage[area] || {})) {
        if (/token|jwt|auth|session|secret|key|password/i.test(k) || /^eyJ/.test(v)) {
          findings.push({ id: 'runtime-token-in-storage', severity: 'high', category: 'client', location: `${area}["${k}"]`, title: `Sensitive value found in ${area} at runtime`, description: 'The live page persisted credential-like data into Web Storage.', evidence: { key: k, valuePreview: v.slice(0, 12) + '…' }, remediation: 'Move to HttpOnly cookies or in-memory storage.', cwe: 'CWE-922' });
        }
      }
    }
  }

  // Forms
  for (const f of ctx.forms) {
    const insecureAction = f.action.startsWith('http://') && f.page.startsWith('https://');
    if (f.hasPassword && (insecureAction || f.page.startsWith('http://'))) findings.push({ id: 'password-form-insecure', severity: 'critical', category: 'client', location: f.page, title: 'Login form submits credentials over HTTP', description: `Password field posts to ${f.action}; credentials traverse the network in plaintext.`, evidence: { action: f.action, method: f.method }, remediation: 'Serve the form and its action over HTTPS only.', cwe: 'CWE-319', owasp: 'A02:2021 Cryptographic Failures' });
    if (f.method === 'POST' && !f.hasCsrfToken && !f.hasPassword) findings.push({ id: 'form-no-csrf-token', severity: 'medium', category: 'client', location: f.page, title: `POST form to ${new URL(f.action).pathname} has no visible CSRF token`, description: 'State-changing forms without an anti-CSRF token can be submitted from attacker pages if session cookies are sent cross-site (SameSite=None or legacy browsers).', evidence: { action: f.action, inputs: f.inputs.map(i => i.name).filter(Boolean) }, remediation: 'Add a synchronizer token (hidden input) validated server-side, or rely on SameSite=Lax/Strict cookies plus Origin header verification.', cwe: 'CWE-352', owasp: 'A01:2021 Broken Access Control', references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'] });
    if (f.hasPassword && f.method === 'GET') findings.push({ id: 'password-form-get', severity: 'high', category: 'client', location: f.page, title: 'Login form uses GET', description: 'Credentials end up in the URL, browser history, proxy and server logs.', remediation: 'Use method="POST".', cwe: 'CWE-598' });
    const pw = f.inputs.find(i => i.type === 'password');
    if (pw && pw.autocomplete && /^(on)$/i.test(pw.autocomplete) === false && pw.autocomplete === 'off') { /* autocomplete=off is ignored by browsers; not a finding */ }
  }

  // SRI for cross-origin scripts
  const thirdParty = ctx.assets.filter(a => a.type === 'script' && !a.url.startsWith(ctx.origin));
  const noSri = thirdParty.filter(a => !a.integrity);
  if (noSri.length) findings.push({ id: 'missing-sri', severity: 'medium', category: 'client', location: noSri[0].foundOn, title: `${noSri.length} third-party script(s) loaded without Subresource Integrity`, description: 'If the CDN or third-party is compromised (e.g. polyfill.io, 2024), malicious code runs with full access to your users\' sessions.', evidence: noSri.slice(0, 10).map(a => a.url), remediation: 'Add integrity="sha384-…" and crossorigin="anonymous" to each external <script>, or self-host the assets.', cwe: 'CWE-829', owasp: 'A08:2021 Software and Data Integrity Failures', references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'] });

  if (ctx.externalOrigins.length > 8) findings.push({ id: 'many-third-parties', severity: 'info', category: 'client', location: ctx.origin, title: `${ctx.externalOrigins.length} distinct third-party origins loaded`, description: 'Every third-party origin is a supply-chain trust decision and increases the tracking surface.', evidence: ctx.externalOrigins.slice(0, 20), remediation: 'Audit and minimize third-party dependencies; gate non-essential ones behind consent.' });

  const inlineHandlers = ctx.pages.filter(p => p.hasInlineEventHandlers);
  if (inlineHandlers.length) findings.push({ id: 'inline-event-handlers', severity: 'info', category: 'client', location: inlineHandlers[0].finalUrl, title: `Inline event handlers on ${inlineHandlers.length} page(s)`, description: 'onclick="…" style handlers require CSP unsafe-inline, blocking adoption of a strict policy.', remediation: 'Attach handlers via addEventListener in external scripts.' });

  return findings;
}

function snippet(code, idx, span = 120) {
  const start = Math.max(0, idx - span / 2);
  return code.slice(start, idx + span).replace(/\s+/g, ' ').trim();
}
function uniq(arr) { return [...new Set(arr)].join(', '); }
function redact(s) { return s.length > 16 ? s.slice(0, 8) + '…' + s.slice(-4) : s.slice(0, 4) + '…'; }
