/**
 * Security header analysis over every HTML document response observed.
 */
const REFS = {
  csp: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP', 'https://csp-evaluator.withgoogle.com/'],
  hsts: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
  xfo: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
  xcto: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
  rp: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
  pp: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'],
  owaspHeaders: ['https://owasp.org/www-project-secure-headers/'],
};

export function headersCheck(ctx) {
  const findings = [];
  const docs = ctx.pages.filter(p => /text\/html/i.test(p.contentType) && p.headers);
  if (!docs.length) return findings;

  // Analyze the landing page in depth; report per-page divergences briefly.
  const main = docs[0];
  const h = main.headers;
  const https = main.finalUrl.startsWith('https://');
  const loc = main.finalUrl;

  // --- Content-Security-Policy ---
  const csp = h['content-security-policy'] || main.metaCsp;
  const cspRo = h['content-security-policy-report-only'];
  if (!csp) {
    findings.push({
      id: 'missing-csp', severity: 'high', category: 'headers', location: loc,
      title: 'Content-Security-Policy header is missing',
      description: cspRo
        ? 'Only a report-only CSP is present; policies in report-only mode are not enforced, so injected scripts still execute.'
        : 'Without a CSP, any successful HTML/script injection (XSS) executes with full page privileges. CSP is the strongest browser-side mitigation for XSS and data exfiltration.',
      evidence: cspRo ? { 'content-security-policy-report-only': cspRo } : null,
      remediation: "Start with a strict nonce/hash-based policy and iterate using report-only mode:\n\nContent-Security-Policy: default-src 'self'; script-src 'self' 'nonce-<random>'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
      references: REFS.csp, cwe: 'CWE-1021', owasp: 'A05:2021 Security Misconfiguration',
    });
  } else {
    const weaknesses = analyzeCsp(csp);
    for (const w of weaknesses) findings.push({ ...w, category: 'headers', location: loc, evidence: { 'content-security-policy': csp }, references: REFS.csp, owasp: 'A05:2021 Security Misconfiguration' });
    if (!h['content-security-policy'] && main.metaCsp) {
      findings.push({ id: 'csp-meta-only', severity: 'low', category: 'headers', location: loc, title: 'CSP delivered only via <meta> tag', description: 'Meta-delivered CSP cannot use frame-ancestors, report-uri or sandbox directives and does not protect content injected before the tag.', remediation: 'Deliver the CSP as an HTTP response header.', references: REFS.csp });
    }
  }

  // --- HSTS ---
  if (https) {
    const hsts = h['strict-transport-security'];
    if (!hsts) {
      findings.push({ id: 'missing-hsts', severity: 'medium', category: 'headers', location: loc, title: 'Strict-Transport-Security header is missing', description: 'Browsers may still attempt plaintext HTTP connections on first visit or via typed URLs, enabling SSL-stripping attacks.', remediation: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\nDeploy with a short max-age first, then increase and submit to hstspreload.org.', references: REFS.hsts, cwe: 'CWE-319', owasp: 'A02:2021 Cryptographic Failures' });
    } else {
      const m = /max-age=(\d+)/i.exec(hsts);
      const maxAge = m ? Number(m[1]) : 0;
      if (maxAge < 15552000) findings.push({ id: 'weak-hsts', severity: 'low', category: 'headers', location: loc, title: 'HSTS max-age is shorter than 180 days', description: `max-age=${maxAge}s. Short lifetimes reduce protection between visits and disqualify the domain from preload lists.`, evidence: { 'strict-transport-security': hsts }, remediation: 'Increase max-age to at least 31536000 (1 year) and add includeSubDomains.', references: REFS.hsts });
      if (!/includesubdomains/i.test(hsts)) findings.push({ id: 'hsts-no-subdomains', severity: 'info', category: 'headers', location: loc, title: 'HSTS does not include subdomains', description: 'Cookies scoped to the parent domain can be leaked over insecure subdomains.', evidence: { 'strict-transport-security': hsts }, remediation: 'Add includeSubDomains once all subdomains support HTTPS.', references: REFS.hsts });
    }
  }

  // --- Clickjacking ---
  const xfo = h['x-frame-options'];
  const frameAncestors = csp && /frame-ancestors/i.test(csp);
  if (!xfo && !frameAncestors) {
    findings.push({ id: 'missing-clickjacking-protection', severity: 'medium', category: 'headers', location: loc, title: 'No clickjacking protection (X-Frame-Options / frame-ancestors)', description: 'The page can be embedded in a cross-origin iframe, enabling UI-redress attacks that trick users into clicking hidden controls.', remediation: "Add CSP `frame-ancestors 'none'` (or 'self') and, for legacy browsers, `X-Frame-Options: DENY`.", references: [...REFS.xfo, ...REFS.csp], cwe: 'CWE-1021', owasp: 'A05:2021 Security Misconfiguration' });
  } else if (xfo && /allow-from/i.test(xfo)) {
    findings.push({ id: 'obsolete-xfo', severity: 'low', category: 'headers', location: loc, title: 'X-Frame-Options uses obsolete ALLOW-FROM', description: 'ALLOW-FROM is unsupported by modern browsers and is silently ignored.', evidence: { 'x-frame-options': xfo }, remediation: 'Replace with CSP frame-ancestors.', references: REFS.xfo });
  }

  // --- MIME sniffing ---
  if (!/nosniff/i.test(h['x-content-type-options'] || '')) {
    findings.push({ id: 'missing-xcto', severity: 'low', category: 'headers', location: loc, title: 'X-Content-Type-Options: nosniff is missing', description: 'Browsers may MIME-sniff responses, allowing uploaded files or mis-typed responses to be interpreted as scripts or stylesheets.', remediation: 'X-Content-Type-Options: nosniff', references: REFS.xcto, cwe: 'CWE-16' });
  }

  // --- Referrer-Policy ---
  const rp = (h['referrer-policy'] || '').toLowerCase();
  if (!rp) {
    findings.push({ id: 'missing-referrer-policy', severity: 'low', category: 'headers', location: loc, title: 'Referrer-Policy header is missing', description: 'Full URLs (which may include tokens, IDs or search terms) can leak to third parties via the Referer header.', remediation: 'Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for sensitive apps)', references: REFS.rp, cwe: 'CWE-200' });
  } else if (/unsafe-url|no-referrer-when-downgrade/.test(rp)) {
    findings.push({ id: 'weak-referrer-policy', severity: 'low', category: 'headers', location: loc, title: `Permissive Referrer-Policy (${rp})`, description: 'Full URL paths and query strings are sent to cross-origin destinations.', evidence: { 'referrer-policy': rp }, remediation: 'Use strict-origin-when-cross-origin or stricter.', references: REFS.rp });
  }

  // --- Permissions-Policy ---
  if (!h['permissions-policy'] && !h['feature-policy']) {
    findings.push({ id: 'missing-permissions-policy', severity: 'info', category: 'headers', location: loc, title: 'Permissions-Policy header is missing', description: 'Powerful browser features (camera, microphone, geolocation, payment) are not explicitly restricted for the page and embedded frames.', remediation: 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()', references: REFS.pp });
  }

  // --- Cross-origin isolation (info) ---
  if (!h['cross-origin-opener-policy']) {
    findings.push({ id: 'missing-coop', severity: 'info', category: 'headers', location: loc, title: 'Cross-Origin-Opener-Policy not set', description: 'Without COOP, cross-origin pages opened via window.open retain a reference to this window, enabling XS-Leaks and tab-nabbing.', remediation: 'Cross-Origin-Opener-Policy: same-origin', references: ['https://web.dev/articles/why-coop-coep'] });
  }

  // --- Deprecated / harmful headers ---
  const xss = h['x-xss-protection'];
  if (xss && /^1/.test(xss.trim()) && !/mode=block/i.test(xss)) {
    findings.push({ id: 'xss-auditor-enabled', severity: 'low', category: 'headers', location: loc, title: 'X-XSS-Protection: 1 without mode=block', description: 'The legacy XSS auditor in filter mode introduced information-leak side channels; modern browsers removed it.', evidence: { 'x-xss-protection': xss }, remediation: 'Remove the header entirely (or set to 0) and rely on CSP.', references: REFS.owaspHeaders });
  }

  // --- Cache-Control for HTML documents that set cookies ---
  if (h['set-cookie'] && !/no-store|private/i.test(h['cache-control'] || '')) {
    findings.push({ id: 'cacheable-authenticated-document', severity: 'low', category: 'headers', location: loc, title: 'Document sets cookies but is cacheable', description: 'Responses that establish sessions should not be stored by shared caches or proxies.', evidence: { 'cache-control': h['cache-control'] || '(absent)' }, remediation: 'Cache-Control: no-store, private', references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control'], cwe: 'CWE-525' });
  }

  // --- Inconsistent headers across pages ---
  const inconsistent = docs.slice(1).filter(p => !!p.headers['content-security-policy'] !== !!h['content-security-policy']);
  if (inconsistent.length) {
    findings.push({ id: 'inconsistent-csp', severity: 'medium', category: 'headers', location: inconsistent[0].finalUrl, title: `CSP applied inconsistently across ${inconsistent.length} page(s)`, description: 'Some pages are served without the same CSP as the landing page, leaving gaps an attacker can target.', evidence: inconsistent.slice(0, 5).map(p => p.finalUrl), remediation: 'Apply security headers at the edge/web-server layer so every response is covered, including error pages.', references: REFS.csp });
  }

  return findings;
}

export function analyzeCsp(csp) {
  const out = [];
  const directives = {};
  for (const part of csp.split(';')) {
    const [name, ...vals] = part.trim().split(/\s+/);
    if (name) directives[name.toLowerCase()] = vals.map(v => v.toLowerCase());
  }
  const scriptSrc = directives['script-src'] || directives['default-src'] || [];
  const hasNonceOrHash = scriptSrc.some(v => /^'(nonce-|sha(256|384|512)-)/.test(v));
  const strictDynamic = scriptSrc.includes("'strict-dynamic'");

  if (scriptSrc.includes("'unsafe-inline'") && !hasNonceOrHash) out.push({ id: 'csp-unsafe-inline', severity: 'high', title: "CSP allows 'unsafe-inline' scripts", description: "'unsafe-inline' in script-src disables the primary XSS protection CSP provides — any injected <script> block executes.", remediation: "Replace 'unsafe-inline' with per-request nonces ('nonce-…') or hashes, and refactor inline handlers into external scripts.", cwe: 'CWE-79' });
  if (scriptSrc.includes("'unsafe-eval'")) out.push({ id: 'csp-unsafe-eval', severity: 'medium', title: "CSP allows 'unsafe-eval'", description: 'eval(), new Function() and string-based timers are permitted, widening the XSS gadget surface.', remediation: "Remove 'unsafe-eval'; update libraries that rely on eval-style template compilation.", cwe: 'CWE-95' });
  if ((scriptSrc.includes('*') || scriptSrc.some(v => /^https?:$/.test(v) || v === 'data:')) && !strictDynamic) out.push({ id: 'csp-wildcard-script', severity: 'high', title: 'CSP script-src contains a wildcard or scheme-only source', description: `Sources like "*", "https:" or "data:" allow scripts from any host, making the policy trivially bypassable. Effective script-src: ${scriptSrc.join(' ')}`, remediation: "Whitelist explicit origins or, preferably, use 'strict-dynamic' with nonces.", cwe: 'CWE-79' });
  if (!directives['object-src'] && !directives['default-src']) out.push({ id: 'csp-no-object-src', severity: 'low', title: "CSP lacks object-src 'none'", description: 'Legacy plugin content (Flash/Java applets) can be used as a script-execution vector.', remediation: "Add object-src 'none'." });
  if (!directives['base-uri']) out.push({ id: 'csp-no-base-uri', severity: 'low', title: 'CSP lacks base-uri', description: 'An injected <base> tag can redirect relative script URLs to an attacker host.', remediation: "Add base-uri 'self' (or 'none')." });
  if (!directives['frame-ancestors']) out.push({ id: 'csp-no-frame-ancestors', severity: 'info', title: 'CSP lacks frame-ancestors', description: 'Clickjacking protection relies solely on X-Frame-Options if present.', remediation: "Add frame-ancestors 'none' or 'self'." });
  return out;
}
