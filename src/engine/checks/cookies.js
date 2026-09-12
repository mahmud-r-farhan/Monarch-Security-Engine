const SESSION_NAME = /sess|sid|token|auth|jwt|login|user|id$|remember|csrf|xsrf/i;

export function cookiesCheck(ctx) {
  const findings = [];
  const https = ctx.origin.startsWith('https://');
  for (const c of ctx.cookies) {
    const sensitive = SESSION_NAME.test(c.name);
    const base = { category: 'cookies', location: `${c.setBy} → cookie "${c.name}"`, evidence: { name: c.name, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite, domain: c.domain, path: c.path, expires: c.expires, maxAge: c.maxAge, valuePreview: preview(c.value) } };

    if (!c.httpOnly) findings.push({ ...base, id: 'cookie-no-httponly', severity: sensitive ? 'high' : 'low', title: `Cookie "${c.name}" lacks HttpOnly`, description: `${sensitive ? 'This looks like a session/auth cookie. ' : ''}Without HttpOnly the value is readable via document.cookie, so any XSS can steal it and hijack the session.`, remediation: `Set-Cookie: ${c.name}=…; HttpOnly; Secure; SameSite=Lax`, cwe: 'CWE-1004', owasp: 'A05:2021 Security Misconfiguration', references: ['https://owasp.org/www-community/HttpOnly'] });

    if (!c.secure && https) findings.push({ ...base, id: 'cookie-no-secure', severity: sensitive ? 'high' : 'medium', title: `Cookie "${c.name}" lacks the Secure flag`, description: 'The cookie will be sent over plaintext HTTP if the user is ever induced to load an http:// URL on this domain, exposing it to network attackers.', remediation: `Add the Secure attribute (and prefer the __Host- prefix): Set-Cookie: __Host-${c.name}=…; Secure; HttpOnly; Path=/; SameSite=Lax`, cwe: 'CWE-614', owasp: 'A02:2021 Cryptographic Failures', references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies'] });

    if (!c.sameSite) findings.push({ ...base, id: 'cookie-no-samesite', severity: sensitive ? 'medium' : 'low', title: `Cookie "${c.name}" has no SameSite attribute`, description: 'Browsers default to Lax but behaviour is inconsistent; an explicit value protects against CSRF and cross-site leaks.', remediation: 'Set SameSite=Lax (or Strict for high-value session cookies).', cwe: 'CWE-1275', owasp: 'A01:2021 Broken Access Control', references: ['https://web.dev/articles/samesite-cookies-explained'] });
    else if (/^none$/i.test(c.sameSite)) findings.push({ ...base, id: 'cookie-samesite-none', severity: sensitive ? 'medium' : 'info', title: `Cookie "${c.name}" uses SameSite=None`, description: 'The cookie is attached to all cross-site requests, re-enabling classic CSRF unless every state-changing endpoint verifies a token.', remediation: 'Use Lax/Strict unless the cookie is genuinely required in third-party contexts; if so, ensure Secure is set and CSRF tokens are enforced.', cwe: 'CWE-352' });

    if (sensitive && looksLikeJwt(c.value)) findings.push({ ...base, id: 'cookie-contains-jwt', severity: 'info', title: `Cookie "${c.name}" carries a JWT`, description: 'JWT detected in cookie value; see JWT analysis findings for algorithm/claim review.', remediation: 'Keep the JWT short-lived, HttpOnly and pair it with a rotating refresh token.' });

    if (sensitive && !c.expires && c.maxAge == null) { /* session cookie — good */ }
    else if (sensitive && c.maxAge && c.maxAge > 60 * 60 * 24 * 30) findings.push({ ...base, id: 'cookie-long-lived-session', severity: 'low', title: `Session-like cookie "${c.name}" persists for ${Math.round(c.maxAge / 86400)} days`, description: 'Long-lived session identifiers extend the window of usefulness for a stolen cookie.', remediation: 'Limit session lifetime and implement idle-timeout + rotation on privilege change.', cwe: 'CWE-613' });

    if (c.domain && c.domain.replace(/^\./, '').split('.').length <= 2 && new URL(ctx.origin).hostname.split('.').length > 2) findings.push({ ...base, id: 'cookie-broad-domain', severity: 'low', title: `Cookie "${c.name}" is scoped to parent domain ${c.domain}`, description: 'The cookie is shared with every subdomain; a compromise of any sibling host exposes it.', remediation: 'Omit the Domain attribute so the cookie is host-only, or use the __Host- prefix.', cwe: 'CWE-287' });
  }
  return findings;
}

function preview(v) { if (!v) return ''; return v.length > 24 ? v.slice(0, 12) + '…' + v.slice(-6) : v; }
export function looksLikeJwt(v) { return /^eyJ[\w-]+\.[\w-]+\.[\w-]*$/.test(String(v || '').trim()); }
