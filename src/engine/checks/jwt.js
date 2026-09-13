/**
 * JWT discovery & structural analysis across cookies, headers, storage, scripts and response bodies.
 * We never verify signatures (no keys) — we evaluate algorithm choice, claims and sensitive payload data.
 */
const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g;
const SENSITIVE_CLAIMS = /^(password|passwd|pwd|secret|ssn|credit|card|cvv|iban|salary|dob|birth|phone|address|email)$/i;

export function jwtCheck(ctx) {
  const findings = [];
  const seen = new Set();
  const sources = [];

  for (const c of ctx.cookies) sources.push({ where: `cookie "${c.name}"`, text: c.value || '' });
  if (ctx.storage) {
    for (const [k, v] of Object.entries(ctx.storage.localStorage || {})) sources.push({ where: `localStorage["${k}"]`, text: v, storage: true });
    for (const [k, v] of Object.entries(ctx.storage.sessionStorage || {})) sources.push({ where: `sessionStorage["${k}"]`, text: v, storage: true });
  }
  for (const s of ctx.inlineScripts) sources.push({ where: `inline script on ${s.page}`, text: s.code, script: true });
  for (const s of ctx.scriptBodies) sources.push({ where: s.url, text: s.code, script: true });
  for (const e of ctx.network) {
    const auth = e.request?.headers?.authorization;
    if (auth) sources.push({ where: `Authorization header → ${e.url}`, text: auth });
  }

  for (const src of sources) {
    for (const token of src.text.match(JWT_RE) || []) {
      if (seen.has(token)) continue;
      seen.add(token);
      const parsed = decodeJwt(token);
      if (!parsed) continue;
      findings.push(...analyzeJwt(parsed, token, src));
    }
  }
  return findings;
}

export function decodeJwt(token) {
  try {
    const [h, p, s] = token.split('.');
    const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    if (typeof header !== 'object' || typeof payload !== 'object') return null;
    return { header, payload, signature: s || '' };
  } catch { return null; }
}

function analyzeJwt({ header, payload, signature }, token, src) {
  const out = [];
  const alg = String(header.alg || '').toUpperCase();
  const redacted = token.slice(0, 20) + '…' + token.slice(-8);
  const base = { category: 'jwt', location: src.where, evidence: { token: redacted, header, claims: redactClaims(payload) }, owasp: 'A02:2021 Cryptographic Failures' };

  if (src.script) {
    out.push({ ...base, id: 'jwt-hardcoded-in-script', severity: 'high', title: 'JWT embedded in client-side JavaScript', description: 'A signed token is shipped inside a script payload. Anyone can extract it and, if valid, impersonate the associated identity or call the backing API.', remediation: 'Never embed tokens in static assets. Issue tokens per-session after authentication and store them in HttpOnly cookies.', cwe: 'CWE-798' });
  }
  if (src.storage) {
    out.push({ ...base, id: 'jwt-in-web-storage', severity: 'high', title: `JWT stored in ${src.where.split('[')[0]}`, description: 'Web Storage is fully readable by any script on the origin. One XSS bug equals complete session theft, and the token survives tab closure (localStorage).', remediation: 'Move the token to an HttpOnly, Secure, SameSite cookie. If a bearer token is unavoidable, keep it in memory only and use short expiry with refresh-token rotation.', cwe: 'CWE-922', owasp: 'A07:2021 Identification and Authentication Failures' });
  }

  if (alg === 'NONE' || !signature) {
    out.push({ ...base, id: 'jwt-alg-none', severity: 'critical', title: 'JWT uses alg=none / unsigned', description: 'The token carries no cryptographic signature. If the server accepts it, anyone can forge arbitrary claims (e.g. role=admin).', remediation: 'Reject alg=none server-side and pin the expected algorithm (e.g. RS256/ES256) in your JWT library configuration.', cwe: 'CWE-347' });
  } else if (/^HS/.test(alg)) {
    out.push({ ...base, id: 'jwt-symmetric-alg', severity: 'low', title: `JWT signed with symmetric ${alg}`, description: 'HMAC tokens share one secret between issuer and every verifier; weak or leaked secrets allow forgery, and offline brute-force is feasible for short secrets.', remediation: 'Prefer asymmetric RS256/ES256/EdDSA so verifiers only hold the public key; if HMAC is retained use ≥256-bit random secrets and rotate them.', cwe: 'CWE-327' });
  }
  if (header.jku || header.x5u) {
    out.push({ ...base, id: 'jwt-remote-key-header', severity: 'medium', title: `JWT header contains ${header.jku ? 'jku' : 'x5u'}`, description: 'Remote key URLs in the header are a classic vector: if the verifier fetches keys from an attacker-controlled URL the signature check can be bypassed.', remediation: 'Verifiers must ignore jku/x5u or restrict them to an allow-list of trusted key endpoints.', cwe: 'CWE-347' });
  }

  if (payload.exp == null) {
    out.push({ ...base, id: 'jwt-no-exp', severity: 'medium', title: 'JWT has no expiration (exp) claim', description: 'A stolen token remains valid forever unless the server maintains a revocation list.', remediation: 'Always set exp (≤15 min for access tokens) and use refresh tokens for longevity.', cwe: 'CWE-613' });
  } else {
    const now = Date.now() / 1000;
    const ttl = payload.exp - (payload.iat || now);
    if (payload.exp < now) out.push({ ...base, id: 'jwt-expired', severity: 'info', title: 'Expired JWT observed', description: `Token expired at ${new Date(payload.exp * 1000).toISOString()}. Leftover expired tokens indicate stale test data or missing cleanup.`, remediation: 'Remove stale tokens from assets/storage.' });
    else if (ttl > 60 * 60 * 24 * 7) out.push({ ...base, id: 'jwt-long-ttl', severity: 'low', title: `JWT lifetime is ${Math.round(ttl / 86400)} days`, description: 'Long-lived tokens dramatically extend the impact window of a leak.', remediation: 'Use short-lived access tokens (5–15 minutes) with rotating refresh tokens.', cwe: 'CWE-613' });
  }

  const sensitiveKeys = Object.keys(payload).filter(k => SENSITIVE_CLAIMS.test(k));
  if (sensitiveKeys.length) {
    out.push({ ...base, id: 'jwt-sensitive-claims', severity: 'medium', title: `JWT payload exposes sensitive claims: ${sensitiveKeys.join(', ')}`, description: 'JWT payloads are only base64-encoded, not encrypted. Anyone holding the token (logs, proxies, browser extensions) can read these values.', remediation: 'Keep PII out of tokens; reference the user by opaque ID and look up details server-side, or use JWE for encryption.', cwe: 'CWE-312', owasp: 'A02:2021 Cryptographic Failures' });
  }
  if (/^(admin|root|superuser)$/i.test(String(payload.role || payload.roles || '')) || payload.isAdmin === true || payload.admin === true) {
    out.push({ ...base, id: 'jwt-privileged-claims', severity: 'medium', title: 'JWT carries privileged role claims', description: 'Authorization is asserted inside the token. Combined with weak signing or alg=none, this permits privilege escalation.', remediation: 'Derive authorization server-side from the subject; treat role claims as hints, never as the source of truth.', cwe: 'CWE-285', owasp: 'A01:2021 Broken Access Control' });
  }
  return out;
}

function redactClaims(p) {
  const out = {};
  for (const [k, v] of Object.entries(p)) out[k] = SENSITIVE_CLAIMS.test(k) ? '[redacted]' : v;
  return out;
}
