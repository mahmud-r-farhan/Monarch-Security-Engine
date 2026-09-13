export function transportCheck(ctx) {
  const findings = [];
  const first = ctx.pages[0];
  if (!first) return findings;

  if (!first.finalUrl.startsWith('https://')) {
    findings.push({ id: 'no-https', severity: 'critical', category: 'transport', location: first.finalUrl, title: 'Site is served over plaintext HTTP', description: 'All traffic — including credentials, cookies and page content — can be read and modified by anyone on the network path.', remediation: 'Obtain a TLS certificate (e.g. Let\'s Encrypt), serve exclusively on 443, and redirect HTTP → HTTPS with a 301 before enabling HSTS.', cwe: 'CWE-319', owasp: 'A02:2021 Cryptographic Failures', references: ['https://letsencrypt.org/getting-started/'] });
  } else if (first.redirectChain.some(u => u.startsWith('http://')) === false && ctx.origin.startsWith('https://')) {
    // We reached https directly; check whether the http variant redirects (observed in network log if the user gave http:// input).
  }

  const httpsToHttp = ctx.pages.filter(p => p.url.startsWith('https://') && p.finalUrl.startsWith('http://'));
  if (httpsToHttp.length) findings.push({ id: 'https-downgrade-redirect', severity: 'high', category: 'transport', location: httpsToHttp[0].url, title: 'HTTPS page redirects to HTTP', description: 'A secure URL downgrades the user to plaintext, defeating TLS entirely.', evidence: httpsToHttp.slice(0, 5).map(p => `${p.url} → ${p.finalUrl}`), remediation: 'Fix redirect targets to use https:// and enable HSTS.', cwe: 'CWE-319', owasp: 'A02:2021 Cryptographic Failures' });

  const mixed = ctx.pages.flatMap(p => p.mixedContent.map(u => ({ page: p.finalUrl, url: u })));
  if (mixed.length) {
    const active = mixed.filter(m => /\.(js|css)(\?|$)/i.test(m.url) || ctx.assets.find(a => a.url === m.url && (a.type === 'script' || a.type === 'stylesheet' || a.type === 'iframe')));
    findings.push({ id: active.length ? 'mixed-content-active' : 'mixed-content-passive', severity: active.length ? 'high' : 'low', category: 'transport', location: mixed[0].page, title: `${active.length ? 'Active' : 'Passive'} mixed content: ${mixed.length} insecure resource(s) on HTTPS page(s)`, description: active.length ? 'Scripts/styles/frames loaded over HTTP can be replaced by a network attacker, giving them full control of the secure page.' : 'Images/media over HTTP break the padlock and can be swapped by network attackers.', evidence: [...new Set(mixed.map(m => m.url))].slice(0, 10), remediation: 'Load all sub-resources over HTTPS, or add CSP `upgrade-insecure-requests` as a stop-gap.', cwe: 'CWE-311', owasp: 'A02:2021 Cryptographic Failures', references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content'] });
  }

  const longChains = ctx.pages.filter(p => p.redirectChain.length >= 3);
  if (longChains.length) findings.push({ id: 'long-redirect-chain', severity: 'info', category: 'transport', location: longChains[0].url, title: `Redirect chain of ${longChains[0].redirectChain.length} hops`, description: 'Every hop is an opportunity for downgrade and adds latency.', evidence: [...longChains[0].redirectChain, longChains[0].finalUrl], remediation: 'Redirect directly to the canonical HTTPS URL in one hop.' });

  // CORS
  if (ctx.cors?.allowOrigin) {
    const ao = ctx.cors.allowOrigin;
    const creds = /true/i.test(ctx.cors.allowCredentials || '');
    if (ao === ctx.cors.requestedOrigin || ao === '*') {
      findings.push({ id: creds && ao !== '*' ? 'cors-reflect-with-credentials' : 'cors-permissive', severity: creds && ao !== '*' ? 'critical' : ao === '*' ? 'low' : 'medium', category: 'transport', location: ctx.origin, title: creds && ao !== '*' ? 'CORS reflects arbitrary Origin with credentials' : ao === '*' ? 'CORS allows any origin (*)' : 'CORS reflects arbitrary Origin header', description: creds && ao !== '*' ? 'Any website can make authenticated cross-origin requests and read the responses — full account takeover for logged-in users.' : ao === '*' ? 'Responses are readable by any origin. Harmless for public data, dangerous if this endpoint ever serves user-specific content.' : 'The server echoes back whatever Origin it receives; combined with credentials this is exploitable.', evidence: { requestedOrigin: ctx.cors.requestedOrigin, 'access-control-allow-origin': ao, 'access-control-allow-credentials': ctx.cors.allowCredentials }, remediation: 'Validate Origin against a strict allow-list; never combine a reflected origin with Access-Control-Allow-Credentials: true.', cwe: 'CWE-942', owasp: 'A05:2021 Security Misconfiguration', references: ['https://portswigger.net/web-security/cors'] });
    }
  }
  return findings;
}
