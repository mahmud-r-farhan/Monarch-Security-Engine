/**
 * Information disclosure via response headers and error pages across the whole network log.
 */
const VERSION_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-drupal-cache', 'x-backend-server'];

export function infoLeakCheck(ctx) {
  const findings = [];
  const seen = new Map();
  for (const e of ctx.network) {
    if (!e.response) continue;
    for (const h of VERSION_HEADERS) {
      const v = e.response.headers[h];
      if (!v) continue;
      const hasVersion = /\d+\.\d+/.test(v);
      const key = `${h}:${v}`;
      if (seen.has(key)) continue;
      seen.set(key, e.url);
      if (h === 'server' && !hasVersion) continue; // "nginx" alone is fine
      findings.push({ id: `version-disclosure-${h}`, severity: hasVersion ? 'low' : 'info', category: 'infoleak', location: e.url, title: `${h} header discloses ${hasVersion ? 'software version' : 'technology stack'}`, description: `Response header "${h}: ${v}" lets attackers target known CVEs for that exact version.`, evidence: { [h]: v }, remediation: h === 'server' ? 'Set server_tokens off (nginx) / ServerTokens Prod (Apache) or override at the CDN.' : `Remove the ${h} header (e.g. app.disable('x-powered-by') in Express, or expose_php=Off).`, cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration' });
    }
  }

  // Stack traces / debug output in bodies we captured (probes, pages).
  const bodies = [...ctx.probes.map(p => ({ url: p.finalUrl, text: p.snippet })), ...ctx.scriptBodies.map(s => ({ url: s.url, text: s.code.slice(0, 5000) }))];
  for (const b of bodies) {
    if (/(Traceback \(most recent call last\)|at\s+\w+\.\w+\s*\(.*\.java:\d+\)|Stack trace:|Exception in thread|Warning: .* on line \d+|node_modules\/.*\.js:\d+:\d+)/i.test(b.text)) {
      findings.push({ id: 'stack-trace-disclosure', severity: 'medium', category: 'infoleak', location: b.url, title: 'Stack trace / debug output disclosed', description: 'Detailed error output reveals file paths, framework internals and sometimes query fragments.', evidence: b.text.slice(0, 200), remediation: 'Disable debug mode in production and render generic error pages; log details server-side only.', cwe: 'CWE-209', owasp: 'A05:2021 Security Misconfiguration' });
      break;
    }
  }

  // Source maps for production bundles
  const maps = ctx.scriptBodies.filter(s => /\/\/# sourceMappingURL=/.test(s.code));
  if (maps.length) findings.push({ id: 'source-map-exposed', severity: 'info', category: 'infoleak', location: maps[0].url, title: `${maps.length} production script(s) reference source maps`, description: 'Source maps expose original (unminified) source, comments and internal file structure.', evidence: maps.slice(0, 5).map(m => m.url), remediation: 'Do not publish .map files for production builds, or restrict access to them.', cwe: 'CWE-540' });

  // Directory listing
  for (const p of ctx.pages) {
    if (p.title && /^Index of \//.test(p.title)) {
      findings.push({ id: 'directory-listing', severity: 'medium', category: 'infoleak', location: p.finalUrl, title: 'Directory listing enabled', description: 'The server enumerates files in this path, exposing backups, configs and unlinked content.', remediation: 'Disable autoindex / Options -Indexes.', cwe: 'CWE-548', owasp: 'A05:2021 Security Misconfiguration' });
    }
  }

  const errors = ctx.network.filter(e => e.status >= 500 && e.type === 'document');
  if (errors.length) findings.push({ id: 'server-errors', severity: 'low', category: 'infoleak', location: errors[0].url, title: `${errors.length} server error (5xx) response(s) during crawl`, description: 'Unhandled errors under normal navigation suggest fragile code paths that may be exploitable under malformed input.', evidence: errors.slice(0, 5).map(e => `${e.status} ${e.url}`), remediation: 'Investigate server logs for the failing routes.' });

  return findings;
}
