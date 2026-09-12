/**
 * Sensitive file & endpoint exposure derived from the well-known probes.
 */
const SIGNATURES = {
  '/.env': { re: /^[A-Z_]+=.+/m, title: 'Environment file (.env) is publicly accessible', severity: 'critical', cwe: 'CWE-538' },
  '/.git/HEAD': { re: /^ref: refs\//m, title: 'Git repository metadata (.git/) is exposed', severity: 'critical', cwe: 'CWE-538' },
  '/.git/config': { re: /\[core\]/, title: 'Git config is exposed', severity: 'critical', cwe: 'CWE-538' },
  '/server-status': { re: /Apache Server Status|Server Version/i, title: 'Apache server-status page is public', severity: 'medium', cwe: 'CWE-200' },
  '/phpinfo.php': { re: /phpinfo\(\)|PHP Version/i, title: 'phpinfo() page is public', severity: 'high', cwe: 'CWE-200' },
  '/.DS_Store': { re: /\x00\x00\x00\x01Bud1/, title: '.DS_Store file exposed (directory listing leak)', severity: 'low', cwe: 'CWE-538' },
  '/backup.zip': { re: /^PK/, title: 'Backup archive is downloadable', severity: 'critical', cwe: 'CWE-538' },
  '/config.json': { re: /"(secret|password|key|token|db|database)"/i, title: 'Configuration JSON with credential-like keys is public', severity: 'high', cwe: 'CWE-538' },
};

export function exposureCheck(ctx) {
  const findings = [];
  for (const p of ctx.probes) {
    if (p.status !== 200) continue;
    const sig = SIGNATURES[p.path];
    if (sig) {
      if (!sig.re.test(p.snippet)) continue; // catch-all 200 pages (SPA fallbacks) are ignored unless content matches
      findings.push({ id: `exposed-${p.path.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '').toLowerCase()}`, severity: sig.severity, category: 'exposure', location: p.finalUrl, title: sig.title, description: `GET ${p.path} returned 200 with content matching the expected signature. This commonly leaks credentials, source code, or internal topology.`, evidence: { status: p.status, contentType: p.contentType, snippet: p.snippet.slice(0, 120).replace(/[^\x20-\x7e\n]/g, '.') }, remediation: 'Block access at the web-server layer (deny dot-files and archives), remove the artifact from the web root, and rotate any credentials it contained.', cwe: sig.cwe, owasp: 'A05:2021 Security Misconfiguration', references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/'] });
      continue;
    }
    if (p.path === '/.well-known/security.txt') continue; // handled below as positive signal
    if ((p.path === '/swagger.json' || p.path === '/openapi.json') && /"(openapi|swagger)"/.test(p.snippet)) {
      findings.push({ id: 'api-spec-public', severity: 'info', category: 'exposure', location: p.finalUrl, title: 'Public API specification discovered', description: 'An OpenAPI/Swagger document is exposed. Useful for attackers mapping the attack surface; acceptable for intentionally public APIs.', evidence: { path: p.path }, remediation: 'Restrict to authenticated users if the API is not intended to be public.' });
    }
    if (p.path === '/graphql' && /graphql|query|errors/i.test(p.snippet)) {
      findings.push({ id: 'graphql-endpoint', severity: 'info', category: 'exposure', location: p.finalUrl, title: 'GraphQL endpoint discovered', description: 'Verify introspection is disabled in production and query depth/complexity limits are enforced.', remediation: 'Disable introspection, add depth limiting and persisted queries.', references: ['https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'] });
    }
    if (p.path === '/admin' && !/text\/html/i.test(p.contentType) === false && p.status === 200 && /login|password|admin/i.test(p.snippet)) {
      findings.push({ id: 'admin-panel-exposed', severity: 'low', category: 'exposure', location: p.finalUrl, title: 'Admin interface reachable from the public internet', description: 'Admin panels are prime targets for credential stuffing and brute force.', remediation: 'Restrict by IP/VPN, enforce MFA, and rate-limit authentication attempts.', cwe: 'CWE-284' });
    }
  }

  const secTxt = ctx.probes.find(p => p.path === '/.well-known/security.txt');
  if (!secTxt || secTxt.status !== 200 || !/contact:/i.test(secTxt.snippet)) {
    findings.push({ id: 'no-security-txt', severity: 'info', category: 'exposure', location: ctx.origin + '/.well-known/security.txt', title: 'No security.txt vulnerability-disclosure contact', description: 'Researchers have no sanctioned channel to report issues (RFC 9116).', remediation: 'Publish /.well-known/security.txt with Contact:, Expires: and Policy: fields.', references: ['https://securitytxt.org/'] });
  }

  const robots = ctx.probes.find(p => p.path === '/robots.txt');
  if (robots?.status === 200) {
    const sensitive = (robots.snippet.match(/Disallow:\s*(\S*(admin|backup|private|internal|secret|config|dev|staging)\S*)/gi) || []).slice(0, 5);
    if (sensitive.length) findings.push({ id: 'robots-sensitive-paths', severity: 'info', category: 'exposure', location: robots.finalUrl, title: 'robots.txt hints at sensitive paths', description: 'Disallow rules advertise interesting locations to attackers; they do not restrict access.', evidence: sensitive, remediation: 'Protect sensitive paths with authentication rather than listing them in robots.txt.' });
  }
  return findings;
}
