/**
 * Deterministic rule-based analyst — the offline fallback.
 * Produces the same insight shape as the AI providers using only the scan data,
 * so the product always generates a remediation plan (no key, provider error,
 * or malformed model output all land here).
 */
import { safeHost, groupBy } from './util.js';

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
