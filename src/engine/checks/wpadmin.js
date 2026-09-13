/**
 * WordPress, PHP & Admin Login Security Analyzer.
 * Probes for exposed administrative consoles, WordPress XML-RPC abuse vectors,
 * user enumeration endpoints, and insecure phpMyAdmin exposures.
 */

const ADMIN_PATHS = [
  { path: '/wp-login.php', name: 'WordPress Login Page', category: 'WordPress' },
  { path: '/wp-admin/', name: 'WordPress Admin Console', category: 'WordPress' },
  { path: '/xmlrpc.php', name: 'WordPress XML-RPC API', category: 'WordPress' },
  { path: '/wp-json/wp/v2/users', name: 'WordPress User Enumeration API', category: 'WordPress' },
  { path: '/?author=1', name: 'WordPress Author 1 Enumeration', category: 'WordPress' },
  { path: '/phpmyadmin/', name: 'phpMyAdmin Database Panel', category: 'PHP / Database' },
  { path: '/pma/', name: 'phpMyAdmin Short Path', category: 'PHP / Database' },
  { path: '/administrator/', name: 'Joomla Admin Console', category: 'Joomla' },
  { path: '/admin/', name: 'Generic Admin Portal', category: 'Admin' },
  { path: '/admin/login', name: 'Admin Login Endpoint', category: 'Admin' },
];

export async function checkWpAdminSecurity(targetUrl, { timeoutMs = 4000 } = {}) {
  const origin = new URL(targetUrl).origin;
  const findings = [];
  const exposedEndpoints = [];
  const userEnumeration = { vulnerable: false, usernames: [] };
  let xmlRpcExposed = false;
  let isWordpress = false;
  let isPhp = false;

  const probePath = async (item) => {
    const url = `${origin}${item.path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
        redirect: 'manual', // Detect 301/302 redirects without automatically following
        headers: {
          'User-Agent': 'Monarch-Security-Engine WP-Audit',
        },
      });
      clearTimeout(timer);

      const status = res.status;
      const contentType = res.headers.get('content-type') || '';
      const location = res.headers.get('location') || '';

      // Check author enumeration redirect
      if (item.path === '/?author=1') {
        if (status === 301 || status === 302) {
          const match = location.match(/\/author\/([^/]+)/i);
          if (match && match[1]) {
            userEnumeration.vulnerable = true;
            userEnumeration.usernames.push(match[1]);
            findings.push({
              id: 'wp-author-enumeration',
              category: 'wpadmin',
              severity: 'medium',
              title: 'WordPress author ID enumeration exposes username',
              location: url,
              description: `Requesting /?author=1 redirected to "${location}", revealing username "${match[1]}". Attackers use this to prepare targeted brute-force attacks.`,
              evidence: { redirectLocation: location, revealedUsername: match[1] },
              remediation: 'Disable author archives via functions.php or redirect author query parameters to the homepage.',
            });
          }
        }
        return;
      }

      // Check REST API user enumeration
      if (item.path === '/wp-json/wp/v2/users' && status === 200) {
        try {
          const json = await res.json();
          if (Array.isArray(json) && json.length > 0) {
            isWordpress = true;
            const names = json.map(u => u.slug || u.name).filter(Boolean);
            userEnumeration.vulnerable = true;
            userEnumeration.usernames.push(...names);
            findings.push({
              id: 'wp-rest-users-leak',
              category: 'wpadmin',
              severity: 'medium',
              title: 'WordPress REST API exposes user directory without authentication',
              location: url,
              description: `Endpoint /wp-json/wp/v2/users returned ${json.length} user profile(s) publicly: ${names.join(', ')}.`,
              evidence: { users: names.slice(0, 5) },
              remediation: 'Restrict access to /wp-json/wp/v2/users for unauthenticated requests using a security plugin or filter.',
            });
          }
        } catch { /* ignore */ }
        return;
      }

      // Check XML-RPC
      if (item.path === '/xmlrpc.php') {
        if (status === 200 || status === 405) {
          xmlRpcExposed = true;
          isWordpress = true;
          findings.push({
            id: 'wp-xmlrpc-exposed',
            category: 'wpadmin',
            severity: 'medium',
            title: 'WordPress XML-RPC interface is publicly enabled',
            location: url,
            description: 'XML-RPC allows remote management but is commonly abused for brute-force amplification (system.multicall) and DDoS reflection.',
            evidence: { status, url },
            remediation: 'Disable XML-RPC via .htaccess or web server config if not required by mobile apps or Jetpack.',
          });
        }
        return;
      }

      // Check exposed admin login or panels
      if (status >= 200 && status < 400) {
        if (item.path.includes('wp-')) isWordpress = true;
        if (item.path.includes('php')) isPhp = true;

        exposedEndpoints.push({
          path: item.path,
          name: item.name,
          category: item.category,
          status,
          url,
        });

        // Flag phpMyAdmin as high severity
        if (item.path.includes('phpmyadmin') || item.path.includes('/pma/')) {
          findings.push({
            id: 'phpmyadmin-publicly-exposed',
            category: 'wpadmin',
            severity: 'high',
            title: 'phpMyAdmin database administration panel exposed to public internet',
            location: url,
            description: 'phpMyAdmin panel is accessible without IP restrictions or VPN, exposing the underlying database to brute force and zero-day vulnerabilities.',
            evidence: { status, url },
            remediation: 'Restrict phpMyAdmin to internal VPN addresses or localhost; enable multi-factor authentication (MFA).',
          });
        }

        // Flag wp-login / wp-admin as informational / low
        if (item.path === '/wp-login.php' || item.path === '/wp-admin/') {
          findings.push({
            id: 'wp-login-exposed',
            category: 'wpadmin',
            severity: 'low',
            title: 'Default WordPress administrative login page is publicly exposed',
            location: url,
            description: 'The standard /wp-login.php page is publicly reachable, inviting automated brute-force attempts and credential stuffing.',
            evidence: { status, url },
            remediation: 'Protect wp-login.php with HTTP Basic Auth, IP allow-listing, rate limiting, and 2FA (Two-Factor Authentication).',
          });
        }
      }
    } catch {
      // Endpoint timed out or refused — that is secure/offline
    }
  };

  await Promise.all(ADMIN_PATHS.map(probePath));

  return {
    isWordpress,
    isPhp,
    xmlRpcExposed,
    userEnumeration: {
      vulnerable: userEnumeration.vulnerable,
      usernames: [...new Set(userEnumeration.usernames)],
    },
    exposedEndpoints,
    findings,
  };
}
