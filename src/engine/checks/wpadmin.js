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
  { path: '/wp-config.php.bak', name: 'WordPress Backup Config', category: 'WordPress Leak' },
  { path: '/wp-content/debug.log', name: 'WordPress Debug Log File', category: 'WordPress Leak' },
  { path: '/readme.html', name: 'WordPress Core Readme', category: 'WordPress Info' },
  { path: '/phpinfo.php', name: 'PHP Info Page', category: 'PHP Exposure' },
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
        const text = (await res.text().catch(() => '')).slice(0, 1000);
        const isRealXmlRpc = /XML-RPC server accepts POST requests only|xmlrpc|<methodResponse|<fault/i.test(text);
        if (isRealXmlRpc && (status === 200 || status === 405)) {
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
        const bodyText = status === 200 ? (await res.text().catch(() => '')).slice(0, 3000) : '';

        // Verify content signature to distinguish real exposures from SPA catch-all 200s
        const isSensitiveFile = item.path.includes('phpmyadmin') || item.path.includes('/pma/') || item.path.includes('wp-config') || item.path.includes('debug.log') || item.path.includes('phpinfo');
        if (isSensitiveFile) {
          if (status !== 200) return; // ignore 3xx redirects for sensitive file leaks
          let matchedSig = false;
          if (item.path.includes('wp-config')) matchedSig = /(DB_PASSWORD|DB_NAME|DB_USER|AUTH_KEY|SECURE_AUTH_KEY|<\?php)/i.test(bodyText);
          else if (item.path.includes('debug.log')) matchedSig = /(PHP Notice:|PHP Fatal error:|PHP Warning:|\[\d{2}-[A-Za-z]{3}-\d{4})/i.test(bodyText);
          else if (item.path.includes('phpinfo')) matchedSig = /(phpinfo\(\)|PHP Version|Configuration File.*php\.ini)/i.test(bodyText);
          else if (item.path.includes('phpmyadmin') || item.path.includes('/pma/')) matchedSig = /(phpmyadmin|pma_|pma_username|Welcome to phpMyAdmin)/i.test(bodyText);
          if (!matchedSig) return; // SPA or custom 200 page without true sensitive signature
        }

        if (item.path === '/wp-login.php' || item.path === '/wp-admin/') {
          if (status === 200 && bodyText && !/(user_login|wp-login|user_pass|wp-submit|wordpress|wp-admin)/i.test(bodyText)) {
            return; // Not a real WordPress login page
          }
        }

        if (item.path === '/readme.html') {
          if (status === 200 && bodyText && !/(WordPress|Semantic Personal Publishing Platform)/i.test(bodyText)) {
            return;
          }
        }

        if (item.path.startsWith('/admin') || item.path === '/administrator/') {
          if (status === 200 && bodyText && !/(login|username|password|admin|auth|sign\s*in|joomla|dashboard)/i.test(bodyText)) {
            return;
          }
        }

        if (item.path.includes('wp-')) isWordpress = true;
        if (item.path.includes('php')) isPhp = true;

        exposedEndpoints.push({
          path: item.path,
          name: item.name,
          category: item.category,
          status,
          url,
        });

        // Flag phpMyAdmin or sensitive leaks as high severity
        if (isSensitiveFile) {
          findings.push({
            id: 'sensitive-admin-file-exposed',
            category: 'wpadmin',
            severity: 'high',
            title: `Sensitive admin resource "${item.name}" exposed publicly`,
            location: url,
            description: `The file or panel at "${item.path}" is accessible publicly. It may leak database credentials, server paths, secret salts, or administrative access.`,
            evidence: { status, url, item: item.name },
            remediation: 'Remove or restrict public web access to this file immediately; disable phpinfo() in production.',
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
