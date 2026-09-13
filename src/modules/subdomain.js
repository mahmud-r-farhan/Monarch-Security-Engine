import dns from 'node:dns/promises';
import { URL } from 'node:url';

/**
 * Subdomain & Asset Discovery
 * - Certificate Transparency via crt.sh (optional)
 * - DNS enumeration for common subdomains
 * - Sitemap parsing
 */

const COMMON_SUBDOMAINS = [
  'www', 'api', 'admin', 'app', 'blog', 'dev', 'staging', 'test', 'mail', 'ftp',
  'shop', 'store', 'support', 'help', 'docs', 'cdn', 'static', 'assets', 'img',
  'vpn', 'secure', 'portal', 'dashboard', 'panel', 'beta', 'alpha', 'demo',
  'm', 'mobile', 'webmail', 'email', 'mx', 'ns1', 'ns2', 'cpanel', 'whm',
  'autodiscover', 'autoconfig', 'webdisk', 'sso', 'auth', 'login', 'signin',
  'graphql', 'rest', 'v1', 'v2', 'internal', 'private', 'prod', 'production',
];

export async function enumerateSubdomains(domain, { concurrency = 10, timeoutMs = 3000, includeCommon = true } = {}) {
  const baseDomain = extractBaseDomain(domain);
  const results = [];
  const queue = includeCommon ? [...COMMON_SUBDOMAINS] : [];

  // Also try to get from certificate transparency (crt.sh) if internet available
  try {
    const ctResults = await fetchCTSubdomains(baseDomain, timeoutMs);
    for (const sub of ctResults) {
      if (!queue.includes(sub.split('.')[0])) {
        // Add full subdomain for checking
        results.push({ subdomain: sub, source: 'ct', status: 'discovered' });
      }
    }
  } catch {
    // CT lookup failed, continue with brute force
  }

  // Brute force common subdomains via DNS
  const workers = [];
  let index = 0;

  const worker = async () => {
    while (index < queue.length) {
      const sub = queue[index++];
      const fqdn = `${sub}.${baseDomain}`;
      try {
        const addrs = await dns.resolve(fqdn);
        if (addrs && addrs.length) {
          results.push({
            subdomain: fqdn,
            source: 'dns',
            ips: addrs,
            status: 'resolved',
          });
        }
      } catch {
        // Not resolved
      }
    }
  };

  for (let i = 0; i < Math.min(concurrency, queue.length); i++) {
    workers.push(worker());
  }

  await Promise.all(workers);

  return {
    domain: baseDomain,
    count: results.length,
    subdomains: results.slice(0, 100),
  };
}

async function fetchCTSubdomains(domain, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Monarch-Security-Engine Subdomain-Enum' },
    });

    if (!res.ok) return [];

    const data = await res.json();
    const subdomains = new Set();

    for (const entry of data) {
      const names = (entry.name_value || '').split('\n');
      for (let name of names) {
        name = name.trim().toLowerCase();
        if (name.endsWith(domain) && !name.includes('*')) {
          subdomains.add(name);
        }
      }
    }

    return Array.from(subdomains).slice(0, 50);
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

function extractBaseDomain(input) {
  try {
    const url = new URL(input.includes('://') ? input : `https://${input}`);
    return url.hostname.replace(/^www\./, '');
  } catch {
    return input.replace(/^www\./, '').split('/')[0];
  }
}

export async function parseSitemap(target, { timeoutMs = 5000 } = {}) {
  try {
    const base = new URL(target.includes('://') ? target : `https://${target}`).origin;
    const sitemapUrls = [`${base}/sitemap.xml`, `${base}/sitemap_index.xml`, `${base}/robots.txt`];

    const discovered = new Set();
    const sitemaps = [];

    for (const sitemapUrl of sitemapUrls) {
      try {
        const res = await fetch(sitemapUrl, {
          signal: AbortSignal.timeout(timeoutMs),
          headers: { 'User-Agent': 'Monarch-Security-Engine Sitemap-Parser' },
        });

        if (!res.ok) continue;

        const text = await res.text();

        if (sitemapUrl.endsWith('robots.txt')) {
          // Parse robots.txt for sitemap locations
          const matches = text.matchAll(/Sitemap:\s*(\S+)/gi);
          for (const m of matches) {
            sitemaps.push(m[1]);
          }
          continue;
        }

        // Parse XML sitemap
        const locMatches = text.matchAll(/<loc>([^<]+)<\/loc>/gi);
        for (const m of locMatches) {
          const loc = m[1].trim();
          if (loc.endsWith('.xml')) {
            sitemaps.push(loc);
          } else {
            discovered.add(loc);
          }
        }
      } catch {
        // Continue
      }
    }

    // Parse nested sitemaps
    for (const nested of sitemaps.slice(0, 5)) {
      try {
        const res = await fetch(nested, {
          signal: AbortSignal.timeout(timeoutMs),
          headers: { 'User-Agent': 'Monarch-Security-Engine Sitemap-Parser' },
        });
        if (!res.ok) continue;
        const text = await res.text();
        const locMatches = text.matchAll(/<loc>([^<]+)<\/loc>/gi);
        for (const m of locMatches) {
          const loc = m[1].trim();
          if (!loc.endsWith('.xml')) discovered.add(loc);
        }
      } catch {
        // Ignore
      }
    }

    return {
      target: base,
      sitemaps,
      urls: Array.from(discovered).slice(0, 200),
      count: discovered.size,
    };
  } catch (err) {
    return { error: err.message, urls: [], count: 0 };
  }
}

export async function analyzeRobotsTxt(target, { timeoutMs = 5000 } = {}) {
  try {
    const base = new URL(target.includes('://') ? target : `https://${target}`).origin;
    const res = await fetch(`${base}/robots.txt`, {
      signal: AbortSignal.timeout(timeoutMs),
      headers: { 'User-Agent': 'Monarch-Security-Engine Robots-Analyzer' },
    });

    if (!res.ok) {
      return { url: `${base}/robots.txt`, exists: false, status: res.status };
    }

    const text = await res.text();
    const lines = text.split('\n');

    const disallows = [];
    const allows = [];
    const sitemaps = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      if (/^disallow:/i.test(trimmed)) {
        const path = trimmed.split(':').slice(1).join(':').trim();
        if (path) disallows.push(path);
      } else if (/^allow:/i.test(trimmed)) {
        const path = trimmed.split(':').slice(1).join(':').trim();
        if (path) allows.push(path);
      } else if (/^sitemap:/i.test(trimmed)) {
        const url = trimmed.split(':').slice(1).join(':').trim();
        if (url) sitemaps.push(url);
      }
    }

    const sensitive = disallows.filter((p) => /(admin|backup|private|internal|secret|config|dev|staging|\.env|\.git)/i.test(p));

    return {
      url: `${base}/robots.txt`,
      exists: true,
      status: res.status,
      size: text.length,
      disallowCount: disallows.length,
      allowCount: allows.length,
      sitemapCount: sitemaps.length,
      disallows: disallows.slice(0, 50),
      allows: allows.slice(0, 50),
      sitemaps,
      sensitivePaths: sensitive,
      hasSensitiveHints: sensitive.length > 0,
    };
  } catch (err) {
    return { error: err.message, exists: false };
  }
}
