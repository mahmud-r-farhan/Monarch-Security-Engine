/**
 * Technology Stack Fingerprinting & API Rate Limit Analyzer.
 * Identifies frameworks, libraries, CMS, and servers from headers, HTML patterns, and DOM markers.
 */

const FINGERPRINTS = [
  // Frameworks & Libraries
  { name: 'Next.js', category: 'Framework', header: 'x-nextjs-page', html: [/__next/i, /_next\/static/i] },
  { name: 'React', category: 'Frontend', html: [/data-reactroot/i, /__reactFiber/i, /react(-dom)?(\.min)?\.js/i] },
  { name: 'Nuxt.js', category: 'Framework', html: [/__nuxt/i, /_nuxt\//i] },
  { name: 'Vue.js', category: 'Frontend', html: [/data-v-[a-f0-9]/i, /vue(\.runtime)?(\.min)?\.js/i] },
  { name: 'Angular', category: 'Frontend', html: [/ng-version=/i, /ng-app=/i] },
  { name: 'Svelte', category: 'Frontend', html: [/class="svelte-[a-z0-9]+"/i] },
  { name: 'jQuery', category: 'Library', html: [/jquery([.-]\d+)?(\.min)?\.js/i] },
  { name: 'Tailwind CSS', category: 'CSS Framework', html: [/class="[^"]*(?:flex|grid|text-|bg-|p-|m-|rounded-)[^"]*"/i] },
  { name: 'Bootstrap', category: 'CSS Framework', html: [/bootstrap(\.min)?\.(css|js)/i, /class="[^"]*(?:container|row|col-|btn-|navbar-)[^"]*"/i] },

  // CMS
  { name: 'WordPress', category: 'CMS', html: [/\/wp-content\//i, /\/wp-includes\//i, /name="generator" content="WordPress/i] },
  { name: 'Drupal', category: 'CMS', header: 'x-drupal-cache', html: [/Drupal\.settings/i, /name="generator" content="Drupal/i] },
  { name: 'Joomla', category: 'CMS', html: [/\/media\/jui\//i, /name="generator" content="Joomla!/i] },
  { name: 'Shopify', category: 'E-commerce', html: [/cdn\.shopify\.com/i, /Shopify\.theme/i] },

  // Backend Platforms & Servers
  { name: 'Express.js', category: 'Backend', headerVal: { header: 'x-powered-by', match: /express/i } },
  { name: 'Fastify', category: 'Backend', headerVal: { header: 'x-powered-by', match: /fastify/i } },
  { name: 'ASP.NET', category: 'Backend', header: 'x-aspnet-version', headerVal: { header: 'x-powered-by', match: /asp\.net/i } },
  { name: 'PHP', category: 'Language', headerVal: { header: 'x-powered-by', match: /php/i } },
  { name: 'Django', category: 'Backend', cookie: /csrftoken/i },
  { name: 'Ruby on Rails', category: 'Backend', cookie: /_session_id/i, headerVal: { header: 'x-powered-by', match: /phusion_passenger|rails/i } },
  { name: 'Laravel', category: 'Backend', cookie: /laravel_session|XSRF-TOKEN/i, headerVal: { header: 'x-powered-by', match: /laravel/i } },
  { name: 'Spring Boot', category: 'Backend', headerVal: { header: 'x-application-context', match: /./i } },

  // CDNs & Infrastructure
  { name: 'Cloudflare', category: 'CDN / WAF', header: 'cf-ray', headerVal: { header: 'server', match: /cloudflare/i } },
  { name: 'AWS CloudFront', category: 'CDN', header: 'x-amz-cf-id', headerVal: { header: 'via', match: /cloudfront/i } },
  { name: 'Vercel', category: 'PaaS', header: 'x-vercel-id', headerVal: { header: 'server', match: /vercel/i } },
  { name: 'Netlify', category: 'PaaS', header: 'x-nf-request-id', headerVal: { header: 'server', match: /netlify/i } },
  { name: 'Nginx', category: 'Web Server', headerVal: { header: 'server', match: /nginx/i } },
  { name: 'Apache', category: 'Web Server', headerVal: { header: 'server', match: /apache/i } },
  { name: 'Caddy', category: 'Web Server', headerVal: { header: 'server', match: /caddy/i } },
];

export function checkTechStack(crawl, network) {
  const findings = [];
  const detected = new Map();

  // Inspect pages
  for (const page of crawl.pages || []) {
    const html = page.html || '';
    const headers = page.headers || {};

    for (const fp of FINGERPRINTS) {
      if (detected.has(fp.name)) continue;

      let matched = false;
      let evidence = '';

      if (fp.header && headers[fp.header.toLowerCase()]) {
        matched = true;
        evidence = `Header "${fp.header}": ${headers[fp.header.toLowerCase()]}`;
      } else if (fp.headerVal) {
        const val = headers[fp.headerVal.header.toLowerCase()];
        if (val && fp.headerVal.match.test(val)) {
          matched = true;
          evidence = `Header "${fp.headerVal.header}": ${val}`;
        }
      } else if (fp.html) {
        for (const pattern of fp.html) {
          if (pattern.test(html)) {
            matched = true;
            evidence = `Pattern ${pattern} matched in HTML source`;
            break;
          }
        }
      }

      if (matched) {
        detected.set(fp.name, {
          name: fp.name,
          category: fp.category,
          evidence,
          detectedAt: page.url,
        });
      }
    }
  }

  // Inspect network log headers & cookies
  for (const entry of (network.entries || [])) {
    const headers = entry.response?.headers || {};

    for (const fp of FINGERPRINTS) {
      if (detected.has(fp.name)) continue;

      if (fp.header && headers[fp.header.toLowerCase()]) {
        detected.set(fp.name, {
          name: fp.name,
          category: fp.category,
          evidence: `Observed header "${fp.header}" on ${entry.url}`,
          detectedAt: entry.url,
        });
      } else if (fp.headerVal) {
        const val = headers[fp.headerVal.header.toLowerCase()];
        if (val && fp.headerVal.match.test(val)) {
          detected.set(fp.name, {
            name: fp.name,
            category: fp.category,
            evidence: `Observed header "${fp.headerVal.header}": ${val}`,
            detectedAt: entry.url,
          });
        }
      }
    }
  }

  // Rate Limiting Analysis across network requests
  const apiRequests = (network.entries || []).filter(e => {
    const url = e.url || '';
    return url.includes('/api/') || url.includes('/v1/') || url.includes('/v2/') || url.includes('/graphql');
  });

  let hasRateLimitHeaders = false;
  let sampleRateLimitHeader = null;

  for (const req of (network.entries || [])) {
    const headers = req.response?.headers || {};
    for (const h of Object.keys(headers)) {
      if (h.startsWith('x-ratelimit-') || h.startsWith('ratelimit-') || h === 'retry-after') {
        hasRateLimitHeaders = true;
        sampleRateLimitHeader = `${h}: ${headers[h]}`;
        break;
      }
    }
    if (hasRateLimitHeaders) break;
  }

  // If there are multiple API requests but zero rate-limiting headers observed
  if (apiRequests.length >= 2 && !hasRateLimitHeaders) {
    findings.push({
      id: 'missing-rate-limit-headers',
      category: 'api',
      severity: 'low',
      title: 'API endpoints lack standard rate-limiting headers',
      location: apiRequests[0]?.url || 'API endpoints',
      description: 'API responses do not expose standard RateLimit (RFC draft) or X-RateLimit-* headers to signal client quota limits.',
      evidence: {
        apiSample: apiRequests.slice(0, 3).map(r => r.url),
        note: 'Absence of rate limiting headers may allow automated credential stuffing or scraping.',
      },
      remediation: 'Implement token-bucket or sliding-window rate limiting on all API routes and return standard headers: RateLimit-Limit, RateLimit-Remaining, and RateLimit-Reset.',
    });
  }

  return {
    technologies: Array.from(detected.values()),
    rateLimiting: {
      enforced: hasRateLimitHeaders,
      sampleHeader: sampleRateLimitHeader,
      apiRequestsObserved: apiRequests.length,
    },
    findings,
  };
}
