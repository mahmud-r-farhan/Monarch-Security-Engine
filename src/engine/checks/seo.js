import * as cheerio from 'cheerio';

/**
 * AIO & SEO Analyzer.
 * Audits technical SEO, social metadata (OpenGraph/Twitter), semantic structure, and AI crawlability.
 */
export function checkSeo(crawlResult) {
  const pages = crawlResult.pages || [];
  const findings = [];
  const pageAudits = [];

  for (const page of pages) {
    if (!page.html) continue;

    const $ = cheerio.load(page.html);
    const issues = [];
    const passes = [];

    // 1. Title Tag
    const title = $('title').first().text().trim();
    if (!title) {
      issues.push('Missing <title> tag');
      findings.push({
        id: `seo-missing-title-${sanitizeId(page.url)}`,
        category: 'seo',
        severity: 'medium',
        title: 'Missing <title> tag on page',
        location: page.url,
        description: 'Search engines and AI indexing engines require a descriptive <title> tag to identify page subject.',
        evidence: { url: page.url },
        remediation: 'Add a concise, descriptive <title> tag between 30 and 60 characters.',
      });
    } else if (title.length < 20) {
      issues.push(`Title too short (${title.length} chars)`);
    } else if (title.length > 70) {
      issues.push(`Title may be truncated in SERPs (${title.length} chars)`);
    } else {
      passes.push(`Optimal title length (${title.length} chars)`);
    }

    // 2. Meta Description
    const metaDesc = $('meta[name="description" i]').attr('content')?.trim() || '';
    if (!metaDesc) {
      issues.push('Missing <meta name="description">');
      findings.push({
        id: `seo-missing-description-${sanitizeId(page.url)}`,
        category: 'seo',
        severity: 'low',
        title: 'Missing meta description tag',
        location: page.url,
        description: 'Page lacks a meta description tag used for search snippets and AI answer overviews.',
        evidence: { url: page.url },
        remediation: 'Provide a compelling 120-160 character meta description summarizing page value.',
      });
    } else if (metaDesc.length < 50) {
      issues.push(`Meta description too short (${metaDesc.length} chars)`);
    } else if (metaDesc.length > 170) {
      issues.push(`Meta description exceeds recommended length (${metaDesc.length} chars)`);
    } else {
      passes.push(`Optimal meta description (${metaDesc.length} chars)`);
    }

    // 3. Canonical Link
    const canonical = $('link[rel="canonical" i]').attr('href')?.trim() || '';
    if (!canonical) {
      issues.push('No canonical URL specified');
    } else {
      passes.push('Canonical tag configured');
    }

    // 4. Headings Structure
    const h1s = $('h1').map((_, el) => $(el).text().trim()).get().filter(Boolean);
    const h2Count = $('h2').length;
    const h3Count = $('h3').length;

    if (h1s.length === 0) {
      issues.push('Page has no <h1> heading');
      findings.push({
        id: `seo-missing-h1-${sanitizeId(page.url)}`,
        category: 'seo',
        severity: 'low',
        title: 'Missing primary <h1> heading',
        location: page.url,
        description: 'The document lacks a top-level <h1> heading to establish semantic content hierarchy.',
        evidence: { url: page.url },
        remediation: 'Include exactly one main <h1> heading summarizing the page topic.',
      });
    } else if (h1s.length > 1) {
      issues.push(`Multiple <h1> headings found (${h1s.length})`);
    } else {
      passes.push('Single clean <h1> heading');
    }

    // 5. OpenGraph & Twitter Cards
    const ogTitle = $('meta[property="og:title" i]').attr('content') || '';
    const ogDesc = $('meta[property="og:description" i]').attr('content') || '';
    const ogImage = $('meta[property="og:image" i]').attr('content') || '';
    const twitterCard = $('meta[name="twitter:card" i]').attr('content') || '';

    const hasOg = Boolean(ogTitle || ogImage);
    if (!hasOg) {
      issues.push('Missing OpenGraph social sharing meta tags');
    } else {
      passes.push('OpenGraph metadata present');
    }

    // 6. Mobile Viewport
    const viewport = $('meta[name="viewport" i]').attr('content') || '';
    if (!viewport) {
      issues.push('Missing responsive viewport meta tag');
    } else {
      passes.push('Mobile viewport defined');
    }

    // 7. Lang attribute
    const htmlLang = $('html').attr('lang')?.trim() || '';
    if (!htmlLang) {
      issues.push('Missing lang attribute on <html> element');
    } else {
      passes.push(`Language specified (${htmlLang})`);
    }

    // 8. Images Alt Attributes
    const totalImages = $('img').length;
    const missingAlt = $('img:not([alt])').length;
    if (missingAlt > 0) {
      issues.push(`${missingAlt} image(s) missing alt attributes`);
    } else if (totalImages > 0) {
      passes.push(`All images have alt tags (${totalImages})`);
    }

    // 9. Structured Data (JSON-LD)
    const jsonLdScripts = $('script[type="application/ld+json"]').get();
    const structuredTypes = [];
    for (const s of jsonLdScripts) {
      try {
        const parsed = JSON.parse($(s).text());
        if (parsed['@type']) structuredTypes.push(parsed['@type']);
      } catch { /* ignore invalid JSON-LD */ }
    }

    // Score calculation
    let score = 100;
    score -= (issues.length * 10);
    score = Math.max(0, Math.min(100, score));

    pageAudits.push({
      url: page.url,
      title: title || '(No Title)',
      metaDescription: metaDesc || '(None)',
      canonical: canonical || '(None)',
      headings: { h1: h1s, h2Count, h3Count },
      openGraph: { ogTitle, ogDesc, ogImage, twitterCard },
      htmlLang: htmlLang || '(None)',
      viewport: Boolean(viewport),
      images: { total: totalImages, missingAlt },
      structuredTypes,
      score,
      issues,
      passes,
    });
  }

  // Aggregate SEO health
  const avgScore = pageAudits.length
    ? Math.round(pageAudits.reduce((acc, p) => acc + p.score, 0) / pageAudits.length)
    : 100;

  return {
    score: avgScore,
    grade: avgScore >= 90 ? 'A' : avgScore >= 80 ? 'B' : avgScore >= 70 ? 'C' : avgScore >= 60 ? 'D' : 'F',
    pages: pageAudits,
    findings,
  };
}

function sanitizeId(str) {
  return str.replace(/[^a-z0-9]/gi, '-').slice(0, 30).toLowerCase();
}
