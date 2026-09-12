import { headersCheck } from './headers.js';
import { cookiesCheck } from './cookies.js';
import { jwtCheck } from './jwt.js';
import { transportCheck } from './transport.js';
import { clientSideCheck } from './clientside.js';
import { exposureCheck } from './exposure.js';
import { infoLeakCheck } from './infoleak.js';

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_WEIGHT = { critical: 40, high: 20, medium: 8, low: 3, info: 0 };

const CHECKS = [headersCheck, cookiesCheck, jwtCheck, transportCheck, clientSideCheck, exposureCheck, infoLeakCheck];

/**
 * Run every check against the crawl result and return normalized, de-duplicated findings.
 */
export function runChecks(crawlResult, networkLog) {
  const findings = [];
  const ctx = { ...crawlResult, network: networkLog.entries };
  for (const check of CHECKS) {
    try {
      for (const f of check(ctx) || []) findings.push(normalizeFinding(f, check.name));
    } catch (err) {
      findings.push(normalizeFinding({ id: `check-error-${check.name}`, title: `Check "${check.name}" failed`, severity: 'info', description: err.message, category: 'engine' }, check.name));
    }
  }
  const dedup = new Map();
  for (const f of findings) {
    const key = `${f.id}|${f.location || ''}`;
    if (!dedup.has(key)) dedup.set(key, f);
  }
  return [...dedup.values()].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}

function normalizeFinding(f, source) {
  return {
    id: f.id,
    title: f.title,
    severity: SEVERITY_ORDER.includes(f.severity) ? f.severity : 'info',
    category: f.category || 'general',
    description: f.description || '',
    evidence: f.evidence ?? null,
    location: f.location || null,
    remediation: f.remediation || '',
    references: f.references || [],
    cwe: f.cwe || null,
    owasp: f.owasp || null,
    source,
  };
}

/** 0–100 security score; higher is better. Findings decay the score with diminishing returns per severity. */
export function scoreFindings(findings) {
  const counts = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  let penalty = 0;
  for (const [sev, n] of Object.entries(counts)) {
    const w = SEVERITY_WEIGHT[sev] || 0;
    for (let i = 0; i < n; i++) penalty += w * Math.pow(0.7, i);
  }
  const score = Math.max(0, Math.round(100 - penalty));
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  return { score, grade, counts };
}
