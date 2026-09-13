import { truncate } from './util.js';

/**
 * System prompt — the contract every provider must follow: strict JSON, defensive
 * framing, findings-grounded remediation.
 */
export const SYSTEM = `You are Monarch, a senior application-security analyst producing a defensive audit for the owner of the scanned application.
Respond ONLY with a JSON object of this exact shape:
{
  "riskLevel": "critical|high|medium|low|minimal",
  "executiveSummary": "3-5 sentences for a non-technical stakeholder",
  "rootCauses": ["short root-cause statements"],
  "actionPlan": [{"priority": 1, "title": "...", "why": "...", "how": "concrete config/code snippet or steps", "effort": "low|medium|high", "findingIds": ["..."]}],
  "quickWins": ["one-line items fixable in under an hour"],
  "attackNarrative": "2-4 sentences describing how an attacker would realistically chain the top findings"
}
Be specific, cite finding ids, never invent findings not in the input, and keep the action plan to at most 7 items.`;

/**
 * Compact a scan report into the user prompt. Findings are reduced to the fields
 * the model needs (id, severity, title, location, truncated evidence) to keep
 * token usage predictable.
 */
export function buildPrompt(scan) {
  const compact = scan.findings.map(f => ({
    id: f.id,
    severity: f.severity,
    title: f.title,
    location: f.location,
    evidence: truncate(JSON.stringify(f.evidence), 300),
  }));

  return `Target: ${scan.target}
Engine: ${scan.crawl.engine}
Pages crawled: ${scan.crawl.pages.length}
Network: ${JSON.stringify(scan.networkSummary)}
Score: ${scan.score.score}/100 (${scan.score.grade})
Third-party origins: ${scan.crawl.externalOrigins.slice(0, 15).join(', ') || 'none'}
Cookies: ${scan.crawl.cookies.map(c => `${c.name}[${c.httpOnly ? 'HttpOnly' : ''}${c.secure ? ' Secure' : ''}${c.sameSite ? ' SameSite=' + c.sameSite : ''}]`).join(', ') || 'none'}

Findings (${compact.length}):
${JSON.stringify(compact, null, 1)}`;
}
