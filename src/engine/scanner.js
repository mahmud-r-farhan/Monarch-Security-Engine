import { randomUUID } from 'node:crypto';
import { NetworkLog } from './network.js';
import { crawl } from './crawler.js';
import { runChecks, scoreFindings } from './checks/index.js';
import { checkTechStack } from './checks/techstack.js';
import { checkSeo } from './checks/seo.js';
import { checkApiSecurity } from './checks/apisecurity.js';
import { generateInsights } from '../ai/insights.js';
import { normalizeTarget } from './safety.js';

import { checkWpAdminSecurity } from './checks/wpadmin.js';

/**
 * Orchestrates a full audit: crawl → checks → score → AI insights.
 * Emits progress events via `onEvent` so UIs can stream the lifecycle in real time.
 */
export async function runScan(input, { id: customId, maxPages, timeoutMs, engine, onEvent = () => {}, ai = true, aiConfig = null, env = process.env } = {}) {
  const target = normalizeTarget(input);
  const id = customId || randomUUID();
  const startedAt = new Date();
  const log = new NetworkLog();
  const unsub = log.onEntry(entry => onEvent({ type: 'network', entry }));
  const emit = (type, data) => onEvent({ type, ...data });

  emit('status', { stage: 'init', message: `Scan ${id} started for ${target}` });
  try {
    const crawlResult = await crawl(target, {
      log,
      maxPages: maxPages ?? Number(env.MAX_PAGES || 25),
      timeoutMs: timeoutMs ?? Number(env.REQUEST_TIMEOUT_MS || 10000),
      engine: engine ?? env.CRAWLER ?? 'fetch',
      onProgress: p => emit('status', p),
    });
    emit('status', { stage: 'analyze', message: `Running security, tech stack, WP-admin, and SEO checks over ${crawlResult.pages.length} page(s) and ${log.entries.length} request(s)` });
    const findings = runChecks(crawlResult, log);

    // Run tech stack detection, SEO analyzer & WP-Admin probe
    const techAnalysis = checkTechStack(crawlResult, log);
    const seoAnalysis = checkSeo(crawlResult);
    const apiFindings = checkApiSecurity(crawlResult, log);
    const wpAnalysis = await checkWpAdminSecurity(target, { timeoutMs: 3000 }).catch(() => ({ isWordpress: false, isPhp: false, exposedEndpoints: [], findings: [] }));

    for (const f of [...techAnalysis.findings, ...apiFindings, ...(wpAnalysis.findings || [])]) {
      findings.push(f);
    }

    const score = scoreFindings(findings);
    for (const f of findings) emit('finding', { finding: f });

    emit('status', { stage: 'tech', message: `Identified ${techAnalysis.technologies.length} technologies, SEO score: ${seoAnalysis.score}/100` });

    const partial = {
      id,
      target,
      startedAt: startedAt.toISOString(),
      crawl: crawlResult,
      findings,
      score,
      networkSummary: log.summary(),
      techStack: techAnalysis.technologies,
      rateLimiting: techAnalysis.rateLimiting,
      seo: seoAnalysis,
      wpAdmin: wpAnalysis,
    };
    let insights = null;
    if (ai) {
      emit('status', { stage: 'ai', message: 'Generating AI insights & remediation plan' });
      insights = await generateInsights(partial, { env, aiConfig });
      if (insights.warning) emit('status', { stage: 'ai', level: 'warn', message: insights.warning });
    }

    const finishedAt = new Date();
    const scan = {
      ...partial,
      insights,
      network: log.entries,
      finishedAt: finishedAt.toISOString(),
      durationMs: finishedAt - startedAt,
      version: 'active',
    };
    emit('done', { scan: summarizeScan(scan) });
    return scan;
  } catch (err) {
    emit('error', { message: err.message });
    throw err;
  } finally {
    unsub();
  }
}

/** Lightweight view for lists / streaming completion events. */
export function summarizeScan(scan) {
  return {
    id: scan.id,
    target: scan.target,
    startedAt: scan.startedAt,
    finishedAt: scan.finishedAt,
    durationMs: scan.durationMs,
    score: scan.score,
    findings: scan.findings.length,
    pages: scan.crawl.pages.length,
    requests: scan.networkSummary.requests,
    engine: scan.crawl.engine,
    riskLevel: scan.insights?.riskLevel || null,
  };
}
