import { randomUUID } from 'node:crypto';
import { NetworkLog } from './network.js';
import { crawl } from './crawler.js';
import { runChecks, scoreFindings } from './checks/index.js';
import { generateInsights } from '../ai/insights.js';
import { normalizeTarget } from './safety.js';

/**
 * Orchestrates a full audit: crawl → checks → score → AI insights.
 * Emits progress events via `onEvent` so UIs can stream the lifecycle in real time.
 */
export async function runScan(input, { maxPages, timeoutMs, engine, onEvent = () => {}, ai = true, env = process.env } = {}) {
  const target = normalizeTarget(input);
  const id = randomUUID();
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
    emit('status', { stage: 'analyze', message: `Running security checks over ${crawlResult.pages.length} page(s) and ${log.entries.length} request(s)` });
    const findings = runChecks(crawlResult, log);
    const score = scoreFindings(findings);
    for (const f of findings) emit('finding', { finding: f });

    const partial = { id, target, startedAt: startedAt.toISOString(), crawl: crawlResult, findings, score, networkSummary: log.summary() };
    let insights = null;
    if (ai) {
      emit('status', { stage: 'ai', message: 'Generating AI insights & remediation plan' });
      insights = await generateInsights(partial, { env });
      if (insights.warning) emit('status', { stage: 'ai', level: 'warn', message: insights.warning });
    }

    const finishedAt = new Date();
    const scan = {
      ...partial,
      insights,
      network: log.entries,
      finishedAt: finishedAt.toISOString(),
      durationMs: finishedAt - startedAt,
      version: '0.1.0',
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
