#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { runScan } from './engine/scanner.js';
import { renderMarkdown } from './report/markdown.js';
import { renderHtml } from './report/html.js';
import { renderSarif } from './report/sarif.js';
import { loadEnv } from './env.js';

loadEnv();
const args = process.argv.slice(2);
if (!args.length || args.includes('-h') || args.includes('--help')) {
  console.log(`
  🦋 Monarch Security Engine — CLI

  Usage:  monarch <url> [options]

  Options:
    --pages <n>        Max pages to crawl (default 25)
    --engine <name>    fetch | playwright (default: $CRAWLER or fetch)
    --no-ai            Skip the AI insights stage
    --out <dir>        Write report.json / report.md / report.html here
    --format <fmt>     Print to stdout: md | json | summary (default summary)
    --quiet            Suppress progress output

  Exit code is 2 when critical findings exist, 1 for high, otherwise 0 (CI-friendly).
`);
  process.exit(0);
}
const target = args.find(a => !a.startsWith('--') && !isValueOf(a));
const opt = name => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : undefined; };
function isValueOf(a) { const i = args.indexOf(a); return i > 0 && /^--(pages|engine|out|format)$/.test(args[i - 1]); }
const quiet = args.includes('--quiet');
const format = opt('format') || 'summary';

const SEV_ICON = { critical: '🟥', high: '🟧', medium: '🟨', low: '🟦', info: '⬜' };
try {
  const scan = await runScan(target, {
    maxPages: opt('pages') ? Number(opt('pages')) : undefined,
    engine: opt('engine'),
    ai: !args.includes('--no-ai'),
    onEvent: ev => {
      if (quiet || format !== 'summary') return;
      if (ev.type === 'status') process.stderr.write(`  ${ev.level === 'warn' ? '⚠' : '›'} [${ev.stage}] ${ev.message}\n`);
      if (ev.type === 'finding') process.stderr.write(`  ${SEV_ICON[ev.finding.severity]} ${ev.finding.severity.toUpperCase().padEnd(8)} ${ev.finding.title}\n`);
    },
  });
  if (opt('out')) {
    const dir = path.resolve(opt('out'));
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(path.join(dir, 'report.json'), JSON.stringify(scan, null, 2));
    await fs.writeFile(path.join(dir, 'report.md'), renderMarkdown(scan));
    await fs.writeFile(path.join(dir, 'report.html'), renderHtml(scan));
    await fs.writeFile(path.join(dir, 'report.sarif'), JSON.stringify(renderSarif(scan), null, 2));
    if (!quiet) process.stderr.write(`\n  Reports written to ${dir}\n`);
  }
  if (format === 'json') console.log(JSON.stringify(scan, null, 2));
  else if (format === 'md') console.log(renderMarkdown(scan));
  else if (format === 'sarif') console.log(JSON.stringify(renderSarif(scan), null, 2));
  else {
    const c = scan.score.counts;
    console.log(`\n  Target   ${scan.target}\n  Score    ${scan.score.score}/100  (grade ${scan.score.grade})  risk: ${scan.insights?.riskLevel || 'n/a'}\n  Findings ${scan.findings.length}  →  critical ${c.critical || 0} · high ${c.high || 0} · medium ${c.medium || 0} · low ${c.low || 0} · info ${c.info || 0}\n  Crawl    ${scan.crawl.pages.length} pages · ${scan.networkSummary.requests} requests · ${(scan.durationMs / 1000).toFixed(1)}s · engine=${scan.crawl.engine}\n`);
    if (scan.insights) console.log(`  ${scan.insights.executiveSummary}\n`);
  }
  process.exit(c(scan.score.counts));
} catch (err) {
  console.error(`\n  ✖ ${err.message}\n`);
  process.exit(3);
}
function c(counts) { return counts.critical ? 2 : counts.high ? 1 : 0; }
