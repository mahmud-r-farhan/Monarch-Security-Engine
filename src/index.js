/**
 * Monarch Security Engine — programmatic API.
 *
 *   import { runScan, renderMarkdown } from 'monarch-security-engine';
 *   const scan = await runScan('https://example.com', { maxPages: 10 });
 */
export { runScan, summarizeScan } from './engine/scanner.js';
export { runChecks, scoreFindings, SEVERITY_ORDER } from './engine/checks/index.js';
export { NetworkLog } from './engine/network.js';
export { crawl } from './engine/crawler.js';
export { generateInsights, heuristicInsights, detectProvider } from './ai/insights.js';
export { checkProvider, checkActiveProvider, checkAllProviders } from './ai/health.js';
export { renderMarkdown } from './report/markdown.js';
export { renderHtml } from './report/html.js';
