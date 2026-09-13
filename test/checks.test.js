import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeCsp } from '../src/engine/checks/headers.js';
import { parseSetCookie } from '../src/engine/crawler.js';
import { decodeJwt } from '../src/engine/checks/jwt.js';
import { runChecks, scoreFindings } from '../src/engine/checks/index.js';
import { NetworkLog } from '../src/engine/network.js';
import { heuristicInsights, parseModelJson, detectProvider } from '../src/ai/insights.js';
import { isPrivateIp, normalizeTarget } from '../src/engine/safety.js';

const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');

function baseCrawl(overrides = {}) {
  return {
    engine: 'fetch', origin: 'https://example.com',
    pages: [{ url: 'https://example.com/', finalUrl: 'https://example.com/', status: 200, headers: {}, contentType: 'text/html', title: 'x', links: [], scripts: [], mixedContent: [], redirectChain: [], hasInlineEventHandlers: false, metaCsp: null }],
    assets: [], forms: [], cookies: [], inlineScripts: [], scriptBodies: [], externalOrigins: [], probes: [], cors: null, storage: null, consoleErrors: [],
    ...overrides,
  };
}

test('CSP analyzer flags unsafe-inline and wildcard', () => {
  const ids = analyzeCsp("default-src *; script-src 'unsafe-inline' https:").map(f => f.id);
  assert.ok(ids.includes('csp-unsafe-inline'));
  assert.ok(ids.includes('csp-wildcard-script'));
});

test('CSP analyzer accepts a strict nonce policy without high findings', () => {
  const out = analyzeCsp("default-src 'self'; script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
  assert.equal(out.filter(f => f.severity === 'high').length, 0);
});

test('Set-Cookie parser extracts attributes', () => {
  const c = parseSetCookie('sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600', 'https://example.com/');
  assert.deepEqual([c.name, c.value, c.httpOnly, c.secure, c.sameSite, c.maxAge], ['sid', 'abc', true, true, 'Lax', 3600]);
});

test('JWT decoder handles alg=none and rejects garbage', () => {
  const tok = `${b64({ alg: 'none' })}.${b64({ sub: 1 })}.`;
  assert.equal(decodeJwt(tok).header.alg, 'none');
  assert.equal(decodeJwt('eyJnot.a.jwt'), null);
});

test('runChecks produces expected findings for a weak target', () => {
  const noneJwt = `${b64({ alg: 'none' })}.${b64({ sub: 1, role: 'admin' })}.`;
  const crawl = baseCrawl({
    cookies: [{ name: 'sessionid', value: 'x', secure: false, httpOnly: false, sameSite: null, domain: null, path: '/', expires: null, maxAge: null, setBy: 'https://example.com/' }],
    scriptBodies: [{ url: 'https://example.com/app.js', code: `localStorage.setItem('auth_token', t); const k="AKIAIOSFODNN7EXAMPLE"; const j="${noneJwt}";`, headers: {} }],
    assets: [{ url: 'https://cdn.example.net/lib.js', type: 'script', integrity: null, crossorigin: null, foundOn: 'https://example.com/' }],
    probes: [{ path: '/.env', kind: 'sensitive', status: 200, contentType: 'text/plain', snippet: 'DB_PASSWORD=x\n', finalUrl: 'https://example.com/.env' }],
    cors: { requestedOrigin: 'https://evil.example', allowOrigin: 'https://evil.example', allowCredentials: 'true' },
  });
  const log = new NetworkLog();
  const findings = runChecks(crawl, log);
  const ids = new Set(findings.map(f => f.id));
  for (const expected of ['missing-csp', 'missing-hsts', 'cookie-no-httponly', 'cookie-no-secure', 'token-in-web-storage', 'secret-aws-access-key', 'jwt-alg-none', 'jwt-hardcoded-in-script', 'missing-sri', 'exposed-env', 'cors-reflect-with-credentials']) {
    assert.ok(ids.has(expected), `expected finding ${expected}`);
  }
  // sorted by severity
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  for (let i = 1; i < findings.length; i++) assert.ok(order.indexOf(findings[i - 1].severity) <= order.indexOf(findings[i].severity));
  const score = scoreFindings(findings);
  assert.equal(score.grade, 'F');
});

test('a hardened target scores an A', () => {
  const crawl = baseCrawl({
    pages: [{ ...baseCrawl().pages[0], headers: { 'content-security-policy': "default-src 'self'; script-src 'self' 'nonce-x'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'", 'strict-transport-security': 'max-age=63072000; includeSubDomains; preload', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'permissions-policy': 'camera=()', 'cross-origin-opener-policy': 'same-origin' } }],
    probes: [{ path: '/.well-known/security.txt', kind: 'info', status: 200, contentType: 'text/plain', snippet: 'Contact: mailto:sec@example.com', finalUrl: 'https://example.com/.well-known/security.txt' }],
  });
  const findings = runChecks(crawl, new NetworkLog());
  assert.equal(findings.filter(f => f.severity !== 'info').length, 0, JSON.stringify(findings.map(f => f.id)));
  assert.equal(scoreFindings(findings).grade, 'A');
});

test('exposure check ignores catch-all 200 pages without signature', () => {
  const crawl = baseCrawl({ probes: [{ path: '/.env', kind: 'sensitive', status: 200, contentType: 'text/html', snippet: '<html>SPA</html>', finalUrl: 'https://example.com/.env' }] });
  assert.ok(!runChecks(crawl, new NetworkLog()).some(f => f.id === 'exposed-env'));
});

test('heuristic insights produce a coherent plan', () => {
  const crawl = baseCrawl();
  const log = new NetworkLog();
  const findings = runChecks(crawl, log);
  const scan = { target: 'https://example.com', crawl, findings, score: scoreFindings(findings), networkSummary: log.summary() };
  const ins = heuristicInsights(scan);
  assert.ok(ins.executiveSummary.includes('example.com'));
  assert.ok(ins.actionPlan.length > 0 && ins.actionPlan.length <= 7);
  assert.ok(ins.actionPlan.every(a => a.findingIds.length));
});

test('model JSON parser tolerates fences', () => {
  assert.equal(parseModelJson('```json\n{"riskLevel":"low"}\n```').riskLevel, 'low');
  assert.equal(parseModelJson('Sure! {"a":1} done').a, 1);
  assert.equal(parseModelJson('nope'), null);
});

test('provider detection', () => {
  assert.equal(detectProvider({}), 'none');
  assert.equal(detectProvider({ OPENAI_API_KEY: 'x' }), 'openai');
  assert.equal(detectProvider({ OPENAI_API_KEY: 'x', AI_PROVIDER: 'gemini' }), 'gemini');
});

test('safety helpers', () => {
  assert.ok(isPrivateIp('127.0.0.1') && isPrivateIp('10.1.2.3') && isPrivateIp('172.20.0.1') && isPrivateIp('192.168.1.1'));
  assert.ok(!isPrivateIp('8.8.8.8'));
  assert.equal(normalizeTarget('example.com/path'), 'https://example.com/path');
  assert.throws(() => normalizeTarget(''));
});

test('network log summary', () => {
  const log = new NetworkLog();
  const e = log.start({ url: 'https://a/', type: 'document' });
  log.finish(e, { status: 200, headers: { 'content-type': 'text/html' }, body: Buffer.from('hi') });
  const f = log.start({ url: 'https://a/x', type: 'script' });
  log.fail(f, new Error('boom'));
  assert.deepEqual(log.summary(), { requests: 2, bytes: 2, byStatus: { '2xx': 1, failed: 1 }, byType: { document: 1, script: 1 } });
});
