import { randomUUID } from 'node:crypto';

/**
 * Calculates percentile from a sorted array of numbers.
 */
function calculatePercentile(sorted, p) {
  if (!sorted.length) return 0;
  const index = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(index, sorted.length - 1))];
}

export class LoadTestRunner {
  constructor(config) {
    this.id = randomUUID();
    this.url = config.url;
    this.method = (config.method || 'GET').toUpperCase();
    this.headers = config.headers || {};
    this.body = config.body || null;
    this.concurrency = Math.min(100, Math.max(1, Number(config.concurrency) || 10));
    this.totalRequests = Math.min(2000, Math.max(1, Number(config.totalRequests) || 50));
    this.timeoutMs = Math.min(15000, Math.max(500, Number(config.timeoutMs) || 5000));
    this.securityProbes = config.securityProbes || {};

    this.aborted = false;
    this.abortController = new AbortController();
    this.latencies = [];
    this.statusCodes = {};
    this.errors = [];
    this.completedCount = 0;
    this.startedAt = null;
    this.finishedAt = null;
    this.securityFindings = [];
  }

  abort() {
    this.aborted = true;
    this.abortController.abort();
  }

  async run(onProgress = () => {}) {
    this.startedAt = Date.now();
    let queued = 0;
    const allTasks = [];

    // Security probes phase if requested
    if (this.securityProbes && Object.keys(this.securityProbes).some(k => this.securityProbes[k])) {
      await this.runSecurityProbes(onProgress);
    }

    const worker = async () => {
      while (queued < this.totalRequests && !this.aborted) {
        queued++;
        const reqIndex = queued;
        const reqStart = Date.now();
        try {
          const reqSignal = AbortSignal.timeout(this.timeoutMs);
          const res = await fetch(this.url, {
            method: this.method,
            headers: {
              'User-Agent': 'Monarch-Security-Engine/2.0 Load-Test-Runner',
              ...this.headers,
            },
            body: ['GET', 'HEAD'].includes(this.method) ? undefined : this.body,
            signal: reqSignal,
          });

          const latency = Date.now() - reqStart;
          this.latencies.push(latency);
          const code = res.status;
          this.statusCodes[code] = (this.statusCodes[code] || 0) + 1;
        } catch (err) {
          const latency = Date.now() - reqStart;
          this.latencies.push(latency);
          const errCode = err.name === 'TimeoutError' ? 'TIMEOUT' : 'ERR';
          this.statusCodes[errCode] = (this.statusCodes[errCode] || 0) + 1;
          if (this.errors.length < 20) {
            this.errors.push({ reqIndex, message: err.message });
          }
        }

        this.completedCount++;
        const elapsedSec = Math.max(0.1, (Date.now() - this.startedAt) / 1000);
        const currentRps = Math.round((this.completedCount / elapsedSec) * 10) / 10;

        onProgress({
          type: 'progress',
          id: this.id,
          completed: this.completedCount,
          total: this.totalRequests,
          concurrency: this.concurrency,
          rps: currentRps,
          statusCodes: { ...this.statusCodes },
          latestLatency: this.latencies[this.latencies.length - 1],
        });
      }
    };

    const workers = Array.from({ length: this.concurrency }, () => worker());
    await Promise.all(workers);

    this.finishedAt = Date.now();
    return this.getSummary();
  }

  async runSecurityProbes(onProgress) {
    onProgress({ type: 'probe_start', message: 'Executing automated security tests on target endpoint…' });

    // 1. Rate-Limiting Burst Probe
    if (this.securityProbes.rateLimit !== false) {
      try {
        const burstResults = await Promise.all(
          Array.from({ length: 15 }, () =>
            fetch(this.url, { method: 'HEAD', headers: { 'User-Agent': 'Monarch-RateLimit-Burst' } }).catch(() => null)
          )
        );
        const throttled = burstResults.some(r => r && (r.status === 429 || r.status === 503));
        const rateLimitHeaders = burstResults.find(r => r && (r.headers.has('x-ratelimit-limit') || r.headers.has('ratelimit-limit')));

        if (!throttled && !rateLimitHeaders) {
          this.securityFindings.push({
            severity: 'medium',
            type: 'NO_RATE_LIMITING',
            title: 'Endpoint lacks rate-limiting headers and burst throttling',
            description: '15 rapid requests returned no 429 or RateLimit headers, allowing potential brute force or resource exhaustion.',
          });
        }
      } catch { /* ignore */ }
    }

    // 2. CSRF / Origin Verification Probe
    if (this.securityProbes.csrf && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(this.method)) {
      try {
        const csrfRes = await fetch(this.url, {
          method: this.method,
          headers: {
            'Origin': 'https://attacker.evil.example',
            'Referer': 'https://attacker.evil.example/csrf-exploit.html',
            ...this.headers,
          },
          body: this.body,
        }).catch(() => null);

        if (csrfRes && csrfRes.status >= 200 && csrfRes.status < 400) {
          this.securityFindings.push({
            severity: 'high',
            type: 'MISSING_CSRF_PROTECTION',
            title: 'Mutating request succeeded with untrusted Origin header',
            description: 'The endpoint accepted a cross-origin state-changing request without rejecting or validating the Origin header.',
          });
        }
      } catch { /* ignore */ }
    }

    // 3. SQL Injection Parameter Probe
    if (this.securityProbes.sqli) {
      try {
        const sqliUrl = new URL(this.url);
        sqliUrl.searchParams.set('sqli_test', "' OR '1'='1");
        const sqliRes = await fetch(sqliUrl.toString(), {
          method: 'GET',
          headers: { 'User-Agent': 'Monarch-SQLi-Probe' },
        }).catch(() => null);

        if (sqliRes) {
          const text = (await sqliRes.text()).toLowerCase();
          const sqlErrors = ['syntax error', 'mysql_fetch', 'ora-01756', 'pg_query', 'sqlite3', 'unclosed quotation mark'];
          const matched = sqlErrors.filter(e => text.includes(e));
          if (matched.length) {
            this.securityFindings.push({
              severity: 'critical',
              type: 'SQL_ERROR_DISCLOSURE',
              title: 'Database SQL syntax error exposed in response body',
              description: `Injection probe elicited database error signature: "${matched.join(', ')}".`,
            });
          }
        }
      } catch { /* ignore */ }
    }

    // 4. XSS Reflection Probe
    if (this.securityProbes.xss) {
      try {
        const xssToken = `monarch_xss_${randomUUID().slice(0, 8)}`;
        const xssUrl = new URL(this.url);
        xssUrl.searchParams.set('q', `<script>${xssToken}</script>`);
        const xssRes = await fetch(xssUrl.toString(), {
          method: 'GET',
          headers: { 'User-Agent': 'Monarch-XSS-Probe' },
        }).catch(() => null);

        if (xssRes) {
          const body = await xssRes.text();
          if (body.includes(`<script>${xssToken}</script>`)) {
            this.securityFindings.push({
              severity: 'high',
              type: 'REFLECTED_XSS_DETECTED',
              title: 'Unescaped HTML payload reflected in response body',
              description: `Target reflected raw probe payload without HTML entity encoding.`,
            });
          }
        }
      } catch { /* ignore */ }
    }

    onProgress({ type: 'probe_done', findings: this.securityFindings });
  }

  getSummary() {
    const totalTimeMs = (this.finishedAt || Date.now()) - (this.startedAt || Date.now());
    const sorted = [...this.latencies].sort((a, b) => a - b);
    const sum = sorted.reduce((acc, v) => acc + v, 0);
    const avg = sorted.length ? Math.round(sum / sorted.length) : 0;
    const rps = totalTimeMs > 0 ? Math.round((this.completedCount / (totalTimeMs / 1000)) * 10) / 10 : 0;

    return {
      id: this.id,
      url: this.url,
      method: this.method,
      totalRequests: this.totalRequests,
      completedRequests: this.completedCount,
      concurrency: this.concurrency,
      totalTimeMs,
      rps,
      statusCodes: this.statusCodes,
      errors: this.errors,
      securityFindings: this.securityFindings,
      latencies: {
        min: sorted[0] || 0,
        max: sorted[sorted.length - 1] || 0,
        avg,
        p50: calculatePercentile(sorted, 50),
        p90: calculatePercentile(sorted, 90),
        p95: calculatePercentile(sorted, 95),
        p99: calculatePercentile(sorted, 99),
      },
    };
  }
}
