/**
 * Monarch Power-Up Bridge
 * Optional integration with Python and Go microservices
 * If services are not running, gracefully degrades to Node.js only
 */

const PYTHON_SERVICE_URL = process.env.PYTHON_SERVICE_URL || 'http://localhost:5001';
const GO_SERVICE_URL = process.env.GO_SERVICE_URL || 'http://localhost:5002';
const POWERUP_TIMEOUT = Number(process.env.POWERUP_TIMEOUT_MS || 5000);

async function fetchWithTimeout(url, options = {}, timeoutMs = POWERUP_TIMEOUT) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(id);
  }
}

/**
 * Check if power-up services are available
 */
export async function checkPowerUpServices() {
  const status = {
    python: { available: false, url: PYTHON_SERVICE_URL },
    go: { available: false, url: GO_SERVICE_URL },
  };

  try {
    const res = await fetchWithTimeout(`${PYTHON_SERVICE_URL}/health`, {}, 2000);
    if (res.ok) {
      const data = await res.json();
      status.python.available = true;
      status.python.info = data;
    }
  } catch {}

  try {
    const res = await fetchWithTimeout(`${GO_SERVICE_URL}/health`, {}, 2000);
    if (res.ok) {
      const data = await res.json();
      status.go.available = true;
      status.go.info = data;
    }
  } catch {}

  return status;
}

/**
 * Run Python advanced scanner (high-entropy secrets, vuln libs)
 */
export async function runPythonScanner(target, html = '') {
  try {
    const res = await fetchWithTimeout(`${PYTHON_SERVICE_URL}/analyze`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target, html: html.slice(0, 500000) }),
    });

    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null; // Graceful degradation
  }
}

/**
 * Run Go fast port scanner
 */
export async function runGoScanner(host, ports = [], options = {}) {
  try {
    const res = await fetchWithTimeout(`${GO_SERVICE_URL}/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        host,
        ports,
        portsStr: options.portsStr,
        timeoutMs: options.timeoutMs || 1000,
        concurrency: options.concurrency || 100,
      }),
    });

    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/**
 * Enhance scan findings with power-up services if available
 */
export async function enhanceWithPowerUps(target, html, baseFindings = []) {
  const enhanced = [...baseFindings];
  const powerUpResults = {};

  // Try Python service for advanced secret detection
  const pythonResult = await runPythonScanner(target, html);
  if (pythonResult?.findings?.length) {
    powerUpResults.python = pythonResult;
    for (const f of pythonResult.findings) {
      // Avoid duplicates
      const exists = enhanced.some(e => e.title === f.title && e.location === f.location);
      if (!exists) {
        enhanced.push({
          ...f,
          source: 'python-powerup',
        });
      }
    }
  }

  return { findings: enhanced, powerUpResults };
}
