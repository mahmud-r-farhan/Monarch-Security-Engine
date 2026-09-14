/**
 * API Security & Sensitive Data Leak Checks.
 * Evaluates REST / GraphQL / WebSocket endpoints, auth headers, and response payload exposures.
 */

export function checkApiSecurity(crawlResult, networkLog) {
  const findings = [];
  const entries = networkLog?.entries || [];

  for (const entry of entries) {
    const url = entry.url || '';
    const status = entry.response?.status || 0;
    const resHeaders = entry.response?.headers || {};
    const reqHeaders = entry.request?.headers || {};
    const method = (entry.method || 'GET').toUpperCase();
    const isApi = url.includes('/api/') || url.includes('/v1/') || url.includes('/v2/') || url.includes('/graphql') || url.includes('/rest/');

    if (!isApi) continue;

    // 1. Unencrypted HTTP API Communication
    if (url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
      findings.push({
        id: `api-plain-http-${sanitizeId(url)}`,
        category: 'api',
        severity: 'high',
        title: 'API endpoint served over plaintext HTTP',
        location: url,
        description: 'The API endpoint transmits data in cleartext without TLS encryption, exposing payloads and authentication tokens to network eavesdropping.',
        evidence: { url, method },
        remediation: 'Force HTTPS redirection and strict HSTS headers across all API endpoints.',
      });
    }

    // 2. Wildcard CORS on API with Sensitive Content
    const acao = resHeaders['access-control-allow-origin'];
    const acac = resHeaders['access-control-allow-credentials'];
    if (acao === '*' && (reqHeaders['authorization'] || reqHeaders['cookie'])) {
      findings.push({
        id: `api-cors-wildcard-auth-${sanitizeId(url)}`,
        category: 'api',
        severity: 'high',
        title: 'Wildcard CORS allowed on authenticated API endpoint',
        location: url,
        description: 'The API returns Access-Control-Allow-Origin: * while receiving authentication credentials, risking unauthorized cross-origin data exposure.',
        evidence: { url, acao, method },
        remediation: 'Specify an explicit, validated origin allow-list instead of a wildcard.',
      });
    }

    // 3. Sensitive Data in Response Body
    const rawBody = entry.response?.body;
    const bodyStr = typeof rawBody === 'string' ? rawBody : (Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : '');
    if (bodyStr) {
      if (/"password"\s*:\s*"[^"]+"/i.test(bodyStr) || /"api[_-]?key"\s*:\s*"[^"]+"/i.test(bodyStr) || /"secret"\s*:\s*"[^"]+"/i.test(bodyStr)) {
        findings.push({
          id: `api-sensitive-field-leak-${sanitizeId(url)}`,
          category: 'api',
          severity: 'critical',
          title: 'Sensitive credential or secret key exposed in API JSON response',
          location: url,
          description: 'API response body appears to contain plaintext password or secret keys in serialized JSON fields.',
          evidence: { url, status, snippet: bodyStr.slice(0, 200) },
          remediation: 'Sanitize all internal database models and DTOs to strip sensitive fields before serializing responses.',
        });
      }
    }
  }

  return findings;
}

function sanitizeId(str) {
  return str.replace(/[^a-z0-9]/gi, '-').slice(0, 30).toLowerCase();
}
