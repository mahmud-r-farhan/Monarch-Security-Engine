import tls from 'node:tls';
import { URL } from 'node:url';

function isPrivateOrLocalHost(hostname) {
  const host = hostname.toLowerCase();

  if (
    host === 'localhost' ||
    host === '::1' ||
    host === '0.0.0.0' ||
    host === '169.254.169.254' ||
    host === 'metadata.google.internal' ||
    host === 'metadata.azure.internal'
  ) {
    return true;
  }

  const ipv4Match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const a = Number(ipv4Match[1]);
    const b = Number(ipv4Match[2]);
    const c = Number(ipv4Match[3]);
    const d = Number(ipv4Match[4]);

    if ([a, b, c, d].some((n) => n < 0 || n > 255)) return true;

    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }

  if (host.startsWith('fc') || host.startsWith('fd') || host.startsWith('fe80:')) return true;

  return false;
}

function sanitizeHeadersCheckUrl(rawUrl) {
  const parsed = new URL(rawUrl);

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only http/https URLs are allowed');
  }

  if (parsed.username || parsed.password) {
    throw new Error('URL credentials are not allowed');
  }

  if (isPrivateOrLocalHost(parsed.hostname)) {
    throw new Error('Target host is not allowed');
  }

  return parsed.toString();
}

/**
 * TLS/SSL Certificate Analyzer
 * Analyzes certificate chain, expiry, protocols, and cipher suites
 */

export async function analyzeTLS(target, { timeoutMs = 8000 } = {}) {
  let hostname, port;
  try {
    const url = new URL(target.includes('://') ? target : `https://${target}`);
    hostname = url.hostname;
    port = Number(url.port) || 443;
  } catch {
    throw new Error(`Invalid target for TLS analysis: ${target}`);
  }

  return new Promise((resolve) => {
    const start = Date.now();
    let certChain = [];
    let protocol = null;
    let cipher = null;
    let authorized = false;
    let authError = null;

    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: true,
        timeout: timeoutMs,
      },
      () => {
        protocol = socket.getProtocol();
        cipher = socket.getCipher();
        authorized = socket.authorized;

        const peerCert = socket.getPeerCertificate(true);
        if (peerCert && Object.keys(peerCert).length) {
          let current = peerCert;
          while (current && Object.keys(current).length) {
            certChain.push({
              subject: current.subject,
              issuer: current.issuer,
              subjectaltname: current.subjectaltname,
              valid_from: current.valid_from,
              valid_to: current.valid_to,
              fingerprint: current.fingerprint,
              fingerprint256: current.fingerprint256,
              serialNumber: current.serialNumber,
              modulus: current.modulus ? `${current.modulus.slice(0, 40)}...` : undefined,
              bits: current.bits,
              pubkey: current.pubkey ? current.pubkey.toString('base64').slice(0, 80) + '...' : undefined,
            });
            if (current.issuerCertificate && current.issuerCertificate !== current) {
              current = current.issuerCertificate;
            } else {
              break;
            }
          }
        }

        socket.end();
      }
    );

    socket.on('error', (err) => {
      resolve({
        hostname,
        port,
        reachable: false,
        error: err.message,
        latencyMs: Date.now() - start,
      });
    });

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      resolve({
        hostname,
        port,
        reachable: false,
        error: `TLS handshake timed out after ${timeoutMs}ms`,
        latencyMs: Date.now() - start,
      });
    });

    socket.on('close', () => {
      if (certChain.length === 0) {
        // Already resolved via error
        return;
      }

      const now = new Date();
      const leaf = certChain[0];
      const expiryDate = leaf ? new Date(leaf.valid_to) : null;
      const daysUntilExpiry = expiryDate ? Math.round((expiryDate - now) / (1000 * 60 * 60 * 24)) : null;

      const findings = [];

      if (!authorized) {
        findings.push({
          severity: 'high',
          title: 'TLS certificate not trusted',
          description: `Certificate validation failed: ${socket.authorizationError || 'untrusted'}`,
        });
      }

      if (daysUntilExpiry !== null) {
        if (daysUntilExpiry < 0) {
          findings.push({
            severity: 'critical',
            title: 'TLS certificate expired',
            description: `Certificate expired ${Math.abs(daysUntilExpiry)} days ago (${leaf.valid_to})`,
          });
        } else if (daysUntilExpiry < 7) {
          findings.push({
            severity: 'critical',
            title: 'TLS certificate expires very soon',
            description: `Certificate expires in ${daysUntilExpiry} days (${leaf.valid_to})`,
          });
        } else if (daysUntilExpiry < 30) {
          findings.push({
            severity: 'high',
            title: 'TLS certificate expires soon',
            description: `Certificate expires in ${daysUntilExpiry} days (${leaf.valid_to})`,
          });
        }
      }

      if (protocol && ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'].includes(protocol)) {
        findings.push({
          severity: 'high',
          title: `Weak TLS protocol: ${protocol}`,
          description: `Server negotiates deprecated protocol ${protocol} which has known vulnerabilities`,
        });
      }

      if (cipher && cipher.name && /RC4|DES|MD5|EXPORT|NULL|anon/i.test(cipher.name)) {
        findings.push({
          severity: 'high',
          title: `Weak cipher suite: ${cipher.name}`,
          description: `Server uses weak cipher ${cipher.name} (${cipher.version})`,
        });
      }

      if (leaf && leaf.subject && leaf.subject.CN !== hostname && !leaf.subjectaltname?.includes(hostname)) {
        // Check SAN
        const sanList = leaf.subjectaltname || '';
        if (!sanList.includes(hostname) && !sanList.includes(`*.${hostname.split('.').slice(1).join('.')}`)) {
          findings.push({
            severity: 'medium',
            title: 'Certificate hostname mismatch',
            description: `Certificate CN=${leaf.subject.CN} does not match hostname ${hostname}`,
          });
        }
      }

      resolve({
        hostname,
        port,
        reachable: true,
        latencyMs: Date.now() - start,
        protocol,
        cipher,
        authorized,
        authError: socket.authorizationError || null,
        chainLength: certChain.length,
        leaf,
        chain: certChain,
        daysUntilExpiry,
        expiryDate: expiryDate?.toISOString() || null,
        findings,
        grade: calculateTLSGrade({ protocol, cipher, authorized, daysUntilExpiry, findings }),
      });
    });
  });
}

function calculateTLSGrade({ protocol, cipher, authorized, daysUntilExpiry, findings }) {
  const hasCritical = findings.some((f) => f.severity === 'critical');
  const hasHigh = findings.some((f) => f.severity === 'high');

  if (hasCritical) return 'F';
  if (!authorized) return 'F';
  if (hasHigh) return 'C';
  if (protocol === 'TLSv1.2') return 'B';
  if (protocol === 'TLSv1.3') return 'A';
  if (findings.length === 0) return 'A';
  return 'B';
}

export async function checkSecurityHeaders(url, { timeoutMs = 5000 } = {}) {
  try {
    const safeUrl = sanitizeHeadersCheckUrl(url);
    const res = await fetch(safeUrl, {
      method: 'GET',
      headers: { 'User-Agent': 'Monarch-Security-Engine TLS-Checker' },
      signal: AbortSignal.timeout(timeoutMs),
    });

    const headers = {};
    for (const [k, v] of res.headers.entries()) {
      headers[k.toLowerCase()] = v;
    }

    const analysis = {
      url: safeUrl,
      status: res.status,
      headers: {
        'strict-transport-security': headers['strict-transport-security'] || null,
        'content-security-policy': headers['content-security-policy'] || null,
        'x-frame-options': headers['x-frame-options'] || null,
        'x-content-type-options': headers['x-content-type-options'] || null,
        'referrer-policy': headers['referrer-policy'] || null,
        'permissions-policy': headers['permissions-policy'] || null,
      },
      score: 0,
      grade: 'F',
      missing: [],
      present: [],
    };

    const checks = [
      { name: 'HSTS', header: 'strict-transport-security', weight: 25 },
      { name: 'CSP', header: 'content-security-policy', weight: 25 },
      { name: 'X-Frame-Options', header: 'x-frame-options', weight: 15 },
      { name: 'X-Content-Type-Options', header: 'x-content-type-options', weight: 15 },
      { name: 'Referrer-Policy', header: 'referrer-policy', weight: 10 },
      { name: 'Permissions-Policy', header: 'permissions-policy', weight: 10 },
    ];

    for (const check of checks) {
      if (analysis.headers[check.header]) {
        analysis.score += check.weight;
        analysis.present.push(check.name);
      } else {
        analysis.missing.push(check.name);
      }
    }

    analysis.grade =
      analysis.score >= 90 ? 'A' : analysis.score >= 75 ? 'B' : analysis.score >= 60 ? 'C' : analysis.score >= 40 ? 'D' : 'F';

    return analysis;
  } catch (err) {
    return { url, error: err.message, score: 0, grade: 'F' };
  }
}
