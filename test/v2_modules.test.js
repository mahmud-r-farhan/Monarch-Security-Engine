import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveVendor, normalizeMac } from '../src/modules/oui.js';
import { parseArpOutput, checkTcpPort, ipToInt, intToIp, parseTargets, expandTargets, getDefaultRoute } from '../src/modules/netdiscovery.js';
import { monitorService } from '../src/modules/monitor.js';
import { checkTechStack } from '../src/engine/checks/techstack.js';
import { checkSeo } from '../src/engine/checks/seo.js';
import { checkApiSecurity } from '../src/engine/checks/apisecurity.js';
import { checkWpAdminSecurity } from '../src/engine/checks/wpadmin.js';
import { createServer } from 'node:http';
import { pokeSsh } from '../src/modules/poking.js';

test('OUI MAC resolution handles standard and unknown MACs', () => {
  assert.equal(normalizeMac('00-03-93-aa-bb-cc'), '00:03:93:aa:bb:cc');
  assert.equal(resolveVendor('00:03:93:11:22:33'), 'Apple');
  assert.equal(resolveVendor('b8:27:eb:01:02:03'), 'Raspberry Pi Foundation');
  assert.equal(resolveVendor('24:0a:c4:00:11:22'), 'Espressif Inc.');
  assert.ok(resolveVendor('00:11:22:33:44:55'));
});

test('ARP output parser parses Windows and Unix ARP formats', () => {
  const winOutput = `
Interface: 192.168.1.100 --- 0x11
  Internet Address      Physical Address      Type
  192.168.1.1           00-03-93-11-22-33     dynamic
  192.168.1.254         b8-27-eb-44-55-66     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
`;
  const devices = parseArpOutput(winOutput);
  assert.equal(devices.length, 2);
  assert.equal(devices[0].ip, '192.168.1.1');
  assert.equal(devices[0].vendor, 'Apple');
  assert.equal(devices[1].ip, '192.168.1.254');
  assert.equal(devices[1].vendor, 'Raspberry Pi Foundation');
});

test('NetLAN IP target parser supports CIDR, ranges, and comma-separated specs', () => {
  assert.equal(ipToInt('192.168.1.1'), 3232235777);
  assert.equal(intToIp(3232235777), '192.168.1.1');

  // Single host
  const single = parseTargets('10.0.0.5');
  assert.equal(single.count, 1);
  assert.equal(intToIp(single.first), '10.0.0.5');

  // Subnet /29 (skips network & broadcast for <= 30)
  const sub = parseTargets('192.168.1.0/29');
  assert.equal(sub.count, 6);
  assert.equal(intToIp(sub.first), '192.168.1.1');
  assert.equal(intToIp(sub.last), '192.168.1.6');

  // IP Range
  const range = parseTargets('172.16.0.10 - 172.16.0.15');
  assert.equal(range.count, 6);
  assert.equal(intToIp(range.first), '172.16.0.10');
  assert.equal(intToIp(range.last), '172.16.0.15');

  // Multi-target expansion
  const expanded = expandTargets('192.168.1.1-192.168.1.3, 192.168.1.2, 10.0.0.1');
  assert.equal(expanded.count, 4);
  assert.ok(expanded.ips.includes('10.0.0.1'));
  assert.ok(expanded.ips.includes('192.168.1.1'));
  assert.ok(expanded.ips.includes('192.168.1.2'));
  assert.ok(expanded.ips.includes('192.168.1.3'));
});

test('Default gateway and route detection returns interface info', async () => {
  const route = await getDefaultRoute();
  assert.ok(route !== null);
  assert.ok('gateway' in route);
});

test('Monitor service computes stats correctly', async () => {
  const m = await monitorService.createMonitor({
    name: 'Test Target',
    url: 'http://localhost:3000/api/health',
    intervalSeconds: 60,
  });
  assert.ok(m.id);
  assert.equal(m.name, 'Test Target');
  assert.equal(typeof m.uptimePercent, 'number');
  await monitorService.deleteMonitor(m.id);
});

test('Tech stack detector identifies Next.js and Express', () => {
  const crawl = {
    pages: [{
      url: 'https://app.example',
      html: '<div id="__next"><div class="text-blue-500 font-bold p-4"></div></div>',
      headers: { 'x-nextjs-page': '/dashboard', 'x-powered-by': 'Express' },
    }],
  };
  const network = { entries: [] };
  const res = checkTechStack(crawl, network);
  const names = res.technologies.map(t => t.name);
  assert.ok(names.includes('Next.js'));
  assert.ok(names.includes('Express.js'));
  assert.ok(names.includes('Tailwind CSS'));
});

test('SEO analyzer checks title, meta description, and headings', () => {
  const crawl = {
    pages: [{
      url: 'https://example.com',
      html: '<!doctype html><html lang="en"><head><title>Optimal Page Title For Testing Purpose</title><meta name="description" content="This is a comprehensive meta description that explains what the website is for testing."></head><body><h1>Main Title</h1></body></html>',
    }],
  };
  const res = checkSeo(crawl);
  assert.ok(res.score >= 70);
  assert.equal(res.pages.length, 1);
  assert.equal(res.pages[0].title, 'Optimal Page Title For Testing Purpose');
  assert.equal(res.pages[0].headings.h1[0], 'Main Title');
});

test('API security check detects plaintext HTTP API and sensitive data leak', () => {
  const network = {
    entries: [
      {
        url: 'http://api.remote-server.example/api/v1/users',
        method: 'GET',
        response: {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ user: 'admin', api_key: 'supersecret123' }),
        },
      },
    ],
  };
  const findings = checkApiSecurity({}, network);
  const ids = findings.map(f => f.id);
  assert.ok(ids.some(id => id.startsWith('api-plain-http')));
  assert.ok(ids.some(id => id.startsWith('api-sensitive-field-leak')));
});

test('WordPress and Admin security analyzer detects exposed login and user enumeration', async () => {
  const server = createServer((req, res) => {
    if (req.url === '/wp-login.php') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body>WordPress Login</body></html>');
    } else if (req.url === '/wp-json/wp/v2/users') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify([{ id: 1, name: 'admin', slug: 'admin' }]));
    } else if (req.url === '/xmlrpc.php') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('XML-RPC server accepts POST requests only.');
    } else if (req.url === '/?author=1') {
      res.writeHead(301, { Location: '/author/sysadmin/' });
      res.end();
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const targetUrl = `http://127.0.0.1:${port}`;

  try {
    const result = await checkWpAdminSecurity(targetUrl, { timeoutMs: 1500 });
    assert.ok(result.isWordpress, 'Should detect WordPress');
    assert.ok(result.xmlRpcExposed, 'Should detect exposed XML-RPC');
    assert.ok(result.userEnumeration.vulnerable, 'Should detect user enumeration');
    assert.ok(result.userEnumeration.usernames.includes('admin') || result.userEnumeration.usernames.includes('sysadmin'));
    assert.ok(result.findings.some(f => f.id === 'wp-login-exposed'));
    assert.ok(result.findings.some(f => f.id === 'wp-xmlrpc-exposed'));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('WordPress and Admin security analyzer ignores catch-all SPA pages without signatures', async () => {
  const server = createServer((req, res) => {
    // SPA catch-all returns 200 HTML on all routes
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><head><title>My React App</title></head><body><div id="root">App Content</div></body></html>');
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const targetUrl = `http://127.0.0.1:${port}`;

  try {
    const result = await checkWpAdminSecurity(targetUrl, { timeoutMs: 1500 });
    // Should NOT flag sensitive admin file exposed or WordPress active
    assert.equal(result.isWordpress, false);
    assert.equal(result.findings.some(f => f.id === 'sensitive-admin-file-exposed'), false);
    assert.equal(result.findings.some(f => f.id === 'wp-login-exposed'), false);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('NetworkLog preserves response body and enables API secret leak detection', async () => {
  const { NetworkLog } = await import('../src/engine/network.js');
  const log = new NetworkLog();
  const entry = log.start({ url: 'http://api.internal/v1/auth', type: 'fetch' });
  const payload = JSON.stringify({ token: 'xyz', password: 'supersecret_admin_pass' });
  log.finish(entry, {
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: Buffer.from(payload),
  });

  assert.ok(entry.response?.body, 'Response body should be attached to entry.response');
  const findings = checkApiSecurity({}, log);
  assert.ok(findings.some(f => f.id.startsWith('api-sensitive-field-leak')));
});

