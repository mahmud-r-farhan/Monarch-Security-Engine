import { Router } from 'express';
import { LoadTestRunner } from '../modules/loadtest.js';
import { getLocalInterfaces, getArpTable, runNetworkDiscovery, scanHostPorts, getDefaultRoute, inspectHostDetails } from '../modules/netdiscovery.js';
import { pokeHttp, pokeSsh } from '../modules/poking.js';
import { testDbConnection, runDbLoadTest } from '../modules/database.js';
import { analyzeTLS, checkSecurityHeaders } from '../modules/tls.js';
import { enumerateSubdomains, parseSitemap, analyzeRobotsTxt } from '../modules/subdomain.js';
import { analyzePageSpeed, quickStatusCheck } from '../modules/speed.js';
import { discoveryLimiter } from '../middleware/rateLimiter.js';

/**
 * Tool routes — page speed, load test, network discovery, inspector,
 * database tester, TLS analyzer and recon. Sliced from the former
 * monolithic server.js for maintainability.
 */
const router = Router();

/* ------------------------- Page Speed (new) ------------------------- */

router.post('/speed/analyze', async (req, res) => {
  const { target, runs, timeoutMs } = req.body || {};
  if (!target) return res.status(400).json({ error: 'target is required' });
  if (typeof target !== 'string' || target.length > 2048) return res.status(400).json({ error: 'Invalid target length' });
  try {
    const result = await analyzePageSpeed(target, { runs, timeoutMs });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/speed/status', async (req, res) => {
  const { target } = req.body || {};
  if (!target) return res.status(400).json({ error: 'target is required' });
  try {
    const result = await quickStatusCheck(target);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/* ------------------------------ TLS ------------------------------ */

router.post('/tls/analyze', async (req, res) => {
  const { target, timeoutMs } = req.body || {};
  if (!target) return res.status(400).json({ error: 'target is required' });
  try {
    const result = await analyzeTLS(target, { timeoutMs });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/tls/headers', async (req, res) => {
  const { url, timeoutMs } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url is required' });
  try {
    const result = await checkSecurityHeaders(url, { timeoutMs });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/* ------------------------------ Recon ------------------------------ */

router.post('/recon/subdomains', async (req, res) => {
  const { domain, concurrency, includeCommon } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'domain is required' });
  try {
    const result = await enumerateSubdomains(domain, { concurrency, includeCommon });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/recon/sitemap', async (req, res) => {
  const { target } = req.body || {};
  if (!target) return res.status(400).json({ error: 'target is required' });
  try {
    const result = await parseSitemap(target);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/recon/robots', async (req, res) => {
  const { target } = req.body || {};
  if (!target) return res.status(400).json({ error: 'target is required' });
  try {
    const result = await analyzeRobotsTxt(target);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/* ---------------------------- Load test ---------------------------- */

router.post('/loadtest/run', async (req, res) => {
  const { url, method, headers, body, concurrency, totalRequests, timeoutMs, securityProbes } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url is required' });
  if (typeof url !== 'string' || url.length > 2048) return res.status(400).json({ error: 'Invalid URL' });

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();

  const runner = new LoadTestRunner({ url, method, headers, body, concurrency, totalRequests, timeoutMs, securityProbes });
  req.on('close', () => runner.abort());

  try {
    const summary = await runner.run(progress => {
      res.write(`event: progress\ndata: ${JSON.stringify(progress)}\n\n`);
    });
    res.write(`event: done\ndata: ${JSON.stringify(summary)}\n\n`);
    res.end();
  } catch (err) {
    res.write(`event: error\ndata: ${JSON.stringify({ error: err.message })}\n\n`);
    res.end();
  }
});

/* -------------------------- Net discovery -------------------------- */

router.get('/netdiscovery/interfaces', async (req, res) => {
  const ifaces = getLocalInterfaces();
  const route = await getDefaultRoute();
  res.json({ interfaces: ifaces, gateway: route.gateway, ifaceIp: route.ifaceIp });
});

router.get('/netdiscovery/arp', async (req, res) => {
  const devices = await getArpTable();
  res.json(devices);
});

router.post('/netdiscovery/scan-host', async (req, res) => {
  const { host, tcpPorts, udpPorts, timeoutMs } = req.body || {};
  if (!host) return res.status(400).json({ error: 'host is required' });
  if (typeof host !== 'string' || host.length > 256) return res.status(400).json({ error: 'Invalid host' });
  try {
    const openPorts = await scanHostPorts(host, tcpPorts, udpPorts, timeoutMs);
    res.json({ host, openPorts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/netdiscovery/inspect-host', async (req, res) => {
  const { host } = req.body || {};
  if (!host) return res.status(400).json({ error: 'host is required' });
  if (typeof host !== 'string' || host.length > 256) return res.status(400).json({ error: 'Invalid host' });
  try {
    const details = await inspectHostDetails(host);
    res.json(details);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/netdiscovery/scan', discoveryLimiter, async (req, res) => {
  const { subnet, mode, customTcp, customUdp, pingTimeout, portTimeout } = req.body || {};

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();

  try {
    const result = await runNetworkDiscovery({
      subnet,
      mode,
      customTcp,
      customUdp,
      pingTimeout,
      portTimeout,
      onEvent: ev => {
        res.write(`event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`);
      },
    });
    res.write(`event: done\ndata: ${JSON.stringify(result)}\n\n`);
    res.end();
  } catch (err) {
    res.write(`event: error\ndata: ${JSON.stringify({ error: err.message })}\n\n`);
    res.end();
  }
});

/* ------------------------- Inspector / poke ------------------------- */

router.post('/poke', async (req, res) => {
  try {
    const result = await pokeHttp(req.body || {});
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/poke/ssh', async (req, res) => {
  try {
    const result = await pokeSsh(req.body || {});
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/* ------------------------------ Database ------------------------------ */

router.post('/db/test', async (req, res) => {
  try {
    const result = await testDbConnection(req.body || {});
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/db/stress', async (req, res) => {
  try {
    const result = await runDbLoadTest(req.body || {});
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

export default router;
