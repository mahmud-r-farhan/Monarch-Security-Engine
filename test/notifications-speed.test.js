import { test } from 'node:test';
import assert from 'node:assert/strict';
import { notificationService } from '../src/modules/notifications.js';
import { analyzePageSpeed, quickStatusCheck } from '../src/modules/speed.js';
import { monitorService } from '../src/modules/monitor.js';
import { createServer } from 'node:http';
import { normalizeOllamaBaseUrl } from '../src/ai/insights.js';

test('notification service creates, lists, marks read and deletes', async () => {
  const created = await notificationService.notify({
    type: 'test_event',
    severity: 'warning',
    title: 'Test notification',
    message: 'unit test body',
  });
  assert.ok(created.id);
  assert.equal(created.read, false);

  const list = notificationService.list({ limit: 10 });
  assert.ok(list.items.some(n => n.id === created.id));
  assert.ok(list.unread >= 1);

  const marked = await notificationService.markRead(created.id);
  assert.equal(marked.read, true);

  const deleted = await notificationService.delete(created.id);
  assert.equal(deleted, true);
});

test('monitor notifyOn=none suppresses notifications on status change', async () => {
  // Point at a port that is definitely closed to force a down check
  const m = await monitorService.createMonitor({
    name: 'Silent Monitor',
    url: 'http://localhost:59999',
    intervalSeconds: 300,
    notifyOn: 'none',
  });
  await monitorService.checkMonitor(m.id);
  const list = notificationService.list({ limit: 10 });
  const silent = list.items.filter(n => n.meta?.monitorId === m.id);
  assert.equal(silent.length, 0);
  await monitorService.deleteMonitor(m.id);
});

test('monitor notifyOn=all emits a notification on down', async () => {
  const before = notificationService.unreadCount();
  const m = await monitorService.createMonitor({
    name: 'Loud Monitor',
    url: 'http://localhost:59998',
    intervalSeconds: 300,
    notifyOn: 'all',
  });
  await monitorService.checkMonitor(m.id);
  const after = notificationService.unreadCount();
  assert.ok(after >= before, 'unread count should not decrease');
  const list = notificationService.list({ limit: 10 });
  const hit = list.items.find(n => n.meta?.monitorId === m.id && n.type === 'monitor_down');
  assert.ok(hit, 'expected a monitor_down notification');
  await monitorService.deleteMonitor(m.id);
  await notificationService.delete(hit.id);
});

test('page speed analyzer measures a local HTTP server and audits output', async () => {
  const srv = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<!doctype html><html><head><title>t</title></head><body><p>fast</p></body></html>');
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;

  const result = await analyzePageSpeed(`http://127.0.0.1:${port}/`, { runs: 1 });
  assert.equal(result.reachable, true);
  assert.ok(result.score >= 0 && result.score <= 100);
  assert.ok(['A', 'B', 'C', 'D', 'F'].includes(result.grade));
  assert.ok(result.metrics.ttfbMs >= 0);
  assert.ok(Array.isArray(result.phases) && result.phases.length === 5);
  assert.ok(Array.isArray(result.audits));
  assert.ok(Array.isArray(result.advice));

  const status = await quickStatusCheck(`http://127.0.0.1:${port}/`);
  assert.equal(status.live, true);
  assert.equal(status.statusCode, 200);

  srv.close();
});

test('page speed analyzer rejects invalid URLs', async () => {
  await assert.rejects(() => analyzePageSpeed('not a url'));
});

test('ollama base URL normalizer accepts valid inputs and rejects bad schemes', () => {
  assert.equal(normalizeOllamaBaseUrl(''), 'http://localhost:11434');
  assert.equal(normalizeOllamaBaseUrl('localhost:11434'), 'http://localhost:11434');
  assert.equal(normalizeOllamaBaseUrl('http://localhost:11434/'), 'http://localhost:11434');
  assert.equal(normalizeOllamaBaseUrl('https://ollama.corp.example'), 'https://ollama.corp.example');
  assert.equal(normalizeOllamaBaseUrl('http://192.168.1.20:11434/api'), 'http://192.168.1.20:11434');
  assert.throws(() => normalizeOllamaBaseUrl('ftp://bad'), /http:\/\/ or https:\/\//);
  assert.throws(() => normalizeOllamaBaseUrl('javascript:alert(1)'));
  assert.throws(() => normalizeOllamaBaseUrl('http://'));
});
