import { Router } from 'express';
import { monitorService } from '../modules/monitor.js';
import { notificationService } from '../modules/notifications.js';

/**
 * Uptime monitor + notification routes.
 * Monitors support per-monitor notification preferences (notifyOn).
 */
const router = Router();

router.get('/monitors', (req, res) => {
  res.json(monitorService.getMonitors());
});

router.post('/monitors', async (req, res) => {
  try {
    const monitor = await monitorService.createMonitor(req.body || {});
    res.status(201).json(monitor);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/monitors/:id', (req, res) => {
  const m = monitorService.getMonitor(req.params.id);
  if (!m) return res.status(404).json({ error: 'monitor not found' });
  res.json(m);
});

router.post('/monitors/:id/check', async (req, res) => {
  const updated = await monitorService.checkMonitor(req.params.id);
  if (!updated) return res.status(404).json({ error: 'monitor not found' });
  res.json(updated);
});

router.post('/monitors/:id/toggle', async (req, res) => {
  const updated = await monitorService.toggleMonitor(req.params.id);
  if (!updated) return res.status(404).json({ error: 'monitor not found' });
  res.json(updated);
});

router.delete('/monitors/:id', async (req, res) => {
  const deleted = await monitorService.deleteMonitor(req.params.id);
  if (!deleted) return res.status(404).json({ error: 'monitor not found' });
  res.status(204).end();
});

/* ------------------------- Notifications ------------------------- */

router.get('/notifications', (req, res) => {
  const limit = Number(req.query.limit) || 100;
  const unreadOnly = req.query.unread === '1' || req.query.unread === 'true';
  res.json(notificationService.list({ limit, unreadOnly }));
});

router.get('/notifications/unread-count', (req, res) => {
  res.json({ unread: notificationService.unreadCount() });
});

router.post('/notifications/:id/read', async (req, res) => {
  const n = await notificationService.markRead(req.params.id);
  if (!n) return res.status(404).json({ error: 'notification not found' });
  res.json({ ok: true, unread: notificationService.unreadCount() });
});

router.post('/notifications/read-all', async (req, res) => {
  const unread = await notificationService.markAllRead();
  res.json({ ok: true, unread });
});

router.delete('/notifications/:id', async (req, res) => {
  const deleted = await notificationService.delete(req.params.id);
  if (!deleted) return res.status(404).json({ error: 'notification not found' });
  res.status(204).end();
});

router.delete('/notifications', async (req, res) => {
  await notificationService.clearAll();
  res.status(204).end();
});

export default router;
