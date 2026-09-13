import { state } from './state.js';
import { $, $$, toast } from './utils.js';
import { setupModals, updateAiLabel } from './components/modals.js';
import { setupScanForm, renderWpAdmin, loadHistory, renderFullScan, renderHistory, setupHistory } from './components/scanner.js';
import { setupNetworkDiscovery, loadNetworkInfo, renderDevicesTable, inspectHostDetailsModal } from './components/netdiscovery.js';
import { setupMonitors, loadMonitors, renderMonitors, updateMonitorBadge } from './components/monitors.js';
import { setupLoadTester } from './components/loadtester.js';
import { setupInspector } from './components/inspector.js';
import { setupDatabaseTester } from './components/dbtester.js';
import { setupTLSAndRecon } from './components/tlsrecon.js';
import { renderDashboard } from './components/dashboard.js';
import { setupSpeedTester } from './components/speedtest.js';
import { setupNotificationCenter, loadNotifications, handleWsNotification, updateBadge } from './components/notifications.js';

declare global {
  interface Window {
    loadScanFromHistory: (id: string) => Promise<void>;
    scanHostPortsModal: (host: string) => Promise<void>;
    inspectHostDetailsModal: (host: string) => Promise<void>;
    copyToClipboard: (text: string, message?: string) => void;
    checkMonitorNow: (id: string) => Promise<void>;
    toggleMonitor: (id: string) => Promise<void>;
    deleteMonitor: (id: string) => Promise<void>;
    switchToView: (view: string) => void;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  setupModals();
  setupScanForm(switchView);
  setupHistory();
  setupNetworkDiscovery();
  setupMonitors();
  setupLoadTester();
  setupInspector();
  setupDatabaseTester();
  setupTLSAndRecon();
  setupSpeedTester();
  setupNotificationCenter();
  setupWebSocket();
  checkHealthAndConfig();
});

function setupNavigation() {
  $$('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const view = (tab as HTMLElement).dataset.view;
      if (!view) return;
      switchView(view);
    });
  });
  $$('.subtab').forEach(tab => {
    tab.addEventListener('click', () => {
      const subtab = (tab as HTMLElement).dataset.subtab;
      if (!subtab) return;
      state.activeSubtab = subtab;
      $$('.subtab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      $$('.panel').forEach(p => p.classList.remove('active'));
      const panel = $('panel-' + subtab);
      if (panel) panel.classList.add('active');
    });
  });
  $$('.itab').forEach(tab => {
    tab.addEventListener('click', () => {
      const target = (tab as HTMLElement).dataset.target;
      $$('.itab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      $$('.ipane').forEach(p => p.classList.remove('active'));
      if (target && $(target)) $(target).classList.add('active');
    });
  });
}

export function switchView(name: string) {
  state.activeView = name;
  $$('.nav-tab').forEach(t => t.classList.toggle('active', (t as HTMLElement).dataset.view === name));
  $$('.view').forEach(p => p.classList.toggle('active', p.id === 'view-' + name));
  if (name === 'dashboard') renderDashboard();
  if (name === 'wpadmin' && state.currentScan) renderWpAdmin((state.currentScan as any).wpAdmin);
  if (name === 'netdiscovery' && !state.networkInterfaces.length) loadNetworkInfo();
  if (name === 'monitor') { loadMonitors(); loadNotifications(); }
}
(window as any).switchToView = switchView;

function setupWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = protocol + '//' + window.location.host + '/ws';
  try {
    const ws = new WebSocket(wsUrl);
    (state as any).ws = ws;
    ws.onopen = () => ws.send(JSON.stringify({ action: 'subscribe', channel: 'all' }));
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.channel === 'monitor_update') {
          const idx = state.monitors.findIndex(m => m.id === msg.data.id);
          if (idx >= 0) state.monitors[idx] = msg.data; else state.monitors.push(msg.data);
          if (state.activeView === 'monitor') renderMonitors();
          updateMonitorBadge();
        } else if (msg.channel === 'notification') {
          handleWsNotification(msg.data);
        }
      } catch {}
    };
    ws.onclose = () => setTimeout(setupWebSocket, 5000);
  } catch {}
}

async function checkHealthAndConfig() {
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    if (data.ok) {
      $('health-text').textContent = 'v' + (data.version || '2.1') + ' • ' + data.running + ' running';
      if (data.ai) { state.aiConfig.provider = data.ai; updateAiLabel(); }
    }
  } catch { $('health-text').textContent = 'Offline'; }
  try {
    const res = await fetch('/api/config');
    const conf = await res.json();
    if (conf.provider) state.aiConfig.provider = conf.provider;
    if (conf.model) state.aiConfig.model = conf.model;
    updateAiLabel();
  } catch {}
  // Initial notification load for the unread badge
  try { await loadNotifications(); } catch {}
  updateBadge();
}

// Window global assignments
window.inspectHostDetailsModal = inspectHostDetailsModal;

window.copyToClipboard = (text, message = 'Copied') => {
  navigator.clipboard.writeText(text).then(() => toast(message, 'success'));
};

window.scanHostPortsModal = async (host) => {
  const btn = (event as any)?.target as HTMLButtonElement;
  if (btn) { btn.disabled = true; btn.textContent = 'Scanning…'; }
  try {
    const res = await fetch('/api/netdiscovery/scan-host', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ host }) });
    const data = await res.json();
    const dev = state.discoveredDevices.find(d => d.ip === host);
    if (dev) { dev.openPorts = data.openPorts || []; renderDevicesTable(); toast('Port scan for ' + host + ' complete', 'success'); }
  } catch (err: any) { toast('Port scan error: ' + err.message, 'error'); }
  finally { if (btn) { btn.disabled = false; btn.textContent = 'Scan'; } }
};

window.checkMonitorNow = async (id) => {
  await fetch('/api/monitors/' + id + '/check', { method: 'POST' }).catch(() => {});
  toast('Check triggered', 'info');
};

window.toggleMonitor = async (id) => {
  try {
    const res = await fetch('/api/monitors/' + id + '/toggle', { method: 'POST' });
    const updated = await res.json();
    const idx = state.monitors.findIndex(m => m.id === id);
    if (idx >= 0 && updated.id) state.monitors[idx] = updated;
    renderMonitors();
    toast(updated.active ? 'Monitor resumed' : 'Monitor paused', 'success');
  } catch (err: any) { toast('Toggle failed: ' + err.message, 'error'); }
};

window.deleteMonitor = async (id) => {
  if (!confirm('Delete this monitor?')) return;
  await fetch('/api/monitors/' + id, { method: 'DELETE' });
  state.monitors = state.monitors.filter(m => m.id !== id);
  renderMonitors();
  updateMonitorBadge();
  toast('Monitor deleted', 'success');
};

window.loadScanFromHistory = async (id) => {
  switchView('scanner');
  $('empty').classList.add('hidden');
  $('scan-view').classList.remove('hidden');
  try {
    const res = await fetch('/api/scans/' + id);
    const scan = await res.json();
    (state as any).currentScan = scan;
    renderFullScan(scan);
    renderHistory();
  } catch (err: any) { toast('Failed to load scan: ' + err.message, 'error'); }
};
