import type { AppState, Finding } from './types.js';

declare global {
  interface Window {
    loadScanFromHistory: (id: string) => Promise<void>;
    scanHostPortsModal: (host: string) => Promise<void>;
    copyToClipboard: (text: string, message?: string) => void;
    checkMonitorNow: (id: string) => Promise<void>;
    deleteMonitor: (id: string) => Promise<void>;
  }
}

const state: AppState = {
  activeView: 'scanner',
  activeSubtab: 'findings',
  currentScan: null,
  scansHistory: [],
  monitors: [],
  discoveredDevices: [],
  networkInterfaces: [],
  gateway: null,
  aiConfig: {
    provider: (sessionStorage.getItem('monarch_provider') as any) || 'openrouter',
    apiKey: sessionStorage.getItem('monarch_ai_key') || '',
    model: sessionStorage.getItem('monarch_model') || 'deepseek/deepseek-r1-distill-qwen-7b',
  },
  filters: {
    findingText: '',
    severities: new Set(['critical', 'high', 'medium', 'low', 'info']),
  },
  ws: null,
};

const $ = (id: string) => document.getElementById(id) as HTMLElement;
const $$ = (sel: string) => document.querySelectorAll(sel);

function toast(message: string, type: 'success' | 'error' | 'info' = 'info') {
  const container = $('toast-container');
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(8px)';
    setTimeout(() => el.remove(), 200);
  }, 3000);
}

function escapeHtml(str: any) {
  if (str == null) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}
function formatBytes(b: number) {
  if (!b) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(b) / Math.log(k));
  return parseFloat((b / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  setupModals();
  setupScanForm();
  setupHistory();
  setupNetworkDiscovery();
  setupMonitors();
  setupLoadTester();
  setupInspector();
  setupDatabaseTester();
  setupTLSAndRecon();
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

function switchView(name: string) {
  state.activeView = name;
  $$('.nav-tab').forEach(t => t.classList.toggle('active', (t as HTMLElement).dataset.view === name));
  $$('.view').forEach(p => p.classList.toggle('active', p.id === 'view-' + name));
  if (name === 'dashboard') renderDashboard();
  if (name === 'wpadmin' && state.currentScan) renderWpAdmin((state.currentScan as any).wpAdmin);
  if (name === 'netdiscovery' && !state.networkInterfaces.length) loadNetworkInfo();
  if (name === 'monitor') loadMonitors();
}

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
      $('health-text').textContent = 'v' + (data.version || '2.0') + ' • ' + data.running + ' running';
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
}
function updateAiLabel() {
  const names: any = { openrouter: 'AI: OpenRouter', openai: 'AI: OpenAI', anthropic: 'AI: Claude', gemini: 'AI: Gemini', none: 'Offline' };
  $('ai-config-label').textContent = names[state.aiConfig.provider] || 'AI: ' + state.aiConfig.provider;
}
function setupModals() {
  const devBtn = $('dev-modal-btn');
  if (devBtn) devBtn.addEventListener('click', () => { loadDevProfile(); $('dev-modal').classList.remove('hidden'); });
  const devClose = $('dev-modal-close');
  if (devClose) devClose.addEventListener('click', () => $('dev-modal').classList.add('hidden'));
  $('ai-config-btn').addEventListener('click', () => {
    ( $('ai-provider-select') as HTMLSelectElement).value = state.aiConfig.provider;
    ( $('ai-key-input') as HTMLInputElement).value = state.aiConfig.apiKey;
    ( $('ai-model-input') as HTMLInputElement).value = state.aiConfig.model || '';
    $('ai-modal').classList.remove('hidden');
  });
  $('ai-modal-close').addEventListener('click', () => $('ai-modal').classList.add('hidden'));
  $('ai-provider-select').addEventListener('change', (e) => {
    const prov = (e.target as HTMLSelectElement).value;
    const defaults: any = { openrouter: 'deepseek/deepseek-r1-distill-qwen-7b', openai: 'gpt-4o-mini', anthropic: 'claude-3-5-haiku-latest', gemini: 'gemini-1.5-flash', none: 'monarch-rules-v1' };
    ( $('ai-model-input') as HTMLInputElement).value = defaults[prov] || '';
    $('ai-key-group').style.display = prov === 'none' ? 'none' : 'block';
  });
  $('ai-config-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const provider = ( $('ai-provider-select') as HTMLSelectElement).value as any;
    const apiKey = ( $('ai-key-input') as HTMLInputElement).value.trim();
    const model = ( $('ai-model-input') as HTMLInputElement).value.trim();
    state.aiConfig = { provider, apiKey, model };
    sessionStorage.setItem('monarch_provider', provider);
    sessionStorage.setItem('monarch_model', model);
    if (apiKey) sessionStorage.setItem('monarch_ai_key', apiKey); else sessionStorage.removeItem('monarch_ai_key');
    await fetch('/api/config', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(state.aiConfig) }).catch(()=>{});
    updateAiLabel();
    $('ai-modal').classList.add('hidden');
    toast('AI configuration saved', 'success');
  });
  $('ai-clear-btn').addEventListener('click', async () => {
    state.aiConfig = { provider: 'none', apiKey: '', model: 'monarch-rules-v1' };
    sessionStorage.removeItem('monarch_ai_key');
    sessionStorage.setItem('monarch_provider', 'none');
    ( $('ai-provider-select') as HTMLSelectElement).value = 'none';
    ( $('ai-key-input') as HTMLInputElement).value = '';
    ( $('ai-model-input') as HTMLInputElement).value = 'monarch-rules-v1';
    await fetch('/api/config', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(state.aiConfig) }).catch(()=>{});
    updateAiLabel();
    $('ai-modal').classList.add('hidden');
    toast('Switched to offline heuristic', 'success');
  });
  const addMonBtn = $('add-monitor-btn');
  if (addMonBtn) addMonBtn.addEventListener('click', () => $('monitor-modal').classList.remove('hidden'));
  const monClose = $('mon-modal-close');
  if (monClose) monClose.addEventListener('click', () => $('monitor-modal').classList.add('hidden'));
  const monCancel = $('mon-cancel-btn');
  if (monCancel) monCancel.addEventListener('click', () => $('monitor-modal').classList.add('hidden'));
  $$('.backdrop').forEach(bd => {
    bd.addEventListener('click', (e) => { if (e.target === bd) bd.classList.add('hidden'); });
  });
}
async function loadDevProfile() {
  try {
    const res = await fetch('https://api.github.com/users/mahmud-r-farhan', { headers: { Accept: 'application/vnd.github.v3+json' } });
    if (res.ok) {
      const d = await res.json();
      if (d.avatar_url) ( $('dev-avatar') as HTMLImageElement).src = d.avatar_url;
      if (d.name) $('dev-name').textContent = d.name;
      if (d.login) $('dev-handle').textContent = '@' + d.login;
      if (d.bio) $('dev-bio').textContent = d.bio;
    }
  } catch {}
}

function setupScanForm() {
  $('scan-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = ( $('target') as HTMLInputElement).value.trim();
    const engine = ( $('engine') as HTMLSelectElement).value;
    const maxPages = Number(( $('pages') as HTMLInputElement).value) || 25;
    if (!target) return;
    switchView('scanner');
    const btn = $('scan-btn') as HTMLButtonElement;
    btn.disabled = true;
    btn.innerHTML = '⏳ Scanning…';
    $('empty').classList.add('hidden');
    $('scan-view').classList.remove('hidden');
    $('s-target').textContent = target;
    $('s-meta').textContent = 'Initializing crawl (' + engine + ')…';
    $('live-status').textContent = 'Connecting to scanner engine…';
    ( $('progress-bar') as HTMLElement).style.width = '10%';
    $('grade').textContent = '–';
    $('grade').className = 'grade-circle';
    $('findings').innerHTML = '<div class="empty">🔍 Discovering endpoints & checking vulnerabilities…</div>';
    const netBody = $('net-body');
    if (netBody) netBody.innerHTML = '';
    $('ai').innerHTML = '<div class="empty">🤖 AI remediation plan will generate upon completion…</div>';

    try {
      const res = await fetch('/api/scans', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ target, engine, maxPages, ai: true, aiConfig: state.aiConfig }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to start scan');
      }
      const data = await res.json() as any;
      streamScanEvents(data.id);
    } catch (err: any) {
      toast('Scan failed: ' + err.message, 'error');
      resetScanBtn();
    }
  });
}
function resetScanBtn() {
  const btn = $('scan-btn') as HTMLButtonElement;
  btn.disabled = false;
  btn.innerHTML = '⚡ Scan';
}
function streamScanEvents(id: string) {
  const es = new EventSource('/api/scans/' + id + '/events');
  let reqCount = 0;
  let pageCount = 0;
  const liveFindings: Finding[] = [];

  es.addEventListener('status', (ev) => {
    const data = JSON.parse((ev as MessageEvent).data);
    $('live-status').textContent = data.message || '';
    if (data.stage === 'crawl') {
      pageCount = data.pages || pageCount;
      ( $('progress-bar') as HTMLElement).style.width = '40%';
      $('s-meta').textContent = 'Crawled ' + pageCount + ' pages · ' + reqCount + ' requests';
    } else if (data.stage === 'analyze') {
      ( $('progress-bar') as HTMLElement).style.width = '70%';
    } else if (data.stage === 'ai') {
      ( $('progress-bar') as HTMLElement).style.width = '90%';
    }
  });
  es.addEventListener('network', (ev) => {
    const d = JSON.parse((ev as MessageEvent).data);
    const entry = d.entry;
    reqCount++;
    $('s-meta').textContent = 'Crawled ' + pageCount + ' pages · ' + reqCount + ' requests';
    $('t-network').textContent = String(reqCount);
    appendNetworkRow(entry, reqCount);
  });
  es.addEventListener('finding', (ev) => {
    const d = JSON.parse((ev as MessageEvent).data);
    const finding = d.finding;
    liveFindings.push(finding);
    $('t-findings').textContent = String(liveFindings.length);
    const badge = $('t-findings-badge');
    if (badge) badge.textContent = String(liveFindings.length);
    renderFindings(liveFindings);
    updateSeverityPills(liveFindings);
  });
  es.addEventListener('done', async () => {
    es.close();
    ( $('progress-bar') as HTMLElement).style.width = '100%';
    $('live-status').textContent = '✅ Audit complete';
    resetScanBtn();
    const fullRes = await fetch('/api/scans/' + id);
    const scan = await fullRes.json();
    (state as any).currentScan = scan;
    renderFullScan(scan);
    loadHistory();
    toast('Scan completed successfully', 'success');
  });
  es.addEventListener('closed', () => { es.close(); resetScanBtn(); });
  es.onerror = () => { es.close(); resetScanBtn(); };
}

function renderFullScan(scan: any) {
  $('grade').textContent = scan.score?.grade || '–';
  $('grade').className = 'grade-circle grade-' + (scan.score?.grade || 'C');
  $('s-target').textContent = scan.target;
  $('s-meta').textContent = 'Completed in ' + Math.round(scan.durationMs/1000) + 's · ' + (scan.crawl?.pages?.length||0) + ' pages · ' + (scan.networkSummary?.requests||0) + ' requests';
  renderFindings(scan.findings||[]);
  renderAiInsights(scan.insights, scan);
  renderCookiesAndStorage(scan);
  renderInventory(scan);
  renderExportButtons(scan.id);
  renderTechStack(scan.techStack||[], scan.rateLimiting);
  renderSeoAudit(scan.seo);
  renderWpAdmin(scan.wpAdmin);
  renderDashboard();
}

function renderFindings(findings: Finding[]) {
  const container = $('findings');
  if (!findings.length) { container.innerHTML = '<div class="empty">✅ No vulnerabilities detected! Posture is hardened.</div>'; return; }
  const query = state.filters.findingText.toLowerCase();
  const filtered = findings.filter(f => {
    if (!state.filters.severities.has(f.severity as any)) return false;
    if (!query) return true;
    return (f.title||'').toLowerCase().includes(query) || (f.category||'').toLowerCase().includes(query) || (f.description||'').toLowerCase().includes(query);
  });
  let html = '';
  for (const f of filtered) {
    const loc = (f as any).location || '';
    const remediation = (f as any).remediation ? '<div class="codeblock"><b>Fix:</b> ' + escapeHtml((f as any).remediation) + '</div>' : '';
    const cwe = ((f as any).cwe || (f as any).owasp) ? '<div style="margin-top:6px;font-size:10px;color:var(--text-muted);font-family:var(--font-mono);">' + escapeHtml((f as any).cwe||'') + ' ' + escapeHtml((f as any).owasp||'') + '</div>' : '';
    html += '<div class="card"><div class="card-head"><div class="card-title"><span class="sev ' + f.severity + '">' + f.severity + '</span><span class="title">' + escapeHtml(f.title) + '</span></div><span class="loc">' + escapeHtml(loc) + '</span></div><div class="desc">' + escapeHtml(f.description) + '</div>' + remediation + cwe + '</div>';
  }
  container.innerHTML = html;
}
function updateSeverityPills(findings: Finding[]) {
  const counts: any = { critical:0, high:0, medium:0, low:0, info:0 };
  findings.forEach(f => counts[f.severity] = (counts[f.severity]||0)+1);
  let html = '';
  if (counts.critical) html += '<span class="pill crit">' + counts.critical + ' Crit</span>';
  if (counts.high) html += '<span class="pill high">' + counts.high + ' High</span>';
  if (counts.medium) html += '<span class="pill med">' + counts.medium + ' Med</span>';
  if (counts.low) html += '<span class="pill low">' + counts.low + ' Low</span>';
  $('sev-counts').innerHTML = html;
}
const fFilter = $('f-filter');
if (fFilter) fFilter.addEventListener('input', (e) => {
  state.filters.findingText = (e.target as HTMLInputElement).value;
  if ((state.currentScan as any)?.findings) renderFindings((state.currentScan as any).findings as any);
});

function renderAiInsights(insights: any, _scan: any) {
  const c = $('ai');
  if (!insights) { c.innerHTML = '<div class="empty">No AI insights generated</div>'; return; }
  let actionPlanHtml = '';
  const plan = insights.actionPlan || [];
  for (const item of plan) {
    actionPlanHtml += '<div class="plan-item"><div class="plan-head"><span class="plan-prio">Priority #' + item.priority + '</span><span class="sev ' + (item.effort==='low'?'low':'medium') + '">' + escapeHtml(item.effort) + ' effort</span></div><div class="plan-title">' + escapeHtml(item.title) + '</div><div class="plan-why">' + escapeHtml(item.why) + '</div><div class="codeblock">' + escapeHtml(item.how) + '</div></div>';
  }
  const attack = insights.attackNarrative ? '<div class="ai-narrative"><b>⚠️ Attack Chain:</b> ' + escapeHtml(insights.attackNarrative) + '</div>' : '';
  const warning = insights.warning ? '<div style="margin-top:10px;padding:8px 12px;background:var(--warning-soft);border:1px solid rgba(255,176,46,0.25);border-radius:8px;font-size:12px;color:var(--warning);">' + escapeHtml(insights.warning) + '</div>' : '';
  c.innerHTML = '<div class="ai-card"><div class="ai-badge">🤖 ' + escapeHtml(insights.provider) + ' • ' + escapeHtml(insights.model) + '</div><div class="ai-summary">' + escapeHtml(insights.executiveSummary||'') + '</div>' + attack + warning + '</div><div class="box"><h3 style="margin-bottom:12px;">Prioritized Action Plan</h3>' + actionPlanHtml + '</div>';
}

function appendNetworkRow(entry: any, index: number) {
  const tbody = $('net-body');
  if (!tbody) return;
  const tr = document.createElement('tr');
  const status = entry.status || 0;
  const statusClass = status>=500?'crit':status>=400?'high':status>=300?'med':'low';
  tr.innerHTML = '<td>' + index + '</td><td><span class="badge">' + escapeHtml(entry.method||'GET') + '</span></td><td><span class="pill ' + statusClass + '">' + status + '</span></td><td>' + escapeHtml(entry.type||'fetch') + '</td><td>' + formatBytes(entry.size||0) + '</td><td>' + (entry.timing?.total||0) + 'ms</td><td title="' + escapeHtml(entry.url) + '">' + escapeHtml(entry.url) + '</td>';
  tr.addEventListener('click', () => {
    const rows = document.querySelectorAll('#net-body tr');
    rows.forEach(r=>r.classList.remove('active'));
    tr.classList.add('active');
    showNetworkDetail(entry);
  });
  tbody.appendChild(tr);
}
function showNetworkDetail(entry: any) {
  const detail = $('net-detail');
  detail.classList.remove('hidden');
  let headersStr = '';
  const hdrs = entry.response?.headers || {};
  for (const k in hdrs) { headersStr += k + ': ' + hdrs[k] + '\n'; }
  detail.innerHTML = '<div style="display:flex;justify-content:space-between;margin-bottom:10px;"><h4 style="font-size:13px;font-weight:700;">Request Details</h4><button class="icon-btn" onclick="document.getElementById(\'net-detail\').classList.add(\'hidden\')">×</button></div><div style="margin-bottom:8px;"><span class="sev low">' + (entry.method||'GET') + '</span><span style="font-family:var(--font-mono);font-size:11px;margin-left:6px;">' + escapeHtml(entry.url) + '</span></div><div class="form-group"><label>Response Headers</label><div class="codeblock" style="max-height:160px;">' + escapeHtml(headersStr) + '</div></div>';
}

function renderCookiesAndStorage(scan: any) {
  const cookies = scan.crawl?.cookies||[];
  const c = $('cookies');
  if (!cookies.length) { c.innerHTML = '<div class="empty">No cookies detected</div>'; return; }
  let rows = '';
  for (const co of cookies) {
    rows += '<tr><td style="font-weight:700;">' + escapeHtml(co.name) + '</td><td>' + (co.httpOnly?'✅':'❌') + '</td><td>' + (co.secure?'✅':'❌') + '</td><td>' + escapeHtml(co.sameSite||'None') + '</td><td>' + escapeHtml(co.path||'/') + '</td><td style="font-size:10px;color:var(--text-muted);">' + escapeHtml(co.setBy||'') + '</td></tr>';
  }
  c.innerHTML = '<div class="table-wrap"><table class="table"><thead><tr><th>Name</th><th>HttpOnly</th><th>Secure</th><th>SameSite</th><th>Path</th><th>Set By</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
}
function renderInventory(scan: any) {
  const origins = scan.crawl?.externalOrigins||[];
  let grid = '';
  for (const o of origins) { grid += '<div class="tech"><div class="tech-name">🌐 ' + escapeHtml(o) + '</div><div class="tech-cat">External</div></div>'; }
  $('inventory').innerHTML = '<div class="box-head"><h3>External Dependencies (' + origins.length + ')</h3></div><div class="tech-grid">' + grid + '</div>';
}
function renderExportButtons(scanId: string) {
  $('export').innerHTML = '<a href="/api/scans/' + scanId + '/report.md" download class="btn btn-ghost" style="height:28px;font-size:11px;">MD</a><a href="/api/scans/' + scanId + '/report.html" target="_blank" class="btn btn-ghost" style="height:28px;font-size:11px;">HTML</a><a href="/api/scans/' + scanId + '/report.json" download class="btn btn-ghost" style="height:28px;font-size:11px;">JSON</a><a href="/api/scans/' + scanId + '/report.sarif" download class="btn btn-ghost" style="height:28px;font-size:11px;">SARIF</a>';
}

function renderWpAdmin(wpAdmin: any) {
  if (!wpAdmin) return;
  const detected = $('wp-detected');
  if (detected) {
    detected.textContent = wpAdmin.isWordpress ? 'WordPress Active' : (wpAdmin.isPhp ? 'PHP App' : 'Not Detected');
    (detected as HTMLElement).style.color = wpAdmin.isWordpress ? 'var(--warning)' : 'var(--text)';
  }
  const xmlrpc = $('wp-xmlrpc');
  if (xmlrpc) {
    xmlrpc.textContent = wpAdmin.xmlRpcExposed ? 'Exposed (Risk)' : 'Blocked';
    (xmlrpc as HTMLElement).style.color = wpAdmin.xmlRpcExposed ? 'var(--danger)' : 'var(--success)';
  }
  const userEnumEl = $('wp-user-enum');
  if (userEnumEl) {
    const count = wpAdmin.userEnumeration?.usernames?.length||0;
    userEnumEl.textContent = wpAdmin.userEnumeration?.vulnerable ? 'Vulnerable (' + count + ')' : 'Protected';
    (userEnumEl as HTMLElement).style.color = wpAdmin.userEnumeration?.vulnerable ? 'var(--danger)' : 'var(--success)';
  }
  const endpointsWrap = $('wp-endpoints-container');
  if (endpointsWrap) {
    if (!wpAdmin.exposedEndpoints?.length) endpointsWrap.innerHTML = '<div class="empty">No exposed admin portals</div>';
    else {
      let h = '';
      for (const ep of wpAdmin.exposedEndpoints) { h += '<div class="tech"><div class="tech-name">🔑 ' + escapeHtml(ep.name) + '</div><div class="tech-cat">' + escapeHtml(ep.category) + ' • ' + ep.status + '</div><div class="tech-ev">' + escapeHtml(ep.path) + '</div></div>'; }
      endpointsWrap.innerHTML = '<div class="tech-grid">' + h + '</div>';
    }
  }
  const usersWrap = $('wp-users-container');
  if (usersWrap) {
    if (!wpAdmin.userEnumeration?.usernames?.length) usersWrap.innerHTML = '<div class="empty">No usernames leaked</div>';
    else {
      let h = '';
      for (const u of wpAdmin.userEnumeration.usernames) { h += '<div class="tech"><div class="tech-name">👤 ' + escapeHtml(u) + '</div><div class="tech-cat">WordPress User</div></div>'; }
      usersWrap.innerHTML = '<div class="tech-grid">' + h + '</div>';
    }
  }
}

function renderTechStack(technologies: any[], rateLimiting: any) {
  const badge = $('tech-badge-count');
  if (badge) badge.textContent = String(technologies.length);
  const techList = $('tech-list');
  if (!technologies.length) techList.innerHTML = '<div class="empty">No technology signatures detected</div>';
  else {
    let h = '';
    for (const t of technologies) { h += '<div class="tech"><div class="tech-name">' + escapeHtml(t.name) + '</div><div class="tech-cat">' + escapeHtml(t.category) + '</div><div class="tech-ev" title="' + escapeHtml(t.evidence) + '">' + escapeHtml(t.evidence) + '</div></div>'; }
    techList.innerHTML = h;
  }
  const rl = $('ratelimit-info');
  if (!rateLimiting) { rl.innerHTML = '<div class="empty">No rate limiting data</div>'; return; }
  const sample = rateLimiting.sampleHeader ? '<div class="codeblock" style="margin-top:6px;">' + escapeHtml(rateLimiting.sampleHeader) + '</div>' : '<p style="font-size:11px;color:var(--text-muted);margin-top:4px;">No standard RateLimit headers observed</p>';
  const enforced = rateLimiting.enforced ? '<span style="color:var(--success);">Enforced</span>' : '<span style="color:var(--warning);">Not Detected</span>';
  rl.innerHTML = '<div class="tech" style="margin-bottom:10px;"><div class="tech-name">Rate Limiting: ' + enforced + '</div><div class="tech-cat">' + rateLimiting.apiRequestsObserved + ' API requests observed</div>' + sample + '</div>';
}

function renderSeoAudit(seo: any) {
  if (!seo) return;
  const scoreEl = $('seo-overall-score').querySelector('.seo-num');
  if (scoreEl) scoreEl.textContent = (seo.score||0) + '%';
  const container = $('seo-pages-container');
  if (!seo.pages?.length) { container.innerHTML = '<div class="empty">No SEO pages audited</div>'; return; }
  let html = '';
  for (const p of seo.pages) {
    html += '<div class="seo-page"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;"><div class="seo-url">📄 ' + escapeHtml(p.url) + '</div><span class="sev ' + (p.score>=80?'low':'medium') + '">' + p.score + '/100</span></div><div class="seo-checks"><div class="seo-item"><div class="seo-k">Title</div><div class="seo-v">' + escapeHtml(p.title) + '</div></div><div class="seo-item"><div class="seo-k">Meta Desc</div><div class="seo-v">' + escapeHtml(p.metaDescription) + '</div></div><div class="seo-item"><div class="seo-k">H1</div><div class="seo-v">' + escapeHtml(p.headings.h1[0]||'(None)') + '</div></div><div class="seo-item"><div class="seo-k">Lang & Viewport</div><div class="seo-v">Lang: ' + p.htmlLang + ' • Viewport: ' + (p.viewport?'✅':'❌') + '</div></div><div class="seo-item"><div class="seo-k">OpenGraph</div><div class="seo-v">' + (p.openGraph.ogTitle?'✅ OG':'❌ No OG') + ' • ' + (p.openGraph.twitterCard?'✅ Twitter':'❌ No Twitter') + '</div></div><div class="seo-item"><div class="seo-k">Images Alt</div><div class="seo-v">' + p.images.missingAlt + ' / ' + p.images.total + ' missing</div></div></div></div>';
  }
  container.innerHTML = html;
}

function renderDashboard() {
  const scan = (state as any).currentScan;
  if (!scan) return;
  const counts = (scan as any).score?.counts||{};
  $('dash-critical').textContent = String(counts.critical||0);
  $('dash-high').textContent = String(counts.high||0);
  $('dash-medium').textContent = String(counts.medium||0);
  $('dash-total-scans').textContent = String(state.scansHistory.length||1);
  $('dash-monitors-up').textContent = String(state.monitors.filter(m=>m.status==='up').length);
  const total = (scan as any).findings?.length||1;
  const sevBars = $('sev-bars');
  if (sevBars) {
    sevBars.innerHTML = '<div style="display:flex;flex-direction:column;gap:8px;"><div><div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:2px;"><span>Critical (' + (counts.critical||0) + ')</span><span>' + Math.round(((counts.critical||0)/total)*100) + '%</span></div><div class="progress-wrap"><div class="progress" style="width:' + ((counts.critical||0)/total)*100 + '%;background:var(--danger);"></div></div></div><div><div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:2px;"><span>High (' + (counts.high||0) + ')</span><span>' + Math.round(((counts.high||0)/total)*100) + '%</span></div><div class="progress-wrap"><div class="progress" style="width:' + ((counts.high||0)/total)*100 + '%;background:#ff7a3d;"></div></div></div><div><div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:2px;"><span>Medium (' + (counts.medium||0) + ')</span><span>' + Math.round(((counts.medium||0)/total)*100) + '%</span></div><div class="progress-wrap"><div class="progress" style="width:' + ((counts.medium||0)/total)*100 + '%;background:var(--warning);"></div></div></div></div>';
  }
  const cats: any = {};
  (scan as any).findings?.forEach((f:any)=>{ cats[f.category]=(cats[f.category]||0)+1; });
  const sortedCats = Object.entries(cats).sort((a:any,b:any)=>(b[1] as number)-(a[1] as number)).slice(0,8);
  let catHtml = '';
  for (const entry of sortedCats) {
    const cat = entry[0] as string;
    const count = entry[1] as number;
    catHtml += '<li style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border-soft);font-size:12px;"><span>' + escapeHtml(cat) + '</span><span class="badge">' + count + '</span></li>';
  }
  $('cat-list').innerHTML = catHtml || '<li class="empty">No categories</li>';
}

let networkSearchQuery = '';
function setupNetworkDiscovery() {
  loadNetworkInfo();
  const modeSelect = $('net-mode-select') as HTMLSelectElement;
  if (modeSelect) modeSelect.addEventListener('change', (e) => {
    const isCustom = (e.target as HTMLSelectElement).value === 'custom';
    const customRow = $('net-custom-row');
    if (customRow) customRow.classList.toggle('hidden', !isCustom);
  });
  const segSelect = $('net-segment-select') as HTMLSelectElement;
  if (segSelect) segSelect.addEventListener('change', (e) => {
    if ((e.target as HTMLSelectElement).value) {
      ( $('net-target-input') as HTMLInputElement).value = (e.target as HTMLSelectElement).value;
    }
  });
  const devSearch = $('dev-search-input') as HTMLInputElement;
  if (devSearch) devSearch.addEventListener('input', (e) => {
    networkSearchQuery = (e.target as HTMLInputElement).value.toLowerCase().trim();
    renderDevicesTable();
  });
  const exportCsv = $('dev-export-csv');
  if (exportCsv) exportCsv.addEventListener('click', () => {
    if (!state.discoveredDevices.length) return toast('No devices to export', 'error');
    const rows = [['IP','MAC','Vendor','Hostname','Gateway','Latency','TCP','UDP']];
    for (const d of state.discoveredDevices) {
      const tcp = (d.openPorts||[]).filter((p:any)=>p.proto==='tcp'||!p.proto).map((p:any)=>p.port + '/' + p.service).join(';');
      const udp = (d.openPorts||[]).filter((p:any)=>p.proto==='udp').map((p:any)=>p.port + '/' + p.service).join(';');
      rows.push([d.ip, d.mac||'', d.vendor||'', d.hostname||'', d.isGateway?'YES':'NO', String(d.rtt??''), tcp, udp]);
    }
    const csv = rows.map(r=>r.map(c=>'"' + String(c).replace(/"/g,'""') + '"').join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'monarch-net-' + new Date().toISOString().slice(0,10) + '.csv'; a.click(); URL.revokeObjectURL(url);
  });
  const exportJson = $('dev-export-json');
  if (exportJson) exportJson.addEventListener('click', () => {
    if (!state.discoveredDevices.length) return toast('No devices to export', 'error');
    const blob = new Blob([JSON.stringify(state.discoveredDevices,null,2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'monarch-net-' + new Date().toISOString().slice(0,10) + '.json'; a.click(); URL.revokeObjectURL(url);
  });
  const scanBtn = $('net-scan-btn') as HTMLButtonElement;
  if (scanBtn) scanBtn.addEventListener('click', async () => {
    const btn = $('net-scan-btn') as HTMLButtonElement;
    const subnet = ( $('net-target-input') as HTMLInputElement).value.trim() || undefined;
    const mode = ( $('net-mode-select') as HTMLSelectElement).value;
    let customTcp: any = undefined;
    let customUdp: any = undefined;
    if (mode==='custom') {
      const tcpRaw = ( $('net-custom-tcp') as HTMLInputElement).value.trim();
      if (tcpRaw) customTcp = tcpRaw.split(',').map(n=>parseInt(n.trim(),10)).filter(n=>!isNaN(n));
      const udpRaw = ( $('net-custom-udp') as HTMLInputElement).value.trim();
      if (udpRaw) customUdp = udpRaw.split(',').map(n=>parseInt(n.trim(),10)).filter(n=>!isNaN(n));
    }
    btn.innerHTML = '⏳ Scanning…';
    btn.disabled = true;
    const progWrap = $('net-progress-wrap');
    if (progWrap) progWrap.classList.remove('hidden');
    ( $('net-progress-fill') as HTMLElement).style.width = '5%';
    $('net-status-text').textContent = 'Initializing network sweep…';
    try {
      const res = await fetch('/api/netdiscovery/scan', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ subnet, mode, customTcp, customUdp }) });
      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      const processLine = (line:string) => {
        if (!line.startsWith('data: ')) return;
        try { const ev = JSON.parse(line.slice(6)); handleDiscoveryEvent(ev); } catch {}
      };
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split('\n\n');
        buffer = parts.pop()!;
        for (const part of parts) for (const line of part.split('\n')) processLine(line);
      }
    } catch (err:any) { toast('Discovery error: ' + err.message, 'error'); }
    finally { btn.disabled = false; btn.innerHTML = '⚡ Start Discovery'; ( $('net-progress-fill') as HTMLElement).style.width = '100%'; $('net-status-text').textContent = 'Completed • ' + state.discoveredDevices.length + ' hosts'; }
  });
}
function handleDiscoveryEvent(ev:any) {
  if (ev.type==='status') $('net-status-text').textContent = ev.message;
  else if (ev.type==='sweep_progress') { ( $('net-progress-fill') as HTMLElement).style.width = Math.round((ev.done/ev.total)*40) + '%'; $('net-status-text').textContent = 'ICMP sweep: ' + ev.done + '/' + ev.total; }
  else if (ev.type==='devices') { state.discoveredDevices = ev.devices||[]; renderDevicesTable(); if (ev.gateway) { $('net-gateway-badge').style.display='inline-flex'; $('net-gateway-badge').textContent='Gateway: ' + ev.gateway; } }
  else if (ev.type==='progress') { ( $('net-progress-fill') as HTMLElement).style.width = (40+Math.round((ev.current/ev.total)*60)) + '%'; $('net-status-text').textContent = 'Scanning ' + ev.device + ' (' + ev.current + '/' + ev.total + ')'; }
  else if (ev.type==='device_updated') { const idx = state.discoveredDevices.findIndex(d=>d.ip===ev.device.ip); if (idx>=0) state.discoveredDevices[idx]=ev.device; else state.discoveredDevices.push(ev.device); renderDevicesTable(); }
  else if (ev.type==='done') { ( $('net-progress-fill') as HTMLElement).style.width='100%'; $('net-status-text').textContent = 'Done • ' + (ev.devices?.length||state.discoveredDevices.length) + ' hosts'; }
}
async function loadNetworkInfo() {
  try {
    const [ifacesRes, arpRes] = await Promise.all([fetch('/api/netdiscovery/interfaces'), fetch('/api/netdiscovery/arp')]);
    const ifacesData = await ifacesRes.json();
    state.networkInterfaces = ifacesData.interfaces || (Array.isArray(ifacesData)?ifacesData:[]);
    state.gateway = ifacesData.gateway||null;
    state.discoveredDevices = await arpRes.json();
    const segSelect = $('net-segment-select') as HTMLSelectElement;
    if (segSelect && state.networkInterfaces.length) {
      let opts = '<option value="">Select Subnet…</option>';
      for (const iface of state.networkInterfaces) {
        const i = iface as any;
        if (!i.internal && i.cidr) {
          const star = state.gateway && i.address.slice(0,i.address.lastIndexOf('.'))===state.gateway.slice(0,state.gateway.lastIndexOf('.'))?'★ ':'';
          opts += '<option value="' + escapeHtml(i.cidr) + '">' + star + escapeHtml(i.cidr) + ' (' + escapeHtml(i.name) + ')</option>';
        }
      }
      segSelect.innerHTML = opts;
      const firstExt = state.networkInterfaces.find((i:any)=>!i.internal&&i.cidr) as any;
      if (firstExt && !( $('net-target-input') as HTMLInputElement).value) { ( $('net-target-input') as HTMLInputElement).value = firstExt.cidr; segSelect.value = firstExt.cidr; }
    }
    if (state.gateway) { const badge = $('net-gateway-badge'); if (badge) { badge.style.display='inline-flex'; badge.textContent='Gateway: ' + state.gateway; } }
    renderInterfaces();
    renderDevicesTable();
  } catch {}
}
function renderInterfaces() {
  const c = $('ifaces-list');
  if (!state.networkInterfaces.length) { c.innerHTML='<div class="empty">No interfaces found</div>'; return; }
  let html = '';
  for (const iface of state.networkInterfaces) {
    const i = iface as any;
    const cidrBadge = i.cidr ? '<span class="badge" style="font-size:10px;">' + escapeHtml(i.cidr) + '</span>' : '';
    html += '<div class="iface"><div style="display:flex;justify-content:space-between;"><span class="iface-name">' + escapeHtml(i.name) + '</span>' + cidrBadge + '</div><div class="iface-ip">' + escapeHtml(i.address) + ' / ' + escapeHtml(i.netmask) + '</div><div class="iface-mac">' + escapeHtml(i.mac||'–') + ' • <span class="vendor">' + escapeHtml(i.vendor||'Unknown') + '</span></div></div>';
  }
  c.innerHTML = html;
}
function renderDevicesTable() {
  const tbody = $('devices-body');
  let list = state.discoveredDevices||[];
  if (networkSearchQuery) list = list.filter(d=>d.ip.toLowerCase().includes(networkSearchQuery)||(d.mac&&d.mac.toLowerCase().includes(networkSearchQuery))||(d.vendor&&d.vendor.toLowerCase().includes(networkSearchQuery))||(d.hostname&&d.hostname.toLowerCase().includes(networkSearchQuery)));
  $('dev-count-badge').textContent = list.length + ' Hosts';
  if (!list.length) { tbody.innerHTML='<tr><td colspan="7" class="empty">No hosts found</td></tr>'; return; }
  let html = '';
  for (const d of list) {
    const tcp = (d.openPorts||[]).filter((p:any)=>p.proto==='tcp'||!p.proto);
    const udp = (d.openPorts||[]).filter((p:any)=>p.proto==='udp');
    let tcpHtml = '';
    for (const p of tcp) { tcpHtml += '<span class="badge-tcp">' + p.port + '/tcp ' + escapeHtml(p.service||'') + '</span>'; }
    let udpHtml = '';
    for (const p of udp) { udpHtml += '<span class="badge-udp">' + p.port + '/udp ' + escapeHtml(p.service||'') + '</span>'; }
    const noPorts = (!tcp.length&&!udp.length) ? '<span style="color:var(--text-muted);font-size:11px;">No open ports</span>' : '';
    const gwBadge = d.isGateway ? '<span style="margin-left:6px;padding:1px 6px;border-radius:6px;background:rgba(255,176,46,0.15);color:#ffb02e;font-size:10px;font-weight:700;">★ GW</span>' : '';
    const selfBadge = d.isSelf ? '<span style="margin-left:6px;padding:1px 6px;border-radius:6px;background:rgba(79,124,255,0.15);color:var(--primary);font-size:10px;font-weight:700;">SELF</span>' : '';
    const rttHtml = d.rtt!=null ? '<span class="badge-icmp">' + Math.round(d.rtt) + 'ms</span>' : (d.alive?'<span class="sev low" style="font-size:9px;">ONLINE</span>':'–');
    html += '<tr><td><span style="font-weight:700;font-family:var(--font-mono);cursor:pointer;" onclick="copyToClipboard(\'' + escapeHtml(d.ip) + '\',\'IP copied\')">' + escapeHtml(d.ip) + '</span>' + gwBadge + selfBadge + '</td><td style="font-family:var(--font-mono);font-size:11px;">' + (d.mac?escapeHtml(d.mac):'–') + '</td><td><span class="vendor">' + escapeHtml(d.vendor||'Unknown') + '</span></td><td style="font-size:11px;color:var(--text-soft);">' + escapeHtml(d.hostname||d.interface||'–') + '</td><td>' + rttHtml + '</td><td><div style="display:flex;flex-wrap:wrap;max-width:340px;">' + tcpHtml + udpHtml + noPorts + '</div></td><td style="text-align:right;"><button class="btn btn-ghost" style="height:26px;font-size:10px;" onclick="scanHostPortsModal(\'' + escapeHtml(d.ip) + '\')">Scan</button></td></tr>';
  }
  tbody.innerHTML = html;
}
window.copyToClipboard = (text, message='Copied') => {
  navigator.clipboard.writeText(text).then(()=>toast(message,'success'));
};
window.scanHostPortsModal = async (host) => {
  const btn = (event as any)?.target as HTMLButtonElement;
  if (btn) { btn.disabled=true; btn.textContent='Scanning…'; }
  try {
    const res = await fetch('/api/netdiscovery/scan-host', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ host }) });
    const data = await res.json();
    const dev = state.discoveredDevices.find(d=>d.ip===host);
    if (dev) { dev.openPorts = data.openPorts||[]; renderDevicesTable(); toast('Port scan for ' + host + ' complete', 'success'); }
  } catch (err:any) { toast('Port scan error: ' + err.message, 'error'); }
  finally { if (btn) { btn.disabled=false; btn.textContent='Scan'; } }
};

function setupMonitors() {
  const form = $('create-monitor-form') as HTMLFormElement;
  if (form) form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = ( $('mon-name') as HTMLInputElement).value.trim();
    const url = ( $('mon-url') as HTMLInputElement).value.trim();
    const intervalSeconds = Number(( $('mon-interval') as HTMLSelectElement).value);
    const expectedStatus = Number(( $('mon-status') as HTMLInputElement).value);
    const keyword = ( $('mon-keyword') as HTMLInputElement).value.trim();
    try {
      const res = await fetch('/api/monitors', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ name, url, intervalSeconds, expectedStatus, keyword }) });
      if (!res.ok) throw new Error((await res.json()).error);
      const newMon = await res.json();
      state.monitors.push(newMon);
      renderMonitors(); updateMonitorBadge(); $('monitor-modal').classList.add('hidden');
      toast('Monitor created', 'success');
    } catch (err:any) { toast('Failed: ' + err.message, 'error'); }
  });
  loadMonitors();
}
async function loadMonitors() {
  try { const res = await fetch('/api/monitors'); state.monitors = await res.json(); renderMonitors(); updateMonitorBadge(); } catch {}
}
function updateMonitorBadge() { const el = $('mon-count'); if (el) el.textContent = String(state.monitors.length); }
function renderMonitors() {
  const grid = $('monitors-grid');
  if (!state.monitors.length) { grid.innerHTML='<div class="empty">No monitors yet. Add your first endpoint.</div>'; return; }
  let html = '';
  for (const m of state.monitors) {
    let spark = '';
    const history = (m.history||[]).slice(-30);
    for (const h of history) {
      const cls = h.status==='down'?'down':h.status==='degraded'?'deg':'';
      const height = Math.min(100,Math.max(15,(h.latencyMs||20)/10));
      spark += '<div class="spark-bar ' + cls + '" style="height:' + height + '%;" title="' + h.latencyMs + 'ms (' + h.status + ')"></div>';
    }
    const statusCls = m.status==='up'?'low':m.status==='degraded'?'medium':'critical';
    const checked = m.lastChecked ? new Date(m.lastChecked).toLocaleTimeString() : 'Never';
    html += '<div class="monitor"><div class="mon-head"><div class="mon-name">' + escapeHtml(m.name) + '</div><span class="sev ' + statusCls + '">' + m.status.toUpperCase() + '</span></div><div class="mon-url" title="' + escapeHtml(m.url) + '">' + escapeHtml(m.url) + '</div><div class="spark">' + spark + '</div><div class="mon-stats"><div class="mon-stat"><div class="mon-val">' + m.uptimePercent + '%</div><div class="mon-lbl">Uptime</div></div><div class="mon-stat"><div class="mon-val">' + (m.lastLatencyMs||0) + 'ms</div><div class="mon-lbl">Latency</div></div><div class="mon-stat"><div class="mon-val">' + m.intervalSeconds + 's</div><div class="mon-lbl">Interval</div></div></div><div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;"><span style="font-size:10px;color:var(--text-muted);">Checked: ' + checked + '</span><div style="display:flex;gap:4px;"><button class="icon-btn" title="Check now" onclick="checkMonitorNow(\'' + m.id + '\')">🔄</button><button class="icon-btn" title="Delete" onclick="deleteMonitor(\'' + m.id + '\')">🗑️</button></div></div></div>';
  }
  grid.innerHTML = html;
}
window.checkMonitorNow = async (id) => { await fetch('/api/monitors/' + id + '/check', { method:'POST' }).catch(()=>{}); toast('Check triggered', 'info'); };
window.deleteMonitor = async (id) => {
  if (!confirm('Delete this monitor?')) return;
  await fetch('/api/monitors/' + id, { method:'DELETE' });
  state.monitors = state.monitors.filter(m=>m.id!==id);
  renderMonitors(); updateMonitorBadge(); toast('Monitor deleted', 'success');
};

function setupLoadTester() {
  const form = $('loadtest-form') as HTMLFormElement;
  if (!form) return;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = ( $('lt-url') as HTMLInputElement).value.trim();
    const method = ( $('lt-method') as HTMLSelectElement).value;
    const concurrency = Number(( $('lt-concurrency') as HTMLInputElement).value)||10;
    const totalRequests = Number(( $('lt-total') as HTMLInputElement).value)||50;
    let headers:any = {};
    try { if (( $('lt-headers') as HTMLTextAreaElement).value.trim()) headers = JSON.parse(( $('lt-headers') as HTMLTextAreaElement).value); } catch {}
    const body = ( $('lt-body') as HTMLTextAreaElement).value.trim()||undefined;
    const securityProbes = { csrf: ( $('lt-probe-csrf') as HTMLInputElement).checked, sqli: ( $('lt-probe-sqli') as HTMLInputElement).checked, xss: ( $('lt-probe-xss') as HTMLInputElement).checked, rateLimit: ( $('lt-probe-rate') as HTMLInputElement).checked };
    const btn = $('lt-start-btn') as HTMLButtonElement;
    btn.disabled=true; btn.innerHTML='⏳ Testing…';
    const liveWrap = $('lt-live-container');
    liveWrap.innerHTML='<div class="empty">Launching concurrent requests…</div>';
    try {
      const res = await fetch('/api/loadtest/run', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ url, method, concurrency, totalRequests, headers, body, securityProbes }) });
      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buffer='';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n\n'); buffer = lines.pop()!;
        for (const block of lines) {
          if (block.includes('event: progress')) {
            const jsonStr = block.slice(block.indexOf('data: ')+6);
            try { const data = JSON.parse(jsonStr); renderLoadProgress(data); } catch {}
          } else if (block.includes('event: done')) {
            const jsonStr = block.slice(block.indexOf('data: ')+6);
            try { const summary = JSON.parse(jsonStr); renderLoadSummary(summary); } catch {}
          }
        }
      }
    } catch (err:any) { liveWrap.innerHTML='<div class="empty" style="color:var(--danger);">Failed: ' + escapeHtml(err.message) + '</div>'; }
    finally { btn.disabled=false; btn.innerHTML='🚀 Launch Test'; }
  });
}
function renderLoadProgress(p:any) {
  $('lt-live-container').innerHTML = '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px;"><div class="stat" style="padding:10px;"><div class="stat-val">' + p.completed + ' / ' + p.total + '</div><div class="stat-lbl">Completed</div></div><div class="stat" style="padding:10px;"><div class="stat-val" style="color:var(--primary);">' + p.rps + '</div><div class="stat-lbl">RPS</div></div><div class="stat" style="padding:10px;"><div class="stat-val">' + p.latestLatency + 'ms</div><div class="stat-lbl">Latency</div></div></div><div class="progress-wrap"><div class="progress" style="width:' + (p.completed/p.total)*100 + '%;"></div></div>';
}
function renderLoadSummary(s:any) {
  let statusHtml = '';
  for (const code in s.statusCodes) { statusHtml += '<span class="badge">' + code + ': ' + s.statusCodes[code] + '</span>'; }
  let secFindings = '';
  if (s.securityFindings?.length) {
    secFindings += '<div style="margin-top:12px;"><h4 style="color:var(--danger);font-size:12px;margin-bottom:8px;">Security Findings (' + s.securityFindings.length + ')</h4>';
    for (const f of s.securityFindings) { secFindings += '<div class="card" style="margin-bottom:6px;"><div style="display:flex;gap:6px;align-items:center;"><span class="sev ' + f.severity + '">' + f.severity + '</span><span class="title">' + escapeHtml(f.title) + '</span></div><div class="desc">' + escapeHtml(f.description) + '</div></div>'; }
    secFindings += '</div>';
  } else {
    secFindings = '<div style="margin-top:10px;font-size:11px;color:var(--success);">✅ Security checks passed</div>';
  }
  $('lt-live-container').innerHTML = '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px;"><div class="stat" style="padding:10px;"><div class="stat-val" style="color:var(--primary);">' + s.rps + '</div><div class="stat-lbl">Avg RPS</div></div><div class="stat" style="padding:10px;"><div class="stat-val">' + s.latencies.p50 + 'ms</div><div class="stat-lbl">p50</div></div><div class="stat" style="padding:10px;"><div class="stat-val" style="color:#ff7a3d;">' + s.latencies.p95 + 'ms</div><div class="stat-lbl">p95</div></div><div class="stat" style="padding:10px;"><div class="stat-val" style="color:var(--danger);">' + s.latencies.p99 + 'ms</div><div class="stat-lbl">p99</div></div></div><div class="form-group"><label>Status Distribution</label><div style="display:flex;gap:6px;flex-wrap:wrap;">' + statusHtml + '</div></div>' + secFindings;
}

function setupInspector() {
  const httpForm = $('poke-http-form') as HTMLFormElement;
  if (httpForm) httpForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const method = ( $('poke-method') as HTMLSelectElement).value;
    const url = ( $('poke-url') as HTMLInputElement).value.trim();
    const authType = ( $('poke-auth-type') as HTMLSelectElement).value;
    const authVal = ( $('poke-auth-val') as HTMLInputElement).value.trim();
    const rawHeaders = ( $('poke-headers') as HTMLTextAreaElement).value.trim();
    const body = ( $('poke-body') as HTMLTextAreaElement).value.trim()||undefined;
    const headers:any = {};
    if (rawHeaders) rawHeaders.split('\n').forEach((line:string)=>{ const idx=line.indexOf(':'); if (idx>0) headers[line.slice(0,idx).trim()]=line.slice(idx+1).trim(); });
    let auth:any=null;
    if (authType==='bearer') auth={ type:'bearer', token:authVal };
    else if (authType==='basic') { const parts=authVal.split(':'); auth={ type:'basic', username:parts[0], password:parts[1] }; }
    else if (authType==='apikey') { const parts=authVal.split(':'); auth={ type:'apikey', header:parts[0]?.trim(), value:parts[1]?.trim() }; }
    const wrap = $('poke-response-wrap');
    wrap.innerHTML='<div class="empty">Sending request…</div>';
    try {
      const res = await fetch('/api/poke', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ url, method, headers, body, auth }) });
      const data = await res.json();
      let hdrStr = '';
      for (const k in data.headers||{}) { hdrStr += k + ': ' + data.headers[k] + '\n'; }
      wrap.innerHTML = '<div style="display:flex;justify-content:space-between;margin-bottom:8px;"><span class="sev ' + (data.status<400?'low':'critical') + '">' + data.status + ' ' + escapeHtml(data.statusText||'') + '</span><span style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">' + data.timingMs + 'ms • ' + formatBytes(data.sizeBytes) + '</span></div><div class="form-group"><label>Headers</label><div class="codeblock" style="max-height:120px;">' + escapeHtml(hdrStr) + '</div></div><div class="form-group"><label>Body (' + escapeHtml(data.contentType||'unknown') + ')</label><div class="codeblock" style="max-height:180px;">' + escapeHtml(data.body||'(Empty)') + '</div></div>';
    } catch (err:any) { wrap.innerHTML='<div class="empty" style="color:var(--danger);">' + escapeHtml(err.message) + '</div>'; }
  });
  const sshForm = $('poke-ssh-form') as HTMLFormElement;
  if (sshForm) sshForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const host = ( $('ssh-host') as HTMLInputElement).value.trim();
    const port = Number(( $('ssh-port') as HTMLInputElement).value)||22;
    const timeoutMs = Number(( $('ssh-timeout') as HTMLInputElement).value)||4000;
    const wrap = $('ssh-response-wrap');
    wrap.innerHTML='<div class="empty">Connecting to SSH…</div>';
    try {
      const res = await fetch('/api/poke/ssh', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ host, port, timeoutMs }) });
      const data = await res.json();
      if (data.reachable) {
        wrap.innerHTML = '<div style="margin-bottom:10px;"><span class="sev low">ONLINE</span><span style="font-family:var(--font-mono);font-size:11px;margin-left:6px;color:var(--text-muted);">' + data.latencyMs + 'ms</span></div><div class="form-group"><label>Banner</label><div class="codeblock">' + escapeHtml(data.banner) + '</div></div><div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:8px;"><div class="seo-item"><div class="seo-k">SSH Version</div><div class="seo-v">' + escapeHtml(data.sshVersion||'–') + '</div></div><div class="seo-item"><div class="seo-k">OS Hint</div><div class="seo-v">' + escapeHtml(data.osHint||'Linux/BSD') + '</div></div></div>';
      } else {
        wrap.innerHTML = '<div class="empty" style="color:var(--danger);">' + escapeHtml(data.error||'Connection refused') + '</div>';
      }
    } catch (err:any) { wrap.innerHTML='<div class="empty" style="color:var(--danger);">' + escapeHtml(err.message) + '</div>'; }
  });
}

function setupDatabaseTester() {
  const dbForm = $('db-form') as HTMLFormElement;
  if (dbForm) dbForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const type = ( $('db-type') as HTMLSelectElement).value;
    const host = ( $('db-host') as HTMLInputElement).value.trim();
    const port = ( $('db-port') as HTMLInputElement).value.trim()||undefined;
    const wrap = $('db-results-wrap');
    wrap.innerHTML='<div class="empty">Executing handshake…</div>';
    try {
      const res = await fetch('/api/db/test', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ type, host, port }) });
      const data = await res.json();
      wrap.innerHTML = '<div style="margin-bottom:10px;"><span class="sev ' + (data.connected?'low':'critical') + '">' + data.status + '</span><span style="font-family:var(--font-mono);font-size:11px;margin-left:6px;color:var(--text-muted);">' + data.latencyMs + 'ms • Port ' + data.port + '</span></div><div class="form-group"><label>Version & Handshake</label><div class="codeblock">' + escapeHtml(data.serverVersion||data.error||'') + '</div></div><div class="desc">' + escapeHtml(data.details||'') + '</div>';
    } catch (err:any) { wrap.innerHTML='<div class="empty" style="color:var(--danger);">' + escapeHtml(err.message) + '</div>'; }
  });
  const stressBtn = $('db-stress-btn');
  if (stressBtn) stressBtn.addEventListener('click', async () => {
    const type = ( $('db-type') as HTMLSelectElement).value;
    const host = ( $('db-host') as HTMLInputElement).value.trim();
    const port = ( $('db-port') as HTMLInputElement).value.trim()||undefined;
    const wrap = $('db-results-wrap');
    wrap.innerHTML='<div class="empty">Running 30 concurrent probes…</div>';
    try {
      const res = await fetch('/api/db/stress', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ type, host, port, concurrency:10, totalQueries:30 }) });
      const data = await res.json();
      wrap.innerHTML = '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px;"><div class="stat" style="padding:10px;"><div class="stat-val" style="color:var(--success);">' + data.successful + ' / ' + data.totalAttempts + '</div><div class="stat-lbl">Success</div></div><div class="stat" style="padding:10px;"><div class="stat-val">' + data.avgLatencyMs + 'ms</div><div class="stat-lbl">Avg Latency</div></div><div class="stat" style="padding:10px;"><div class="stat-val">' + data.maxLatencyMs + 'ms</div><div class="stat-lbl">Max</div></div></div>';
    } catch (err:any) { wrap.innerHTML='<div class="empty" style="color:var(--danger);">' + escapeHtml(err.message) + '</div>'; }
  });
}

function setupTLSAndRecon() {
  const tlsForm = $('tls-form') as HTMLFormElement;
  if (tlsForm) tlsForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = ( $('tls-target') as HTMLInputElement).value.trim();
    const wrap = $('tls-results');
    wrap.innerHTML = '<div class="empty">Analyzing TLS certificate…</div>';
    try {
      const res = await fetch('/api/tls/analyze', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ target }) });
      const data = await res.json();
      if (!data.reachable) { wrap.innerHTML = '<div class="empty" style="color:var(--danger);">❌ ' + escapeHtml(data.error||'Unreachable') + '</div>'; return; }
      let findingsHtml = '';
      if (data.findings?.length) {
        findingsHtml += '<div style="margin-top:10px;"><h4 style="font-size:12px;font-weight:700;margin-bottom:6px;">Findings (' + data.findings.length + ')</h4>';
        for (const f of data.findings) {
          const sevCls = f.severity==='critical'?'critical':f.severity==='high'?'high':'medium';
          findingsHtml += '<div class="card" style="margin-bottom:6px;"><span class="sev ' + sevCls + '">' + f.severity + '</span> <span class="title">' + escapeHtml(f.title) + '</span><div class="desc">' + escapeHtml(f.description) + '</div></div>';
        }
        findingsHtml += '</div>';
      } else {
        findingsHtml = '<div style="margin-top:8px;font-size:11px;color:var(--success);">✅ No TLS issues detected</div>';
      }
      const gradeCls = data.grade==='A'?'low':data.grade==='B'?'info':data.grade==='C'?'medium':'critical';
      wrap.innerHTML = '<div style="display:flex;gap:8px;margin-bottom:12px;"><span class="sev ' + gradeCls + '">Grade ' + data.grade + '</span><span class="badge">' + data.protocol + ' • ' + (data.cipher?.name||'') + '</span><span class="badge">' + data.daysUntilExpiry + ' days until expiry</span></div><div class="form-group"><label>Leaf Certificate</label><div class="codeblock">Subject: ' + escapeHtml(JSON.stringify(data.leaf?.subject||{}, null, 2)) + '\nIssuer: ' + escapeHtml(JSON.stringify(data.leaf?.issuer||{}, null, 2)) + '\nValid: ' + escapeHtml(data.leaf?.valid_from||'') + ' → ' + escapeHtml(data.leaf?.valid_to||'') + '\nSAN: ' + escapeHtml(data.leaf?.subjectaltname||'') + '</div></div>' + findingsHtml;
    } catch (err:any) { wrap.innerHTML = '<div class="empty" style="color:var(--danger);">' + escapeHtml(err.message) + '</div>'; }
  });

  const headersForm = $('headers-form') as HTMLFormElement;
  if (headersForm) headersForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = ( $('headers-target') as HTMLInputElement).value.trim();
    const wrap = $('headers-results');
    wrap.innerHTML = '<div class="empty">Checking security headers…</div>';
    try {
      const res = await fetch('/api/tls/headers', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url }) });
      const data = await res.json();
      if (data.error) { wrap.innerHTML = '<div class="empty" style="color:var(--danger);">' + escapeHtml(data.error) + '</div>'; return; }
      let hdrHtml = '';
      for (const k in data.headers) {
        const v = data.headers[k];
        hdrHtml += '<div style="display:flex;justify-content:space-between;padding:6px 10px;background:var(--bg);border:1px solid var(--border);border-radius:6px;font-size:11px;"><span style="font-weight:700;">' + escapeHtml(k) + '</span><span style="font-family:var(--font-mono);color:' + (v?'var(--success)':'var(--danger)') + ';">' + (v? '✅ Present' : '❌ Missing') + '</span></div>';
      }
      const gradeCls = data.grade==='A'?'low':data.grade==='B'?'info':data.grade==='C'?'medium':'critical';
      const missing = data.missing?.length ? '<div style="margin-top:10px;font-size:11px;color:var(--warning);">Missing: ' + data.missing.join(', ') + '</div>' : '';
      wrap.innerHTML = '<div style="display:flex;gap:8px;margin-bottom:12px;"><span class="sev ' + gradeCls + '">Grade ' + data.grade + ' (' + data.score + '/100)</span></div><div style="display:grid;gap:6px;">' + hdrHtml + '</div>' + missing;
    } catch (err:any) { wrap.innerHTML = '<div class="empty" style="color:var(--danger);">' + escapeHtml(err.message) + '</div>'; }
  });

  const subForm = $('subdomain-form') as HTMLFormElement;
  if (subForm) subForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = ( $('subdomain-target') as HTMLInputElement).value.trim();
    const wrap = $('subdomain-results');
    wrap.innerHTML = '<div class="empty">Enumerating subdomains via CT logs and DNS…</div>';
    try {
      const res = await fetch('/api/recon/subdomains', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ domain }) });
      const data = await res.json();
      if (!data.subdomains?.length) { wrap.innerHTML = '<div class="empty">No subdomains discovered</div>'; return; }
      let html = '';
      for (const s of data.subdomains) { html += '<div class="tech"><div class="tech-name">' + escapeHtml(s.subdomain) + '</div><div class="tech-cat">' + escapeHtml(s.source) + ' • ' + (s.ips? s.ips.join(', ') : 'discovered') + '</div></div>'; }
      wrap.innerHTML = '<div style="margin-bottom:8px;font-size:11px;color:var(--text-muted);">Found ' + data.count + ' subdomains for ' + escapeHtml(data.domain) + '</div><div class="tech-grid">' + html + '</div>';
    } catch (err:any) { wrap.innerHTML = '<div class="empty" style="color:var(--danger);">' + escapeHtml(err.message) + '</div>'; }
  });

  const sitemapBtn = $('recon-sitemap-btn');
  if (sitemapBtn) sitemapBtn.addEventListener('click', async () => {
    const target = ( $('recon-target') as HTMLInputElement).value.trim();
    if (!target) return toast('Enter target URL', 'error');
    const wrap = $('recon-results');
    wrap.innerHTML = '<div class="empty">Parsing sitemap…</div>';
    try {
      const res = await fetch('/api/recon/sitemap', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ target }) });
      const data = await res.json();
      let html = '';
      const urls = data.urls.slice(0,30);
      for (const u of urls) { html += '<div class="tech"><div class="tech-name" style="font-size:10px;word-break:break-all;">' + escapeHtml(u) + '</div></div>'; }
      wrap.innerHTML = '<div style="margin-bottom:8px;font-size:11px;color:var(--text-muted);">Found ' + data.count + ' URLs • ' + (data.sitemaps?.length||0) + ' sitemaps</div><div class="tech-grid">' + html + '</div>';
    } catch (err:any) { wrap.innerHTML = '<div class="empty" style="color:var(--danger);">' + escapeHtml(err.message) + '</div>'; }
  });

  const robotsBtn = $('recon-robots-btn');
  if (robotsBtn) robotsBtn.addEventListener('click', async () => {
    const target = ( $('recon-target') as HTMLInputElement).value.trim();
    if (!target) return toast('Enter target URL', 'error');
    const wrap = $('recon-results');
    wrap.innerHTML = '<div class="empty">Analyzing robots.txt…</div>';
    try {
      const res = await fetch('/api/recon/robots', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ target }) });
      const data = await res.json();
      if (!data.exists) { wrap.innerHTML = '<div class="empty">robots.txt not found (status ' + (data.status||'N/A') + ')</div>'; return; }
      let sensitive = '';
      if (data.sensitivePaths?.length) {
        sensitive = '<div style="margin-bottom:10px;"><h4 style="font-size:11px;font-weight:700;margin-bottom:4px;color:var(--danger);">Sensitive Paths in robots.txt</h4><div class="codeblock">' + data.sensitivePaths.map((p:string)=>escapeHtml(p)).join('\n') + '</div></div>';
      }
      let disallowSample = '';
      const disallows = (data.disallows||[]).slice(0,20);
      for (const d of disallows) { disallowSample += escapeHtml(d) + '\n'; }
      wrap.innerHTML = '<div style="display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap;"><span class="badge">Disallow: ' + data.disallowCount + '</span><span class="badge">Allow: ' + data.allowCount + '</span><span class="badge">Sitemaps: ' + data.sitemapCount + '</span>' + (data.hasSensitiveHints?'<span class="pill crit">Sensitive hints</span>':'') + '</div>' + sensitive + '<div class="form-group"><label>Disallows (sample)</label><div class="codeblock" style="max-height:120px;">' + disallowSample + '</div></div>';
    } catch (err:any) { wrap.innerHTML = '<div class="empty" style="color:var(--danger);">' + escapeHtml(err.message) + '</div>'; }
  });
}

function setupHistory() {
  const refreshBtn = $('refresh-history');
  if (refreshBtn) refreshBtn.addEventListener('click', loadHistory);
  loadHistory();
}
async function loadHistory() {
  try { const res = await fetch('/api/scans'); state.scansHistory = await res.json(); renderHistory(); } catch {}
}
function renderHistory() {
  const list = $('history');
  if (!state.scansHistory.length) { list.innerHTML = '<div class="history-empty">No scans yet.<br>Run your first scan above.</div>'; return; }
  let html = '';
  for (const s of state.scansHistory) {
    const active = (state.currentScan as any)?.id===s.id ? 'active' : '';
    const grade = s.score?.grade||'C';
    const score = s.score?.score??'–';
    const date = s.startedAt ? new Date(s.startedAt).toLocaleDateString() : '';
    html += '<div class="history-item ' + active + '" onclick="loadScanFromHistory(\'' + s.id + '\')"><div class="history-target">' + escapeHtml(s.target) + '</div><div class="history-meta"><span class="grade grade-' + grade + '">' + grade + ' (' + score + ')</span><span>' + date + '</span></div></div>';
  }
  list.innerHTML = html;
}
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
  } catch (err:any) { toast('Failed to load scan: ' + err.message, 'error'); }
};
