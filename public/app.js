/**
 * Monarch Security Engine
 * Clean, Natural & High-Performance Desktop Client Orchestrator
 */

// ========================================================
// APPLICATION STATE
// ========================================================
const state = {
  activeView: 'scanner',
  activeSubtab: 'findings',
  currentScan: null,
  scansHistory: [],
  monitors: [],
  discoveredDevices: [],
  networkInterfaces: [],
  aiConfig: {
    provider: 'openrouter',
    apiKey: sessionStorage.getItem('monarch_ai_key') || '',
    model: 'deepseek/deepseek-r1-distill-qwen-7b',
  },
  filters: {
    findingText: '',
    severities: new Set(['critical', 'high', 'medium', 'low', 'info']),
  },
  ws: null,
};

// ========================================================
// DOM SHORTCUTS
// ========================================================
const $ = (id) => document.getElementById(id);
const $$ = (sel) => document.querySelectorAll(sel);

// ========================================================
// INITIALIZATION
// ========================================================
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
  setupWebSocket();
  checkHealthAndConfig();
});

// ========================================================
// NAVIGATION & VIEW SWITCHING
// ========================================================
function setupNavigation() {
  // Main navigation tab switcher
  $$('.nav-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      const view = tab.dataset.view;
      if (!view) return;
      state.activeView = view;

      $$('.nav-tab').forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');

      $$('.view-pane').forEach((p) => p.classList.remove('active'));
      const targetPane = $(`view-${view}`);
      if (targetPane) targetPane.classList.add('active');

      if (view === 'dashboard') renderDashboard();
      if (view === 'wpadmin' && state.currentScan) renderWpAdmin(state.currentScan.wpAdmin);
      if (view === 'netdiscovery' && !state.networkInterfaces.length) loadNetworkInfo();
      if (view === 'monitor') loadMonitors();
    });
  });

  // Scanner subtab switcher
  $$('.sub-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      const subtab = tab.dataset.subtab;
      if (!subtab) return;
      state.activeSubtab = subtab;

      $$('.sub-tab').forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');

      $$('.sub-panel').forEach((p) => p.classList.remove('active'));
      const targetPanel = $(`panel-${subtab}`);
      if (targetPanel) targetPanel.classList.add('active');
    });
  });

  // Inspector subtabs (HTTP vs SSH)
  $$('.insp-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      const target = tab.dataset.target;
      $$('.insp-tab').forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      $$('.insp-pane').forEach((p) => p.classList.remove('active'));
      if ($(target)) $(target).classList.add('active');
    });
  });
}

// ========================================================
// WEBSOCKET CLIENT
// ========================================================
function setupWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  try {
    const ws = new WebSocket(wsUrl);
    state.ws = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ action: 'subscribe', channel: 'all' }));
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.channel === 'monitor_update') {
          handleMonitorWsUpdate(msg.data);
        }
      } catch { /* ignore */ }
    };

    ws.onclose = () => {
      setTimeout(setupWebSocket, 5000);
    };
  } catch { /* ignore */ }
}

function handleMonitorWsUpdate(updatedMon) {
  const idx = state.monitors.findIndex((m) => m.id === updatedMon.id);
  if (idx >= 0) state.monitors[idx] = updatedMon;
  else state.monitors.push(updatedMon);

  if (state.activeView === 'monitor') renderMonitors();
  updateMonitorCountBadge();
}

// ========================================================
// HEALTH, DEVELOPER MODAL & AI CONFIGURATION
// ========================================================
async function checkHealthAndConfig() {
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    if (data.ok) {
      $('health-text').textContent = 'System Active · Info';
      if (data.ai) {
        state.aiConfig.provider = data.ai;
        updateAiTopbarLabel();
      }
    }
  } catch {
    $('health-text').textContent = 'Server Offline';
  }

  // Load server AI config
  try {
    const res = await fetch('/api/config');
    const conf = await res.json();
    if (conf.provider) state.aiConfig.provider = conf.provider;
    if (conf.model) state.aiConfig.model = conf.model;
    updateAiTopbarLabel();
  } catch { /* ignore */ }
}

function updateAiTopbarLabel() {
  const p = state.aiConfig.provider || 'openrouter';
  const displayNames = {
    openrouter: 'AI: OpenRouter',
    openai: 'AI: OpenAI',
    anthropic: 'AI: Anthropic',
    gemini: 'AI: Gemini',
    none: 'Offline ML-Kit',
  };
  $('ai-config-label').textContent = displayNames[p] || `AI: ${p}`;
}

function setupModals() {
  // Developer & App Info Modal
  $('dev-modal-btn')?.addEventListener('click', () => {
    loadDeveloperProfile();
    $('dev-modal').classList.remove('hidden');
  });

  $('dev-modal-close')?.addEventListener('click', () => {
    $('dev-modal').classList.add('hidden');
  });

  // AI Config Modal
  $('ai-config-btn').addEventListener('click', () => {
    $('ai-provider-select').value = state.aiConfig.provider;
    $('ai-key-input').value = state.aiConfig.apiKey;
    $('ai-model-input').value = state.aiConfig.model;
    $('ai-modal').classList.remove('hidden');
  });

  $('ai-modal-close').addEventListener('click', () => {
    $('ai-modal').classList.add('hidden');
  });

  $('ai-provider-select').addEventListener('change', (e) => {
    const prov = e.target.value;
    const defaults = {
      openrouter: 'deepseek/deepseek-r1-distill-qwen-7b',
      openai: 'gpt-4o-mini',
      anthropic: 'claude-3-5-haiku-latest',
      gemini: 'gemini-1.5-flash',
      none: 'monarch-ml-heuristics-v1',
    };
    $('ai-model-input').value = defaults[prov] || '';
    $('ai-key-group').style.display = prov === 'none' ? 'none' : 'block';
  });

  $('ai-config-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const provider = $('ai-provider-select').value;
    const apiKey = $('ai-key-input').value.trim();
    const model = $('ai-model-input').value.trim();

    state.aiConfig = { provider, apiKey, model };
    if (apiKey) sessionStorage.setItem('monarch_ai_key', apiKey);
    else sessionStorage.removeItem('monarch_ai_key');

    await fetch('/api/config', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(state.aiConfig),
    }).catch(() => {});

    updateAiTopbarLabel();
    $('ai-modal').classList.add('hidden');
  });

  $('ai-clear-btn').addEventListener('click', async () => {
    state.aiConfig = { provider: 'none', apiKey: '', model: 'monarch-ml-heuristics-v1' };
    sessionStorage.removeItem('monarch_ai_key');
    $('ai-provider-select').value = 'none';
    $('ai-key-input').value = '';
    $('ai-model-input').value = 'monarch-ml-heuristics-v1';
    await fetch('/api/config', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(state.aiConfig),
    }).catch(() => {});
    updateAiTopbarLabel();
    $('ai-modal').classList.add('hidden');
  });

  // Uptime Monitor Modal
  $('add-monitor-btn')?.addEventListener('click', () => {
    $('monitor-modal').classList.remove('hidden');
  });
  $('mon-modal-close')?.addEventListener('click', () => {
    $('monitor-modal').classList.add('hidden');
  });
  $('mon-cancel-btn')?.addEventListener('click', () => {
    $('monitor-modal').classList.add('hidden');
  });
}

async function loadDeveloperProfile() {
  try {
    const res = await fetch('https://api.github.com/users/mahmud-r-farhan', {
      headers: { 'Accept': 'application/vnd.github.v3+json' },
    });
    if (res.ok) {
      const data = await res.json();
      if (data.avatar_url) $('dev-avatar').src = data.avatar_url;
      if (data.name) $('dev-name').textContent = data.name;
      if (data.login) $('dev-handle').textContent = `@${data.login}`;
      if (data.bio) $('dev-bio').textContent = data.bio;
    }
  } catch {
    // Fallback default details already in DOM
  }
}

// ========================================================
// SCAN FORM & REAL-TIME STREAMING
// ========================================================
function setupScanForm() {
  $('scan-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = $('target').value.trim();
    const engine = $('engine').value;
    const maxPages = Number($('pages').value) || 25;

    if (!target) return;

    switchView('scanner');

    $('scan-btn').disabled = true;
    $('scan-btn').innerHTML = '<span class="pulse-dot"></span> Scanning…';

    $('empty').classList.add('hidden');
    $('scan-view').classList.remove('hidden');

    $('s-target').textContent = target;
    $('s-meta').textContent = `Initializing crawl (${engine})…`;
    $('live-status').textContent = 'Connecting to scanner engine…';
    $('progress-bar').style.width = '10%';
    $('grade').textContent = '–';
    $('grade').className = 'grade-badge';

    $('findings').innerHTML = '<div class="empty-hint">Discovering endpoints &amp; checking vulnerabilities…</div>';
    $('net-body').innerHTML = '';
    $('ai').innerHTML = '<div class="empty-hint">AI Remediation plan will generate upon scan completion…</div>';

    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          target,
          engine,
          maxPages,
          ai: true,
          aiConfig: state.aiConfig,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to initiate scan');
      }

      const { id } = await res.json();
      streamScanEvents(id);
    } catch (err) {
      alert(`Scan failed: ${err.message}`);
      resetScanButton();
    }
  });
}

function streamScanEvents(id) {
  const es = new EventSource(`/api/scans/${id}/events`);
  let reqCount = 0;
  let pageCount = 0;
  const liveFindings = [];

  es.addEventListener('status', (ev) => {
    const data = JSON.parse(ev.data);
    $('live-status').textContent = data.message || '';

    if (data.stage === 'crawl') {
      pageCount = data.pages || pageCount;
      $('progress-bar').style.width = '40%';
      $('s-meta').textContent = `Crawled ${pageCount} pages · ${reqCount} requests observed`;
    } else if (data.stage === 'analyze') {
      $('progress-bar').style.width = '70%';
    } else if (data.stage === 'ai') {
      $('progress-bar').style.width = '90%';
    }
  });

  es.addEventListener('network', (ev) => {
    const { entry } = JSON.parse(ev.data);
    reqCount++;
    $('s-meta').textContent = `Crawled ${pageCount} pages · ${reqCount} requests observed`;
    $('t-network').textContent = reqCount;
    appendNetworkRow(entry, reqCount);
  });

  es.addEventListener('finding', (ev) => {
    const { finding } = JSON.parse(ev.data);
    liveFindings.push(finding);
    $('t-findings').textContent = liveFindings.length;
    renderFindings(liveFindings);
    updateSeverityPills(liveFindings);
  });

  es.addEventListener('done', async () => {
    es.close();
    $('progress-bar').style.width = '100%';
    $('live-status').textContent = 'Audit complete';
    resetScanButton();

    const fullRes = await fetch(`/api/scans/${id}`);
    const scan = await fullRes.json();
    state.currentScan = scan;

    renderFullScan(scan);
    loadHistory();
  });

  es.addEventListener('error', () => {
    es.close();
    resetScanButton();
  });
}

function resetScanButton() {
  $('scan-btn').disabled = false;
  $('scan-btn').innerHTML = '<span class="btn-icon">⚡</span> Scan Target';
}

function switchView(viewName) {
  state.activeView = viewName;
  $$('.nav-tab').forEach((t) => t.classList.toggle('active', t.dataset.view === viewName));
  $$('.view-pane').forEach((p) => p.classList.toggle('active', p.id === `view-${viewName}`));
}

// ========================================================
// RENDER FULL SCAN RESULTS
// ========================================================
function renderFullScan(scan) {
  $('grade').textContent = scan.score?.grade || '–';
  $('grade').className = `grade-badge grade-${scan.score?.grade || 'C'}`;
  $('s-target').textContent = scan.target;
  $('s-meta').textContent = `Completed in ${Math.round(scan.durationMs / 1000)}s · ${scan.crawl?.pages?.length || 0} pages · ${scan.networkSummary?.requests || 0} requests`;

  renderFindings(scan.findings || []);
  renderAiInsights(scan.insights, scan);
  renderCookiesAndStorage(scan);
  renderInventory(scan);
  renderExportButtons(scan.id);

  renderTechStack(scan.techStack || [], scan.rateLimiting);
  renderSeoAudit(scan.seo);
  renderWpAdmin(scan.wpAdmin);
  renderDashboard();
}

// ========================================================
// FINDINGS RENDERING
// ========================================================
function renderFindings(findings) {
  const container = $('findings');
  if (!findings.length) {
    container.innerHTML = '<div class="empty-hint">No vulnerabilities detected! Posture is hardened.</div>';
    return;
  }

  const query = state.filters.findingText.toLowerCase();
  const filtered = findings.filter((f) => {
    if (!state.filters.severities.has(f.severity)) return false;
    if (!query) return true;
    return (
      (f.title || '').toLowerCase().includes(query) ||
      (f.category || '').toLowerCase().includes(query) ||
      (f.description || '').toLowerCase().includes(query)
    );
  });

  container.innerHTML = filtered
    .map(
      (f) => `
    <div class="finding-card">
      <div class="finding-header">
        <div class="finding-title-wrap">
          <span class="sev-tag ${f.severity}">${f.severity}</span>
          <span class="finding-title">${escapeHtml(f.title)}</span>
        </div>
        <span class="finding-loc">${escapeHtml(f.location || '')}</span>
      </div>
      <div class="finding-desc">${escapeHtml(f.description)}</div>
      ${f.remediation ? `<div class="finding-code"><b>Fix:</b> ${escapeHtml(f.remediation)}</div>` : ''}
    </div>
  `
    )
    .join('');
}

function updateSeverityPills(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => counts[f.severity] = (counts[f.severity] || 0) + 1);

  $('sev-counts').innerHTML = `
    ${counts.critical ? `<span class="sev-pill crit">${counts.critical} Crit</span>` : ''}
    ${counts.high ? `<span class="sev-pill high">${counts.high} High</span>` : ''}
    ${counts.medium ? `<span class="sev-pill med">${counts.medium} Med</span>` : ''}
    ${counts.low ? `<span class="sev-pill low">${counts.low} Low</span>` : ''}
  `;
}

$('f-filter')?.addEventListener('input', (e) => {
  state.filters.findingText = e.target.value;
  if (state.currentScan?.findings) renderFindings(state.currentScan.findings);
});

// ========================================================
// AI INSIGHTS RENDERING
// ========================================================
function renderAiInsights(insights, scan) {
  const aiContainer = $('ai');
  if (!insights) {
    aiContainer.innerHTML = '<div class="empty-hint">No AI insights generated.</div>';
    return;
  }

  aiContainer.innerHTML = `
    <div class="ai-summary-card">
      <div class="ai-badge">🤖 Intelligence: ${escapeHtml(insights.provider)} (${escapeHtml(insights.model)})</div>
      <p style="font-size: 13px; line-height: 1.5; color: var(--text-primary);">${escapeHtml(insights.executiveSummary || '')}</p>
      ${
        insights.attackNarrative
          ? `<div class="ai-narrative-box"><b>⚠️ Potential Attack Chain:</b> ${escapeHtml(insights.attackNarrative)}</div>`
          : ''
      }
    </div>

    <div class="box-header" style="margin-top: 14px;">
      <h3>Prioritized Action Plan</h3>
    </div>

    <div class="ai-plan-list">
      ${(insights.actionPlan || [])
        .map(
          (item) => `
        <div class="ai-plan-item">
          <div class="ai-plan-head">
            <span class="plan-priority">Priority #${item.priority}</span>
            <span class="sev-tag ${item.effort === 'low' ? 'low' : 'medium'}">${escapeHtml(item.effort)} effort</span>
          </div>
          <h4 style="color: var(--text-primary); margin-bottom: 4px; font-size: 13px;">${escapeHtml(item.title)}</h4>
          <p style="font-size: 12px; color: var(--text-secondary); margin-bottom: 6px;">${escapeHtml(item.why)}</p>
          <div class="finding-code">${escapeHtml(item.how)}</div>
        </div>
      `
        )
        .join('')}
    </div>
  `;
}

// ========================================================
// DEVTOOLS NETWORK LOG & ROW RENDERING
// ========================================================
function appendNetworkRow(entry, index) {
  const tbody = $('net-body');
  if (!tbody) return;
  const tr = document.createElement('tr');
  const status = entry.response?.status || 0;
  const statusClass = status >= 500 ? 'crit' : status >= 400 ? 'high' : status >= 300 ? 'med' : 'low';

  tr.innerHTML = `
    <td>${index}</td>
    <td><span class="badge">${escapeHtml(entry.method || 'GET')}</span></td>
    <td><span class="sev-pill ${statusClass}">${status}</span></td>
    <td>${escapeHtml(entry.type || 'fetch')}</td>
    <td>${formatBytes(entry.response?.size || 0)}</td>
    <td>${entry.durationMs || 0}ms</td>
    <td title="${escapeHtml(entry.url)}">${escapeHtml(entry.url)}</td>
  `;

  tr.addEventListener('click', () => {
    $$('#net-body tr').forEach((r) => r.classList.remove('active'));
    tr.classList.add('active');
    showNetworkDetail(entry);
  });

  tbody.appendChild(tr);
}

function showNetworkDetail(entry) {
  const detail = $('net-detail');
  detail.classList.remove('hidden');

  detail.innerHTML = `
    <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
      <h4 style="color: var(--text-primary); font-size: 13px;">Request Details</h4>
      <button class="ghost-btn" onclick="$('net-detail').classList.add('hidden')">&times;</button>
    </div>
    <div style="margin-bottom: 8px;">
      <span class="sev-tag low">${entry.method || 'GET'}</span>
      <span style="font-family: var(--font-mono); font-size: 11px; margin-left: 6px;">${escapeHtml(entry.url)}</span>
    </div>
    <div class="form-group">
      <label>Response Headers</label>
      <div class="finding-code" style="max-height: 160px;">${Object.entries(entry.response?.headers || {})
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n')}</div>
    </div>
  `;
}

// ========================================================
// COOKIES & INVENTORY RENDERING
// ========================================================
function renderCookiesAndStorage(scan) {
  const cookies = scan.crawl?.cookies || [];
  const container = $('cookies');

  if (!cookies.length) {
    container.innerHTML = '<div class="empty-hint">No cookies detected during crawl.</div>';
    return;
  }

  container.innerHTML = `
    <div class="net-table-wrap">
      <table class="net-table">
        <thead>
          <tr><th>Name</th><th>HttpOnly</th><th>Secure</th><th>SameSite</th><th>Path</th><th>Set By</th></tr>
        </thead>
        <tbody>
          ${cookies
            .map(
              (c) => `
            <tr>
              <td style="font-weight: 600; color: var(--text-primary);">${escapeHtml(c.name)}</td>
              <td>${c.httpOnly ? '✅' : '❌'}</td>
              <td>${c.secure ? '✅' : '❌'}</td>
              <td>${escapeHtml(c.sameSite || 'None')}</td>
              <td>${escapeHtml(c.path || '/')}</td>
              <td style="font-size: 10px; color: var(--text-muted);">${escapeHtml(c.setBy || '')}</td>
            </tr>
          `
            )
            .join('')}
        </tbody>
      </table>
    </div>
  `;
}

function renderInventory(scan) {
  const origins = scan.crawl?.externalOrigins || [];
  const container = $('inventory');

  container.innerHTML = `
    <div class="box-header">
      <h3>External Dependencies (${origins.length})</h3>
    </div>
    <div class="tech-grid">
      ${origins
        .map(
          (o) => `
        <div class="tech-card">
          <div class="tech-name">🌐 ${escapeHtml(o)}</div>
          <div class="tech-cat">External Dependency</div>
        </div>
      `
        )
        .join('')}
    </div>
  `;
}

function renderExportButtons(scanId) {
  $('export').innerHTML = `
    <a href="/api/scans/${scanId}/report.md" download class="btn btn-glass" style="font-size: 11px; padding: 4px 8px;">Markdown</a>
    <a href="/api/scans/${scanId}/report.html" target="_blank" class="btn btn-glass" style="font-size: 11px; padding: 4px 8px;">HTML</a>
    <a href="/api/scans/${scanId}/report.json" download class="btn btn-glass" style="font-size: 11px; padding: 4px 8px;">JSON</a>
  `;
}

// ========================================================
// VIEW: WORDPRESS & ADMIN SECURITY (NEW)
// ========================================================
function renderWpAdmin(wpAdmin) {
  if (!wpAdmin) return;

  $('wp-detected').textContent = wpAdmin.isWordpress ? 'WordPress Active' : (wpAdmin.isPhp ? 'PHP Application' : 'Not Detected');
  $('wp-detected').style.color = wpAdmin.isWordpress ? 'var(--sev-high-fg)' : 'var(--text-primary)';

  $('wp-xmlrpc').textContent = wpAdmin.xmlRpcExposed ? 'Exposed (Risk)' : 'Blocked / Disabled';
  $('wp-xmlrpc').style.color = wpAdmin.xmlRpcExposed ? 'var(--sev-crit-fg)' : 'var(--sev-low-fg)';

  const userEnumCount = wpAdmin.userEnumeration?.usernames?.length || 0;
  $('wp-user-enum').textContent = wpAdmin.userEnumeration?.vulnerable ? `Vulnerable (${userEnumCount} users leaked)` : 'Protected';
  $('wp-user-enum').style.color = wpAdmin.userEnumeration?.vulnerable ? 'var(--sev-crit-fg)' : 'var(--sev-low-fg)';

  // Render endpoints
  const endpointsWrap = $('wp-endpoints-container');
  if (!wpAdmin.exposedEndpoints || !wpAdmin.exposedEndpoints.length) {
    endpointsWrap.innerHTML = '<div class="empty-hint">No exposed admin portals detected on this host.</div>';
  } else {
    endpointsWrap.innerHTML = `
      <div class="tech-grid">
        ${wpAdmin.exposedEndpoints.map(ep => `
          <div class="tech-card">
            <div class="tech-name">🔑 ${escapeHtml(ep.name)}</div>
            <div class="tech-cat">${escapeHtml(ep.category)} · Status ${ep.status}</div>
            <div class="tech-evidence">${escapeHtml(ep.path)}</div>
          </div>
        `).join('')}
      </div>
    `;
  }

  // Render users
  const usersWrap = $('wp-users-container');
  if (!wpAdmin.userEnumeration?.usernames?.length) {
    usersWrap.innerHTML = '<div class="empty-hint">No usernames leaked via author query or REST API.</div>';
  } else {
    usersWrap.innerHTML = `
      <div class="tech-grid">
        ${wpAdmin.userEnumeration.usernames.map(u => `
          <div class="tech-card">
            <div class="tech-name">👤 ${escapeHtml(u)}</div>
            <div class="tech-cat">WordPress Author / Admin User</div>
          </div>
        `).join('')}
      </div>
    `;
  }
}

// ========================================================
// VIEW: TECH STACK & RATE LIMITS
// ========================================================
function renderTechStack(technologies, rateLimiting) {
  const techList = $('tech-list');
  $('tech-badge-count').textContent = technologies.length;

  if (!technologies.length) {
    techList.innerHTML = '<div class="empty-hint">No technology signatures detected yet.</div>';
  } else {
    techList.innerHTML = technologies
      .map(
        (t) => `
      <div class="tech-card">
        <div class="tech-name">${escapeHtml(t.name)}</div>
        <div class="tech-cat">${escapeHtml(t.category)}</div>
        <div class="tech-evidence" title="${escapeHtml(t.evidence)}">${escapeHtml(t.evidence)}</div>
      </div>
    `
      )
      .join('');
  }

  const rlContainer = $('ratelimit-info');
  if (!rateLimiting) {
    rlContainer.innerHTML = '<div class="empty-hint">No API rate limiting data observed.</div>';
    return;
  }

  rlContainer.innerHTML = `
    <div class="tech-card" style="margin-bottom: 10px;">
      <div class="tech-name">Rate Limiting: ${rateLimiting.enforced ? '<span style="color:var(--sev-low-fg);">Enforced</span>' : '<span style="color:var(--sev-med-fg);">Not Detected</span>'}</div>
      <div class="tech-cat">${rateLimiting.apiRequestsObserved} API requests observed</div>
      ${rateLimiting.sampleHeader ? `<div class="finding-code" style="margin-top: 6px;">Header: ${escapeHtml(rateLimiting.sampleHeader)}</div>` : '<p style="font-size:11px;color:var(--text-muted);margin-top:4px;">No standard RateLimit or X-RateLimit headers observed on API routes.</p>'}
    </div>
  `;
}

// ========================================================
// VIEW: SEO & AIO AUDIT
// ========================================================
function renderSeoAudit(seo) {
  if (!seo) return;

  const scoreBadge = $('seo-overall-score');
  scoreBadge.querySelector('.seo-score-num').textContent = `${seo.score || 0}%`;

  const container = $('seo-pages-container');
  if (!seo.pages || !seo.pages.length) {
    container.innerHTML = '<div class="empty-hint">No SEO pages audited.</div>';
    return;
  }

  container.innerHTML = seo.pages
    .map(
      (p) => `
    <div class="seo-page-card">
      <div class="seo-page-head">
        <div class="seo-page-url">📄 ${escapeHtml(p.url)}</div>
        <span class="sev-tag ${p.score >= 80 ? 'low' : 'medium'}">${p.score}/100 Score</span>
      </div>

      <div class="seo-checks-grid">
        <div class="seo-item">
          <div class="seo-lbl">Title Tag</div>
          <div class="seo-val">${escapeHtml(p.title)}</div>
        </div>
        <div class="seo-item">
          <div class="seo-lbl">Meta Description</div>
          <div class="seo-val">${escapeHtml(p.metaDescription)}</div>
        </div>
        <div class="seo-item">
          <div class="seo-lbl">Primary &lt;h1&gt;</div>
          <div class="seo-val">${escapeHtml(p.headings.h1[0] || '(None)')}</div>
        </div>
        <div class="seo-item">
          <div class="seo-lbl">Language &amp; Viewport</div>
          <div class="seo-val">Lang: ${p.htmlLang} · Viewport: ${p.viewport ? '✅' : '❌'}</div>
        </div>
        <div class="seo-item">
          <div class="seo-lbl">OpenGraph &amp; Twitter</div>
          <div class="seo-val">${p.openGraph.ogTitle ? '✅ OpenGraph' : '❌ No OG'} · ${p.openGraph.twitterCard ? '✅ Twitter' : '❌ No Twitter'}</div>
        </div>
        <div class="seo-item">
          <div class="seo-lbl">Images Missing Alt</div>
          <div class="seo-val">${p.images.missingAlt} / ${p.images.total} images</div>
        </div>
      </div>
    </div>
  `
    )
    .join('');
}

// ========================================================
// VIEW: SECURITY DASHBOARD
// ========================================================
function renderDashboard() {
  const scan = state.currentScan;
  if (!scan) return;

  const counts = scan.score?.counts || {};
  $('dash-critical').textContent = counts.critical || 0;
  $('dash-high').textContent = counts.high || 0;
  $('dash-medium').textContent = counts.medium || 0;
  $('dash-total-scans').textContent = state.scansHistory.length || 1;
  $('dash-monitors-up').textContent = state.monitors.filter((m) => m.status === 'up').length;

  const total = scan.findings?.length || 1;
  $('sev-bars').innerHTML = `
    <div style="width: 100%; display: flex; flex-direction: column; gap: 8px;">
      <div>
        <div style="display:flex; justify-content:space-between; font-size:11px; margin-bottom:2px;">
          <span>Critical (${counts.critical || 0})</span>
          <span>${Math.round(((counts.critical || 0) / total) * 100)}%</span>
        </div>
        <div class="progress-bar-wrap"><div class="progress-bar-fill" style="width:${((counts.critical || 0) / total) * 100}%; background:var(--sev-crit-fg);"></div></div>
      </div>
      <div>
        <div style="display:flex; justify-content:space-between; font-size:11px; margin-bottom:2px;">
          <span>High (${counts.high || 0})</span>
          <span>${Math.round(((counts.high || 0) / total) * 100)}%</span>
        </div>
        <div class="progress-bar-wrap"><div class="progress-bar-fill" style="width:${((counts.high || 0) / total) * 100}%; background:var(--sev-high-fg);"></div></div>
      </div>
      <div>
        <div style="display:flex; justify-content:space-between; font-size:11px; margin-bottom:2px;">
          <span>Medium (${counts.medium || 0})</span>
          <span>${Math.round(((counts.medium || 0) / total) * 100)}%</span>
        </div>
        <div class="progress-bar-wrap"><div class="progress-bar-fill" style="width:${((counts.medium || 0) / total) * 100}%; background:var(--sev-med-fg);"></div></div>
      </div>
    </div>
  `;
}

// ========================================================
// VIEW: NETWORK DISCOVERY & PORT MAPPER (NetLAN Architecture)
// ========================================================
let netScanEventSource = null;
let networkSearchQuery = '';

function setupNetworkDiscovery() {
  loadNetworkInfo();

  // Mode switcher (shows custom ports row when 'custom')
  $('net-mode-select')?.addEventListener('change', (e) => {
    const isCustom = e.target.value === 'custom';
    $('net-custom-row')?.classList.toggle('hidden', !isCustom);
  });

  // Segment select dropdown auto-fills target input
  $('net-segment-select')?.addEventListener('change', (e) => {
    if (e.target.value) {
      $('net-target-input').value = e.target.value;
    }
  });

  // Live device search / filter
  $('dev-search-input')?.addEventListener('input', (e) => {
    networkSearchQuery = e.target.value.toLowerCase().trim();
    renderDevicesTable();
  });

  // Export CSV
  $('dev-export-csv')?.addEventListener('click', () => {
    if (!state.discoveredDevices.length) return alert('No devices to export.');
    const rows = [
      ['IP Address', 'MAC Address', 'Vendor', 'Hostname', 'Is Gateway', 'Latency Ms', 'Open TCP Ports', 'Open UDP Ports'],
      ...state.discoveredDevices.map(d => [
        d.ip,
        d.mac || '',
        d.vendor || '',
        d.hostname || '',
        d.isGateway ? 'YES' : 'NO',
        d.rtt ?? '',
        (d.openPorts || []).filter(p => p.proto === 'tcp' || !p.proto).map(p => `${p.port}/${p.service}`).join('; '),
        (d.openPorts || []).filter(p => p.proto === 'udp').map(p => `${p.port}/${p.service}`).join('; '),
      ]),
    ];
    const csvContent = rows.map(r => r.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netlan-discovery-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Export JSON
  $('dev-export-json')?.addEventListener('click', () => {
    if (!state.discoveredDevices.length) return alert('No devices to export.');
    const blob = new Blob([JSON.stringify(state.discoveredDevices, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netlan-discovery-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Clear devices
  $('dev-clear-btn')?.addEventListener('click', () => {
    state.discoveredDevices = [];
    renderDevicesTable();
  });

  // Start / Cancel Discovery Sweep
  $('net-scan-btn')?.addEventListener('click', async () => {
    const scanBtn = $('net-scan-btn');
    if (netScanEventSource) {
      // Cancel active scan
      netScanEventSource.close();
      netScanEventSource = null;
      scanBtn.disabled = false;
      scanBtn.innerHTML = '<span class="btn-icon">⚡</span> Start Discovery';
      $('net-progress-wrap')?.classList.add('hidden');
      return;
    }

    const subnet = $('net-target-input').value.trim() || undefined;
    const mode = $('net-mode-select').value;
    let customTcp = undefined;
    let customUdp = undefined;

    if (mode === 'custom') {
      const tcpRaw = $('net-custom-tcp').value.trim();
      if (tcpRaw) customTcp = tcpRaw.split(',').map(n => parseInt(n.trim(), 10)).filter(n => !isNaN(n));
      const udpRaw = $('net-custom-udp').value.trim();
      if (udpRaw) customUdp = udpRaw.split(',').map(n => parseInt(n.trim(), 10)).filter(n => !isNaN(n));
    }

    scanBtn.disabled = false;
    scanBtn.innerHTML = '<span class="pulse-dot"></span> Stop Discovery';
    $('net-progress-wrap')?.classList.remove('hidden');
    $('net-progress-fill').style.width = '5%';
    $('net-status-text').textContent = 'Initializing network sweep…';

    try {
      const res = await fetch('/api/netdiscovery/scan', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ subnet, mode, customTcp, customUdp }),
      });

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      const processLine = (line) => {
        if (!line.startsWith('data: ')) return;
        try {
          const ev = JSON.parse(line.slice(6));
          handleDiscoveryEvent(ev);
        } catch { /* ignore parse error */ }
      };

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split('\n\n');
        buffer = parts.pop();
        for (const part of parts) {
          const lines = part.split('\n');
          for (const line of lines) processLine(line);
        }
      }
    } catch (err) {
      alert(`Discovery scan error: ${err.message}`);
    } finally {
      scanBtn.disabled = false;
      scanBtn.innerHTML = '<span class="btn-icon">⚡</span> Start Discovery';
      $('net-progress-fill').style.width = '100%';
      $('net-status-text').textContent = `Discovery completed · Found ${state.discoveredDevices.length} hosts`;
    }
  });
}

function handleDiscoveryEvent(ev) {
  if (ev.type === 'status') {
    $('net-status-text').textContent = ev.message;
  } else if (ev.type === 'sweep_progress') {
    const pct = Math.round((ev.done / ev.total) * 40);
    $('net-progress-fill').style.width = `${pct}%`;
    $('net-status-text').textContent = `ICMP ping sweeping: ${ev.done} / ${ev.total} targets checked…`;
  } else if (ev.type === 'devices') {
    state.discoveredDevices = ev.devices || [];
    renderDevicesTable();
    if (ev.gateway) {
      $('net-gateway-badge').style.display = 'inline-block';
      $('net-gateway-badge').textContent = `Gateway: ${ev.gateway}`;
    }
  } else if (ev.type === 'progress') {
    const pct = 40 + Math.round((ev.current / ev.total) * 60);
    $('net-progress-fill').style.width = `${pct}%`;
    $('net-status-text').textContent = `Scanning services on ${ev.device} (${ev.current}/${ev.total})…`;
  } else if (ev.type === 'device_updated') {
    const { device } = ev;
    const idx = state.discoveredDevices.findIndex(d => d.ip === device.ip);
    if (idx >= 0) state.discoveredDevices[idx] = device;
    else state.discoveredDevices.push(device);
    renderDevicesTable();
  } else if (ev.type === 'done') {
    $('net-progress-fill').style.width = '100%';
    $('net-status-text').textContent = `Network discovery complete · ${ev.devices?.length || state.discoveredDevices.length} hosts mapped.`;
  }
}

async function loadNetworkInfo() {
  try {
    const [ifacesRes, arpRes] = await Promise.all([
      fetch('/api/netdiscovery/interfaces'),
      fetch('/api/netdiscovery/arp'),
    ]);
    const ifacesData = await ifacesRes.json();
    state.networkInterfaces = ifacesData.interfaces || (Array.isArray(ifacesData) ? ifacesData : []);
    state.gateway = ifacesData.gateway || null;
    state.discoveredDevices = await arpRes.json();

    // Populate segment select dropdown
    const segSelect = $('net-segment-select');
    if (segSelect && state.networkInterfaces.length) {
      segSelect.innerHTML = '<option value="">Select Subnet Segment…</option>' + state.networkInterfaces
        .filter(i => !i.internal && i.cidr)
        .map(i => {
          const isGw = state.gateway && i.address.slice(0, i.address.lastIndexOf('.')) === state.gateway.slice(0, state.gateway.lastIndexOf('.'));
          return `<option value="${escapeHtml(i.cidr)}">${isGw ? '★ ' : ''}${escapeHtml(i.cidr)} (${escapeHtml(i.name)})</option>`;
        })
        .join('');

      // Auto-select first external CIDR
      const firstExt = state.networkInterfaces.find(i => !i.internal && i.cidr);
      if (firstExt && !$('net-target-input').value) {
        $('net-target-input').value = firstExt.cidr;
        segSelect.value = firstExt.cidr;
      }
    }

    if (state.gateway) {
      $('net-gateway-badge').style.display = 'inline-block';
      $('net-gateway-badge').textContent = `Gateway: ${state.gateway}`;
    }

    renderInterfaces();
    renderDevicesTable();
  } catch { /* ignore */ }
}

function renderInterfaces() {
  const container = $('ifaces-list');
  if (!state.networkInterfaces.length) {
    container.innerHTML = '<div class="empty-hint">No active network interfaces found.</div>';
    return;
  }
  container.innerHTML = state.networkInterfaces
    .map(
      (iface) => `
    <div class="iface-card">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <span class="iface-name">${escapeHtml(iface.name)}</span>
        ${iface.cidr ? `<span class="badge" style="font-size:10px;">${escapeHtml(iface.cidr)}</span>` : ''}
      </div>
      <div class="iface-ip">${escapeHtml(iface.address)} / ${escapeHtml(iface.netmask)}</div>
      <div class="iface-mac">${escapeHtml(iface.mac || '–')} · <span class="vendor-badge">${escapeHtml(iface.vendor || 'Unknown')}</span></div>
    </div>
  `
    )
    .join('');
}

function renderDevicesTable() {
  const tbody = $('devices-body');
  let list = state.discoveredDevices || [];

  if (networkSearchQuery) {
    list = list.filter(d =>
      d.ip.toLowerCase().includes(networkSearchQuery) ||
      (d.mac && d.mac.toLowerCase().includes(networkSearchQuery)) ||
      (d.vendor && d.vendor.toLowerCase().includes(networkSearchQuery)) ||
      (d.hostname && d.hostname.toLowerCase().includes(networkSearchQuery))
    );
  }

  $('dev-count-badge').textContent = `${list.length} ${list.length === 1 ? 'Host' : 'Hosts'}`;

  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-hint">No hosts found matching current filter or subnet.</td></tr>';
    return;
  }

  tbody.innerHTML = list
    .map((d) => {
      const tcpPorts = (d.openPorts || []).filter(p => p.proto === 'tcp' || !p.proto);
      const udpPorts = (d.openPorts || []).filter(p => p.proto === 'udp');

      return `
    <tr>
      <td>
        <span class="copyable" onclick="copyToClipboard('${escapeHtml(d.ip)}', 'IP Copied')" title="Click to copy IP" style="font-weight:600; color:var(--text-primary); font-family:var(--font-mono);">
          ${escapeHtml(d.ip)}
        </span>
        ${d.isGateway ? '<span class="gateway-badge" title="Default Route Gateway">★ Gateway</span>' : ''}
        ${d.isSelf ? '<span class="self-badge" title="Local System Interface">This Host</span>' : ''}
      </td>
      <td>
        ${
          d.mac
            ? `<span class="copyable" onclick="copyToClipboard('${escapeHtml(d.mac)}', 'MAC Copied')" title="Click to copy MAC" style="font-family:var(--font-mono); font-size:11px;">${escapeHtml(d.mac)}</span>`
            : '<span style="color:var(--text-muted);">–</span>'
        }
      </td>
      <td><span class="vendor-badge">${escapeHtml(d.vendor || 'Unknown')}</span></td>
      <td style="font-size:11px; color:var(--text-secondary);">${escapeHtml(d.hostname || d.interface || '–')}</td>
      <td>
        ${
          d.rtt !== null && d.rtt !== undefined
            ? `<span class="badge-icmp" title="ICMP Echo Round-Trip Time">${Math.round(d.rtt)}ms</span>`
            : d.alive
            ? '<span class="sev-tag low" style="font-size:9px; padding:1px 5px;">ONLINE</span>'
            : '<span style="color:var(--text-muted); font-size:11px;">–</span>'
        }
      </td>
      <td>
        <div style="display:flex; flex-wrap:wrap; gap:2px; max-width:350px;">
          ${tcpPorts.map(p => `<span class="badge-tcp" title="${escapeHtml(p.banner || p.service || '')}">${p.port}/tcp ${escapeHtml(p.service || '')}</span>`).join('')}
          ${udpPorts.map(p => `<span class="badge-udp" title="${escapeHtml(p.service || '')}">${p.port}/udp ${escapeHtml(p.service || '')}</span>`).join('')}
          ${!tcpPorts.length && !udpPorts.length ? '<span style="color:var(--text-muted); font-size:11px;">No open ports found</span>' : ''}
        </div>
      </td>
      <td style="text-align:right;">
        <button class="btn btn-glass" style="font-size:10px; padding:2px 7px;" onclick="scanHostPortsModal('${escapeHtml(d.ip)}')">Port Scan</button>
      </td>
    </tr>
  `;
    })
    .join('');
}

window.copyToClipboard = (text, message = 'Copied') => {
  navigator.clipboard.writeText(text).then(() => {
    // transient visual indicator
    const note = document.createElement('div');
    note.style.position = 'fixed';
    note.style.bottom = '20px';
    note.style.right = '20px';
    note.style.background = 'var(--bg-surface)';
    note.style.border = '1px solid var(--border-focus)';
    note.style.color = 'var(--text-primary)';
    note.style.padding = '6px 12px';
    note.style.borderRadius = 'var(--radius-md)';
    note.style.fontSize = '12px';
    note.style.zIndex = '9999';
    note.textContent = message;
    document.body.appendChild(note);
    setTimeout(() => note.remove(), 1200);
  });
};

window.scanHostPortsModal = async (host) => {
  const btn = event.target;
  btn.disabled = true;
  btn.textContent = 'Scanning…';
  try {
    const res = await fetch('/api/netdiscovery/scan-host', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ host }),
    });
    const data = await res.json();
    const dev = state.discoveredDevices.find((d) => d.ip === host);
    if (dev) {
      dev.openPorts = data.openPorts || [];
      renderDevicesTable();
    }
  } catch (err) {
    alert(`Port scan error: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Port Scan';
  }
};

// ========================================================
// VIEW: UPTIME MONITORS
// ========================================================
function setupMonitors() {
  $('create-monitor-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = $('mon-name').value.trim();
    const url = $('mon-url').value.trim();
    const intervalSeconds = Number($('mon-interval').value);
    const expectedStatus = Number($('mon-status').value);
    const keyword = $('mon-keyword').value.trim();

    try {
      const res = await fetch('/api/monitors', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name, url, intervalSeconds, expectedStatus, keyword }),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      const newMon = await res.json();
      state.monitors.push(newMon);
      renderMonitors();
      updateMonitorCountBadge();
      $('monitor-modal').classList.add('hidden');
    } catch (err) {
      alert(`Failed to create monitor: ${err.message}`);
    }
  });

  loadMonitors();
}

async function loadMonitors() {
  try {
    const res = await fetch('/api/monitors');
    state.monitors = await res.json();
    renderMonitors();
    updateMonitorCountBadge();
  } catch { /* ignore */ }
}

function updateMonitorCountBadge() {
  $('mon-count').textContent = state.monitors.length;
}

function renderMonitors() {
  const grid = $('monitors-grid');
  if (!state.monitors.length) {
    grid.innerHTML = '<div class="empty-hint">No uptime monitors configured yet. Add one above!</div>';
    return;
  }

  grid.innerHTML = state.monitors
    .map(
      (m) => `
    <div class="monitor-card">
      <div class="mon-head">
        <div class="mon-name">${escapeHtml(m.name)}</div>
        <span class="sev-tag ${m.status === 'up' ? 'low' : m.status === 'degraded' ? 'medium' : 'critical'}">${m.status.toUpperCase()}</span>
      </div>
      <div class="mon-url" title="${escapeHtml(m.url)}">${escapeHtml(m.url)}</div>

      <div class="mon-sparkline">
        ${(m.history || [])
          .slice(-30)
          .map(
            (h) => `
          <div class="spark-bar ${h.status === 'down' ? 'down' : h.status === 'degraded' ? 'deg' : ''}" style="height: ${Math.min(100, Math.max(15, (h.latencyMs || 20) / 10))}%;" title="${h.latencyMs}ms (${h.status})"></div>
        `
          )
          .join('')}
      </div>

      <div class="mon-stats-row">
        <div class="mon-stat-col">
          <div class="mon-stat-val">${m.uptimePercent}%</div>
          <div class="mon-stat-lbl">Uptime</div>
        </div>
        <div class="mon-stat-col">
          <div class="mon-stat-val">${m.lastLatencyMs || 0}ms</div>
          <div class="mon-stat-lbl">Latency</div>
        </div>
        <div class="mon-stat-col">
          <div class="mon-stat-val">${m.intervalSeconds}s</div>
          <div class="mon-stat-lbl">Interval</div>
        </div>
      </div>

      <div style="display:flex; justify-content:space-between; align-items:center; margin-top:8px;">
        <span style="font-size:10px; color:var(--text-muted);">Checked: ${m.lastChecked ? new Date(m.lastChecked).toLocaleTimeString() : 'Never'}</span>
        <div style="display:flex; gap:4px;">
          <button class="ghost-btn" title="Check now" onclick="checkMonitorNow('${m.id}')">🔄</button>
          <button class="ghost-btn" title="Delete" onclick="deleteMonitor('${m.id}')">🗑️</button>
        </div>
      </div>
    </div>
  `
    )
    .join('');
}

window.checkMonitorNow = async (id) => {
  await fetch(`/api/monitors/${id}/check`, { method: 'POST' }).catch(() => {});
};

window.deleteMonitor = async (id) => {
  if (!confirm('Delete this monitor?')) return;
  await fetch(`/api/monitors/${id}`, { method: 'DELETE' });
  state.monitors = state.monitors.filter((m) => m.id !== id);
  renderMonitors();
  updateMonitorCountBadge();
};

// ========================================================
// VIEW: HTTP LOAD TESTER
// ========================================================
function setupLoadTester() {
  $('loadtest-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = $('lt-url').value.trim();
    const method = $('lt-method').value;
    const concurrency = Number($('lt-concurrency').value) || 10;
    const totalRequests = Number($('lt-total').value) || 50;

    let headers = {};
    try {
      if ($('lt-headers').value.trim()) headers = JSON.parse($('lt-headers').value);
    } catch { /* ignore */ }

    const body = $('lt-body').value.trim() || undefined;

    const securityProbes = {
      csrf: $('lt-probe-csrf').checked,
      sqli: $('lt-probe-sqli').checked,
      xss: $('lt-probe-xss').checked,
      rateLimit: $('lt-probe-rate').checked,
    };

    $('lt-start-btn').disabled = true;
    $('lt-start-btn').innerHTML = '<span class="pulse-dot"></span> Testing in progress…';

    const liveWrap = $('lt-live-container');
    liveWrap.innerHTML = '<div class="empty-hint">Launching concurrent requests…</div>';

    try {
      const res = await fetch('/api/loadtest/run', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url, method, concurrency, totalRequests, headers, body, securityProbes }),
      });

      const reader = res.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n\n');
        buffer = lines.pop();

        for (const block of lines) {
          if (block.includes('event: progress')) {
            const jsonStr = block.slice(block.indexOf('data: ') + 6);
            try {
              const data = JSON.parse(jsonStr);
              renderLoadTestProgress(data);
            } catch { /* ignore */ }
          } else if (block.includes('event: done')) {
            const jsonStr = block.slice(block.indexOf('data: ') + 6);
            try {
              const summary = JSON.parse(jsonStr);
              renderLoadTestSummary(summary);
            } catch { /* ignore */ }
          }
        }
      }
    } catch (err) {
      liveWrap.innerHTML = `<div class="empty-hint" style="color:var(--sev-crit-fg);">Load test failed: ${escapeHtml(err.message)}</div>`;
    } finally {
      $('lt-start-btn').disabled = false;
      $('lt-start-btn').innerHTML = '<span class="btn-icon">🚀</span> Launch Load Test';
    }
  });
}

function renderLoadTestProgress(p) {
  const liveWrap = $('lt-live-container');
  liveWrap.innerHTML = `
    <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:10px; margin-bottom:12px;">
      <div class="dash-card" style="padding:10px;">
        <div class="dash-card-val">${p.completed} / ${p.total}</div>
        <div class="dash-card-lbl">Completed Requests</div>
      </div>
      <div class="dash-card" style="padding:10px;">
        <div class="dash-card-val" style="color:var(--accent-blue);">${p.rps}</div>
        <div class="dash-card-lbl">RPS</div>
      </div>
      <div class="dash-card" style="padding:10px;">
        <div class="dash-card-val">${p.latestLatency}ms</div>
        <div class="dash-card-lbl">Latency</div>
      </div>
    </div>
    <div class="progress-bar-wrap"><div class="progress-bar-fill" style="width: ${(p.completed / p.total) * 100}%;"></div></div>
  `;
}

function renderLoadTestSummary(s) {
  const liveWrap = $('lt-live-container');
  liveWrap.innerHTML = `
    <div style="display:grid; grid-template-columns: repeat(4, 1fr); gap:8px; margin-bottom:14px;">
      <div class="dash-card" style="padding:10px;">
        <div class="dash-card-val" style="color:var(--accent-blue);">${s.rps}</div>
        <div class="dash-card-lbl">Average RPS</div>
      </div>
      <div class="dash-card" style="padding:10px;">
        <div class="dash-card-val">${s.latencies.p50}ms</div>
        <div class="dash-card-lbl">p50 Latency</div>
      </div>
      <div class="dash-card" style="padding:10px;">
        <div class="dash-card-val" style="color:var(--sev-high-fg);">${s.latencies.p95}ms</div>
        <div class="dash-card-lbl">p95 Latency</div>
      </div>
      <div class="dash-card" style="padding:10px;">
        <div class="dash-card-val" style="color:var(--sev-crit-fg);">${s.latencies.p99}ms</div>
        <div class="dash-card-lbl">p99 Latency</div>
      </div>
    </div>

    <div class="form-group">
      <label>Status Distribution</label>
      <div style="display:flex; gap:6px; flex-wrap:wrap;">
        ${Object.entries(s.statusCodes)
          .map(([code, count]) => `<span class="badge" style="font-size:11px; padding:2px 6px;">${code}: ${count}</span>`)
          .join('')}
      </div>
    </div>

    ${
      s.securityFindings && s.securityFindings.length
        ? `
      <div class="box-header" style="margin-top:12px;">
        <h4 style="color:var(--sev-crit-fg); font-size:12px;">Security Findings (${s.securityFindings.length})</h4>
      </div>
      ${s.securityFindings
        .map(
          (f) => `
        <div class="finding-card" style="margin-bottom:6px;">
          <div class="finding-header">
            <span class="sev-tag ${f.severity}">${f.severity}</span>
            <span class="finding-title">${escapeHtml(f.title)}</span>
          </div>
          <p class="finding-desc">${escapeHtml(f.description)}</p>
        </div>
      `
        )
        .join('')}
    `
        : '<div style="margin-top:10px; font-size:11px; color:var(--sev-low-fg);">✅ Automated security checks passed.</div>'
    }
  `;
}

// ========================================================
// VIEW: HTTP INSPECTOR & SSH POKER
// ========================================================
function setupInspector() {
  $('poke-http-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const method = $('poke-method').value;
    const url = $('poke-url').value.trim();
    const authType = $('poke-auth-type').value;
    const authVal = $('poke-auth-val').value.trim();
    const rawHeaders = $('poke-headers').value.trim();
    const body = $('poke-body').value.trim() || undefined;

    const headers = {};
    if (rawHeaders) {
      rawHeaders.split('\n').forEach((line) => {
        const idx = line.indexOf(':');
        if (idx > 0) headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      });
    }

    let auth = null;
    if (authType === 'bearer') auth = { type: 'bearer', token: authVal };
    else if (authType === 'basic') {
      const [username, password] = authVal.split(':');
      auth = { type: 'basic', username, password };
    } else if (authType === 'apikey') {
      const [header, value] = authVal.split(':');
      auth = { type: 'apikey', header: header?.trim(), value: value?.trim() };
    }

    const resWrap = $('poke-response-wrap');
    resWrap.innerHTML = '<div class="empty-hint">Sending request…</div>';

    try {
      const res = await fetch('/api/poke', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url, method, headers, body, auth }),
      });
      const data = await res.json();

      resWrap.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <div>
            <span class="sev-tag ${data.status < 400 ? 'low' : 'critical'}">${data.status} ${escapeHtml(data.statusText || '')}</span>
            <span style="font-family:var(--font-mono); font-size:11px; margin-left:6px; color:var(--text-muted);">${data.timingMs}ms · ${formatBytes(data.sizeBytes)}</span>
          </div>
        </div>

        <div class="form-group">
          <label>Response Headers</label>
          <div class="finding-code" style="max-height: 120px;">${Object.entries(data.headers || {})
            .map(([k, v]) => `${k}: ${v}`)
            .join('\n')}</div>
        </div>

        <div class="form-group">
          <label>Response Body (${escapeHtml(data.contentType || 'unknown')})</label>
          <div class="finding-code" style="max-height: 180px;">${escapeHtml(data.body || '(Empty body)')}</div>
        </div>
      `;
    } catch (err) {
      resWrap.innerHTML = `<div class="empty-hint" style="color:var(--sev-crit-fg);">${escapeHtml(err.message)}</div>`;
    }
  });

  $('poke-ssh-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const host = $('ssh-host').value.trim();
    const port = Number($('ssh-port').value) || 22;
    const timeoutMs = Number($('ssh-timeout').value) || 4000;

    const resWrap = $('ssh-response-wrap');
    resWrap.innerHTML = '<div class="empty-hint">Connecting to SSH service…</div>';

    try {
      const res = await fetch('/api/poke/ssh', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ host, port, timeoutMs }),
      });
      const data = await res.json();

      resWrap.innerHTML = `
        <div style="margin-bottom: 10px;">
          <span class="sev-tag ${data.reachable ? 'low' : 'critical'}">${data.reachable ? 'ONLINE' : 'UNREACHABLE'}</span>
          <span style="font-family:var(--font-mono); font-size:11px; margin-left:6px; color:var(--text-muted);">${data.latencyMs}ms latency</span>
        </div>

        ${
          data.reachable
            ? `
          <div class="form-group">
            <label>Identification Banner</label>
            <div class="finding-code">${escapeHtml(data.banner)}</div>
          </div>
          <div class="seo-checks-grid" style="margin-top:8px;">
            <div class="seo-item">
              <div class="seo-lbl">SSH Version</div>
              <div class="seo-val">${escapeHtml(data.sshVersion || '–')}</div>
            </div>
            <div class="seo-item">
              <div class="seo-lbl">Operating System</div>
              <div class="seo-val">${escapeHtml(data.osHint || 'Standard Linux/BSD')}</div>
            </div>
          </div>
        `
            : `<div class="empty-hint" style="color:var(--sev-crit-fg);">${escapeHtml(data.error || 'Connection refused')}</div>`
        }
      `;
    } catch (err) {
      resWrap.innerHTML = `<div class="empty-hint" style="color:var(--sev-crit-fg);">${escapeHtml(err.message)}</div>`;
    }
  });
}

// ========================================================
// VIEW: DATABASE CONNECTION TESTER
// ========================================================
function setupDatabaseTester() {
  $('db-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const type = $('db-type').value;
    const host = $('db-host').value.trim();
    const port = $('db-port').value.trim() || undefined;

    const resWrap = $('db-results-wrap');
    resWrap.innerHTML = '<div class="empty-hint">Executing protocol handshake…</div>';

    try {
      const res = await fetch('/api/db/test', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ type, host, port }),
      });
      const data = await res.json();

      resWrap.innerHTML = `
        <div style="margin-bottom: 10px;">
          <span class="sev-tag ${data.connected ? 'low' : 'critical'}">${data.status}</span>
          <span style="font-family:var(--font-mono); font-size:11px; margin-left:6px; color:var(--text-muted);">${data.latencyMs}ms · Port ${data.port}</span>
        </div>
        <div class="form-group">
          <label>Server Version &amp; Handshake</label>
          <div class="finding-code">${escapeHtml(data.serverVersion || data.error || '')}</div>
        </div>
        <div class="finding-desc">${escapeHtml(data.details || '')}</div>
      `;
    } catch (err) {
      resWrap.innerHTML = `<div class="empty-hint" style="color:var(--sev-crit-fg);">${escapeHtml(err.message)}</div>`;
    }
  });

  $('db-stress-btn')?.addEventListener('click', async () => {
    const type = $('db-type').value;
    const host = $('db-host').value.trim();
    const port = $('db-port').value.trim() || undefined;

    const resWrap = $('db-results-wrap');
    resWrap.innerHTML = '<div class="empty-hint">Executing 30 concurrent connection probes…</div>';

    try {
      const res = await fetch('/api/db/stress', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ type, host, port, concurrency: 10, totalQueries: 30 }),
      });
      const data = await res.json();

      resWrap.innerHTML = `
        <div class="box-header">
          <h4>Database Stress Test Complete</h4>
        </div>
        <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:8px; margin-bottom:12px;">
          <div class="dash-card" style="padding:10px;">
            <div class="dash-card-val" style="color:var(--sev-low-fg);">${data.successful} / ${data.totalAttempts}</div>
            <div class="dash-card-lbl">Success Rate</div>
          </div>
          <div class="dash-card" style="padding:10px;">
            <div class="dash-card-val">${data.avgLatencyMs}ms</div>
            <div class="dash-card-lbl">Average Latency</div>
          </div>
          <div class="dash-card" style="padding:10px;">
            <div class="dash-card-val">${data.maxLatencyMs}ms</div>
            <div class="dash-card-lbl">Max Latency</div>
          </div>
        </div>
      `;
    } catch (err) {
      resWrap.innerHTML = `<div class="empty-hint" style="color:var(--sev-crit-fg);">${escapeHtml(err.message)}</div>`;
    }
  });
}

// ========================================================
// HISTORY SIDEBAR
// ========================================================
function setupHistory() {
  $('refresh-history')?.addEventListener('click', loadHistory);
  loadHistory();
}

async function loadHistory() {
  try {
    const res = await fetch('/api/scans');
    state.scansHistory = await res.json();
    renderHistory();
  } catch { /* ignore */ }
}

function renderHistory() {
  const list = $('history');
  if (!state.scansHistory.length) {
    list.innerHTML = '<li class="history-empty">No previous scans found.</li>';
    return;
  }

  list.innerHTML = state.scansHistory
    .map(
      (s) => `
    <li class="history-item ${state.currentScan?.id === s.id ? 'active' : ''}" onclick="loadScanFromHistory('${s.id}')">
      <div class="history-target">${escapeHtml(s.target)}</div>
      <div class="history-meta">
        <span class="history-grade grade-${s.score?.grade || 'C'}">${s.score?.grade || '–'} (${s.score?.score ?? '–'})</span>
        <span>${s.startedAt ? new Date(s.startedAt).toLocaleDateString() : ''}</span>
      </div>
    </li>
  `
    )
    .join('');
}

window.loadScanFromHistory = async (id) => {
  switchView('scanner');
  $('empty').classList.add('hidden');
  $('scan-view').classList.remove('hidden');

  try {
    const res = await fetch(`/api/scans/${id}`);
    const scan = await res.json();
    state.currentScan = scan;
    renderFullScan(scan);
    renderHistory();
  } catch (err) {
    alert(`Failed to load scan: ${err.message}`);
  }
};

// ========================================================
// UTILITIES
// ========================================================
function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}
