import { $, toast, escapeHtml, formatBytes } from '../utils.js';
import { state } from '../state.js';
import { renderDashboard } from './dashboard.js';
import type { Finding } from '../types.js';

export function setupScanForm(switchViewFn: (name: string) => void) {
  $('scan-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = ( $('target') as HTMLInputElement).value.trim();
    const engine = ( $('engine') as HTMLSelectElement).value;
    const maxPages = Number(( $('pages') as HTMLInputElement).value) || 25;
    if (!target) return;
    switchViewFn('scanner');
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

  const fFilter = $('f-filter');
  if (fFilter) fFilter.addEventListener('input', (e) => {
    state.filters.findingText = (e.target as HTMLInputElement).value;
    if ((state.currentScan as any)?.findings) renderFindings((state.currentScan as any).findings as any);
  });
}

export function resetScanBtn() {
  const btn = $('scan-btn') as HTMLButtonElement;
  if (btn) {
    btn.disabled = false;
    btn.innerHTML = '⚡ Scan';
  }
}

export function streamScanEvents(id: string) {
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

export function renderFullScan(scan: any) {
  $('grade').textContent = scan.score?.grade || '–';
  $('grade').className = 'grade-circle grade-' + (scan.score?.grade || 'C');
  $('s-target').textContent = scan.target;
  $('s-meta').textContent = 'Completed in ' + Math.round(scan.durationMs/1000) + 's · ' + (scan.crawl?.pages?.length||0) + ' pages · ' + (scan.networkSummary?.requests||0) + ' requests';
  renderFindings(scan.findings||[]);
  renderAiInsights(scan.insights);
  renderCookiesAndStorage(scan);
  renderInventory(scan);
  renderExportButtons(scan.id);
  renderTechStack(scan.techStack||[], scan.rateLimiting);
  renderSeoAudit(scan.seo);
  renderWpAdmin(scan.wpAdmin);
  renderDashboard();
}

export function renderFindings(findings: Finding[]) {
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

export function updateSeverityPills(findings: Finding[]) {
  const counts: any = { critical:0, high:0, medium:0, low:0, info:0 };
  findings.forEach(f => counts[f.severity] = (counts[f.severity]||0)+1);
  let html = '';
  if (counts.critical) html += '<span class="pill crit">' + counts.critical + ' Crit</span>';
  if (counts.high) html += '<span class="pill high">' + counts.high + ' High</span>';
  if (counts.medium) html += '<span class="pill med">' + counts.medium + ' Med</span>';
  if (counts.low) html += '<span class="pill low">' + counts.low + ' Low</span>';
  $('sev-counts').innerHTML = html;
}

export function renderAiInsights(insights: any) {
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

export function appendNetworkRow(entry: any, index: number) {
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

export function showNetworkDetail(entry: any) {
  const detail = $('net-detail');
  detail.classList.remove('hidden');
  let headersStr = '';
  const hdrs = entry.response?.headers || {};
  for (const k in hdrs) { headersStr += k + ': ' + hdrs[k] + '\n'; }
  detail.innerHTML = '<div style="display:flex;justify-content:space-between;margin-bottom:10px;"><h4 style="font-size:13px;font-weight:700;">Request Details</h4><button class="icon-btn" onclick="document.getElementById(\'net-detail\').classList.add(\'hidden\')">×</button></div><div style="margin-bottom:8px;"><span class="sev low">' + (entry.method||'GET') + '</span><span style="font-family:var(--font-mono);font-size:11px;margin-left:6px;">' + escapeHtml(entry.url) + '</span></div><div class="form-group"><label>Response Headers</label><div class="codeblock" style="max-height:160px;">' + escapeHtml(headersStr) + '</div></div>';
}

export function renderCookiesAndStorage(scan: any) {
  const cookies = scan.crawl?.cookies||[];
  const c = $('cookies');
  if (!cookies.length) { c.innerHTML = '<div class="empty">No cookies detected</div>'; return; }
  let rows = '';
  for (const co of cookies) {
    rows += '<tr><td style="font-weight:700;">' + escapeHtml(co.name) + '</td><td>' + (co.httpOnly?'✅':'❌') + '</td><td>' + (co.secure?'✅':'❌') + '</td><td>' + escapeHtml(co.sameSite||'None') + '</td><td>' + escapeHtml(co.path||'/') + '</td><td style="font-size:10px;color:var(--text-muted);">' + escapeHtml(co.setBy||'') + '</td></tr>';
  }
  c.innerHTML = '<div class="table-wrap"><table class="table"><thead><tr><th>Name</th><th>HttpOnly</th><th>Secure</th><th>SameSite</th><th>Path</th><th>Set By</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
}

export function renderInventory(scan: any) {
  const origins = scan.crawl?.externalOrigins||[];
  let grid = '';
  for (const o of origins) { grid += '<div class="tech"><div class="tech-name">🌐 ' + escapeHtml(o) + '</div><div class="tech-cat">External</div></div>'; }
  $('inventory').innerHTML = '<div class="box-head"><h3>External Dependencies (' + origins.length + ')</h3></div><div class="tech-grid">' + grid + '</div>';
}

export function renderExportButtons(scanId: string) {
  $('export').innerHTML = '<a href="/api/scans/' + scanId + '/report.md" download class="btn btn-ghost" style="height:28px;font-size:11px;">MD</a><a href="/api/scans/' + scanId + '/report.html" target="_blank" class="btn btn-ghost" style="height:28px;font-size:11px;">HTML</a><a href="/api/scans/' + scanId + '/report.json" download class="btn btn-ghost" style="height:28px;font-size:11px;">JSON</a><a href="/api/scans/' + scanId + '/report.sarif" download class="btn btn-ghost" style="height:28px;font-size:11px;">SARIF</a>';
}

export function renderWpAdmin(wpAdmin: any) {
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

export function renderTechStack(technologies: any[], rateLimiting: any) {
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

export function renderSeoAudit(seo: any) {
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

export function setupHistory() {
  const refreshBtn = $('refresh-history');
  if (refreshBtn) refreshBtn.addEventListener('click', loadHistory);
  loadHistory();
}

export async function loadHistory() {
  try { const res = await fetch('/api/scans'); state.scansHistory = await res.json(); renderHistory(); } catch {}
}

export function renderHistory() {
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
