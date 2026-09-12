/* Monarch dashboard — vanilla JS, no build step. */
(() => {
  const $ = s => document.querySelector(s);
  const SEV = ['critical', 'high', 'medium', 'low', 'info'];
  const COLOR = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280' };
  const GRADE_COLOR = { A: '#16a34a', B: '#65a30d', C: '#ca8a04', D: '#ea580c', F: '#dc2626' };
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtBytes = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`;
  const hostOf = u => { try { return new URL(u).host; } catch { return u; } };

  const state = { id: null, scan: null, findings: [], network: [], es: null, sevOn: new Set(SEV), typeOn: new Set(), fFilter: '', nFilter: '', selected: null, t0: 0 };

  /* ---------------- health & history ---------------- */
  async function health() {
    try {
      const h = await (await fetch('/api/health')).json();
      $('#health').textContent = `online · AI: ${h.ai} · crawler: ${h.crawler}`;
      $('#health').classList.add('ok');
      if (h.crawler === 'playwright') $('#engine').value = 'playwright';
    } catch { $('#health').textContent = 'offline'; }
  }
  async function loadHistory() {
    const list = await (await fetch('/api/scans')).json().catch(() => []);
    $('#history').innerHTML = list.map(s => `
      <li data-id="${s.id}" class="${s.id === state.id ? 'active' : ''}">
        <div class="h-grade" style="background:${s.score ? GRADE_COLOR[s.score.grade] : '#334155'}">${s.score ? s.score.grade : (s.status === 'running' ? '…' : '!')}</div>
        <div style="min-width:0"><div class="h-host">${esc(hostOf(s.target))}</div><div class="h-meta">${s.score ? `${s.score.score}/100 · ${s.findings} findings` : esc(s.status || '')} · ${new Date(s.startedAt).toLocaleString()}</div></div>
      </li>`).join('') || '<li class="muted" style="cursor:default">No scans yet</li>';
    $('#history').querySelectorAll('li[data-id]').forEach(li => li.onclick = () => openScan(li.dataset.id));
  }

  /* ---------------- start / open scans ---------------- */
  $('#scan-form').onsubmit = async e => {
    e.preventDefault();
    const target = $('#target').value.trim();
    if (!target) return;
    $('#scan-btn').disabled = true;
    try {
      const r = await fetch('/api/scans', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ target, engine: $('#engine').value, maxPages: Number($('#pages').value) || 25 }) });
      const j = await r.json();
      if (!r.ok) throw new Error(j.error || r.statusText);
      if (j.status === 'error') throw new Error(j.error);
      resetView(target);
      state.id = j.id;
      history.replaceState(null, '', `#${j.id}`);
      stream(j.id);
      loadHistory();
    } catch (err) {
      alert(`Scan failed to start: ${err.message}`);
    } finally { $('#scan-btn').disabled = false; }
  };

  async function openScan(id) {
    if (state.es) { state.es.close(); state.es = null; }
    const r = await fetch(`/api/scans/${id}`);
    const j = await r.json();
    if (!r.ok) return alert(j.error || 'not found');
    if (j.status === 'running') { resetView(j.target || ''); state.id = id; stream(id); return; }
    if (j.status === 'error') return alert(`Scan failed: ${j.error}`);
    resetView(j.target);
    state.id = id;
    history.replaceState(null, '', `#${id}`);
    state.findings = j.findings; state.network = j.network;
    finish(j);
    loadHistory();
  }

  function resetView(target) {
    Object.assign(state, { scan: null, findings: [], network: [], selected: null, t0: 0 });
    state.typeOn = new Set();
    $('#empty').classList.add('hidden'); $('#scan-view').classList.remove('hidden');
    $('#s-target').textContent = target;
    $('#s-meta').textContent = 'starting…';
    $('#grade').textContent = '–'; $('#grade').style.background = '';
    $('#progress-bar').style.width = '2%'; $('.progress').classList.remove('done');
    $('#live-status').textContent = '';
    $('#sev-counts').innerHTML = ''; $('#export').innerHTML = '';
    $('#findings').innerHTML = ''; $('#net-body').innerHTML = ''; $('#ai').innerHTML = '<div class="ai-loading">AI insights will appear once the scan completes…</div>';
    $('#cookies').innerHTML = ''; $('#inventory').innerHTML = '';
    $('#net-detail').classList.add('hidden'); $('.net-wrap').classList.remove('split');
    renderSevChips(); renderTypeChips(); updateCounts();
  }

  const STAGE_PCT = { init: 3, crawl: 30, assets: 55, probe: 70, analyze: 85, ai: 93 };
  function stream(id) {
    const es = new EventSource(`/api/scans/${id}/events`);
    state.es = es;
    es.addEventListener('status', e => {
      const d = JSON.parse(e.data);
      $('#live-status').textContent = `${d.level === 'warn' ? '⚠ ' : ''}[${d.stage}] ${d.message}`;
      const pct = STAGE_PCT[d.stage]; if (pct) $('#progress-bar').style.width = Math.max(parseFloat($('#progress-bar').style.width) || 0, pct) + '%';
      if (d.stage === 'crawl') $('#s-meta').textContent = `crawling… ${d.pages ?? 0} page(s) · ${state.network.length} requests`;
    });
    es.addEventListener('network', e => {
      const { entry } = JSON.parse(e.data);
      if (!state.t0) state.t0 = entry.startedAt;
      state.network.push(entry);
      if (!state.typeOn.has(entry.type)) { state.typeOn.add(entry.type); renderTypeChips(); }
      appendNetRow(entry);
      $('#t-network').textContent = state.network.length;
      $('#net-summary').textContent = netSummary();
    });
    es.addEventListener('finding', e => {
      const { finding } = JSON.parse(e.data);
      state.findings.push(finding);
      $('#findings').insertAdjacentHTML('beforeend', findingHtml(finding));
      updateCounts();
    });
    es.addEventListener('done', () => { });
    es.addEventListener('error', e => { if (e.data) { const d = JSON.parse(e.data); $('#live-status').textContent = `✖ ${d.message}`; $('#s-meta').textContent = 'failed'; } });
    es.addEventListener('closed', async () => {
      es.close(); state.es = null;
      const j = await (await fetch(`/api/scans/${id}`)).json();
      if (j.findings) { state.findings = j.findings; state.network = j.network; finish(j); }
      loadHistory();
    });
    es.onerror = () => { /* server closed or restart; 'closed' handles the normal path */ };
  }

  function finish(scan) {
    state.scan = scan;
    state.network = scan.network;
    state.t0 = state.network.length ? Math.min(...state.network.map(e => e.startedAt)) : 0;
    state.typeOn = new Set(state.network.map(e => e.type));
    renderTypeChips();
    $('#progress-bar').style.width = '100%'; $('.progress').classList.add('done');
    $('#live-status').textContent = `completed in ${(scan.durationMs / 1000).toFixed(1)}s · engine ${scan.crawl.engine}`;
    $('#s-meta').textContent = `${scan.crawl.pages.length} pages · ${scan.networkSummary.requests} requests · ${fmtBytes(scan.networkSummary.bytes)} · ${new Date(scan.finishedAt).toLocaleString()}`;
    $('#grade').textContent = scan.score.grade; $('#grade').style.background = GRADE_COLOR[scan.score.grade];
    $('#grade').title = `${scan.score.score}/100`;
    $('#export').innerHTML = `<a href="/api/scans/${scan.id}/report.html" target="_blank">HTML / PDF</a><a href="/api/scans/${scan.id}/report.md">Markdown</a><a href="/api/scans/${scan.id}/report.json">JSON</a>`;
    renderFindings(); renderNetwork(); renderAi(scan.insights); renderCookies(scan); renderInventory(scan);
    updateCounts();
  }

  /* ---------------- findings ---------------- */
  function updateCounts() {
    const counts = {}; for (const f of state.findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
    $('#t-findings').textContent = state.findings.length;
    $('#sev-counts').innerHTML = SEV.map(s => `<span style="background:${COLOR[s]}">${s} ${counts[s] || 0}</span>`).join('');
  }
  function renderSevChips() {
    $('#sev-chips').innerHTML = SEV.map(s => `<button data-sev="${s}" class="${state.sevOn.has(s) ? 'on' : ''}" style="${state.sevOn.has(s) ? `background:${COLOR[s]}` : ''}">${s}</button>`).join('');
    $('#sev-chips').querySelectorAll('button').forEach(b => b.onclick = () => { const s = b.dataset.sev; state.sevOn.has(s) ? state.sevOn.delete(s) : state.sevOn.add(s); renderSevChips(); renderFindings(); });
  }
  function findingHtml(f) {
    const ev = f.evidence == null ? '' : typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 2);
    return `<details class="finding" style="border-left-color:${COLOR[f.severity]}" data-id="${esc(f.id)}">
      <summary><span class="sev-badge" style="background:${COLOR[f.severity]}">${f.severity}</span><span class="f-title">${esc(f.title)}</span><span class="f-cat">${esc(f.category)}${f.cwe ? `<span class="tag">${esc(f.cwe)}</span>` : ''}</span></summary>
      <div class="f-body">
        ${f.location ? `<div class="loc">📍 ${esc(f.location)}</div>` : ''}
        <div>${esc(f.description)}</div>
        ${ev ? `<h5>Evidence</h5><pre>${esc(ev.slice(0, 2000))}</pre>` : ''}
        ${f.remediation ? `<h5>Remediation</h5><pre class="rem">${esc(f.remediation)}</pre>` : ''}
        ${f.owasp ? `<div class="muted" style="font-size:11.5px;margin-top:6px">OWASP ${esc(f.owasp)} · id <code>${esc(f.id)}</code></div>` : ''}
        ${f.references?.length ? `<h5>References</h5><div class="f-refs">${f.references.map(r => `<a href="${esc(r)}" target="_blank" rel="noopener">${esc(r)}</a>`).join('')}</div>` : ''}
      </div></details>`;
  }
  function renderFindings() {
    const q = state.fFilter.toLowerCase();
    const list = state.findings.filter(f => state.sevOn.has(f.severity) && (!q || `${f.title} ${f.id} ${f.category} ${f.location} ${f.description}`.toLowerCase().includes(q)));
    $('#findings').innerHTML = list.map(findingHtml).join('') || `<div class="muted" style="padding:30px;text-align:center">${state.findings.length ? 'No findings match the filter.' : state.scan ? 'No findings — great job! 🎉' : 'Waiting for findings…'}</div>`;
  }
  $('#f-filter').oninput = e => { state.fFilter = e.target.value; renderFindings(); };

  /* ---------------- AI ---------------- */
  function renderAi(ins) {
    if (!ins) { $('#ai').innerHTML = '<div class="ai-loading">AI insights were disabled for this scan.</div>'; return; }
    const riskColor = { critical: COLOR.critical, high: COLOR.high, medium: COLOR.medium, low: COLOR.low, minimal: '#22c55e' }[ins.riskLevel] || COLOR.info;
    $('#ai').innerHTML = `
      <div><span class="risk" style="background:${riskColor}">${esc(ins.riskLevel)} risk</span><span class="prov">analysis by ${esc(ins.provider)}${ins.model ? ` · ${esc(ins.model)}` : ''}</span></div>
      ${ins.warning ? `<div class="warn" style="margin-top:10px">${esc(ins.warning)}</div>` : ''}
      ${ins.provider === 'heuristic' && !ins.warning ? `<div class="warn" style="margin-top:10px">Rules-based analyst active. Set <code>OPENAI_API_KEY</code>, <code>ANTHROPIC_API_KEY</code> or <code>GEMINI_API_KEY</code> in <code>.env</code> to enable LLM-generated insights.</div>` : ''}
      <blockquote>${esc(ins.executiveSummary)}</blockquote>
      ${ins.attackNarrative ? `<h3>Likely attack path</h3><p>${esc(ins.attackNarrative)}</p>` : ''}
      ${ins.rootCauses?.length ? `<h3>Root causes</h3><ul>${ins.rootCauses.map(r => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
      ${ins.actionPlan?.length ? `<h3>Prioritised remediation plan</h3>${ins.actionPlan.map(a => `<div class="plan"><div class="p-head"><span class="n">${a.priority}</span>${esc(a.title)}<span class="eff">effort: ${esc(a.effort)}</span></div><p><b>Why:</b> ${esc(a.why)}</p><pre>${esc(a.how)}</pre><div class="ids">${(a.findingIds || []).map(esc).join(' · ')}</div></div>`).join('')}` : ''}
      ${ins.quickWins?.length ? `<h3>Quick wins</h3><ul>${ins.quickWins.map(q => `<li>${esc(q)}</li>`).join('')}</ul>` : ''}`;
  }

  /* ---------------- network ---------------- */
  function netSummary() {
    const n = state.network, bytes = n.reduce((a, e) => a + (e.size || 0), 0), failed = n.filter(e => e.error).length;
    const span = n.length ? Math.max(...n.map(e => e.startedAt + (e.timing.total || 0))) - state.t0 : 0;
    return `${n.length} requests · ${fmtBytes(bytes)} transferred · ${failed} failed · ${(span / 1000).toFixed(2)}s`;
  }
  function renderTypeChips() {
    const types = [...new Set(state.network.map(e => e.type))];
    $('#type-chips').innerHTML = types.map(t => `<button data-t="${esc(t)}" class="${state.typeOn.has(t) ? 'on' : ''}" style="${state.typeOn.has(t) ? 'background:var(--accent2)' : ''}">${esc(t)}</button>`).join('');
    $('#type-chips').querySelectorAll('button').forEach(b => b.onclick = () => { const t = b.dataset.t; state.typeOn.has(t) ? state.typeOn.delete(t) : state.typeOn.add(t); renderTypeChips(); renderNetwork(); });
  }
  function netRowHtml(e) {
    const span = Math.max(1, Math.max(...state.network.map(x => x.startedAt + (x.timing.total || 0))) - state.t0);
    const left = ((e.startedAt - state.t0) / span * 100).toFixed(1), width = Math.max(0.8, (e.timing.total || 0) / span * 100).toFixed(1);
    const st = e.error ? 'err' : Math.floor((e.status || 0) / 100);
    let name; try { const u = new URL(e.url); name = (u.pathname.split('/').filter(Boolean).pop() || u.host) + u.search; } catch { name = e.url; }
    return `<tr data-id="${e.id}" class="${state.selected === e.id ? 'sel' : ''}"><td>${e.id}</td><td>${esc(e.method)}</td><td class="st-${st}">${e.error ? '(failed)' : e.status}</td><td>${esc(e.type)}</td><td>${fmtBytes(e.size || 0)}</td><td>${e.timing.total ?? '–'} ms</td><td class="name" title="${esc(e.url)}">${esc(name)}</td><td class="wf"><div style="margin-left:${left}%;width:${width}%"></div></td></tr>`;
  }
  function appendNetRow(e) { if (!state.nFilter && state.typeOn.has(e.type)) $('#net-body').insertAdjacentHTML('beforeend', netRowHtml(e)); }
  function renderNetwork() {
    const q = state.nFilter.toLowerCase();
    $('#net-body').innerHTML = state.network.filter(e => state.typeOn.has(e.type) && (!q || e.url.toLowerCase().includes(q))).map(netRowHtml).join('');
    $('#net-summary').textContent = netSummary();
  }
  $('#net-body').onclick = e => { const tr = e.target.closest('tr'); if (!tr) return; state.selected = Number(tr.dataset.id); renderNetwork(); showDetail(state.network.find(x => x.id === state.selected)); };
  $('#n-filter').oninput = e => { state.nFilter = e.target.value; renderNetwork(); };
  function showDetail(e) {
    if (!e) return;
    const kv = o => Object.entries(o || {}).map(([k, v]) => `<div class="kv"><b>${esc(k)}:</b> ${esc(Array.isArray(v) ? v.join('\n') : v)}</div>`).join('') || '<div class="muted">—</div>';
    $('#net-detail').innerHTML = `<button class="ghost close" id="nd-close">✕</button>
      <h4>General</h4><div class="kv"><b>URL:</b> ${esc(e.url)}</div><div class="kv"><b>Method:</b> ${esc(e.method)}</div><div class="kv"><b>Status:</b> ${e.error ? esc(e.error) : `${e.status} ${esc(e.statusText)}`}</div><div class="kv"><b>Type:</b> ${esc(e.type)} · ${esc(e.mimeType || '')}</div><div class="kv"><b>Initiator:</b> ${esc(e.initiator)}</div>${e.redirectedFrom ? `<div class="kv"><b>Redirected from:</b> ${esc(e.redirectedFrom)}</div>` : ''}
      <h4>Timing</h4><div class="kv"><b>TTFB:</b> ${e.timing.ttfb ?? '–'} ms · <b>Total:</b> ${e.timing.total ?? '–'} ms · <b>Size:</b> ${fmtBytes(e.size || 0)}</div>
      <h4>Response headers</h4>${kv(e.response?.headers)}
      <h4>Request headers</h4>${kv(e.request?.headers)}`;
    $('#net-detail').classList.remove('hidden'); $('.net-wrap').classList.add('split');
    $('#nd-close').onclick = () => { $('#net-detail').classList.add('hidden'); $('.net-wrap').classList.remove('split'); state.selected = null; renderNetwork(); };
  }

  /* ---------------- cookies / inventory ---------------- */
  function renderCookies(scan) {
    const flag = v => v ? '<span class="ok">✓</span>' : '<span class="bad">✗</span>';
    const c = scan.crawl.cookies;
    let html = `<div class="tbl"><h3>Cookies (${c.length})</h3>` + (c.length ? `<table><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Domain</th><th>Path</th><th>Expires</th><th>Set by</th></tr>${c.map(k => `<tr><td class="mono">${esc(k.name)}</td><td>${flag(k.secure)}</td><td>${flag(k.httpOnly)}</td><td>${k.sameSite ? esc(k.sameSite) : '<span class="bad">✗</span>'}</td><td class="mono">${esc(k.domain || '(host-only)')}</td><td class="mono">${esc(k.path)}</td><td class="mono">${esc(k.expires || (k.maxAge != null ? `max-age ${k.maxAge}` : 'session'))}</td><td class="mono">${esc(k.setBy)}</td></tr>`).join('')}</table>` : '<div class="muted">No cookies set during crawl.</div>');
    const st = scan.crawl.storage;
    html += `<h3>Web Storage</h3>` + (st ? ['localStorage', 'sessionStorage'].map(a => `<b>${a}</b>` + (Object.keys(st[a] || {}).length ? `<table>${Object.entries(st[a]).map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td class="mono">${esc(v.slice(0, 120))}</td></tr>`).join('')}</table>` : '<div class="muted">empty</div>')).join('') : '<div class="muted">Runtime storage inspection requires the browser (Playwright) engine.</div>');
    html += '</div>';
    $('#cookies').innerHTML = html;
  }
  function renderInventory(scan) {
    const cr = scan.crawl;
    $('#inventory').innerHTML = `<div class="tbl">
      <h3>Pages (${cr.pages.length})</h3><table><tr><th>Status</th><th>URL</th><th>Title</th><th>Scripts</th><th>Redirects</th></tr>${cr.pages.map(p => `<tr><td>${p.status}</td><td class="mono">${esc(p.finalUrl)}</td><td>${esc(p.title || '')}</td><td>${p.scripts.length}</td><td>${p.redirectChain.length}</td></tr>`).join('')}</table>
      <h3>Forms (${cr.forms.length})</h3>${cr.forms.length ? `<table><tr><th>Page</th><th>Method</th><th>Action</th><th>Inputs</th><th>CSRF token</th><th>Password</th></tr>${cr.forms.map(f => `<tr><td class="mono">${esc(f.page)}</td><td>${f.method}</td><td class="mono">${esc(f.action)}</td><td class="mono">${esc(f.inputs.map(i => i.name || i.type).join(', '))}</td><td>${f.hasCsrfToken ? '<span class="ok">✓</span>' : '<span class="bad">✗</span>'}</td><td>${f.hasPassword ? 'yes' : ''}</td></tr>`).join('')}</table>` : '<div class="muted">none</div>'}
      <h3>Third-party origins (${cr.externalOrigins.length})</h3>${cr.externalOrigins.length ? `<div class="mono">${cr.externalOrigins.map(esc).join('<br>')}</div>` : '<div class="muted">none</div>'}
      <h3>Scripts (${cr.assets.filter(a => a.type === 'script').length})</h3><table><tr><th>URL</th><th>SRI</th><th>Found on</th></tr>${cr.assets.filter(a => a.type === 'script').map(a => `<tr><td class="mono">${esc(a.url)}</td><td>${a.integrity ? '<span class="ok">✓</span>' : a.url.startsWith(cr.origin) ? '<span class="muted">n/a</span>' : '<span class="bad">✗</span>'}</td><td class="mono">${esc(a.foundOn)}</td></tr>`).join('')}</table>
      <h3>Probes</h3><table><tr><th>Path</th><th>Status</th><th>Type</th></tr>${cr.probes.map(p => `<tr><td class="mono">${esc(p.path)}</td><td class="${p.status === 200 && p.kind === 'sensitive' ? 'bad' : ''}">${p.status}</td><td class="mono">${esc(p.contentType)}</td></tr>`).join('')}</table>
      ${cr.cors ? `<h3>CORS probe</h3><div class="mono">Origin: ${esc(cr.cors.requestedOrigin)} → Access-Control-Allow-Origin: ${esc(cr.cors.allowOrigin || '(none)')} · Allow-Credentials: ${esc(cr.cors.allowCredentials || '(none)')}</div>` : ''}
    </div>`;
  }

  /* ---------------- tabs & boot ---------------- */
  document.querySelectorAll('.tabs button').forEach(b => b.onclick = () => {
    document.querySelectorAll('.tabs button').forEach(x => x.classList.toggle('active', x === b));
    document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === `panel-${b.dataset.tab}`));
  });
  $('#refresh-history').onclick = loadHistory;
  health(); loadHistory();
  if (location.hash.length > 10) openScan(location.hash.slice(1));
})();
