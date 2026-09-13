import { $, escapeHtml, toast } from '../utils.js';

export function setupTLSAndRecon() {
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
