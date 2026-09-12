import { SEVERITY_ORDER } from '../engine/checks/index.js';
import { host, fmtBytes } from './markdown.js';

const COLORS = { critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#64748b' };

/** Self-contained, print-optimised HTML report (open → Print → Save as PDF). */
export function renderHtml(scan) {
  const s = scan.score;
  const ins = scan.insights;
  const esc = e => String(e ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const grade = s.grade;
  const gradeColor = grade === 'A' ? '#16a34a' : grade === 'B' ? '#65a30d' : grade === 'C' ? '#ca8a04' : grade === 'D' ? '#ea580c' : '#dc2626';

  const findingsHtml = SEVERITY_ORDER.map(sev => {
    const group = scan.findings.filter(f => f.severity === sev);
    if (!group.length) return '';
    return `<h3 style="color:${COLORS[sev]}">${sev.toUpperCase()} <span class="muted">(${group.length})</span></h3>` + group.map(f => `
      <section class="finding" style="border-left-color:${COLORS[sev]}">
        <h4>${esc(f.title)}</h4>
        <div class="meta"><code>${esc(f.id)}</code> · ${esc(f.category)}${f.cwe ? ` · ${esc(f.cwe)}` : ''}${f.owasp ? ` · ${esc(f.owasp)}` : ''}</div>
        ${f.location ? `<div class="meta">📍 ${esc(f.location)}</div>` : ''}
        <p>${esc(f.description)}</p>
        ${f.evidence ? `<details><summary>Evidence</summary><pre>${esc(JSON.stringify(f.evidence, null, 2).slice(0, 1500))}</pre></details>` : ''}
        ${f.remediation ? `<div class="rem"><strong>Remediation</strong><pre>${esc(f.remediation)}</pre></div>` : ''}
        ${f.references?.length ? `<div class="meta">References: ${f.references.map(r => `<a href="${esc(r)}">${esc(r)}</a>`).join(' · ')}</div>` : ''}
      </section>`).join('');
  }).join('');

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Monarch Security Audit — ${esc(host(scan.target))}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root{color-scheme:light}
  body{font:14px/1.55 -apple-system,Segoe UI,Inter,Roboto,sans-serif;color:#0f172a;margin:0;background:#f8fafc}
  .wrap{max-width:960px;margin:0 auto;padding:32px 24px}
  header{display:flex;justify-content:space-between;align-items:center;gap:24px;border-bottom:2px solid #e2e8f0;padding-bottom:20px;margin-bottom:24px}
  header h1{margin:0;font-size:24px}
  .brand{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:#7c3aed;font-weight:700}
  .grade{width:88px;height:88px;border-radius:50%;display:grid;place-items:center;color:#fff;font-weight:800;font-size:40px;background:${gradeColor};flex:none}
  .kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:16px 0}
  .kv div{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:12px}
  .kv b{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#64748b}
  .sev{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
  .sev span{padding:4px 10px;border-radius:999px;color:#fff;font-weight:600;font-size:12px}
  h2{margin-top:36px;border-bottom:1px solid #e2e8f0;padding-bottom:6px}
  .finding{background:#fff;border:1px solid #e2e8f0;border-left:5px solid;border-radius:8px;padding:14px 16px;margin:12px 0;page-break-inside:avoid}
  .finding h4{margin:0 0 6px}
  .meta{font-size:12px;color:#64748b;margin-bottom:4px}
  .muted{color:#94a3b8;font-weight:400}
  pre{background:#0f172a;color:#e2e8f0;padding:10px 12px;border-radius:6px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-word}
  .rem pre{background:#f0fdf4;color:#14532d;border:1px solid #bbf7d0}
  details summary{cursor:pointer;color:#475569;font-size:13px}
  .plan{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:14px 16px;margin:10px 0}
  .plan .n{display:inline-grid;place-items:center;width:26px;height:26px;border-radius:50%;background:#7c3aed;color:#fff;font-weight:700;margin-right:8px}
  table{width:100%;border-collapse:collapse;font-size:12px;background:#fff}
  th,td{border:1px solid #e2e8f0;padding:6px 8px;text-align:left;vertical-align:top}
  th{background:#f1f5f9}
  td.url{max-width:420px;overflow-wrap:anywhere}
  blockquote{border-left:4px solid #7c3aed;background:#faf5ff;margin:0;padding:12px 16px;border-radius:0 8px 8px 0}
  footer{margin-top:40px;font-size:12px;color:#64748b;text-align:center}
  @media print{body{background:#fff}.wrap{padding:0}details{open:true}}
</style></head><body><div class="wrap">
<header><div><div class="brand">Monarch Security Engine</div><h1>Security Audit — ${esc(host(scan.target))}</h1><div class="meta">${esc(scan.target)} · ${esc(scan.finishedAt)} · scan <code>${esc(scan.id)}</code></div></div><div class="grade">${grade}</div></header>
<div class="kv"><div><b>Score</b>${s.score}/100</div><div><b>Risk level</b>${esc(ins?.riskLevel || 'n/a')}</div><div><b>Pages crawled</b>${scan.crawl.pages.length}</div><div><b>Requests</b>${scan.networkSummary.requests} · ${fmtBytes(scan.networkSummary.bytes)}</div><div><b>Engine</b>${esc(scan.crawl.engine)}</div><div><b>Duration</b>${(scan.durationMs / 1000).toFixed(1)}s</div></div>
<div class="sev">${SEVERITY_ORDER.map(sev => `<span style="background:${COLORS[sev]}">${sev} ${s.counts[sev] || 0}</span>`).join('')}</div>
${ins ? `<h2>Executive summary</h2><blockquote>${esc(ins.executiveSummary)}<div class="meta" style="margin-top:8px">Generated by ${esc(ins.provider)}${ins.model ? ` · ${esc(ins.model)}` : ''}</div></blockquote>
${ins.attackNarrative ? `<h3>Likely attack path</h3><p>${esc(ins.attackNarrative)}</p>` : ''}
${ins.rootCauses?.length ? `<h3>Root causes</h3><ul>${ins.rootCauses.map(r => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
${ins.actionPlan?.length ? `<h2>Prioritised remediation plan</h2>${ins.actionPlan.map(a => `<div class="plan"><h4 style="margin:0 0 6px"><span class="n">${a.priority}</span>${esc(a.title)} <span class="muted">· effort ${esc(a.effort)}</span></h4><p style="margin:4px 0"><b>Why:</b> ${esc(a.why)}</p><b>How:</b><pre>${esc(a.how)}</pre><div class="meta">Addresses: ${(a.findingIds || []).map(i => `<code>${esc(i)}</code>`).join(', ') || '—'}</div></div>`).join('')}` : ''}
${ins.quickWins?.length ? `<h3>Quick wins</h3><ul>${ins.quickWins.map(q => `<li>☐ ${esc(q)}</li>`).join('')}</ul>` : ''}` : ''}
<h2>Detailed findings (${scan.findings.length})</h2>${findingsHtml || '<p>No findings 🎉</p>'}
<h2>Cookies</h2>${scan.crawl.cookies.length ? `<table><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Domain</th><th>Set by</th></tr>${scan.crawl.cookies.map(c => `<tr><td>${esc(c.name)}</td><td>${c.secure ? '✅' : '❌'}</td><td>${c.httpOnly ? '✅' : '❌'}</td><td>${esc(c.sameSite || '❌')}</td><td>${esc(c.domain || '(host-only)')}</td><td class="url">${esc(c.setBy)}</td></tr>`).join('')}</table>` : '<p class="muted">No cookies set during crawl.</p>'}
<h2>Network inventory (${scan.network.length})</h2><table><tr><th>#</th><th>Method</th><th>Status</th><th>Type</th><th>Size</th><th>Time</th><th>URL</th></tr>${scan.network.slice(0, 300).map(e => `<tr><td>${e.id}</td><td>${esc(e.method)}</td><td>${e.error ? '✖' : e.status}</td><td>${esc(e.type)}</td><td>${fmtBytes(e.size || 0)}</td><td>${e.timing.total ?? '-'}ms</td><td class="url">${esc(e.url)}</td></tr>`).join('')}</table>
<footer>Generated by Monarch Security Engine v${esc(scan.version)} · For authorised defensive auditing only · Print this page to save as PDF</footer>
</div></body></html>`;
}
