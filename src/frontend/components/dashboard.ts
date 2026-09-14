import { $, escapeHtml } from '../utils.js';
import { state } from '../state.js';

export function renderDashboard() {
  const scansCount = state.scansHistory?.length || 0;
  const upMonitors = state.monitors?.filter(m => m.status === 'up').length || 0;
  const totalScansEl = $('dash-total-scans');
  if (totalScansEl) totalScansEl.textContent = String(scansCount);
  const upMonitorsEl = $('dash-monitors-up');
  if (upMonitorsEl) upMonitorsEl.textContent = String(upMonitors);

  const scan = (state as any).currentScan;
  if (!scan) {
    $('dash-critical').textContent = '0';
    $('dash-high').textContent = '0';
    $('dash-medium').textContent = '0';
    const sevBars = $('sev-bars');
    if (sevBars) sevBars.innerHTML = '<div class="empty">Run or select a scan to view severity analytics</div>';
    const catList = $('cat-list');
    if (catList) catList.innerHTML = '<li class="empty">No categories yet</li>';
    return;
  }

  const counts = (scan as any).score?.counts||{};
  $('dash-critical').textContent = String(counts.critical||0);
  $('dash-high').textContent = String(counts.high||0);
  $('dash-medium').textContent = String(counts.medium||0);
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
