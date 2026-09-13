import { $, toast, escapeHtml } from '../utils.js';
import { state } from '../state.js';

export interface NotifItem {
  id: string;
  type: string;
  severity: 'critical' | 'warning' | 'success' | 'info';
  title: string;
  message: string;
  meta?: any;
  read: boolean;
  createdAt: string;
}

const SEVERITY_ICON: Record<string, string> = {
  critical: '🔴',
  warning: '🟠',
  success: '🟢',
  info: '🔵',
};

/**
 * Notification Center — bell dropdown in the topbar.
 * Receives `notification` WebSocket events, shows toasts + browser
 * notifications, and syncs state with the REST API.
 */
export function setupNotificationCenter() {
  const bell = $('notif-bell-btn');
  const dropdown = $('notif-dropdown');

  if (bell && dropdown) {
    bell.addEventListener('click', (e) => {
      e.stopPropagation();
      const isHidden = dropdown.classList.contains('hidden');
      if (isHidden) {
        dropdown.classList.remove('hidden');
        loadNotifications();
      } else {
        dropdown.classList.add('hidden');
      }
    });
    document.addEventListener('click', (e) => {
      if (!dropdown.classList.contains('hidden') && !dropdown.contains(e.target as Node)) {
        dropdown.classList.add('hidden');
      }
    });
  }

  $('notif-mark-all')?.addEventListener('click', async () => {
    await fetch('/api/notifications/read-all', { method: 'POST' }).catch(() => {});
    loadNotifications();
  });

  $('notif-clear')?.addEventListener('click', async () => {
    await fetch('/api/notifications', { method: 'DELETE' }).catch(() => {});
    loadNotifications();
  });

  if ('Notification' in window && Notification.permission === 'default') {
    // Defer permission prompt until first interaction to avoid nagging
    document.addEventListener('click', () => {
      Notification.requestPermission().catch(() => {});
    }, { once: true });
  }

  updateBadge();
}

export async function loadNotifications() {
  try {
    const res = await fetch('/api/notifications?limit=60');
    const data = await res.json();
    state.notifications = data.items || [];
    renderNotifications();
    updateBadge();
  } catch { /* offline — keep cache */ }
}

export function handleWsNotification(n: NotifItem) {
  state.notifications.unshift(n);
  if (state.notifications.length > 60) state.notifications.pop();
  renderNotifications();
  updateBadge();

  // Toast for immediate feedback
  toast(n.title + (n.message ? ' — ' + n.message : ''), n.severity === 'critical' ? 'error' : n.severity === 'warning' ? 'info' : 'success');

  // Native browser notification (if permitted)
  if ('Notification' in window && Notification.permission === 'granted') {
    try {
      const native = new Notification(n.title, { body: n.message || undefined, tag: n.id });
      native.onclick = () => { window.focus(); native.close(); };
    } catch { /* Safari may throw without SW; ignore */ }
  }
}

export function renderNotifications() {
  const list = $('notif-list');
  if (!list) return;
  if (!state.notifications.length) {
    list.innerHTML = '<div class="empty notif-empty">No notifications yet.<br>Create a monitor to get site status alerts.</div>';
    return;
  }
  const html = state.notifications.map(n => {
    const icon = SEVERITY_ICON[n.severity] || '🔵';
    const when = formatRelative(n.createdAt);
    const unread = n.read ? '' : ' unread';
    return `<div class="notif-item${unread}" data-id="${n.id}" title="${escapeHtml(n.message)}">
      <span class="notif-icon">${icon}</span>
      <div class="notif-body">
        <div class="notif-msg-title">${escapeHtml(n.title)}</div>
        ${n.message ? `<div class="notif-msg-detail">${escapeHtml(n.message)}</div>` : ''}
        <div class="notif-time">${when}</div>
      </div>
    </div>`;
  }).join('');
  list.innerHTML = html;

  list.querySelectorAll('.notif-item').forEach(el => {
    el.addEventListener('click', async () => {
      const id = (el as HTMLElement).dataset.id;
      if (!id) return;
      el.classList.remove('unread');
      await fetch(`/api/notifications/${id}/read`, { method: 'POST' }).catch(() => {});
      updateBadge();
      // Jump to monitor view for monitor-related notifications
      const item = state.notifications.find(n => n.id === id);
      if (item?.meta?.monitorId && (window as any).switchToView) (window as any).switchToView('monitor');
    });
  });
}

export function updateBadge() {
  const badge = $('notif-badge');
  if (!badge) return;
  const unread = state.notifications.filter(n => !n.read).length;
  badge.textContent = String(unread);
  badge.classList.toggle('hidden', unread === 0);
}

function formatRelative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return 'just now';
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return new Date(iso).toLocaleDateString();
}
