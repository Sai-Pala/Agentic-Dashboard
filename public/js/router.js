/**
 * View switching and the sidebar
 * ==============================
 *
 * showView() toggles which #view-* block is visible and kicks that view's own load/render.
 * Also owns the collapse toggle and the nav badges (running-scan dot, open-findings count).
 */

import { state } from './state.js';
import { renderDashboard } from './views/dashboard.js';
import { renderFindingsView } from './views/findings/index.js';
import { openSurfaceView } from './views/surface.js';
import { renderSettings } from './views/settings.js';
import { updateTimelineClockDots } from './views/timeline.js';

const NAV_COLLAPSE_KEY = 'appsecops-nav-collapsed';

const VIEW_IDS = ['dashboard', 'scans', 'settings', 'findings', 'finding-detail', 'surface', 'reports'];

export function showView(view, opts = {}) {
  state.currentView = view;
  for (const id of VIEW_IDS) document.getElementById(`view-${id}`).hidden = view !== id;
  document.querySelectorAll('.nav-item').forEach((n) => n.classList.toggle('active', n.dataset.view === view));

  if (opts.skipInit) return;

  if (view === 'dashboard') renderDashboard();
  if (view === 'findings') renderFindingsView();
  if (view === 'surface') openSurfaceView();
  if (view === 'settings') renderSettings();
}

export function applyNavCollapsed(collapsed) {
  const navEl = document.getElementById('global-nav');
  const btn = document.getElementById('nav-collapse-btn');
  navEl.classList.toggle('collapsed', collapsed);
  btn.title = collapsed ? 'Expand sidebar' : 'Collapse sidebar';
  btn.querySelector('span').textContent = collapsed ? 'Expand' : 'Collapse';
}

/** Kept as the name every call site already uses; it only refreshes the nav badges. */
export function renderNavStatus() {
  renderNavBadges();
}

export function renderNavBadges() {
  updateTimelineClockDots();

  const findingsBadge = document.getElementById('nav-badge-findings');
  const openCount = state.findings.filter((f) => f.status !== 'closed').length;
  if (openCount > 0) {
    findingsBadge.hidden = false;
    findingsBadge.textContent = String(openCount);
    findingsBadge.title = `${openCount} open finding${openCount === 1 ? '' : 's'}`;
  } else {
    findingsBadge.hidden = true;
  }

  const scansBadge = document.getElementById('nav-badge-scans');
  const runningScanCount = state.scansList.filter((s) => s.status === 'running').length;
  if (runningScanCount > 0) {
    scansBadge.hidden = false;
    scansBadge.className = 'nav-badge running';
    scansBadge.title = `${runningScanCount} scan${runningScanCount === 1 ? '' : 's'} running`;
  } else {
    scansBadge.hidden = true;
  }
}

export function initNav() {
  document.querySelectorAll('.nav-item[data-view]').forEach((btn) => {
    btn.addEventListener('click', () => showView(btn.dataset.view));
    btn.title = btn.querySelector('span').textContent;
  });

  const navEl = document.getElementById('global-nav');
  document.getElementById('nav-collapse-btn').addEventListener('click', () => {
    const collapsed = !navEl.classList.contains('collapsed');
    applyNavCollapsed(collapsed);
    try { localStorage.setItem(NAV_COLLAPSE_KEY, collapsed ? '1' : '0'); } catch (e) {}
  });
  try { applyNavCollapsed(localStorage.getItem(NAV_COLLAPSE_KEY) === '1'); } catch (e) {}
}
