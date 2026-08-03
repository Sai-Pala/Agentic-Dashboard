/**
 * Nav mechanics: which view is showing, and the sidebar.
 *
 * This module knows how to switch views and refresh the nav badges. It deliberately does NOT
 * know what any view is — it imports nothing but `state`.
 *
 * Why the registry: a view needs to navigate (`showView`) and to refresh the badges after it
 * changes data, and the router needs to render a view when navigation lands on it. Wiring both
 * directions with imports makes router and every view mutually dependent, which is what put 16
 * of 31 client modules into a single cluster where none could be read, tested or moved alone.
 *
 * Inverting one direction fixes it: views call *into* this module, and whatever owns the view
 * list registers *with* it. The dependency now points one way, so this file stays a leaf and the
 * views stop depending on each other through the router.
 */

import { state } from './state.js';

const NAV_COLLAPSE_KEY = 'appsecops-nav-collapsed';

const VIEW_IDS = ['dashboard', 'scans', 'settings', 'findings', 'finding-detail', 'surface', 'insights', 'reports'];

/** view id -> the function that loads/renders it. Populated by router.js at startup. */
const viewRenderers = new Map();

/** Extra work to run whenever the badges refresh (the timeline's clock dots). */
const badgeHooks = [];

/**
 * Register what to run when navigation lands on `id`. Views without a renderer are static
 * markup and simply become visible.
 */
export function registerView(id, render) {
  viewRenderers.set(id, render);
}

export function registerBadgeHook(fn) {
  badgeHooks.push(fn);
}

export function showView(view, opts = {}) {
  state.currentView = view;
  for (const id of VIEW_IDS) document.getElementById(`view-${id}`).hidden = view !== id;
  document.querySelectorAll('.nav-item').forEach((n) => n.classList.toggle('active', n.dataset.view === view));

  if (opts.skipInit) return;

  const render = viewRenderers.get(view);
  if (render) render();
}

function applyNavCollapsed(collapsed) {
  const navEl = document.getElementById('global-nav');
  const btn = document.getElementById('nav-collapse-btn');
  navEl.classList.toggle('collapsed', collapsed);
  // Title only: the button holds a bare <svg>, which app.css rotates 180deg when collapsed.
  // A previous version also set a <span> label here and threw on every click, which aborted
  // the handler before it could persist the state.
  btn.title = collapsed ? 'Expand sidebar' : 'Collapse sidebar';
}

/** Kept as the name every call site already uses; it only refreshes the nav badges. */
export function renderNavStatus() {
  renderNavBadges();
}

export function renderNavBadges() {
  for (const hook of badgeHooks) hook();

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
    try { localStorage.setItem(NAV_COLLAPSE_KEY, collapsed ? '1' : '0'); } catch { /* private mode: collapse is session-only */ }
  });
  try { applyNavCollapsed(localStorage.getItem(NAV_COLLAPSE_KEY) === '1'); } catch { /* private mode: start expanded */ }
}
