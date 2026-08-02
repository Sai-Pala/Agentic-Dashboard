/**
 * Settings and the theme toggle
 * =============================
 *
 * The environment panel (stating in-product that scans are not sandboxed) and the danger-zone
 * "Clear session" reset. The theme switch lives in the nav footer, not on this screen.
 */

import { state } from '../state.js';
import { postSessionClear } from '../api.js';
import { escapeHtml } from '../lib/html.js';
import { KNOWN_AGENTS } from '../lib/meta.js';
import { renderNavStatus } from '../router.js';
import { renderDashboard } from './dashboard.js';
import { renderFindingsView } from './findings/index.js';
import { renderTimeline } from './timeline.js';
import { stopScanElapsedTimer } from './scans/progress.js';

const THEME_KEY = 'appsecops-theme';

/** How many of the built-in pipeline agents' files are present, vs. agentsList's custom ones. */
function knownAgentsAvailableCount() {
  return KNOWN_AGENTS.filter((a) => state.agentsList.includes(a)).length;
}

function applyTheme(theme) {
  if (theme === 'light') document.documentElement.dataset.theme = 'light';
  else delete document.documentElement.dataset.theme;
  try { localStorage.setItem(THEME_KEY, theme); } catch (e) {}
  renderThemeToggle();
}

function renderThemeToggle() {
  const current = document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
  document.getElementById('nav-theme-label').textContent = current === 'light' ? 'Light theme' : 'Dark theme';
  const btn = document.getElementById('nav-theme-btn');
  btn.title = current === 'light' ? 'Switch to dark theme' : 'Switch to light theme';
  btn.setAttribute('aria-checked', current === 'dark' ? 'true' : 'false');
}

export function renderSettings() {
  renderThemeToggle();
  const agentCount = state.agentsList.length;
  document.getElementById('settings-env').innerHTML = `
    <div class="hint">Findings and scans are stored in-memory on the server and reset whenever it restarts — there's no database yet.</div>
    <div class="hint">Scans run <code>claude</code> against whatever directory path you give them, using this machine's own filesystem permissions — this app does not sandbox or restrict which directories can be scanned. Only point it at directories you trust reading.</div>
    <div class="hint">${agentCount} per-finding agent${agentCount === 1 ? '' : 's'} available (${knownAgentsAvailableCount()}/${KNOWN_AGENTS.length} core) · ${escapeHtml(String(state.scansList.length))} scan${state.scansList.length === 1 ? '' : 's'} run this session.</div>
  `;
}

async function clearSession() {
  if (!confirm('Clear this session? This permanently deletes every finding and scan on the server. This cannot be undone.')) return;
  const res = await postSessionClear();
  if (!res.ok) {
    alert(res.error);
    return;
  }
  // Match the now-empty server, and tear down any still-ticking elapsed timers.
  state.findings = [];
  state.findingCache.clear();
  state.scansList = [];
  state.timelineEntries = [];
  state.timelineLoaded = false;
  state.scanDetailCache.clear();
  for (const run of state.scanRuns.values()) stopScanElapsedTimer(run);
  state.scanRuns.clear();
  document.getElementById('scan-live-container').innerHTML = '';
  state.timelineUnseenDone = 0;
  renderNavStatus();
  if (state.currentView === 'dashboard') renderDashboard();
  if (state.currentView === 'findings') renderFindingsView();
  if (state.timelineDrawerOpen) renderTimeline();
}

export function wireSettings() {
  const btn = document.getElementById('nav-theme-btn');
  btn.addEventListener('click', () => {
    const current = document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
    applyTheme(current === 'light' ? 'dark' : 'light');
  });
  renderThemeToggle();
  document.getElementById('clear-session-btn').addEventListener('click', clearSession);
}
