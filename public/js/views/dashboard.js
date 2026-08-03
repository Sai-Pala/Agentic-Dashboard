/**
 * Dashboard
 *
 * A pure status screen: the briefing line, six stat tiles, and a display list of the
 * per-finding agents. Nothing here starts a run.
 */

import { state } from '../state.js';
import { on, EVENTS } from '../events.js';
import { escapeHtml } from '../lib/html.js';
import { icon } from '../lib/icons.js';
import { agentMeta } from '../lib/meta.js';
import { truncate, formatRelativeTime, dateGroupLabel } from '../lib/format.js';

function renderDashboardHeader() {
  document.getElementById('dash-greeting').textContent = 'Dashboard';
  document.getElementById('dash-date').textContent = new Date().toLocaleDateString(undefined, {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
  });
}

function statTile(iconName, value, label, sub, accent) {
  const div = document.createElement('div');
  div.className = 'stat-tile' + (accent ? ' accent-' + accent : '');
  div.innerHTML = `
    <div class="stat-icon">${icon(iconName, 'icon-lg')}</div>
    <div class="stat-value">${escapeHtml(String(value))}</div>
    <div class="stat-label">${escapeHtml(label)}</div>
    ${sub ? `<div class="stat-sub">${escapeHtml(sub)}</div>` : ''}
  `;
  return div;
}

function computeBriefing() {
  const runningScans = state.scansList.filter((s) => s.status === 'running');
  const running = state.findings.filter((f) => f.latestRun && f.latestRun.status === 'running');
  const notTriaged = state.findings.filter((f) => f.status === 'new').length;
  const parts = [];
  if (runningScans.length) {
    parts.push(`Scanning "${truncate(runningScans[0].path, 45)}"${runningScans.length > 1 ? ` (+${runningScans.length - 1} more running)` : ''}`);
  } else if (running.length) {
    const r = running[0];
    parts.push(`${agentMeta(r.latestRun.agent).label} is working on "${truncate(r.title, 50)}"${running.length > 1 ? ` (+${running.length - 1} more running)` : ''}`);
  } else {
    parts.push('No agents currently running');
  }
  parts.push(`${notTriaged} finding${notTriaged === 1 ? '' : 's'} awaiting remediation`);
  parts.push(`${state.agentsList.length} agent${state.agentsList.length === 1 ? '' : 's'} available`);
  return parts.join('. ') + '.';
}

export function renderDashboard() {
  renderDashboardHeader();

  document.getElementById('dash-briefing-text').textContent = computeBriefing();

  const statsEl = document.getElementById('dash-stats');
  statsEl.innerHTML = '';
  const findings = state.findings;
  const inProgress = findings.filter((f) => f.latestRun && f.latestRun.status === 'running').length;
  const notTriaged = findings.filter((f) => f.status === 'new').length;
  const inReview = findings.filter((f) => f.status === 'in_review').length;
  const remediationReady = findings.filter((f) => f.status === 'remediation_ready').length;
  const closed = findings.filter((f) => f.status === 'closed').length;
  const runsToday = state.timelineEntries.filter((e) => dateGroupLabel(e.startedAt) === 'Today').length;
  const totalRuns = state.timelineEntries.length || findings.reduce((n, f) => n + f.runCount, 0);

  statsEl.appendChild(statTile('hourglass', inProgress, 'In Progress', inProgress ? 'agents running' : '', inProgress ? 'warn' : ''));
  statsEl.appendChild(statTile('inbox', notTriaged, 'Not Started', '', ''));
  statsEl.appendChild(statTile('eye', inReview, 'In Review', '', ''));
  statsEl.appendChild(statTile('checkCircle', remediationReady, 'Remediation Ready', remediationReady ? 'ready to fix' : '', remediationReady ? 'ok' : ''));
  statsEl.appendChild(statTile('folder', findings.length, 'Total Findings', `${closed} closed`, ''));
  statsEl.appendChild(statTile('trending', totalRuns, 'Agent Runs', `${runsToday} today`, 'accent'));

  const agentsEl = document.getElementById('dash-agents');
  agentsEl.innerHTML = '';
  for (const name of state.agentsList) {
    const meta = agentMeta(name);
    const lastEntry = state.timelineEntries.find((e) => e.agent === name);
    const row = document.createElement('div');
    row.className = 'agent-row';
    row.innerHTML = `
      <span class="a-icon">${icon(meta.icon)}</span>
      <div class="agent-row-main">
        <div class="agent-row-name">${escapeHtml(meta.label)}</div>
        <div class="agent-row-meta">${escapeHtml(meta.role)}</div>
      </div>
      <div class="agent-row-status">${lastEntry ? `${escapeHtml(truncate(lastEntry.findingTitle, 26))}<br>${formatRelativeTime(lastEntry.startedAt)}` : 'no runs yet'}</div>
    `;
    agentsEl.appendChild(row);
  }
}

/** The dashboard shows connection state, so it redraws when the socket flips. */
export function wireDashboard() {
  on(EVENTS.WS_STATUS, () => {
    if (state.currentView === 'dashboard') renderDashboard();
  });
}
