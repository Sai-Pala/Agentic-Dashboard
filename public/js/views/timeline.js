/**
 * Timeline drawer
 * ===============
 *
 * Every scan and agent run, newest first, date-grouped, filterable by kind. Not a nav
 * destination — a slide-in drawer opened by the clock button on Hybrid Scan (pre-scoped to
 * scans) or the Dashboard's quick action (unscoped). Scan rows expand in place; agent rows
 * navigate to the finding.
 */

import { state } from '../state.js';
import { getTimeline, getScan } from '../api.js';
import { escapeHtml } from '../lib/html.js';
import { icon } from '../lib/icons.js';
import { agentMeta, SCAN_TYPE_META } from '../lib/meta.js';
import { truncate, formatRelativeTime, dateGroupLabel } from '../lib/format.js';
import { renderNavBadges } from '../nav.js';
import { on, EVENTS, emit } from '../events.js';
import { renderScanFindingsBody } from './scans/index.js';

export async function loadTimeline() {
  state.timelineEntries = await getTimeline();
  state.timelineLoaded = true;
  renderTimeline();
}

/** presetKind scopes the drawer on open; the pills inside still let the user broaden it. */
function openTimelineDrawer(presetKind) {
  if (presetKind !== undefined) state.timelineFilter = presetKind;
  state.timelineDrawerOpen = true;
  document.getElementById('timeline-drawer-backdrop').hidden = false;
  document.getElementById('timeline-drawer').hidden = false;
  document.getElementById('timeline-drawer').classList.add('open');
  state.timelineUnseenDone = 0;
  renderNavBadges();
  if (!state.timelineLoaded) loadTimeline(); else renderTimeline();
}

export function closeTimelineDrawer() {
  state.timelineDrawerOpen = false;
  document.getElementById('timeline-drawer').classList.remove('open');
  document.getElementById('timeline-drawer-backdrop').hidden = true;
  document.getElementById('timeline-drawer').hidden = true;
}

function renderTimelineFilters() {
  const el = document.getElementById('timeline-filters');
  el.innerHTML = '';
  const makePill = (key, label, color) => {
    const pill = document.createElement('button');
    const isActive = state.timelineFilter === key;
    pill.className = 'filter-pill' + (isActive ? ' active' : '');
    pill.innerHTML = color ? `<span class="fp-dot" style="background:${color}"></span>${escapeHtml(label)}` : escapeHtml(label);
    pill.addEventListener('click', () => {
      state.timelineFilter = key;
      renderTimeline();
    });
    el.appendChild(pill);
  };
  makePill('all', 'All', null);
  // One pill covers every scan record: pattern-matching, reasoning and SCA all run inside a
  // single Hybrid Scan, so there is no separate SCA-kind scan record to filter to.
  makePill('scan', 'Hybrid Scan', SCAN_TYPE_META.reasoning.color);
  for (const kind of state.agentsList) makePill(kind, agentMeta(kind).label, agentMeta(kind).color);

  const subtitleEl = document.getElementById('timeline-drawer-subtitle');
  if (state.timelineFilter === 'scan') {
    subtitleEl.textContent = 'Hybrid Scan runs, newest first';
  } else if (state.timelineFilter !== 'all') {
    subtitleEl.textContent = `${agentMeta(state.timelineFilter).label} runs, newest first`;
  } else {
    subtitleEl.textContent = 'Every scan and agent run, newest first';
  }
}

function timelineStatusBadge(entry) {
  if (entry.status === 'running') return { cls: 'in_review', text: 'running' };
  if (entry.status === 'cancelled') return { cls: 'new', text: 'cancelled' };
  if (entry.status === 'error') return { cls: 'high', text: 'error' };
  if (entry.kind === 'scan') return { cls: 'remediation_ready', text: 'done' };
  const v = entry.verdict && entry.verdict.verdict;
  return { cls: v || 'new', text: v || 'done' };
}

function timelineSummary(entry) {
  if (entry.kind === 'scan') {
    if (entry.status === 'running') return entry.instruction ? `Scanning — ${truncate(entry.instruction, 100)}` : 'Scanning…';
    if (entry.status === 'cancelled') return 'Cancelled';
    if (entry.status === 'error') return entry.error ? truncate(entry.error, 140) : 'Error';
    const n = entry.findingCount || 0;
    return `${n} finding${n === 1 ? '' : 's'} created`;
  }
  if (entry.status === 'running') return entry.instruction ? `Running — ${truncate(entry.instruction, 100)}` : 'Running…';
  if (entry.status === 'cancelled') return 'Cancelled';
  if (entry.status === 'error') return 'Error';
  if (entry.verdict && entry.verdict.reasoning) return truncate(entry.verdict.reasoning, 140);
  if (entry.verdict && entry.verdict.verdict) return `Verdict: ${entry.verdict.verdict}`;
  return 'Completed — no verdict block found';
}

export function renderTimeline() {
  renderTimelineFilters();
  const listEl = document.getElementById('timeline-list');
  listEl.innerHTML = '';

  const filtered = state.timelineFilter === 'all'
    ? state.timelineEntries
    : state.timelineEntries.filter((e) => e.kind === state.timelineFilter);
  if (!filtered.length) {
    const empty = document.createElement('div');
    empty.id = 'timeline-empty';
    empty.textContent = 'No activity yet.';
    listEl.appendChild(empty);
    return;
  }

  let lastGroup = null;
  for (const entry of filtered) {
    const group = dateGroupLabel(entry.startedAt);
    if (group !== lastGroup) {
      const groupEl = document.createElement('div');
      groupEl.className = 'timeline-date';
      groupEl.textContent = group;
      listEl.appendChild(groupEl);
      lastGroup = group;
    }

    const meta = agentMeta(entry.kind);
    const badge = timelineStatusBadge(entry);
    const isScan = entry.kind === 'scan';
    const title = isScan ? entry.path : entry.findingTitle;

    const row = document.createElement('div');
    row.className = 'timeline-row' + (isScan ? ' expandable' : '');
    row.style.borderLeftColor = meta.color;
    row.innerHTML = `
      <div style="display:flex; align-items:flex-start; gap:10px; width:100%;">
        <span class="tl-icon" style="color:${meta.color};">${icon(meta.icon)}</span>
        <div class="tl-main">
          <span class="tl-kind" style="color:${meta.color};">${escapeHtml(meta.label)} Agent</span>
          <div class="tl-top">
            <span class="tl-title${isScan ? ' path-text' : ''}">${escapeHtml(title)}</span>
            <span class="badge ${badge.cls}">${escapeHtml(badge.text)}</span>
          </div>
          <div class="tl-summary">${escapeHtml(timelineSummary(entry))}</div>
        </div>
        <div class="tl-time">${escapeHtml(formatRelativeTime(entry.startedAt))}</div>
      </div>
    `;

    if (isScan) {
      row.addEventListener('click', async () => {
        let body = row.querySelector('.timeline-row-body');
        if (body) { body.remove(); return; }
        body = document.createElement('div');
        body.className = 'timeline-row-body';
        body.innerHTML = '<div class="hint">Loading…</div>';
        row.appendChild(body);
        if (!entry.scanId) { body.innerHTML = '<div class="hint">No findings to show yet.</div>'; return; }
        let detail = state.scanDetailCache.get(entry.scanId);
        if (!detail) {
          detail = await getScan(entry.scanId);
          state.scanDetailCache.set(entry.scanId, detail);
        }
        renderScanFindingsBody(body, detail.findings, entry.scanId, detail);
      });
    } else {
      row.addEventListener('click', () => emit(EVENTS.DETAIL_OPEN, entry.findingId));
    }
    listEl.appendChild(row);
  }
}

export function upsertTimelineEntry(entry) {
  const entries = state.timelineEntries;
  const idx = entries.findIndex((e) => e.runId === entry.runId);
  const priorStatus = idx >= 0 ? entries[idx].status : null;
  if (idx >= 0) entries[idx] = { ...entries[idx], ...entry };
  else entries.unshift(entry);

  const newStatus = idx >= 0 ? entries[idx].status : entries[0].status;
  if (priorStatus === 'running' && newStatus !== 'running' && !state.timelineDrawerOpen) {
    state.timelineUnseenDone++;
  }

  if (state.timelineDrawerOpen) renderTimeline();
  renderNavBadges();
}

/**
 * The dot on each page's clock button: yellow while that page's own scope has a run in flight
 * (read from scansList, so it works before the drawer has ever been loaded), green if something
 * finished anywhere since the drawer was last opened.
 */
export function updateTimelineClockDots() {
  const setDot = (id, running) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (running) { el.hidden = false; el.className = 'clock-btn-dot running'; }
    else if (state.timelineUnseenDone > 0) { el.hidden = false; el.className = 'clock-btn-dot completed'; }
    else { el.hidden = true; }
  };
  setDot('scans-clock-dot', state.scansList.some((s) => s.status === 'running'));
}

export function wireTimeline() {
  on(EVENTS.TIMELINE_UPSERT, upsertTimelineEntry);

  document.getElementById('timeline-refresh').addEventListener('click', loadTimeline);
  document.getElementById('timeline-drawer-close').addEventListener('click', closeTimelineDrawer);
  document.getElementById('timeline-drawer-backdrop').addEventListener('click', closeTimelineDrawer);
  document.getElementById('scans-clock-btn').addEventListener('click', () => openTimelineDrawer('scan'));
  document.getElementById('dash-timeline-link').addEventListener('click', () => openTimelineDrawer('all'));
}
