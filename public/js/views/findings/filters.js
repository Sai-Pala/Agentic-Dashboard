/**
 * Agent Triage filters
 *
 * The type tabs (All / Hybrid / SCA) and the per-scan filter popover.
 */

import { state } from '../../state.js';
import { escapeHtml } from '../../lib/html.js';
import { truncate, scanFilterLabel } from '../../lib/format.js';
import { FINDINGS_TYPE_LABEL } from '../../lib/meta.js';
import { renderFindingsView } from './index.js';

export function findingsScanScoped() {
  if (state.findingsScanFilter === 'all') return state.findings;
  return state.findings.filter((f) => f.sourceScanId === state.findingsScanFilter);
}

/**
 * Only scans that produced findings still on record are offered — anything else is a dead-end.
 *
 * state.findingsScanFilter is the single source of truth and flows one way (JS -> rendered
 * button text). Never read the selection back out of the DOM: doing so silently discarded a
 * filter set programmatically by a link rather than by the dropdown.
 */
export function renderFindingsScanFilter() {
  const btn = document.getElementById('findings-scan-filter-btn');
  const menuEl = document.getElementById('findings-scan-filter-menu');
  const scansWithFindings = state.scansList.filter((s) => s.id && state.findings.some((f) => f.sourceScanId === s.id));
  scansWithFindings.sort((a, b) => (b.startedAt || 0) - (a.startedAt || 0));

  if (!scansWithFindings.some((s) => s.id === state.findingsScanFilter)) state.findingsScanFilter = 'all';
  const current = state.findingsScanFilter === 'all' ? null : scansWithFindings.find((s) => s.id === state.findingsScanFilter);
  btn.textContent = current ? truncate(scanFilterLabel(current), 46) : 'All scans';
  btn.title = current ? scanFilterLabel(current) : 'All scans';

  menuEl.innerHTML = '';
  const selectScan = (scanId) => {
    state.findingsScanFilter = scanId;
    menuEl.hidden = true;
    renderFindingsView();
  };

  const allItem = document.createElement('button');
  allItem.type = 'button';
  allItem.className = 'scan-filter-item' + (state.findingsScanFilter === 'all' ? ' active' : '');
  allItem.textContent = 'All scans';
  allItem.addEventListener('click', () => selectScan('all'));
  menuEl.appendChild(allItem);

  for (const s of scansWithFindings) {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'scan-filter-item' + (state.findingsScanFilter === s.id ? ' active' : '');
    item.textContent = scanFilterLabel(s);
    item.title = scanFilterLabel(s);
    item.addEventListener('click', () => selectScan(s.id));
    menuEl.appendChild(item);
  }
}

export function renderFindingsTypeTabs(scanScoped) {
  const el = document.getElementById('findings-type-tabs');
  el.innerHTML = '';
  for (const key of ['all', 'reasoning', 'sca']) {
    const count = key === 'all' ? scanScoped.length : scanScoped.filter((f) => f.scanType === key).length;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'group-toggle-btn' + (state.findingsTypeFilter === key ? ' active' : '');
    btn.innerHTML = `${escapeHtml(FINDINGS_TYPE_LABEL[key])} <span class="gt-count">${count}</span>`;
    btn.addEventListener('click', () => {
      state.findingsTypeFilter = key;
      renderFindingsView();
    });
    el.appendChild(btn);
  }
}
