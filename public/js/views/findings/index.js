/**
 * Agent Triage
 *
 * Loads the findings list and renders the subtitle, type tabs and table. Also the entry point
 * other views use to jump here scoped to one scan's findings.
 */

import { state } from '../../state.js';
import { getFindings, FINDINGS_CSV_URL } from '../../api.js';
import { renderNavStatus, showView } from '../../nav.js';
import { on, emit, EVENTS } from '../../events.js';
import { renderDashboard } from '../dashboard.js';
import { renderFindingsScanFilter, renderFindingsTypeTabs, findingsScanScoped } from './filters.js';
import { renderFindingsTable } from './table.js';

export async function loadFindings() {
  state.findings = await getFindings();
  renderFindingsView();
  renderNavStatus();
  if (state.currentView === 'dashboard') renderDashboard();
}

export function renderFindingsView() {
  renderFindingsScanFilter();
  const scanScoped = findingsScanScoped();
  document.getElementById('findings-subtitle').textContent =
    `${scanScoped.length} finding${scanScoped.length === 1 ? '' : 's'}`
    + (state.findingsScanFilter !== 'all' ? ` · filtered to 1 scan` : '');
  renderFindingsTypeTabs(scanScoped);
  renderFindingsTable();
}

/** Reached through EVENTS.FINDING_UPDATED, subscribed in wireFindingsView. */
function updateFindingListItem(findingId, patch) {
  const item = state.findings.find((f) => f.id === findingId);
  if (item) Object.assign(item, patch);
  if (state.currentView === 'findings') renderFindingsTable();
  emit(EVENTS.DETAIL_REFRESH, findingId);
  if (state.currentView === 'dashboard') renderDashboard();
}

export function openFindingsFilteredByScan(scanId) {
  state.findingsScanFilter = scanId;
  showView('findings');
}

export function wireFindingsView() {
  on(EVENTS.FINDINGS_RELOAD, loadFindings);
  on(EVENTS.FINDINGS_FILTER_BY_SCAN, openFindingsFilteredByScan);
  on(EVENTS.FINDING_UPDATED, updateFindingListItem);

  const menuEl = document.getElementById('findings-scan-filter-menu');
  document.getElementById('findings-scan-filter-btn').addEventListener('click', (e) => {
    e.stopPropagation();
    menuEl.hidden = !menuEl.hidden;
  });
  document.addEventListener('click', (e) => {
    if (!menuEl.hidden && !e.target.closest('.scan-filter-dropdown')) menuEl.hidden = true;
  });
  document.getElementById('export-csv-btn').addEventListener('click', () => {
    window.open(FINDINGS_CSV_URL, '_blank');
  });
}
