/**
 * Agent Triage table
 * ==================
 *
 * Column configurations per type tab, the cell renderers, and the sortable table itself. Rows
 * open the finding; the only row-level action is the "…" agent menu.
 */

import { state } from '../../state.js';
import { escapeHtml } from '../../lib/html.js';
import { icon } from '../../lib/icons.js';
import { statusLabel, severityLabel } from '../../lib/format.js';
import { SCAN_TYPE_META, SEV_ORDER_MAP, STATUS_ORDER_MAP } from '../../lib/meta.js';
import { findingLoopCellHtml } from '../../components/loop/cell.js';
import { onViewDiffClick } from '../../components/loop/actions.js';
import { openMenuUnderButton, openFindingContextMenu } from '../../components/menu.js';
import { openFindingDetail } from '../finding-detail/index.js';
import { findingsScanScoped } from './filters.js';

export const FINDINGS_COLUMNS = {
  all: [
    { key: 'severity', label: 'Severity', sortable: true },
    { key: 'type', label: 'Type' },
    { key: 'title', label: 'Title', sortable: true },
    // "Loop", not "Remediation Loop": table cells clip overflowing header text at the cell
    // boundary regardless of overflow CSS, and the longer label silently truncated once the
    // column was width-capped (see data-col="loop" in app.css).
    { key: 'loop', label: 'Loop', sortable: true },
  ],
  // A reasoning finding can be file-based (a code pattern) or endpoint-based (attack surface),
  // so one merged 'location' cell shows whichever it has.
  reasoning: [
    { key: 'severity', label: 'Severity', sortable: true },
    { key: 'title', label: 'Title', sortable: true },
    { key: 'location', label: 'Location' },
    { key: 'rule', label: 'Rule / CWE' },
    { key: 'loop', label: 'Loop', sortable: true },
  ],
  // No loop column: an SCA finding's fix is a dependency version bump, which Package/Fixed-in
  // already say, not a code edit the agents reason about.
  sca: [
    { key: 'severity', label: 'Severity', sortable: true },
    { key: 'title', label: 'Title', sortable: true },
    { key: 'package', label: 'Package' },
    { key: 'fix', label: 'Fixed in' },
    { key: 'status', label: 'Status', sortable: true },
  ],
};

export function findingsSortValue(f, key) {
  if (key === 'severity') return SEV_ORDER_MAP[f.severity] ?? 99;
  if (key === 'status' || key === 'loop') return STATUS_ORDER_MAP[f.status] ?? 99;
  if (key === 'title') return f.title.toLowerCase();
  return '';
}

/**
 * Which of Hybrid Scan's two code-analysis engines found this, read off the synthetic triage
 * verdict's `source`. Absent for manually-added and SCA findings.
 */
export function findingSourceTagHtml(f) {
  const source = f.stageRuns && f.stageRuns.triage && f.stageRuns.triage.verdict && f.stageRuns.triage.verdict.source;
  if (source === 'sast-engine-verifier') {
    return `<span class="finding-source-tag" title="Found by the deterministic pattern-matching engine">Pattern match</span>`;
  }
  if (source === 'reasoning-scan') {
    return `<span class="finding-source-tag" title="Found by the LLM reasoning pass">Reasoning</span>`;
  }
  return '';
}

export function findingsCellHtml(f, key) {
  switch (key) {
    case 'severity':
      return `<div class="ft-sev-cell"><span class="sev-dot ${f.severity}"></span>${escapeHtml(severityLabel(f.severity))}</div>`;
    case 'type': {
      const m = SCAN_TYPE_META[f.scanType] || SCAN_TYPE_META.reasoning;
      return `<span class="scan-type-chip">${escapeHtml(m.label)}</span>`;
    }
    case 'title':
      return `<div class="ft-title">${escapeHtml(f.title)}${findingSourceTagHtml(f)}</div>`;
    case 'file':
      return f.file ? `<span class="ft-mono">${escapeHtml(f.file)}</span>` : '<span class="hint">—</span>';
    case 'location':
      if (f.file) return `<span class="ft-mono">${escapeHtml(f.file)}</span>`;
      if (f.endpoint) return `<span class="ft-mono">${escapeHtml(f.endpoint)}${f.method ? ' (' + escapeHtml(f.method.toUpperCase()) + ')' : ''}</span>`;
      return '<span class="hint">—</span>';
    case 'rule':
      return f.rule ? escapeHtml(f.rule) : '<span class="hint">—</span>';
    case 'package':
      return f.packageName ? `${escapeHtml(f.packageName)}${f.packageVersion ? ` <span class="ft-mono">@${escapeHtml(f.packageVersion)}</span>` : ''}` : '<span class="hint">—</span>';
    case 'fix':
      return f.fixedVersion ? `<span class="ft-mono">${escapeHtml(f.fixedVersion)}</span>` : '<span class="hint">—</span>';
    case 'endpoint':
      return f.endpoint ? `<span class="ft-mono">${escapeHtml(f.endpoint)}</span>` : '<span class="hint">—</span>';
    case 'method':
      return f.method ? escapeHtml(f.method.toUpperCase()) : '<span class="hint">—</span>';
    case 'status':
      return `<span class="badge ${f.status}">${escapeHtml(statusLabel(f.status))}</span>`;
    case 'loop':
      return findingLoopCellHtml(f);
    default:
      return '';
  }
}

export function renderFindingsTable() {
  const headEl = document.getElementById('findings-table-head');
  const bodyEl = document.getElementById('findings-table-body');
  const columns = FINDINGS_COLUMNS[state.findingsTypeFilter] || FINDINGS_COLUMNS.all;

  const scanScoped = findingsScanScoped();
  const rows = (state.findingsTypeFilter === 'all' ? scanScoped.slice() : scanScoped.filter((f) => f.scanType === state.findingsTypeFilter));
  rows.sort((a, b) => {
    const va = findingsSortValue(a, state.findingsSort.key);
    const vb = findingsSortValue(b, state.findingsSort.key);
    const cmp = va < vb ? -1 : va > vb ? 1 : 0;
    return state.findingsSort.dir === 'asc' ? cmp : -cmp;
  });

  headEl.innerHTML = '';
  const headRow = document.createElement('tr');
  for (const col of columns) {
    const th = document.createElement('th');
    th.textContent = col.label;
    th.dataset.col = col.key;
    if (col.sortable) {
      th.classList.add('sortable');
      if (state.findingsSort.key === col.key) {
        th.classList.add('sorted');
        const arrow = document.createElement('span');
        arrow.className = 'sort-arrow';
        arrow.textContent = state.findingsSort.dir === 'asc' ? '↑' : '↓';
        th.appendChild(arrow);
      }
      th.addEventListener('click', () => {
        state.findingsSort = state.findingsSort.key === col.key
          ? { key: col.key, dir: state.findingsSort.dir === 'asc' ? 'desc' : 'asc' }
          : { key: col.key, dir: 'asc' };
        renderFindingsTable();
      });
    }
    headRow.appendChild(th);
  }
  headRow.appendChild(document.createElement('th')); // actions column, no label
  headEl.appendChild(headRow);

  bodyEl.innerHTML = '';
  if (!rows.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = columns.length + 1;
    td.className = 'ft-empty';
    td.textContent = scanScoped.length
      ? 'No findings match this type.'
      : state.findingsScanFilter !== 'all'
        ? 'No findings from this scan.'
        : 'No findings yet — click "+ Add" to create one, or start a scan from the Dashboard.';
    tr.appendChild(td);
    bodyEl.appendChild(tr);
    return;
  }

  for (const f of rows) {
    const tr = document.createElement('tr');
    tr.dataset.findingId = f.id;
    tr.innerHTML = columns.map((col) => `<td data-col="${col.key}">${findingsCellHtml(f, col.key)}</td>`).join('')
      + `<td class="ft-actions-col"><div class="ft-actions-cell">`
      + `<button class="console-toggle-btn" type="button" data-run-agent-btn title="Run agent…">${icon('more')}</button>`
      + `</div></td>`;
    tr.querySelector('[data-run-agent-btn]').addEventListener('click', (e) => openMenuUnderButton(e, f.id, f));
    const viewDiffBtn = tr.querySelector('[data-view-diff-btn]');
    if (viewDiffBtn) {
      viewDiffBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        onViewDiffClick(f.id);
      });
    }
    tr.addEventListener('click', () => openFindingDetail(f.id));
    tr.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      openFindingContextMenu(e.clientX, e.clientY, f.id, f);
    });
    bodyEl.appendChild(tr);
  }
}
