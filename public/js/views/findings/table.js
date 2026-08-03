/**
 * Agent Triage table
 *
 * Column configurations per type tab, the cell renderers, and the sortable table itself. Rows
 * open the finding; the only row-level action is the "…" agent menu.
 */

import { state } from '../../state.js';
import { emit, EVENTS } from '../../events.js';
import { escapeHtml, statusBadgeHtml } from '../../lib/html.js';
import { icon } from '../../lib/icons.js';
import { severityLabel } from '../../lib/format.js';
import { SCAN_TYPE_META, SEV_ORDER_MAP, STATUS_ORDER_MAP, findingSourceTagHtml, findingDispositionTagsHtml } from '../../lib/meta.js';
import { findingLoopCellHtml } from '../../components/loop/cell.js';
import { onViewDiffClick } from '../../components/loop/actions.js';
import { openMenuUnderButton, openFindingContextMenu } from '../../components/menu.js';
import { findingsScanScoped } from './filters.js';

const FINDINGS_COLUMNS = {
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
function findingsCellHtml(f, key) {
  switch (key) {
    case 'severity':
      return `<div class="ft-sev-cell"><span class="sev-dot ${f.severity}"></span>${escapeHtml(severityLabel(f.severity))}</div>`;
    case 'type': {
      const m = SCAN_TYPE_META[f.scanType] || SCAN_TYPE_META.reasoning;
      return `<span class="scan-type-chip">${escapeHtml(m.label)}</span>`;
    }
    case 'title':
      return `<div class="ft-title">${escapeHtml(f.title)}${findingSourceTagHtml(f)}${findingDispositionTagsHtml(f)}</div>`;
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
      return statusBadgeHtml(f);
    case 'loop':
      return findingLoopCellHtml(f);
    default:
      return '';
  }
}

/**
 * Collapse repeated hits of one rule into a single row.
 *
 * A rule that fires 17 times is one decision, not 17. Ungrouped, the triage list showed three
 * genuinely distinct findings followed by seventeen consecutive copies of
 * "XSS via innerHTML Assignment" — so the first screen, which is all anyone reads, carried three
 * pieces of information instead of twenty.
 *
 * This is presentation only. Every finding still exists, is still counted, still has its own
 * detail page and its own place in the pipeline; the group is just a lid. Nothing is suppressed,
 * which is why this needs no corpus to justify — unlike the materiality scoring that comes next,
 * it cannot hide a true positive.
 *
 * A group's severity and sort position come from its worst member, so collapsing can never push
 * a rule further down the list than its most severe occurrence would have reached alone.
 *
 * @returns {Array<{key: string, lead: object, findings: object[]}>}
 */
function groupFindingsByRule(rows, sortKey, dir) {
  const byRule = new Map();
  for (const f of rows) {
    // Fall back to the title so manually-added findings, which carry no rule, still group
    // sensibly rather than every one becoming its own singleton key of `null`.
    const key = f.rule || f.title;
    const list = byRule.get(key);
    if (list) list.push(f);
    else byRule.set(key, [f]);
  }

  const groups = [...byRule.entries()].map(([key, findings]) => {
    const lead = findings.reduce(
      (worst, f) => ((SEV_ORDER_MAP[f.severity] ?? 99) < (SEV_ORDER_MAP[worst.severity] ?? 99) ? f : worst),
      findings[0],
    );
    return { key, lead, findings };
  });

  groups.sort((a, b) => {
    const va = findingsSortValue(a.lead, sortKey);
    const vb = findingsSortValue(b.lead, sortKey);
    const cmp = va < vb ? -1 : va > vb ? 1 : 0;
    return dir === 'asc' ? cmp : -cmp;
  });
  return groups;
}

export function renderFindingsTable() {
  const headEl = document.getElementById('findings-table-head');
  const bodyEl = document.getElementById('findings-table-body');
  const columns = FINDINGS_COLUMNS[state.findingsTypeFilter] || FINDINGS_COLUMNS.all;

  const scanScoped = findingsScanScoped();
  const rows = (state.findingsTypeFilter === 'all' ? scanScoped.slice() : scanScoped.filter((f) => f.scanType === state.findingsTypeFilter));
  const groups = groupFindingsByRule(rows, state.findingsSort.key, state.findingsSort.dir);

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

  /** A normal finding row — unchanged behaviour, indented when it sits inside a group. */
  const appendFindingRow = (f, inGroup, isLast = false) => {
    const tr = document.createElement('tr');
    tr.dataset.findingId = f.id;
    if (inGroup) tr.className = 'ft-grouped-row' + (isLast ? ' last' : '');
    // Inside a group every member shares the rule, so the title column repeats the group
    // header 36 times and the rows become indistinguishable. What actually differs is WHERE
    // each one is, so members show their location instead — the header already said what.
    tr.innerHTML = columns.map((col) => {
      const key = inGroup && col.key === 'title' ? 'location' : col.key;
      // Disposition rides on the title cell, so a grouped member — whose title cell became a
      // location — would lose it. That is precisely where it matters most: members of one group
      // share a rule but not a fate, and one of seventeen being closed as a false positive is
      // invisible otherwise.
      const extra = inGroup && col.key === 'title' ? findingDispositionTagsHtml(f) : '';
      return `<td data-col="${key}">${findingsCellHtml(f, key)}${extra}</td>`;
    }).join('')
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
    tr.addEventListener('click', () => emit(EVENTS.DETAIL_OPEN, f.id));
    tr.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      openFindingContextMenu(e.clientX, e.clientY, f.id, f);
    });
    bodyEl.appendChild(tr);
  };

  for (const group of groups) {
    // One occurrence is not a group — render it as an ordinary row so the common case gains no
    // chrome and no extra click.
    if (group.findings.length === 1) {
      appendFindingRow(group.findings[0], false);
      continue;
    }

    const expanded = state.findingsExpandedRules.has(group.key);
    const open = group.findings.filter((f) => f.status !== 'closed').length;
    const files = new Set(group.findings.map((f) => (f.file || '').split(':')[0]).filter(Boolean));
    // A collapsed group hides every member's disposition behind one row. Rolling the two that
    // change whether the group is worth opening up to the header keeps the lid from concealing
    // them — without it, "17×" reads the same whether all 17 are live or 14 were closed.
    const dispo = group.findings.reduce((acc, f) => {
      const d = f.disposition;
      if (d && d.closedAs) acc.closed++;
      if (d && d.severityApplied) acc.resev++;
      if (d && d.collapsed) acc.folded += d.collapsed;
      return acc;
    }, { closed: 0, resev: 0, folded: 0 });

    const tr = document.createElement('tr');
    tr.className = 'ft-group-row' + (expanded ? ' expanded' : '');
    const cells = columns.map((col) => {
      if (col.key === 'severity') return `<td data-col="severity">${findingsCellHtml(group.lead, 'severity')}</td>`;
      if (col.key === 'title') {
        return `<td data-col="title"><div class="ft-title">`
          + `<span class="ft-group-caret">${expanded ? '▾' : '▸'}</span>`
          + `${escapeHtml(group.lead.title)}`
          + `<span class="ft-group-count">${group.findings.length}\u00d7</span>`
          + `</div>`
          + `<div class="hint ft-group-sub">${open} open`
          + `${dispo.closed ? ` · <span class="ft-group-dispo">${dispo.closed} closed as not real</span>` : ''}`
          + `${dispo.resev ? ` · <span class="ft-group-dispo">${dispo.resev} re-severitied</span>` : ''}`
          + `${dispo.folded ? ` · <span class="ft-group-dispo">${dispo.folded} more folded in</span>` : ''}`
          + `${files.size > 1 ? ` · ${files.size} files` : ''}`
          + `${group.lead.rule ? ` · ${escapeHtml(group.lead.rule)}` : ''}</div></td>`;
      }
      return `<td data-col="${col.key}"></td>`;
    }).join('');
    tr.innerHTML = cells + '<td class="ft-actions-col"></td>';
    // Toggling is the only action on a group row: the per-finding agent menu would be ambiguous
    // across N findings, and each member row still carries its own.
    tr.addEventListener('click', () => {
      if (expanded) state.findingsExpandedRules.delete(group.key);
      else state.findingsExpandedRules.add(group.key);
      renderFindingsTable();
    });
    bodyEl.appendChild(tr);

    if (expanded) {
      group.findings.forEach((f, i) => appendFindingRow(f, true, i === group.findings.length - 1));
    }
  }
}
