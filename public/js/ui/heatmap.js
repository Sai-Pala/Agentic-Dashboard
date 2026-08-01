/**
 * The OWASP category x severity heat map
 * ======================================
 *
 * Plain HTML/CSS built from a per-cell count — no charting library and no SVG. Shared by two
 * callers with different shapes of input: the per-finding Threat Model page reads
 * verdict.severity_confirmed, while the whole-app report reads risk.severity, so the severity
 * accessor is a callback rather than a field name.
 *
 * Moved verbatim out of the single inline <script> during the Phase 4 split.
 */

import { escapeHtml } from '../util/html.js';
import { severityLabel } from '../util/format.js';
import { SEV_ORDER_MAP } from '../data/meta.js';

// Shared by both the per-finding Threat Model page and the app-level report's diagram: rows are
// categories (OWASP, sorted by finding/risk count descending), columns are the fixed severity
// scale. Cells only carry data-category/data-sev — callers re-derive the underlying items for a
// clicked cell from their own already-grouped data rather than the DOM, since a cell represents
// a whole category+severity bucket, not a single item.
export function buildThreatHeatmap(categories, getSeverity) {
  const headerCells = HEATMAP_SEVERITY_COLS.map((sev) => `<div class="tm-heat-col-label">${severityLabel(sev)}</div>`).join('');
  const rowsHtml = categories.map(([category, list]) => {
    const counts = new Map(HEATMAP_SEVERITY_COLS.map((s) => [s, 0]));
    for (const item of list) {
      const sev = getSeverity(item);
      const key = counts.has(sev) ? sev : 'informational';
      counts.set(key, counts.get(key) + 1);
    }
    const maxCount = Math.max(1, ...HEATMAP_SEVERITY_COLS.map((s) => counts.get(s)));
    const cellsHtml = HEATMAP_SEVERITY_COLS.map((sev) => {
      const count = counts.get(sev);
      const intensity = count ? (0.28 + 0.72 * (count / maxCount)).toFixed(2) : 0;
      return `<button type="button" class="tm-heat-cell${count ? ` has-findings sev-${sev}` : ' empty'}" style="--heat-intensity:${intensity}" data-category="${escapeHtml(category)}" data-sev="${sev}"${count ? '' : ' disabled'}>${count || ''}</button>`;
    }).join('');
    const rowSev = worstOfList(list, getSeverity);
    return `
      <div class="tm-heat-row">
        <div class="tm-heat-row-label sev-${rowSev}" title="${escapeHtml(category)}">${escapeHtml(category)} <span class="tm-heat-row-count">${list.length}</span></div>
        <div class="tm-heat-row-cells">${cellsHtml}</div>
      </div>
    `;
  }).join('');

  return `
    <div class="tm-heatmap">
      <div class="tm-heat-header"><div class="tm-heat-row-label"></div><div class="tm-heat-row-cells">${headerCells}</div></div>
      ${rowsHtml}
    </div>
  `;
}

export function worstOfList(list, getSeverity) {
  let worst = null;
  for (const item of list) {
    const sev = getSeverity(item);
    if (!sev) continue;
    if (worst === null || (SEV_ORDER_MAP[sev] ?? 99) < (SEV_ORDER_MAP[worst] ?? 99)) worst = sev;
  }
  return worst || 'informational';
}
