/**
 * Finding Detail
 * ==============
 *
 * A full page per finding: badges, meta grid, description, data flow, code, the four loop
 * stage boxes plus "Run all stages", the agent menu, and every run against this finding.
 */

import { state } from '../../state.js';
import { getFinding } from '../../api.js';
import { showView } from '../../nav.js';
import { on, emit, EVENTS } from '../../events.js';
import { escapeHtml } from '../../lib/html.js';
import { icon } from '../../lib/icons.js';
import { highlightCode } from '../../lib/highlight.js';
import { truncate, statusLabel, severityLabel } from '../../lib/format.js';
import { SCAN_TYPE_META, findingSourceTagHtml } from '../../lib/meta.js';
import { wireConsoleToggles, reattachConsoleRefs } from '../../components/console.js';
import { findingStageRuns } from '../../components/loop/state.js';
import { fdLoopBoxesHtml } from '../../components/loop/boxes.js';
import { onLoopAdvanceClick, onLoopRunAllClick } from '../../components/loop/actions.js';
import { hasEligibleAgents, openMenuUnderButton } from '../../components/menu.js';
import { runCardHtml } from './run-card.js';

/** Reached through EVENTS.DETAIL_OPEN, subscribed in wireFindingDetail — not imported directly. */
async function openFindingDetail(findingId) {
  state.currentFindingDetailId = findingId;
  showView('finding-detail');
  const bodyEl = document.getElementById('fd-body');
  bodyEl.innerHTML = '<div class="hint" style="padding:30px 4px;">Loading…</div>';
  const finding = await getFinding(findingId);
  if (!finding) {
    bodyEl.innerHTML = '<div class="hint" style="padding:30px 4px;">Finding not found.</div>';
    return;
  }
  state.findingCache.set(findingId, finding);
  renderFindingDetail(findingId);
}

/**
 * A cross-line taint finding renders the path the value takes, not just a line number: "SQL
 * injection at line 20" is unactionable without the lines that read and concatenated the input.
 * Captured once at finding-creation time, so it is a snapshot rather than a live read.
 */
function findingFlowHtml(finding) {
  const flow = finding.flow;
  if (!flow || !Array.isArray(flow.lines) || !flow.lines.length) return '';

  const rows = flow.lines.map((l) => {
    const isSource = l.n === flow.sourceLine;
    const isSink = l.n === flow.sinkLine;
    const cls = isSource ? 'flow-line source' : isSink ? 'flow-line sink' : 'flow-line';
    const marker = isSource ? '▸' : isSink ? '▸' : ' ';
    const label = isSource ? '<span class="flow-tag source">user input enters</span>'
      : isSink ? '<span class="flow-tag sink">reaches the sink</span>'
      : '';
    return `<div class="${cls}">`
      + `<span class="flow-marker">${marker}</span>`
      + `<span class="flow-num">${l.n}</span>`
      + `<span class="flow-code">${highlightCode(l.text)}</span>`
      + label
      + '</div>';
  }).join('');

  const span = flow.sinkLine - flow.sourceLine;
  return `
    <div class="fd-section">
      <div class="fd-section-title">Data flow</div>
      <div class="flow-summary">Untrusted input enters at line ${flow.sourceLine} and reaches a dangerous operation ${span} line${span === 1 ? '' : 's'} later, with nothing validating it in between.</div>
      <div class="flow-block">${rows}</div>
    </div>
  `;
}

/** Reached through EVENTS.DETAIL_REFRESH, subscribed in wireFindingDetail. */
function renderFindingDetail(findingId) {
  const finding = state.findingCache.get(findingId);
  if (!finding || state.currentFindingDetailId !== findingId) return;

  document.getElementById('fd-title').textContent = finding.title;
  document.getElementById('fd-subtitle').textContent =
    `${finding.runs.length} agent run${finding.runs.length === 1 ? '' : 's'} · created ${new Date(finding.createdAt).toLocaleString()}`;

  const typeMeta = SCAN_TYPE_META[finding.scanType] || SCAN_TYPE_META.reasoning;

  const badgesHtml = `
    <div class="fd-badges">
      <span class="badge ${finding.severity}">${escapeHtml(severityLabel(finding.severity))}</span>
      <span class="badge ${finding.status}">${escapeHtml(statusLabel(finding.status))}</span>
      <span class="scan-type-chip">${escapeHtml(typeMeta.label)}</span>
      ${findingSourceTagHtml({ stageRuns: findingStageRuns(finding) })}
    </div>
  `;

  const sourceScan = finding.sourceScanId ? state.scansList.find((s) => s.id === finding.sourceScanId) : null;
  const scanSourceHtml = sourceScan ? `
    <div class="fd-scan-source">
      Found by scan of <span class="mono">${escapeHtml(truncate(sourceScan.path, 60))}</span>
      <button class="link-btn" type="button" data-action="view-source-scan">View all findings from this scan →</button>
    </div>
  ` : '';

  const metaItems = [];
  if (finding.scanType === 'sca') {
    if (finding.packageName) metaItems.push(['Package', finding.packageName + (finding.packageVersion ? '@' + finding.packageVersion : ''), true]);
    if (finding.fixedVersion) metaItems.push(['Fixed in', finding.fixedVersion, true]);
  }
  if (finding.endpoint) metaItems.push(['Endpoint', finding.endpoint, true]);
  if (finding.method) metaItems.push(['Method', finding.method.toUpperCase(), true]);
  if (finding.file) metaItems.push(['File', finding.file, true]);
  if (finding.rule) metaItems.push(['Rule / CWE', finding.rule, false]);

  const metaHtml = metaItems.length ? `
    <div class="fd-meta-grid">
      ${metaItems.map(([label, value, mono]) => `
        <div class="fd-meta-item">
          <div class="fd-meta-label">${escapeHtml(label)}</div>
          <div class="fd-meta-value${mono ? ' mono' : ''}">${escapeHtml(value)}</div>
        </div>
      `).join('')}
    </div>
  ` : '';

  const descriptionHtml = `
    <div class="fd-section">
      <div class="fd-section-title">Description</div>
      <div class="fd-prose">${escapeHtml(finding.description)}</div>
    </div>
  `;

  const codeHtml = finding.code ? `
    <div class="fd-section">
      <div class="fd-section-title">Code</div>
      <div class="fd-code-wrap">
        <button class="secondary fd-copy-btn" type="button" data-action="copy-code">Copy</button>
        <pre class="code-block"><code>${highlightCode(finding.code)}</code></pre>
      </div>
    </div>
  ` : '';

  const runsHtml = `
    <div class="fd-section">
      <div class="fd-section-title">Agent runs</div>
      ${finding.runs.length
        ? finding.runs.slice().reverse().map(runCardHtml).join('')
        : '<div class="fd-runs-empty">No agent runs yet — use the buttons above to start one.</div>'}
    </div>
  `;

  const bodyEl = document.getElementById('fd-body');
  bodyEl.innerHTML = badgesHtml + scanSourceHtml + metaHtml + descriptionHtml
    + findingFlowHtml(finding) + codeHtml + runsHtml;

  const copyBtn = bodyEl.querySelector('[data-action="copy-code"]');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(finding.code).then(() => {
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
      });
    });
  }

  const viewSourceScanBtn = bodyEl.querySelector('[data-action="view-source-scan"]');
  if (viewSourceScanBtn) {
    viewSourceScanBtn.addEventListener('click', () => emit(EVENTS.FINDINGS_FILTER_BY_SCAN, finding.sourceScanId));
  }

  wireConsoleToggles(bodyEl, state.stageConsoles, () => renderFindingDetail(findingId));
  reattachConsoleRefs(bodyEl, state.stageConsoles, 'stage-console');

  renderFindingDetailActions(finding);
}

function renderFindingDetailActions(finding) {
  const actionsEl = document.getElementById('fd-header-actions');
  const hasMenuAgents = hasEligibleAgents();
  const menuBtnHtml = `<button class="console-toggle-btn" type="button" id="fd-agent-menu-btn"${hasMenuAgents ? '' : ' disabled'} title="${hasMenuAgents ? 'Run agent…' : 'No agent actions apply to this finding'}">${icon('more')}</button>`;
  actionsEl.innerHTML = fdLoopBoxesHtml(finding) + menuBtnHtml;

  document.getElementById('fd-agent-menu-btn').addEventListener('click', (e) => openMenuUnderButton(e, finding.id, finding));
  actionsEl.querySelectorAll('[data-fd-loop-box]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      // Guard against a double-click firing two real runs; the next render replaces this node.
      e.currentTarget.disabled = true;
      onLoopAdvanceClick(finding.id);
    });
  });
  const runAllBtn = actionsEl.querySelector('[data-fd-runall]');
  if (runAllBtn) {
    runAllBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      e.currentTarget.disabled = true;
      onLoopRunAllClick(finding.id);
    });
  }
}

/**
 * True when this page is currently showing that finding.
 *
 * Lived in components/runs.js, where every caller had to remember to guard with it before
 * asking for a re-render. It is a fact about this view, so this view now owns it and the
 * refresh subscriber below applies it once — callers just announce that a finding changed.
 */
function isShowing(findingId) {
  return state.currentView === 'finding-detail' && state.currentFindingDetailId === findingId;
}

export function wireFindingDetail() {
  document.getElementById('fd-back-btn').addEventListener('click', () => showView('findings'));

  on(EVENTS.DETAIL_OPEN, openFindingDetail);
  on(EVENTS.DETAIL_REFRESH, (findingId) => {
    if (isShowing(findingId)) renderFindingDetail(findingId);
  });
}
