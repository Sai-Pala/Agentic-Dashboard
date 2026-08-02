/**
 * The live scan card
 * ==================
 *
 * Card markup, status dot, footer actions and result rows. Cards are created once by
 * beginScanRun() and updated through cached refs — they are never rebuilt from scansList, so a
 * page reload loses them (the timeline drawer's scan row is the durable view of a past scan).
 */

import { state } from '../../state.js';
import { deleteScan } from '../../api.js';
import { send } from '../../ws.js';
import { escapeHtml } from '../../lib/html.js';
import { icon } from '../../lib/icons.js';
import { truncate } from '../../lib/format.js';
import { SCAN_TYPE_META } from '../../lib/meta.js';
import { stopScanElapsedTimer } from './progress.js';
import { renderNavStatus } from '../../router.js';
import { renderDashboard } from '../dashboard.js';
import { renderTimeline } from '../timeline.js';
import { openFindingsFilteredByScan } from '../findings/index.js';
import { openFindingDetail } from '../finding-detail/index.js';

export function makeScanCard(runId, targetPath, meta, containerEl) {
  const typeMeta = SCAN_TYPE_META[meta.scanType] || SCAN_TYPE_META.reasoning;
  const metaTags = [
    `<span class="scan-type-chip">${escapeHtml(typeMeta.label)}</span>`,
    `<span class="scan-type-chip scope-chip">${meta.scope === 'diff' ? `Diff vs ${escapeHtml(meta.baseBranch)}` : 'Full scan'}</span>`,
  ];
  if (meta.branch) metaTags.push(`<span class="scan-meta-text">${icon('branch')}${escapeHtml(meta.branch)}</span>`);
  if (meta.app) metaTags.push(`<span class="scan-meta-text">${escapeHtml(meta.app)}</span>`);
  if (meta.scanType === 'reasoning' && meta.budgetEnabled === false) {
    metaTags.push(`<span class="scan-meta-text" style="color:var(--warn);" title="Reasoning calls have no --max-budget-usd cap for this scan">No budget cap</span>`);
  }
  const nSkippedAgents = (meta.agentsSkipped || []).length;
  if (meta.agentsRun && nSkippedAgents) {
    const tip = `${meta.agentsRun} of ${meta.agentsRun + nSkippedAgents} pattern agents apply to this codebase.\n\n`
      + `Not applicable here (skipped by their own relevance check):\n`
      + meta.agentsSkipped.map((n) => `• ${n}`).join('\n');
    metaTags.push(`<span class="scan-meta-text" title="${escapeHtml(tip)}">${meta.agentsRun}/${meta.agentsRun + nSkippedAgents} agents</span>`);
  }

  // Three engines run in parallel and their results are merged; these bars are the only place
  // that is visible before findings land. All three share one accent — the engines are told
  // apart by their labels, since colour here is reserved for severity and status.
  const engineBarsHtml = meta.scanType === 'reasoning' ? `
    <div class="scan-engine-bars">
      <div class="scan-engine-bar">
        <span class="scan-engine-bar-label"><span class="engine-dot" style="background:var(--text-dim);"></span>Pattern match</span>
        <div class="scan-engine-bar-track"><div class="scan-engine-bar-fill det-fill" style="width:0%; background:var(--text-dim);"></div></div>
        <span class="scan-engine-bar-stat det-stat">Starting…</span>
      </div>
      <div class="scan-engine-bar">
        <span class="scan-engine-bar-label"><span class="engine-dot" style="background:var(--text-dim);"></span>Reasoning</span>
        <div class="scan-engine-bar-track"><div class="scan-engine-bar-fill reasoning-fill" style="width:0%; background:var(--text-dim);"></div></div>
        <span class="scan-engine-bar-stat reasoning-stat">Starting…</span>
      </div>
      <div class="scan-engine-bar">
        <span class="scan-engine-bar-label"><span class="engine-dot" style="background:var(--text-dim);"></span>Dependency audit</span>
        <div class="scan-engine-bar-track"><div class="scan-engine-bar-fill sca-fill" style="width:0%; background:var(--text-dim);"></div></div>
        <span class="scan-engine-bar-stat sca-stat">Starting…</span>
      </div>
    </div>
  ` : '';

  const cardEl = document.createElement('article');
  cardEl.className = 'stage-card scan-card status-running';
  cardEl.dataset.runId = runId;
  cardEl.innerHTML = `
    <div class="stage-header">
      <span class="stage-agent">${icon(typeMeta.icon)}<span class="path-text">${escapeHtml(targetPath)}</span></span>
      <button class="console-toggle-btn" type="button" style="margin-left:auto;" data-console-toggle data-run-id="${escapeHtml(runId)}" title="View model's live reasoning">${icon('terminal')}</button>
    </div>
    <div class="scan-meta-row">${metaTags.join('')}</div>
    ${engineBarsHtml}
    <div class="scan-stats">
      <span class="stat scan-status-stat"><span class="status-dot running"></span><span class="status-text">Starting…</span></span>
      <span class="stat"><b class="ss-tokens">0</b> tokens</span>
      <span class="stat"><b class="ss-tools">0</b> checks</span>
      <span class="stat"><b class="ss-files">0</b> files read</span>
      <span class="stat"><b class="ss-elapsed">0:00</b> elapsed</span>
    </div>
    <pre class="console-panel ss-console" hidden></pre>
    <div class="scan-error-msg" hidden></div>
    <div class="scan-warning-msg" hidden></div>
    <div class="scan-sev-chips"><span class="hint">No candidates yet</span></div>
    <div class="scan-live-findings"></div>
    <div class="scan-results" hidden></div>
    <div class="scan-actions"></div>
  `;
  containerEl.prepend(cardEl);
  return cardEl;
}

/** Also used for the card's own status dot/text, which is why it lives with the card. */
export function setStageStatus(stage, status, text) {
  stage.status = status;
  stage.cardEl.classList.remove('status-running', 'status-done', 'status-error');
  stage.cardEl.classList.add('status-' + (status === 'cancelled' ? 'error' : status));
  const dot = stage.cardEl.querySelector('.status-dot');
  dot.classList.remove('running', 'done', 'error', 'cancelled');
  dot.classList.add(status);
  const statusText = stage.cardEl.querySelector('.status-text');
  statusText.classList.remove('running', 'done', 'error', 'cancelled');
  statusText.classList.add(status);
  statusText.textContent = text;
}

export function updateScanCardActions(run) {
  const el = run.actionsEl;
  if (!el) return;
  el.innerHTML = '';
  if (run.status === 'running') {
    const btn = document.createElement('button');
    btn.className = 'secondary';
    btn.textContent = 'Stop scan';
    btn.addEventListener('click', () => cancelScanRun(run));
    el.appendChild(btn);
  } else {
    if (run.scanId && run.status === 'done') {
      const viewBtn = document.createElement('button');
      viewBtn.className = 'secondary';
      viewBtn.textContent = 'View in Agent Triage →';
      viewBtn.addEventListener('click', () => openFindingsFilteredByScan(run.scanId));
      el.appendChild(viewBtn);
    }
    const btn = document.createElement('button');
    btn.className = 'secondary';
    btn.textContent = 'Delete';
    btn.addEventListener('click', () => deleteScanRun(run));
    el.appendChild(btn);
  }
}

function cancelScanRun(run) {
  if (run.status !== 'running') return;
  send({ type: 'cancel', runId: run.runId });
  setStageStatus(run, 'cancelled', 'Cancelling…');
  updateScanCardActions(run);
}

async function deleteScanRun(run) {
  if (run.scanId) await deleteScan(run.scanId);
  stopScanElapsedTimer(run);
  state.scanRuns.delete(run.runId);
  run.cardEl.remove();
  state.scansList = state.scansList.filter((s) => s.runId !== run.runId);
  state.timelineEntries = state.timelineEntries.filter((e) => e.runId !== run.runId);
  renderNavStatus();
  if (state.currentView === 'dashboard') renderDashboard();
  if (state.timelineDrawerOpen) renderTimeline();
}

export function renderScanCardResults(run, scanFindings) {
  if (!run.resultsEl) return;
  if (!scanFindings.length) { run.resultsEl.hidden = true; return; }
  run.resultsEl.hidden = false;
  run.resultsEl.innerHTML = '';
  for (const f of scanFindings) {
    const item = document.createElement('div');
    item.className = 'scan-result-row';
    item.innerHTML = `
      <span class="sev-dot ${f.severity}"></span>
      <div class="scan-result-main">
        <div class="scan-result-title">${escapeHtml(f.title)}</div>
        <div class="scan-result-why">${escapeHtml(truncate(f.description || '', 160))}</div>
      </div>
    `;
    item.addEventListener('click', () => openFindingDetail(f.id));
    run.resultsEl.appendChild(item);
  }
}
