/**
 * Hybrid Scan
 * ===========
 *
 * The kickoff form, the live cards it creates, and the WS message handling that drives them.
 * A scan runs three engines over a directory server-side and creates findings on completion —
 * the entry point of Scan -> Agent Triage -> Remediation.
 */

import { state } from '../../state.js';
import { getScans } from '../../api.js';
import { send } from '../../ws.js';
import { escapeHtml } from '../../lib/html.js';
import { uid, statusLabel } from '../../lib/format.js';
import { renderNavStatus, showView } from '../../router.js';
import { renderDashboard } from '../dashboard.js';
import { upsertTimelineEntry } from '../timeline.js';
import { loadFindings, openFindingsFilteredByScan } from '../findings/index.js';
import { openFindingDetail } from '../finding-detail/index.js';
import { makeScanCard, setStageStatus, updateScanCardActions, renderScanCardResults } from './card.js';
import {
  updateScanElapsed, stopScanElapsedTimer, updateDetBar, updateScaBar,
  updateReasoningModuleProgress, markReasoningBarDone, handleScanRawEvent,
} from './progress.js';

const SCAN_TYPE = 'reasoning';

export async function loadScans() {
  state.scansList = await getScans();
  state.scansLoaded = true;
  renderNavStatus();
  if (state.currentView === 'dashboard') renderDashboard();
}

/**
 * The findings a scan produced, for the timeline drawer's expanded row. `detail` is the full
 * scan record — the coverage line needs fields the finding list doesn't carry.
 */
export function renderScanFindingsBody(body, scanFindings, scanId, detail) {
  body.innerHTML = '';

  // The durable answer to "what did that scan actually cover": refetched from the server every
  // time the drawer opens, unlike the live card, which is gone after a reload.
  if (detail && detail.agentsRun && (detail.agentsSkipped || []).length) {
    const nSkipped = detail.agentsSkipped.length;
    const cov = document.createElement('div');
    cov.className = 'hint';
    cov.style.cssText = 'padding:6px 14px 2px;';
    cov.title = 'Not applicable here (skipped by their own relevance check):\n'
      + detail.agentsSkipped.map((n) => `• ${n}`).join('\n');
    cov.textContent = `${detail.agentsRun} of ${detail.agentsRun + nSkipped} pattern agents applied to this codebase · ${nSkipped} not applicable`;
    body.appendChild(cov);
  }

  if (!scanFindings.length) {
    const none = document.createElement('div');
    none.className = 'hint';
    none.style.cssText = 'padding:10px 14px;';
    none.textContent = 'No findings produced by this scan.';
    body.appendChild(none);
    return;
  }
  if (scanId) {
    const linkRow = document.createElement('div');
    linkRow.style.cssText = 'padding:2px 14px 8px;';
    linkRow.innerHTML = '<button class="link-btn" type="button">View all in Agent Triage →</button>';
    linkRow.querySelector('button').addEventListener('click', (e) => { e.stopPropagation(); openFindingsFilteredByScan(scanId); });
    body.appendChild(linkRow);
  }
  for (const f of scanFindings) {
    const item = document.createElement('div');
    item.className = 'finding-row';
    item.style.padding = '9px 14px';
    item.innerHTML = `
      <span class="sev-dot ${f.severity}"></span>
      <div class="finding-row-main">
        <div class="finding-row-title">${escapeHtml(f.title)}</div>
        <div class="finding-row-meta"><span class="badge ${f.status}">${escapeHtml(statusLabel(f.status))}</span></div>
      </div>
    `;
    item.addEventListener('click', () => openFindingDetail(f.id));
    body.appendChild(item);
  }
}

function beginScanRun(targetPath, instruction, scanMeta, containerEl) {
  const runId = uid();
  const cardEl = makeScanCard(runId, targetPath, scanMeta, containerEl);
  const startedAt = Date.now();
  const run = {
    runId, path: targetPath, instruction,
    status: 'running',
    cardEl,
    startTime: startedAt,
    toolCount: 0,
    fileCount: 0,
    tokenCount: 0,
    sevCounts: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    toolsEl: cardEl.querySelector('.ss-tools'),
    filesEl: cardEl.querySelector('.ss-files'),
    tokensEl: cardEl.querySelector('.ss-tokens'),
    elapsedEl: cardEl.querySelector('.ss-elapsed'),
    // The reasoning bar reuses toolCount/tokenCount: the deterministic engine's synthetic
    // events carry no tool_use/usage blocks, so those counters only ever move for reasoning.
    detDone: 0,
    detTotal: 0,
    detFillEl: cardEl.querySelector('.det-fill'),
    detStatEl: cardEl.querySelector('.det-stat'),
    reasoningFillEl: cardEl.querySelector('.reasoning-fill'),
    reasoningStatEl: cardEl.querySelector('.reasoning-stat'),
    scaFillEl: cardEl.querySelector('.sca-fill'),
    scaStatEl: cardEl.querySelector('.sca-stat'),
    reasoningModulesDone: 0,
    reasoningModulesTotal: 0,
    reasoningCostUsd: 0,
    errorEl: cardEl.querySelector('.scan-error-msg'),
    warningEl: cardEl.querySelector('.scan-warning-msg'),
    chipsEl: cardEl.querySelector('.scan-sev-chips'),
    findingsEl: cardEl.querySelector('.scan-live-findings'),
    resultsEl: cardEl.querySelector('.scan-results'),
    actionsEl: cardEl.querySelector('.scan-actions'),
    consoleText: '',
    consoleOpen: false,
    consoleEl: cardEl.querySelector('.ss-console'),
    elapsedTimer: null,
  };
  state.scanRuns.set(runId, run);
  cardEl.querySelector('[data-console-toggle]').addEventListener('click', (e) => {
    // The toggle sits inside the card header; stop the click reaching the card itself.
    e.stopPropagation();
    run.consoleOpen = !run.consoleOpen;
    e.currentTarget.classList.toggle('active', run.consoleOpen);
    run.consoleEl.hidden = !run.consoleOpen;
  });
  run.elapsedTimer = setInterval(() => updateScanElapsed(run), 1000);
  updateScanCardActions(run);
  state.scansList.unshift({ id: null, runId, path: targetPath, instruction, ...scanMeta, status: 'running', error: null, findingIds: [], startedAt, finishedAt: null });
  upsertTimelineEntry({ kind: 'scan', runId, path: targetPath, instruction, ...scanMeta, status: 'running', findingCount: 0, startedAt, finishedAt: null });
  renderNavStatus();
  if (state.currentView === 'dashboard') renderDashboard();

  send({ type: 'scan', runId, path: targetPath, instruction, ...scanMeta });
  return runId;
}

function startScan() {
  const targetPath = document.getElementById('scan-path-input').value.trim();
  if (!targetPath) {
    alert('Enter a target directory path.');
    return;
  }
  const branch = document.getElementById('scan-branch-input').value.trim();
  const app = document.getElementById('scan-app-input').value.trim();
  const baseBranch = document.getElementById('scan-base-branch-input').value.trim();
  if (state.scanScope === 'diff' && !baseBranch) {
    alert('Enter a base branch to diff against (e.g. main).');
    return;
  }

  const scanMeta = {
    branch, app, scanType: SCAN_TYPE, scope: state.scanScope,
    baseBranch: state.scanScope === 'diff' ? baseBranch : null,
    budgetEnabled: state.scanBudgetEnabled,
  };
  beginScanRun(targetPath, '', scanMeta, document.getElementById('scan-live-container'));
}

export function handleScanServerMessage(msg) {
  const run = msg.runId ? state.scanRuns.get(msg.runId) : null;
  const listItem = msg.runId ? state.scansList.find((s) => s.runId === msg.runId) : null;

  if (msg.type === 'scan-started') {
    if (run) run.scanId = msg.scanId;
    if (listItem) listItem.id = msg.scanId;
    return;
  }
  if (!run) return;

  if (msg.type === 'scan-progress') {
    if (msg.engine === 'reasoning') updateReasoningModuleProgress(run, msg.done, msg.total, msg.costUsd);
    else if (msg.engine === 'sca') updateScaBar(run, msg.done, msg.total, msg.failed);
    else updateDetBar(run, msg.done, msg.total, msg.skipped);
    return;
  }
  if (msg.type === 'scan-event') {
    handleScanRawEvent(run, msg.event);
    return;
  }
  if (msg.type === 'scan-stderr') {
    return; // CLI-internal chatter, not actionable
  }
  if (msg.type === 'scan-warning') {
    // A non-fatal note this app generated, unlike scan-stderr's raw CLI noise. Appended rather
    // than replaced so several stay visible; never touches run.status or the elapsed timer.
    if (run.warningEl) {
      run.warningEl.hidden = false;
      run.warningEl.textContent = run.warningEl.textContent
        ? `${run.warningEl.textContent}\n${msg.message}`
        : msg.message;
    }
    return;
  }
  if (msg.type === 'scan-error') {
    const cancelled = run.status === 'cancelled';
    if (!cancelled) {
      setStageStatus(run, 'error', 'Error');
      if (run.errorEl) { run.errorEl.hidden = false; run.errorEl.textContent = msg.message; }
    } else {
      setStageStatus(run, 'cancelled', 'Cancelled');
    }
    stopScanElapsedTimer(run);
    markReasoningBarDone(run);
    updateScanCardActions(run);
    const finalStatus = cancelled ? 'cancelled' : 'error';
    if (listItem) { listItem.status = finalStatus; listItem.error = cancelled ? null : msg.message; listItem.finishedAt = Date.now(); }
    upsertTimelineEntry({ runId: msg.runId, status: finalStatus, error: cancelled ? null : msg.message, finishedAt: Date.now() });
    if (state.currentView === 'dashboard') renderDashboard();
    return;
  }
  if (msg.type === 'scan-done') {
    const cancelled = run.status === 'cancelled';
    stopScanElapsedTimer(run);
    markReasoningBarDone(run);
    // Fallbacks in case a final scan-progress arrives after scan-done.
    if (run.detFillEl && run.detTotal) updateDetBar(run, run.detTotal, run.detTotal);
    if (run.scaFillEl) updateScaBar(run, 1, 1);
    const n = msg.findings.length;
    const finalStatus = cancelled ? 'cancelled' : (msg.code === 0 ? 'done' : 'error');
    setStageStatus(run, finalStatus, cancelled ? 'Cancelled' : `${n} finding${n === 1 ? '' : 's'} created`);
    if (run.findingsEl) run.findingsEl.hidden = true;
    renderScanCardResults(run, msg.findings);
    updateScanCardActions(run);
    if (listItem) { listItem.status = finalStatus; listItem.findingIds = msg.findings.map((f) => f.id); listItem.finishedAt = Date.now(); }
    upsertTimelineEntry({ runId: msg.runId, scanId: msg.scanId, status: finalStatus, findingCount: n, finishedAt: Date.now() });
    loadFindings();
    loadScans();
    return;
  }
}

export function wireScansView() {
  const baseBranchWrap = document.getElementById('scan-base-branch-wrap');
  const baseBranchInput = document.getElementById('scan-base-branch-input');
  document.querySelectorAll('#scan-scope-toggle .group-toggle-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const scope = btn.dataset.scope;
      state.scanScope = scope;
      document.querySelectorAll('#scan-scope-toggle .group-toggle-btn').forEach((b) => b.classList.toggle('active', b === btn));
      baseBranchWrap.hidden = scope !== 'diff';
      if (scope === 'diff') baseBranchInput.focus();
    });
  });

  document.querySelectorAll('#scan-budget-toggle .group-toggle-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.scanBudgetEnabled = btn.dataset.budget === 'on';
      document.querySelectorAll('#scan-budget-toggle .group-toggle-btn').forEach((b) => b.classList.toggle('active', b === btn));
      document.getElementById('scan-budget-hint').hidden = state.scanBudgetEnabled;
    });
  });

  document.getElementById('scan-start-btn').addEventListener('click', startScan);
  document.getElementById('dash-scans-link').addEventListener('click', () => showView('scans'));
}
