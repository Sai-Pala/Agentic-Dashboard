/**
 * Per-finding agent runs
 *
 * Starting a stage, the context string every agent is handed, and the WS lifecycle of a run
 * once it is in flight. Shared by the loop actions, the context menu and the stage modal.
 *
 * These runs deliberately have no live stats feed — only the opt-in console panel's text
 * buffer is fed while one is running; results land via `done`/`error`.
 */

import { state } from '../state.js';
import { getFinding } from '../api.js';
import { send } from '../ws.js';
import { uid } from '../lib/format.js';
import { agentMeta } from '../lib/meta.js';
import { trackConsoleText } from './console.js';
import { emit, on, EVENTS } from '../events.js';
import { findingStageRuns } from './loop/state.js';

export async function ensureFindingCached(findingId) {
  if (state.findingCache.has(findingId)) return state.findingCache.get(findingId);
  const finding = await getFinding(findingId);
  if (!finding) return null;
  state.findingCache.set(findingId, finding);
  return finding;
}

/**
 * The directory a finding's Verify/Fix run should act against — the target path of the scan
 * that produced it. null for manually-added findings, which is what disables those stages.
 */
export function findingSourcePath(finding) {
  if (!finding || !finding.sourceScanId) return null;
  const scan = state.scansList.find((s) => s.id === finding.sourceScanId);
  return scan ? scan.path : null;
}

/**
 * The context block an agent is handed: the finding's own fields plus the most recent run's
 * full verdict, so each stage sees what the previous one concluded rather than re-deriving it.
 */
export function buildBaseContext(finding) {
  const latestRun = finding.runs && finding.runs.length ? finding.runs[finding.runs.length - 1] : null;
  const parts = [
    `Title: ${finding.title}`,
    `Type: ${finding.scanType || 'reasoning'}`,
    `Severity (as reported by scanner): ${finding.severity}`,
    finding.rule ? `Rule: ${finding.rule}` : '',
    finding.file ? `File: ${finding.file}` : '',
    finding.packageName ? `Package: ${finding.packageName}${finding.packageVersion ? '@' + finding.packageVersion : ''}` : '',
    finding.fixedVersion ? `Fixed version: ${finding.fixedVersion}` : '',
    finding.endpoint ? `Endpoint: ${finding.endpoint}${finding.method ? ' (' + finding.method + ')' : ''}` : '',
    `Description:\n${finding.description}`,
    finding.code ? `Code:\n${finding.code}` : '',
    latestRun && latestRun.verdict ? `Prior ${agentMeta(latestRun.agent).label} verdict:\n${JSON.stringify(latestRun.verdict, null, 2)}` : '',
  ];
  return parts.filter(Boolean).join('\n');
}

export function startStage(findingId, agent, context, instruction) {
  const finding = state.findingCache.get(findingId);
  const runId = uid();

  state.stages.set(runId, findingId);
  state.stageConsoles.set(runId, { runId, consoleText: '', consoleOpen: false, consoleEl: null });

  const startedAt = Date.now();
  emit(EVENTS.TIMELINE_UPSERT, {
    kind: agent, runId, findingId, findingTitle: finding ? finding.title : '(finding)', agent,
    status: 'running', instruction, verdict: null, startedAt, finishedAt: null,
  });

  // Optimistic "running" placeholder so an open detail page shows the run starting immediately.
  if (finding) {
    finding.runs.push({ runId, agent, status: 'running', verdict: null, startedAt, finishedAt: null });
    emit(EVENTS.DETAIL_REFRESH, findingId);
  }

  const runMsg = { type: 'run', runId, findingId, agent, context, instruction };
  // Verify needs live-directory access to confirm a fix landed.
  if (agent === 'verify' || agent === 'triage') {
    const path = findingSourcePath(finding);
    if (path) runMsg.path = path;
  }
  send(runMsg);
  return runId;
}

async function refreshFindingAfterRun(findingId) {
  const finding = await getFinding(findingId);
  if (!finding) return;
  state.findingCache.set(findingId, finding);
  emit(EVENTS.FINDING_UPDATED, findingId, {
    status: finding.status,
    runCount: finding.runs.length,
    latestRun: finding.runs.length ? (({ agent, status, verdict }) => ({ agent, status, verdict }))(finding.runs[finding.runs.length - 1]) : null,
    stageRuns: findingStageRuns(finding),
  });
}

export function wireRunMessages() {
  on(EVENTS.WS_RUN_MESSAGE, handleFindingRunMessage);
}

function handleFindingRunMessage(msg) {
  const findingId = msg.runId ? state.stages.get(msg.runId) : null;

  if (msg.type === 'error' && !findingId) {
    alert(msg.message);
    return;
  }
  if (!findingId) return;

  if (msg.type === 'started') {
    // Most flows push their own placeholder before sending. A chained remediate_all's Fix and
    // Verify stages can't — the chain doesn't yet know they'll run — so push one here if missing.
    const finding = state.findingCache.get(findingId);
    if (finding && !finding.runs.some((r) => r.runId === msg.runId)) {
      finding.runs.push({ runId: msg.runId, agent: msg.agent, status: 'running', verdict: null, startedAt: Date.now(), finishedAt: null });
      emit(EVENTS.DETAIL_REFRESH, findingId);
    }
    return;
  }
  if (msg.type === 'event') {
    const consoleRun = state.stageConsoles.get(msg.runId);
    if (consoleRun) trackConsoleText(consoleRun, msg.event);
    return;
  }
  if (msg.type === 'stderr') {
    return; // CLI-internal chatter, not actionable
  }
  if (msg.type === 'error') {
    // A precheck failure never gets a run pushed server-side, so there is nothing for the
    // normal error badge to attach to — surface it directly instead.
    if (state.precheckRunIds.has(msg.runId)) {
      state.precheckRunIds.delete(msg.runId);
      alert(msg.message);
    }
    emit(EVENTS.TIMELINE_UPSERT, { runId: msg.runId, status: 'error', finishedAt: Date.now() });
    refreshFindingAfterRun(findingId);
    return;
  }
  if (msg.type === 'done') {
    emit(EVENTS.TIMELINE_UPSERT, { runId: msg.runId, status: msg.code === 0 ? 'done' : 'error', verdict: msg.verdict, finishedAt: Date.now() });
    state.precheckRunIds.delete(msg.runId);
    refreshFindingAfterRun(findingId);
    return;
  }
}
