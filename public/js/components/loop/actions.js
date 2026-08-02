/**
 * Advancing the Remediation Loop
 * ==============================
 *
 * The click handlers behind Finding Detail's stage boxes and "Run all stages". Remediate is
 * read-only and needs no confirmation; Fix is the one step that writes, so it is gated by a
 * native confirm() naming the target directory and the clean-git-tree requirement — that is
 * the friction point, deliberately visible rather than a hidden mode toggle.
 *
 * The applied diff is never shown in a popup: Finding Detail already renders a fix run's
 * applied_diff as a diff block, so "see what changed" is "look at the finding".
 */

import { state } from '../../state.js';
import { uid } from '../../lib/format.js';
import { send } from '../../ws.js';
import { emit, EVENTS } from '../../events.js';
import { ensureFindingCached, findingSourcePath, buildBaseContext, startStage } from '../runs.js';
import { findingLoopNextAction } from './state.js';

function confirmApplyWrite(targetPath) {
  return confirm(
    `This writes the proposed fix directly to files in:\n${targetPath}\n\n` +
    `The target must be a clean git working tree (no uncommitted changes) — the run will refuse ` +
    `otherwise. You'll see the resulting diff once it's done. Continue?`
  );
}

function confirmRunAll(targetPath) {
  return confirm(
    `This proposes a fix, applies it, and verifies it in sequence against:\n${targetPath}\n\n` +
    `Applying the fix directly edits files there, so the target must be a clean git working tree ` +
    `(no uncommitted changes) — the run will refuse otherwise. Continue?`
  );
}

/** Runs exactly the next stage and stops. One deliberate click per stage. */
export async function onLoopAdvanceClick(findingId) {
  const finding = await ensureFindingCached(findingId);
  if (!finding) return;
  const next = findingLoopNextAction(finding);
  if (!next) return;
  if (next === 'triage' || next === 'verify') {
    startStage(findingId, next, buildBaseContext(finding), '');
    return;
  }
  const targetPath = findingSourcePath(finding);
  if (!targetPath) {
    alert('This finding has no known source directory (it wasn\'t produced by a scan), so there\'s nothing to run this stage against.');
    return;
  }
  if (next === 'remediate') {
    startRemediatePreview(findingId, finding, targetPath);
    return;
  }
  // next === 'fix' — the one step that writes.
  if (!confirmApplyWrite(targetPath)) return;
  startRemediateFix(findingId, finding, targetPath);
}

/** Remediate -> Fix -> Verify chained under one confirm(). There is no live Triage sub-call. */
export async function onLoopRunAllClick(findingId) {
  const finding = await ensureFindingCached(findingId);
  if (!finding) return;
  const targetPath = findingSourcePath(finding);
  if (!targetPath) {
    alert('This finding has no known source directory (it wasn\'t produced by a scan), so there\'s nothing to run the full pipeline against.');
    return;
  }
  if (!confirmRunAll(targetPath)) return;
  startRemediateAll(findingId, finding, targetPath);
}

export function onViewDiffClick(findingId) {
  emit(EVENTS.DETAIL_OPEN, findingId);
}

/** Read-only propose. Tracked in precheckRunIds since "is this a real directory" can still fail. */
function startRemediatePreview(findingId, finding, targetPath) {
  const runId = uid();
  state.stages.set(runId, findingId);
  state.stageConsoles.set(runId, { runId, consoleText: '', consoleOpen: false, consoleEl: null });
  state.precheckRunIds.add(runId);

  const startedAt = Date.now();
  const context = buildBaseContext(finding);
  emit(EVENTS.TIMELINE_UPSERT, {
    kind: 'remediation', runId, findingId, findingTitle: finding.title, agent: 'remediation',
    status: 'running', instruction: '', verdict: null, startedAt, finishedAt: null,
  });
  finding.runs.push({ runId, agent: 'remediation', status: 'running', verdict: null, startedAt, finishedAt: null });
  emit(EVENTS.DETAIL_REFRESH, findingId);

  send({ type: 'remediate_preview', runId, findingId, context, instruction: '', path: targetPath });
}

/** The write step. No console tracking: it makes no `claude` call, so there is no narration. */
function startRemediateFix(findingId, finding, targetPath) {
  const runId = uid();
  state.stages.set(runId, findingId);
  state.precheckRunIds.add(runId);

  const startedAt = Date.now();
  emit(EVENTS.TIMELINE_UPSERT, {
    kind: 'fix', runId, findingId, findingTitle: finding.title, agent: 'fix',
    status: 'running', instruction: '', verdict: null, startedAt, finishedAt: null,
  });
  finding.runs.push({ runId, agent: 'fix', status: 'running', verdict: null, startedAt, finishedAt: null });
  emit(EVENTS.DETAIL_REFRESH, findingId);

  send({ type: 'remediate_fix', runId, findingId, path: targetPath });
}

/**
 * Only Remediate gets an optimistic placeholder — the chain doesn't yet know whether Fix and
 * Verify will run at all, so their placeholders arrive with the server's own `started` message.
 */
function startRemediateAll(findingId, finding, targetPath) {
  const remediationRunId = uid();
  const fixRunId = uid();
  const verifyRunId = uid();
  state.stages.set(remediationRunId, findingId);
  state.stages.set(fixRunId, findingId);
  state.stages.set(verifyRunId, findingId);
  state.stageConsoles.set(remediationRunId, { runId: remediationRunId, consoleText: '', consoleOpen: false, consoleEl: null });
  state.stageConsoles.set(verifyRunId, { runId: verifyRunId, consoleText: '', consoleOpen: false, consoleEl: null });
  // A precheck failure is tagged with the first stage's runId — the only one with a
  // client-side placeholder before the server responds.
  state.precheckRunIds.add(remediationRunId);

  const startedAt = Date.now();
  const context = buildBaseContext(finding);
  emit(EVENTS.TIMELINE_UPSERT, {
    kind: 'remediation', runId: remediationRunId, findingId, findingTitle: finding.title, agent: 'remediation',
    status: 'running', instruction: '', verdict: null, startedAt, finishedAt: null,
  });
  finding.runs.push({ runId: remediationRunId, agent: 'remediation', status: 'running', verdict: null, startedAt, finishedAt: null });
  emit(EVENTS.DETAIL_REFRESH, findingId);

  send({ type: 'remediate_all', findingId, remediationRunId, fixRunId, verifyRunId, context, instruction: '', path: targetPath });
}
