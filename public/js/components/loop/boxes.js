/**
 * The four stage boxes on Finding Detail
 * ======================================
 *
 * Triage / Remediate / Fix / Verify plus "Run all stages". Only one box is ever clickable —
 * findingLoopNextAction() resolves a strictly linear pipeline to a single next stage, so every
 * box dispatches the same handler rather than carrying per-stage logic of its own.
 */

import { escapeHtml } from '../../lib/html.js';
import { icon } from '../../lib/icons.js';
import { agentMeta } from '../../lib/meta.js';
import { findingSourcePath } from '../runs.js';
import { findingLoopState, findingLoopNextAction } from './state.js';

export function fdLoopBoxesHtml(f) {
  if (f.scanType === 'sca') return '';
  if (f.status === 'closed') return `<div class="hint">Closed — remediation loop not applicable.</div>`;

  const { triaged, remediated, fixed, verified } = findingLoopState(f);
  const next = findingLoopNextAction(f);
  const hasPath = !!findingSourcePath(f);
  const anyRunning = triaged === 'running' || remediated === 'running' || fixed === 'running' || verified === 'running';

  const box = (stage, agentKey, label, caption, runningLabel, boxState, actionable, actionTitle) => {
    const meta = agentMeta(agentKey);
    const statusText = boxState === 'running' ? runningLabel
      : boxState === 'attention' ? (stage === 'verify' ? 'Not fixed' : 'Failed')
      : boxState === 'unavailable' ? 'No fix proposed'
      : boxState === 'done' ? 'Done' : 'Not started';
    // Every stage past Triage needs a directory to act against, so a finding added by hand —
    // with no sourceScanId — has nothing any of them could run on. Without hasPath the
    // Remediate box rendered active, and clicking it only produced an alert, having already
    // disabled itself.
    const clickable = actionable && !anyRunning && hasPath;
    const title = clickable ? actionTitle
      : boxState === 'done' ? `${label} complete`
      : boxState === 'unavailable' ? 'Remediate didn’t propose a specific edit for this finding — nothing to apply'
      : !hasPath && stage !== 'triage' ? 'No known source directory — this finding wasn\'t produced by a scan'
      : '';
    return `
      <button class="fd-loop-box${clickable ? ' clickable' : ''} state-${boxState}" type="button"
        data-fd-loop-box${clickable ? '' : ' disabled'} title="${escapeHtml(title)}">
        ${icon(meta.icon)}<span class="fd-loop-box-text">
          <span class="fd-loop-box-label">${escapeHtml(label)}</span>
          <span class="fd-loop-box-caption">${escapeHtml(caption)}</span>
          <span class="fd-loop-box-status">${escapeHtml(statusText)}</span>
        </span>
      </button>`;
  };

  const boxesHtml = '<div class="fd-loop-boxes">'
    + box('triage', 'triage', 'Triage', 'Confirms it’s real', 'Triaging…', triaged, next === 'triage', 'Run Triage')
    + box('remediate', 'remediation', 'Remediate', 'Proposes a fix to review', 'Proposing…', remediated, next === 'remediate', 'Propose a fix — nothing written yet')
    + box('fix', 'fix', 'Fix', 'Writes the fix to your code', 'Applying…', fixed, next === 'fix', 'Apply the proposed fix — writes to your code')
    + box('verify', 'verify', 'Verify', 'Re-checks the live code', 'Verifying…', verified, next === 'verify', 'Verify the fix actually landed')
    + '</div>';

  const runAllDisabled = anyRunning || !next || !hasPath;
  const runAllTitle = !hasPath ? 'No known source directory — this finding wasn\'t produced by a scan'
    : !next ? 'Nothing left to run'
    : 'Run all remaining stages';
  const runAllHtml = `<button class="fd-loop-runall-btn" type="button" data-fd-runall="${escapeHtml(f.id)}"${runAllDisabled ? ' disabled' : ''} title="${escapeHtml(runAllTitle)}">${icon('skipForward')}Run all stages</button>`;

  return boxesHtml + runAllHtml;
}
