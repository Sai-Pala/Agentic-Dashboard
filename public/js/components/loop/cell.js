/**
 * The loop cell in the Agent Triage table
 *
 * A four-dot track plus a one-line label. Pure status readout — no buttons live here;
 * advancing the loop happens on the finding's own detail page.
 */

import { escapeHtml, statusBadgeHtml } from '../../lib/html.js';
import { icon } from '../../lib/icons.js';
import { findingLoopState } from './state.js';

export function loopTrackHtml(triaged, remediated, fixed, verified) {
  return `
    <div class="loop-track" title="Triaged → Remediated → Fixed → Verified">
      <span class="loop-seg ${triaged}"></span>
      <span class="loop-seg ${remediated}"></span>
      <span class="loop-seg ${fixed === 'unavailable' ? 'pending' : fixed}"></span>
      <span class="loop-seg ${verified}"></span>
    </div>
  `;
}

export function findingLoopCellHtml(f) {
  // An SCA finding's fix is a dependency bump, not a code edit — show plain status instead of
  // implying a loop. Only reachable from the "All" tab; the SCA tab uses the 'status' key.
  if (f.scanType === 'sca') return statusBadgeHtml(f);
  if (f.status === 'closed') {
    return `<div class="loop-cell"><span class="hint">Closed — not applicable</span></div>`;
  }

  const { triaged, remediated, fixed, verified } = findingLoopState(f);
  const track = loopTrackHtml(triaged, remediated, fixed, verified);

  let statusHtml;
  if (triaged === 'running') {
    statusHtml = `<span class="loop-status-text">Triaging…</span>`;
  } else if (remediated === 'running') {
    statusHtml = `<span class="loop-status-text">Proposing fix…</span>`;
  } else if (fixed === 'running') {
    statusHtml = `<span class="loop-status-text">Applying fix…</span>`;
  } else if (verified === 'running') {
    statusHtml = `<span class="loop-status-text">Verifying…</span>`;
  } else if (triaged === 'attention') {
    statusHtml = `<span class="loop-status-text attention">Triage failed</span>`;
  } else if (verified === 'attention') {
    statusHtml = `<span class="loop-status-text attention">Not fixed yet</span>`;
  } else if (fixed === 'attention') {
    statusHtml = `<span class="loop-status-text attention">Apply failed</span>`;
  } else if (remediated === 'attention') {
    statusHtml = `<span class="loop-status-text attention">Propose failed</span>`;
  } else if (verified === 'done') {
    statusHtml = `<span class="loop-status-text ok">Verified fixed</span>`
      + `<button class="loop-view-diff" type="button" data-view-diff-btn="${escapeHtml(f.id)}" title="View the applied diff">${icon('checkCircle')}View diff</button>`;
  } else if (fixed === 'done') {
    statusHtml = `<span class="loop-status-text accent">Fixed</span>`;
  } else if (fixed === 'unavailable') {
    statusHtml = `<span class="loop-status-text">No fix proposed</span>`;
  } else if (remediated === 'done') {
    statusHtml = `<span class="loop-status-text accent">Fix proposed</span>`;
  } else if (triaged === 'done') {
    statusHtml = `<span class="loop-status-text accent">Triaged</span>`;
  } else {
    statusHtml = `<span class="loop-status-text">Not started</span>`;
  }

  return `<div class="loop-cell">${track}<div class="loop-status-row">${statusHtml}</div></div>`;
}
