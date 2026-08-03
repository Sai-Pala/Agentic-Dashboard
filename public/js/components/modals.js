/**
 * The two modals
 *
 * The stage modal (pick an agent, review the context, add instructions, start) and the
 * add-finding modal. Nothing here runs an agent without an explicit "Start stage" click.
 */

import { state } from '../state.js';
import { postFinding } from '../api.js';
import { agentMeta } from '../lib/meta.js';
import { startStage, findingSourcePath } from './runs.js';
import { emitAsync, EVENTS } from '../events.js';

const $ = (id) => document.getElementById(id);

// ---------- stage modal ----------

/**
 * Verify's behaviour depends on the cwd it gets spawned with, which isn't visible in the
 * editable context — spell it out so starting one isn't a black box.
 */
function updateStageModalVerifyHint() {
  const hintEl = $('stage-modal-verify-hint');
  if ($('stage-modal-agent').value !== 'verify' || !state.stageModalState) { hintEl.hidden = true; return; }
  const finding = state.findingCache.get(state.stageModalState.findingId);
  const path = findingSourcePath(finding);
  hintEl.hidden = false;
  hintEl.textContent = path
    ? `Will re-check the live code at: ${path}`
    : 'No known source directory for this finding — review will be based on the saved snippet only.';
}

export function openFreshStageModal(findingId, agent, context) {
  state.stageModalState = { findingId };
  $('stage-modal-title').textContent = `Run ${agentMeta(agent).label} with instructions`;
  // Rebuild the options every open. Setting .value on an empty <select> silently does nothing,
  // so skipping this sends an empty agent name to the server.
  renderStageModalAgents();
  $('stage-modal-agent').value = state.agentsList.includes(agent) ? agent : state.agentsList[0];
  $('stage-modal-context').value = context;
  $('stage-modal-instruction').value = '';
  $('stage-modal-overlay').hidden = false;
  $('stage-modal-instruction').focus();
  updateStageModalVerifyHint();
}

export function closeStageModal() {
  $('stage-modal-overlay').hidden = true;
  state.stageModalState = null;
}

/** Populates the stage modal's agent dropdown from the loaded agent list. */
function renderStageModalAgents() {
  const sel = $('stage-modal-agent');
  sel.innerHTML = '';
  for (const a of state.agentsList) {
    const opt = document.createElement('option');
    opt.value = a; opt.textContent = a;
    sel.appendChild(opt);
  }
}

// ---------- add-finding modal ----------

function updateFindingModalTypeFields() {
  const type = $('finding-modal-scantype').value;
  $('fm-fields-reasoning').hidden = type !== 'reasoning';
  $('fm-fields-sca').hidden = type !== 'sca';
}

function openFindingModal() {
  for (const id of ['finding-modal-title', 'finding-modal-rule', 'finding-modal-file', 'finding-modal-code',
    'finding-modal-package', 'finding-modal-package-version', 'finding-modal-fixed-version',
    'finding-modal-endpoint', 'finding-modal-method', 'finding-modal-description']) {
    $(id).value = '';
  }
  $('finding-modal-scantype').value = 'reasoning';
  $('finding-modal-severity').value = 'medium';
  updateFindingModalTypeFields();
  $('finding-modal-overlay').hidden = false;
  $('finding-modal-title').focus();
}

export function closeFindingModal() {
  $('finding-modal-overlay').hidden = true;
}

async function saveFinding() {
  const title = $('finding-modal-title').value.trim();
  const description = $('finding-modal-description').value.trim();
  if (!title || !description) {
    alert('Title and description are required.');
    return;
  }
  const res = await postFinding({
    title,
    scanType: $('finding-modal-scantype').value,
    severity: $('finding-modal-severity').value,
    rule: $('finding-modal-rule').value.trim() || null,
    file: $('finding-modal-file').value.trim() || null,
    code: $('finding-modal-code').value.trim() || null,
    packageName: $('finding-modal-package').value.trim() || null,
    packageVersion: $('finding-modal-package-version').value.trim() || null,
    fixedVersion: $('finding-modal-fixed-version').value.trim() || null,
    endpoint: $('finding-modal-endpoint').value.trim() || null,
    method: $('finding-modal-method').value.trim() || null,
    description,
  });
  if (!res.ok) {
    alert(res.error);
    return;
  }
  state.findingCache.set(res.finding.id, res.finding);
  closeFindingModal();
  await emitAsync(EVENTS.FINDINGS_RELOAD);
  await emitAsync(EVENTS.DETAIL_OPEN, res.finding.id);
}

export function wireModals() {
  $('stage-modal-agent').addEventListener('change', updateStageModalVerifyHint);
  $('stage-modal-cancel').addEventListener('click', closeStageModal);
  $('stage-modal-overlay').addEventListener('click', (e) => {
    if (e.target === $('stage-modal-overlay')) closeStageModal();
  });
  $('stage-modal-start').addEventListener('click', () => {
    if (!state.stageModalState) return;
    const { findingId } = state.stageModalState;
    startStage(findingId, $('stage-modal-agent').value, $('stage-modal-context').value, $('stage-modal-instruction').value);
    closeStageModal();
  });

  $('add-finding-btn').addEventListener('click', openFindingModal);
  $('finding-modal-cancel').addEventListener('click', closeFindingModal);
  $('finding-modal-overlay').addEventListener('click', (e) => {
    if (e.target === $('finding-modal-overlay')) closeFindingModal();
  });
  $('finding-modal-scantype').addEventListener('change', updateFindingModalTypeFields);
  $('finding-modal-save').addEventListener('click', saveFinding);
}
