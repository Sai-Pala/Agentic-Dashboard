/**
 * Entry point.
 *
 * Nothing but startup: each view wires its own listeners, this decides the order and opens the
 * socket. If you are looking for what a screen does, open its file under views/ — not this one.
 */

import { state } from './state.js';
import { getAgents } from './api.js';
import { initNav, showView } from './router.js';
import { connect } from './ws.js';

import { loadFindings, wireFindingsView } from './views/findings/index.js';
import { loadScans, wireScansView } from './views/scans/index.js';
import { loadTimeline, wireTimeline, closeTimelineDrawer } from './views/timeline.js';
import { wireFindingDetail } from './views/finding-detail/index.js';
import { wireSettings } from './views/settings.js';
import { wireModals, closeStageModal, closeFindingModal } from './components/modals.js';
import { closeContextMenu } from './components/menu.js';

/** The stage modal builds its dropdown from this on open, so only the fetch happens here. */
async function loadAgents() {
  state.agentsList = await getAgents();
}

/**
 * Dismissal that spans several components: one outside-click and one Escape, rather than each
 * overlay registering its own document listener and racing the others.
 */
function wireGlobalDismiss() {
  const menuEl = document.getElementById('context-menu');
  document.addEventListener('click', (e) => {
    if (!menuEl.hidden && !menuEl.contains(e.target)) closeContextMenu();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    closeContextMenu();
    closeStageModal();
    closeFindingModal();
    if (state.timelineDrawerOpen) closeTimelineDrawer();
  });
}

async function init() {
  initNav();
  wireScansView();
  wireFindingsView();
  wireFindingDetail();
  wireTimeline();
  wireSettings();
  wireModals();
  wireGlobalDismiss();

  await loadAgents();
  await loadFindings();
  await loadScans();
  await loadTimeline();

  showView('dashboard');
  connect();
}

init();
