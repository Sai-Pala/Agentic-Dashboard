/**
 * The per-finding agent menu
 * ==========================
 *
 * One "Run <Agent>…" item per entry in agentsList, minus the fix-flow agents (which have their
 * own dedicated controls). Opened by right-clicking an Agent Triage row or by the "…" button on
 * a row / Finding Detail's header. Every item opens the stage modal — nothing runs instantly.
 */

import { state } from '../state.js';
import { agentMeta, FIX_FLOW_AGENTS } from '../lib/meta.js';
import { ensureFindingCached, buildBaseContext } from './runs.js';
import { openFreshStageModal } from './modals.js';

function menuEl() {
  return document.getElementById('context-menu');
}

/** `finding` is optional — pass it so an SCA finding's empty menu can say why it's empty. */
export function openFindingContextMenu(x, y, findingId, finding) {
  const el = menuEl();
  el.innerHTML = '';
  const addItem = (label, disabled, onClick) => {
    const btn = document.createElement('button');
    btn.textContent = label;
    btn.disabled = !!disabled;
    btn.addEventListener('click', () => { closeContextMenu(); onClick(); });
    el.appendChild(btn);
  };
  const runAgentItem = (agentName) => {
    addItem(`Run ${agentMeta(agentName).label}…`, false, async () => {
      const f = await ensureFindingCached(findingId);
      if (f) openFreshStageModal(findingId, agentName, buildBaseContext(f));
    });
  };

  const isSca = finding && finding.scanType === 'sca';
  const eligibleAgents = state.agentsList.filter((a) => !FIX_FLOW_AGENTS.includes(a));

  if (!eligibleAgents.length) {
    addItem(isSca ? 'No agent actions apply — update the package instead' : 'No agents available', true, () => {});
  } else {
    for (const agentName of eligibleAgents) runAgentItem(agentName);
  }

  positionAndShowMenu(x, y);
}

export function positionAndShowMenu(x, y) {
  const el = menuEl();
  el.hidden = false;
  const rect = el.getBoundingClientRect();
  const left = Math.min(x, window.innerWidth - rect.width - 8);
  const top = Math.min(y, window.innerHeight - rect.height - 8);
  el.style.left = Math.max(8, left) + 'px';
  el.style.top = Math.max(8, top) + 'px';
}

export function closeContextMenu() {
  menuEl().hidden = true;
}

/**
 * A menu-opening button must stopPropagation: otherwise the click bubbles to the
 * document-level "click outside closes the menu" listener and shuts it in the same tick.
 */
export function openMenuUnderButton(e, findingId, finding) {
  e.stopPropagation();
  const rect = e.currentTarget.getBoundingClientRect();
  openFindingContextMenu(rect.right, rect.bottom + 4, findingId, finding);
}
