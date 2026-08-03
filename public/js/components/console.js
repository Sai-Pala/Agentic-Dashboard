/**
 * The opt-in raw console panel
 *
 * Shared by every live-run surface (scan cards, Finding Detail's run cards). Captures the
 * model's narrated prose only — not tool calls or results — and renders it behind a toggle.
 * Live-only: nothing is persisted, so a finished run's text dies with its tracking object.
 */

import { escapeHtml } from '../lib/html.js';
import { icon } from '../lib/icons.js';

/** Appends to the run's buffer (survives a re-render) and, if attached, straight to the DOM. */
export function trackConsoleText(run, event) {
  if (event.type !== 'assistant' || !event.message || !Array.isArray(event.message.content)) return;
  let text = '';
  for (const block of event.message.content) {
    if (block.type === 'text' && typeof block.text === 'string') text += block.text;
  }
  if (!text) return;
  run.consoleText = (run.consoleText || '') + text;
  if (run.consoleEl) {
    run.consoleEl.textContent += text;
    run.consoleEl.scrollTop = run.consoleEl.scrollHeight;
  }
}

// Button and panel are separate because the button belongs inside a nowrap flex header row
// while the <pre> needs to be a full-width block sibling below it.
export function consoleToggleButtonHtml(run) {
  return `<button class="console-toggle-btn${run.consoleOpen ? ' active' : ''}" type="button" data-console-toggle data-run-id="${escapeHtml(run.runId)}" title="View model's live reasoning">${icon('terminal')}</button>`;
}

export function consolePanelHtml(run, panelClass) {
  return `<pre class="console-panel ${panelClass}" data-run-id="${escapeHtml(run.runId)}"${run.consoleOpen ? '' : ' hidden'}>${escapeHtml(run.consoleText || '')}</pre>`;
}

/** For containers rebuilt wholesale on every update (Finding Detail's run cards). */
export function wireConsoleToggles(containerEl, runsMap, rerender) {
  containerEl.querySelectorAll('[data-console-toggle]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      // The button sits inside a clickable row; without this the row's own handler also fires.
      e.stopPropagation();
      const run = runsMap.get(btn.dataset.runId);
      if (!run) return;
      run.consoleOpen = !run.consoleOpen;
      rerender();
    });
  });
}

/** Re-points each run's consoleEl at its freshly-rendered panel after an innerHTML rebuild. */
export function reattachConsoleRefs(containerEl, runsMap, panelClass) {
  for (const run of runsMap.values()) {
    run.consoleEl = containerEl.querySelector(`.${panelClass}[data-run-id="${run.runId}"]`) || null;
  }
}
