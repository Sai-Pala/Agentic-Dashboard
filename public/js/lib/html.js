/**
 * HTML helpers that need a document
 *
 * Split out from util/format.js precisely because these touch the DOM: escapeHtml round-trips
 * through a detached element rather than doing regex replacement. Keeping them here is what
 * lets util/format.js stay Node-importable.
 */

import { statusLabel } from './format.js';

export function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

// Lives here, not in the findings table, so the loop cell can render an SCA finding's status
// without importing the table that imports it back.
export function statusBadgeHtml(f) {
  return `<span class="badge ${f.status}">${escapeHtml(statusLabel(f.status))}</span>`;
}

// Agent free-text arrives with Markdown-ish backtick spans and `**` bold, written assuming a
// renderer downstream. There is none, so without this they show up as stray punctuation.
// Escape first, then the two inline forms only — verdict fields never use lists, headers or
// links, so a Markdown dependency would buy nothing.
export function formatInlineText(str) {
  return escapeHtml(str)
    .replace(/`([^`]+)`/g, (_, code) => `<code>${code}</code>`)
    .replace(/\*\*([^*]+)\*\*/g, (_, b) => `<strong>${b}</strong>`);
}
