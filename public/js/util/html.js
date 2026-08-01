/**
 * HTML helpers that need a document
 * =================================
 *
 * Split out from util/format.js precisely because these touch the DOM: escapeHtml round-trips
 * through a detached element rather than doing regex replacement, and downloadTextFile builds
 * a Blob and clicks a synthetic anchor. Keeping them here is what lets util/format.js stay
 * Node-importable.
 *
 * Moved verbatim out of the single inline <script> during the Phase 4 split.
 */

export function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

// Agent free-text (reasoning/root_cause/evidence/etc.) commonly contains Markdown-ish inline
// code spans and bold the model wrote assuming a Markdown renderer downstream — this app had
// none, so a literal backtick or `**` pair just showed up as stray punctuation. A small
// hand-rolled inline formatter (escape first, then linkify backtick spans and bold — no lists/
// headers/links, this app's verdict fields never use them) fixes that without pulling in an
// external Markdown library, consistent with this app's other hand-rolled renderers
// (highlightCode(), diffLineHtml()).
export function formatInlineText(str) {
  return escapeHtml(str)
    .replace(/`([^`]+)`/g, (_, code) => `<code>${code}</code>`)
    .replace(/\*\*([^*]+)\*\*/g, (_, b) => `<strong>${b}</strong>`);
}

export function downloadTextFile(filename, content) {
  const blob = new Blob([content], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
