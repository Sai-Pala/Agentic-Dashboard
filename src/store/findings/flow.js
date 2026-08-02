/**
 * The source -> sink line span behind a dataflow finding.
 */

const fs = require('fs');

// Past this a span is a wall of code rather than an explanation, so the finding falls back to
// its plain snippet.
const MAX_FLOW_SPAN_LINES = 25;

/**
 * Reads the real lines between where untrusted input entered and where it reached a sink — the
 * difference between "a rule fired here" and "this is the route an attacker takes". Returns
 * null for anything that isn't a bounded, readable cross-line flow.
 *
 * This is a snapshot taken once, at finding-creation time; it does not track later edits.
 */
function readFlowSpan(f) {
  if (!f.taintSourceLine || !f.line || f.taintSourceLine >= f.line || !f.file) return null;
  if (f.line - f.taintSourceLine > MAX_FLOW_SPAN_LINES) return null;
  try {
    const all = fs.readFileSync(f.file, 'utf8').split(/\r?\n/);
    return {
      sourceLine: f.taintSourceLine,
      sinkLine: f.line,
      lines: all
        .slice(f.taintSourceLine - 1, f.line)
        .map((text, i) => ({ n: f.taintSourceLine + i, text })),
    };
  } catch {
    // The file may have moved or become unreadable since the scan.
    return null;
  }
}

module.exports = { MAX_FLOW_SPAN_LINES, readFlowSpan };
