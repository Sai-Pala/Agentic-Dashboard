/**
 * Hybrid-scan result merging
 * ==========================
 *
 * A Hybrid Scan runs three engines over one directory and has to reconcile their output. This
 * module is the reconciliation logic, on its own because it is pure, subtle, and the place
 * where a careless change silently deletes real findings.
 *
 * Two of the three dedupe axes live here (the third — reasoning vs SCA — does not exist,
 * since SCA findings are package-keyed and have no file+line to collide with):
 *   - dedupeAdjacentSameRule: one deterministic rule firing repeatedly down one file
 *   - isDuplicateOfReasoning: one reasoning call restating something already kept
 *
 * Extracted from server.js unchanged. Pure: no I/O, no module state.
 */

const path = require('path');

/**
 * Splits agents/scan.md's "path:line" file convention into parts for the dedup comparisons.
 *
 * CONCERN (recorded, not fixed): the backslash normalization is a no-op on POSIX, because
 * `path.sep` is already '/' there. A model-emitted `src\a.js` therefore never normalizes and
 * can never match sast-engine's `src/a.js`, so the stated intent only holds when the server
 * itself runs on Windows.
 */
function parseFileLine(fileStr) {
  if (!fileStr) return { file: null, line: null };
  const normalized = String(fileStr).trim().split(path.sep).join('/');
  const m = normalized.match(/^(.*?)(?::(\d+))?$/);
  return { file: m ? m[1] : normalized, line: m && m[2] ? parseInt(m[2], 10) : null };
}

/**
 * Whether a reasoning finding restates one already kept from another reasoning call.
 *
 * Location, not title, is the signal: titles vary far too much between calls to compare as
 * text ("requireAuth ... applied to zero routes" vs "Payment, order and profile endpoints
 * registered without requireAuth"), but the two calls land on the same line consistently.
 *
 * A finding with no resolvable line ALWAYS survives — most business-logic and attack-surface
 * findings have none, and there is nothing to compare them against.
 */
function isDuplicateOfReasoning(rf, kept) {
  const loc = parseFileLine(rf.file);
  if (!loc.file || loc.line == null) return false;
  return kept.some((k) => {
    const kl = parseFileLine(k.file);
    return kl.file === loc.file && kl.line != null && Math.abs(kl.line - loc.line) <= 2;
  });
}

// How far apart two hits of the same rule in the same file can be and still be treated as one
// condition rather than two distinct sites. Small on purpose — see below.
const ADJACENT_RULE_LINES = 3;

/**
 * Collapse runs of the same rule firing on nearby lines of the same file down to their first
 * occurrence: a file-wide condition flagged on four consecutive lines becomes one finding,
 * while the same rule at line 12 and line 200 stays two.
 *
 * Distance is the entire signal here — it is what separates "one condition observed
 * repeatedly" from "several distinct sites" — so the two invariants below are load-bearing
 * and both have explicit tests:
 *
 *  1. Same rule, DISTANT lines must NOT collapse. Three SQL injections in one file are three
 *     real findings.
 *  2. A group can never span more than ADJACENT_RULE_LINES. The comparison is anchored to the
 *     line that OPENED the group, not to the previous hit. Anchoring to the previous hit let
 *     groups chain without bound — hits at 10,12,14,16,18,20 collapsed into ONE finding
 *     despite the ends being 10 lines apart, silently discarding the distinct ones.
 */
function dedupeAdjacentSameRule(findings) {
  const groups = new Map();
  for (const f of findings) {
    const key = `${f.file}::${f.rule}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }
  const kept = new Set();
  for (const group of groups.values()) {
    const sorted = [...group].sort((a, b) => (a.line || 0) - (b.line || 0));
    let groupStart = null;
    for (const f of sorted) {
      // CONCERN (recorded, not fixed): `f.line || 0` means every lineless hit of one rule in
      // one file collapses to a single finding. That is correct for the file-level rules that
      // actually emit them (NO_RATE_LIMIT, MISSING_SECURITY_HEADERS), but it is incidental
      // rather than intended.
      const line = f.line || 0;
      if (groupStart == null || line - groupStart > ADJACENT_RULE_LINES) {
        kept.add(f);
        groupStart = line;
      }
    }
  }
  // Preserve the engine's own severity ordering rather than the grouping order.
  return findings.filter((f) => kept.has(f));
}

module.exports = {
  ADJACENT_RULE_LINES,
  parseFileLine,
  isDuplicateOfReasoning,
  dedupeAdjacentSameRule,
};
