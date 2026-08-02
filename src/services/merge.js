/**
 * Hybrid-scan result merging: two of the three dedupe axes (reasoning vs SCA does not exist —
 * SCA findings are package-keyed and have no file+line to collide with). Pure, subtle, and the
 * place where a careless change silently deletes real findings.
 */

const path = require('path');

/**
 * Splits the model's "path:line" file convention into parts for the dedup comparisons.
 *
 * CONCERN (recorded, not fixed): the backslash normalization is a no-op on POSIX, where
 * `path.sep` is already '/', so a model-emitted `src\a.js` never matches `src/a.js`.
 */
function parseFileLine(fileStr) {
  if (!fileStr) return { file: null, line: null };
  const normalized = String(fileStr).trim().split(path.sep).join('/');
  const m = normalized.match(/^(.*?)(?::(\d+))?$/);
  return { file: m ? m[1] : normalized, line: m && m[2] ? parseInt(m[2], 10) : null };
}

/**
 * Whether a reasoning finding restates one already kept. Location, not title, is the signal:
 * titles vary far too much between calls to compare as text, but they land on the same line.
 * A finding with no resolvable line ALWAYS survives — there is nothing to compare it against.
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
 * Collapse the same rule firing on nearby lines of one file down to its first occurrence.
 * Distance is the entire signal — it separates "one condition observed repeatedly" from
 * "several distinct sites" — so two invariants are load-bearing and both have tests:
 *
 *  1. Same rule, DISTANT lines must NOT collapse. Three SQL injections in one file are three.
 *  2. Comparison is anchored to the line that OPENED the group, never to the previous hit.
 *     Anchoring to the previous hit lets groups chain without bound (10,12,14,16,18,20 become
 *     one finding despite spanning 10 lines), silently discarding the distinct ones.
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
