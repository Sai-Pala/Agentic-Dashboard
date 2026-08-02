/**
 * Dead-code guard.
 *
 * WHY THIS EXISTS
 * ---------------
 * Deleting a feature leaves behind code that still reads fine but describes a system that no
 * longer exists. That residue is invisible to every other test: it compiles, it passes lint (if
 * there were one), and the functions it contains are individually correct. It is only found by
 * asking "does anything actually reach this?".
 *
 * Real examples this repo accumulated before the check existed:
 *   - POST/PUT/DELETE /api/agents outlived the browser admin screen that called them, leaving
 *     unauthenticated writes to the prompt files that define agent behaviour
 *   - plugin-loader's scaffoldPlugin emitted an import path that could never resolve
 *   - renderStageModalAgents() was never called, so the stage modal's <select> had no options
 *     and starting a run from it sent an empty agent name
 *
 * WHAT IT CATCHES
 *   1. A declared-and-exported symbol nothing references anywhere.
 *   2. A symbol exported but used only inside its own file. `export` is a claim about a
 *      module's public surface; a false claim misleads whoever reads it next.
 *   3. A module-level declaration that is neither exported nor used in its own file. Check 2
 *      creates these: unexporting something that turned out to have no callers leaves an
 *      orphaned const behind, which is exactly how BUILTIN_AGENTS survived a cleanup pass.
 *
 * WHAT IT DOES NOT CATCH — do not mistake a pass here for "no dead code"
 *   - Dead CSS. Classes are routinely built by interpolation (`class="badge ${verdict}"`), so a
 *     static sweep reports live rules as dead. Checked by hand instead.
 *   - Dead markup, or a control in index.html that nothing wires up.
 *   - An unused *variant* of a used API (`.accent-warn` where only `.accent-accent` is passed).
 *   - Anything reached dynamically, by computed name or string dispatch.
 *
 * Matching is by word occurrence, not by resolving imports, so it errs toward calling something
 * live. A hit is therefore worth trusting; a pass is weaker evidence.
 *
 * sast-engine/ IS EXEMPT ENTIRELY — deliberately, and do not "tidy" it
 * -------------------------------------------------------------------
 * The engine is vendored third-party code (MIT, from ship-safe) with its own public API. A
 * symbol this app never imports is not dead there — it is surface the engine offers to other
 * callers and to plugins. Two concrete cases from when this check was written:
 *
 *   - SUSPICIOUS_NAME_PATTERNS holds a `@scope/name-<digits>` regex that matched 0 of 90 real
 *     packages in this repo's lockfile. That is genuine dependency-confusion signal that was
 *     simply never wired in — a coverage question for whoever owns the rules, not dead code.
 *     (Its sibling `four-hyphenated-words` regex matched `call-bind-apply-helpers`, so wiring
 *     the list up as-is would misfire. That is why it is a judgement call, not a sweep.)
 *   - HERMES_FILE_PATTERNS documents a wider scanning intent than _findHermesFiles() implements.
 *   - base-agent's SUPPRESSION_FLOOR_SEVERITIES / isSuppressible are plugin-facing API.
 *
 * Deleting any of these quietly narrows what the scanner claims to look for, and that is not a
 * refactor's call to make. Treat the engine with caution: improve it, do not prune it.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

/**
 * Exported for the test suite alone. Each entry is a deliberate choice, not an oversight —
 * a pure helper worth testing directly that nothing else happens to need yet. Keep it short:
 * a long list means production code is being shaped by its tests.
 */
const TEST_ONLY_EXPORTS = new Set([
  'ADJACENT_RULE_LINES',  // merge.js — the dedupe window, asserted directly
  'loopTrackHtml',        // loop/cell.js — rendered markup, asserted directly
  'AGENT_META',           // lib/meta.js — the label table
  'findingsSortValue',    // findings/table.js — pure sort key
  'locateFindString',     // remediation-apply.js — plan validation internals
  'countOccurrences',     // remediation-apply.js — ditto
]);

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name !== 'node_modules') walk(p, out);
    } else if (e.name.endsWith('.js')) out.push(p);
  }
  return out;
}

/** Code this app owns. sast-engine is deliberately absent — see the header. */
const appFiles = [
  ...walk(path.join(ROOT, 'src')),
  ...walk(path.join(ROOT, 'public', 'js')),
  path.join(ROOT, 'server.js'),
];

/** Read for *usage* only: the engine may reference app symbols, but is never itself audited. */
const referenceOnlyFiles = walk(path.join(ROOT, 'sast-engine'));
const testFiles = walk(__dirname);
const source = new Map([...appFiles, ...referenceOnlyFiles, ...testFiles].map((f) => [f, fs.readFileSync(f, 'utf8')]));

/** Every exported symbol, ESM and CommonJS alike. */
function declaredExports() {
  const out = [];
  for (const file of appFiles) {
    const src = source.get(file);
    for (const m of src.matchAll(/^export\s+(?:async\s+)?(?:function|const|let|class)\s+([A-Za-z_$][\w$]*)/gm)) {
      out.push({ file, name: m[1] });
    }
    // Anchored to column 0: `module.exports = { … }` also appears inside doc comments, and an
    // unanchored match starts there and scoops identifiers out of unrelated prose.
    const cjs = src.match(/^module\.exports\s*=\s*\{([\s\S]*?)^\};?\s*$/m);
    if (cjs) {
      for (const raw of cjs[1].split(',')) {
        const name = raw.split(':')[0].trim().replace(/\/\/.*/, '').trim();
        if (/^[A-Za-z_$][\w$]*$/.test(name)) out.push({ file, name });
      }
    }
  }
  return out;
}

/**
 * `\b` is defined against word characters, so it never matches beside `$` — a plain
 * `\b\$\b` finds nothing and reports the near-universal `const $ = id => …` helper as dead.
 * Names that are entirely non-word characters get a bare escaped match instead.
 */
const wordRe = (name) => {
  const escaped = name.replace(/[$]/g, '\\$&');
  return /^\w/.test(name) ? new RegExp(`\\b${escaped}\\b`) : new RegExp(escaped);
};
const usedIn = (files, name, skip) =>
  files.some((f) => f !== skip && wordRe(name).test(source.get(f)));
const selfMentions = (file, name) =>
  (source.get(file).match(new RegExp(wordRe(name).source, 'g')) || []).length;

describe('dead code', () => {
  const declared = declaredExports();

  test('the scan found real exports (guards against the matcher silently breaking)', () => {
    assert.ok(declared.length > 50, `only found ${declared.length} exports — the matcher is broken`);
  });

  test('nothing is exported and then never referenced anywhere', () => {
    const dead = declared.filter(({ file, name }) =>
      !usedIn([...appFiles, ...referenceOnlyFiles], name, file) &&
      !usedIn(testFiles, name, file) &&
      selfMentions(file, name) <= 1);

    assert.deepEqual(
      dead.map((d) => `${path.relative(ROOT, d.file)} -> ${d.name}`),
      [],
      'declared, exported, and referenced by nothing. Delete it, or wire it up if it was meant to be called.',
    );
  });

  test('no module-level declaration is left orphaned — not exported, not used', () => {
    // Only top-level `const NAME` / `function name` at column 0, so locals inside functions are
    // out of scope. Anything referenced by another file is live regardless of export style
    // (CommonJS re-exports by name, so the word appears in the exporting file).
    const orphans = [];
    for (const file of appFiles) {
      const src = source.get(file);
      for (const m of src.matchAll(/^(?:const|let|function|async function|class)\s+([A-Za-z_$][\w$]*)/gm)) {
        const name = m[1];
        if (declared.some((d) => d.file === file && d.name === name)) continue; // exported: checks 1-2 own it
        if (selfMentions(file, name) > 1) continue;
        if (usedIn([...appFiles, ...referenceOnlyFiles], name, file) || usedIn(testFiles, name, file)) continue;
        orphans.push(`${path.relative(ROOT, file)} -> ${name}`);
      }
    }
    assert.deepEqual(orphans, [], 'declared at module scope and never used or exported. Delete it.');
  });

  test('nothing is exported that only its own file uses', () => {
    const overExported = declared.filter(({ file, name }) =>
      !TEST_ONLY_EXPORTS.has(name) &&
      !usedIn([...appFiles, ...referenceOnlyFiles], name, file) &&
      !usedIn(testFiles, name, file) &&
      selfMentions(file, name) > 1);

    assert.deepEqual(
      overExported.map((d) => `${path.relative(ROOT, d.file)} -> ${d.name}`),
      [],
      'used only inside its own file — drop the `export` keyword, or add it to TEST_ONLY_EXPORTS with a reason.',
    );
  });
});
