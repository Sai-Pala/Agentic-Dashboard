/**
 * Guards on the client module graph.
 *
 * The views import each other on purpose — findings opens finding-detail, the timeline opens a
 * scan, a finished run re-renders whichever view is showing. That makes the graph cyclic. ES
 * module cycles are fine while every cross-edge is a call inside a function body, and break
 * when a module *reads* an imported binding during evaluation.
 *
 * WHAT THESE TESTS DO AND DO NOT CATCH — read before trusting them
 * ---------------------------------------------------------------
 * They do NOT prove the cycles are safe. Whether a cycle breaks depends on evaluation order
 * from the real entry point, and importing a module directly here does not reproduce the
 * browser's order. This was verified, not assumed: injecting a module-scope read of a `const`
 * across an existing cycle did not fail these tests. Only loading the app in a browser does
 * that, which is why the app is still opened and clicked after client changes.
 *
 * What they DO catch:
 *   1. A module that cannot be loaded at all — bad path, syntax error, missing export, or a
 *      dependency that needs a DOM at import time.
 *   2. New cycles. The count is a ratchet: adding one fails the suite. That is the point —
 *      the existing tangle is tolerated because it works, but it should not grow silently.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const JS_DIR = path.join(__dirname, '..', 'public', 'js');

/**
 * Cycles present when this guard was written. Lower it when you remove one; raising it needs a
 * reason in the commit message, because every cycle is a place the load order matters.
 */
const KNOWN_CYCLE_COUNT = 25;

/** Modules that legitimately need a document at import time and so cannot load in bare Node. */
const NEEDS_DOM = new Set(['main.js']);

function allModules(dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...allModules(p));
    else if (e.name.endsWith('.js')) out.push(p);
  }
  return out;
}

/** Static import graph: file -> [resolved relative deps]. */
function buildGraph(files) {
  const graph = new Map();
  for (const f of files) {
    const deps = [];
    const src = fs.readFileSync(f, 'utf8');
    for (const m of src.matchAll(/(?:^|\n)\s*import[^'"]*['"](\.[^'"]+)['"]/g)) {
      const target = path.resolve(path.dirname(f), m[1]);
      if (fs.existsSync(target)) deps.push(target);
    }
    graph.set(f, deps);
  }
  return graph;
}

function findCycles(graph) {
  const found = new Set();
  const done = new Set();
  const visit = (node, stack) => {
    if (done.has(node)) return;
    const at = stack.indexOf(node);
    if (at !== -1) {
      found.add(stack.slice(at).concat(node).map((p) => path.relative(JS_DIR, p)).sort().join('|'));
      return;
    }
    stack.push(node);
    for (const d of graph.get(node) || []) visit(d, stack);
    stack.pop();
    done.add(node);
  };
  for (const f of graph.keys()) visit(f, []);
  return [...found];
}

describe('client module graph', () => {
  const modules = allModules(JS_DIR);

  test('the tree is real, not an empty directory', () => {
    assert.ok(modules.length > 20, `expected a real module tree, found ${modules.length}`);
  });

  test('no new import cycles', () => {
    const cycles = findCycles(buildGraph(modules));
    assert.ok(
      cycles.length <= KNOWN_CYCLE_COUNT,
      `import cycles went from ${KNOWN_CYCLE_COUNT} to ${cycles.length}. New cycle(s):\n` +
        cycles.map((c) => '  ' + c.split('|').join(' <-> ')).join('\n'),
    );
  });

  for (const file of modules) {
    const rel = path.relative(JS_DIR, file);
    if (NEEDS_DOM.has(rel)) continue;

    test(`${rel} loads standalone`, async () => {
      await assert.doesNotReject(() => import(`file://${file}`), `${rel} failed to load`);
    });
  }
});
