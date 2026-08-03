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

/**
 * Size of the largest mutually-dependent cluster (strongly-connected component).
 *
 * This is the metric that actually tracks coupling, and the cycle count above does not. A cycle
 * count can fall while the tangle stays exactly as bad — 25 cycles over 16 modules that all reach
 * each other is one blob, not 25 separate problems. What matters to a reader is "how many files
 * must I hold in my head to understand this one", and that is the SCC size.
 *
 * Splitting a monolith into many small files does not by itself reduce this number, which is why
 * it is guarded separately: it is the difference between modular and merely subdivided.
 */
const MAX_SCC_SIZE = 3;

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

/**
 * Tarjan's algorithm: every maximal set of modules that can all reach each other.
 * Singletons are dropped — a module with no cycle is a component of size 1 and says nothing.
 */
function stronglyConnectedComponents(graph) {
  let index = 0;
  const indices = new Map();
  const lowlinks = new Map();
  const stack = [];
  const onStack = new Set();
  const components = [];

  const strongConnect = (v) => {
    indices.set(v, index);
    lowlinks.set(v, index);
    index++;
    stack.push(v);
    onStack.add(v);

    for (const w of graph.get(v) || []) {
      if (!indices.has(w)) {
        strongConnect(w);
        lowlinks.set(v, Math.min(lowlinks.get(v), lowlinks.get(w)));
      } else if (onStack.has(w)) {
        lowlinks.set(v, Math.min(lowlinks.get(v), indices.get(w)));
      }
    }

    if (lowlinks.get(v) === indices.get(v)) {
      const component = [];
      let w;
      do {
        w = stack.pop();
        onStack.delete(w);
        component.push(w);
      } while (w !== v);
      if (component.length > 1) components.push(component);
    }
  };

  for (const v of graph.keys()) if (!indices.has(v)) strongConnect(v);
  return components;
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

  test('no large mutually-dependent cluster', () => {
    const components = stronglyConnectedComponents(buildGraph(modules))
      .sort((a, b) => b.length - a.length);
    const largest = components.length ? components[0].length : 0;
    assert.ok(
      largest <= MAX_SCC_SIZE,
      `largest mutually-dependent cluster is ${largest} modules (limit ${MAX_SCC_SIZE}).\n` +
        `Every module below can reach every other, so none can be read, tested or moved alone:\n` +
        (components[0] || []).map((f) => '  ' + path.relative(JS_DIR, f)).join('\n'),
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
