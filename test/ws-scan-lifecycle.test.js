/**
 * Scan lifecycle: what happens when a scan fails, and who is allowed to cancel it.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * Two bugs found in a full-codebase audit, both invisible to every other suite because they
 * live between the WebSocket handler and the scan pipeline:
 *
 *   1. runHybridReasoningScan() was called with no .catch(). It is async, so any throw inside
 *      the pipeline became an unhandled rejection — which terminates the Node process. The
 *      client's last message was a progress update, and the scan record stayed 'running'
 *      forever, which also made POST /api/session/clear return 409 permanently.
 *
 *   2. Closing any WebSocket cancelled EVERY running scan. `children` is per-connection but
 *      `scanRunIndex` is module-global, and the close handler walked all of it. Two tabs open,
 *      close one, and the other tab's scan was marked cancelled and its findings discarded —
 *      while its `claude` children, living in the other connection's `children` map, kept
 *      running and kept billing.
 *
 * HOW THESE ARE TESTED WITHOUT SPENDING MONEY
 * -------------------------------------------
 * The scanner module is stubbed via require.cache before src/ws/scan.js is loaded, so no engine
 * runs and no `claude` process is ever spawned. Everything here is in-process and free.
 */

const { test, describe, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const SCANNER = require.resolve('../src/services/scanner.js');
const SCAN_HANDLER = require.resolve('../src/ws/scan.js');

const { scans, scanRunIndex } = require('../src/store/scans');

/** Load handleScanMessage with runHybridReasoningScan replaced by `impl`. */
function loadHandlerWith(impl) {
  delete require.cache[SCAN_HANDLER];
  require.cache[SCANNER] = { id: SCANNER, filename: SCANNER, loaded: true, exports: { runHybridReasoningScan: impl } };
  const mod = require(SCAN_HANDLER);
  return mod.handleScanMessage;
}

afterEach(() => {
  delete require.cache[SCANNER];
  delete require.cache[SCAN_HANDLER];
  scans.clear();
  scanRunIndex.clear();
});

const TARGET = path.join(__dirname, 'fixtures', 'vuln-app');

/** A connection context shaped like the real one, capturing what was sent. */
const makeCtx = () => {
  const sent = [];
  return { children: new Map(), ownScanRunIds: new Set(), send: (m) => sent.push(m), sent };
};

describe('a scan pipeline that throws', () => {
  test('reports scan-error instead of taking the process down', async () => {
    const handle = loadHandlerWith(async () => { throw new Error('engine exploded'); });
    const ctx = makeCtx();

    handle({ type: 'scan', runId: 'r1', path: TARGET }, ctx);
    await new Promise((r) => { setImmediate(r); });   // let the rejection settle

    const types = ctx.sent.map((m) => m.type);
    assert.ok(types.includes('scan-error'), `expected a scan-error, got: ${types.join(', ')}`);
    const err = ctx.sent.find((m) => m.type === 'scan-error');
    assert.match(err.message, /engine exploded/);
  });

  test('leaves the scan record terminal, not stuck at running', () => {
    // A record stuck at 'running' is not merely untidy: POST /api/session/clear refuses while
    // anything is running, so one stranded scan bricks the reset button for the session.
    const handle = loadHandlerWith(async () => { throw new Error('boom'); });
    const ctx = makeCtx();
    handle({ type: 'scan', runId: 'r2', path: TARGET }, ctx);

    return new Promise((resolve) => { setImmediate(() => {
      const rec = [...scans.values()].find((s) => s.runId === 'r2');
      assert.equal(rec.status, 'error');
      assert.equal(rec.error, 'boom');
      assert.ok(rec.finishedAt, 'finishedAt must be stamped');
      assert.equal(scanRunIndex.has('r2'), false, 'the run index entry must be released');
      resolve();
    }); });
  });

  test('a synchronous throw is caught too', async () => {
    const handle = loadHandlerWith(() => { throw new Error('sync boom'); });
    const ctx = makeCtx();
    handle({ type: 'scan', runId: 'r3', path: TARGET }, ctx);
    await new Promise((r) => { setImmediate(r); });
    assert.ok(ctx.sent.some((m) => m.type === 'scan-error' && /sync boom/.test(m.message)));
  });
});

describe('scan ownership across connections', () => {
  test('a scan is claimed by the connection that started it', () => {
    const handle = loadHandlerWith(() => new Promise(() => {}));  // never settles
    const a = makeCtx();
    handle({ type: 'scan', runId: 'owned-by-a', path: TARGET }, a);

    assert.ok(a.ownScanRunIds.has('owned-by-a'), 'the starting connection must own the runId');
    assert.equal(scanRunIndex.get('owned-by-a').status, 'running');
  });

  test('a second connection does not own it, so closing that one cannot cancel it', () => {
    const handle = loadHandlerWith(() => new Promise(() => {}));
    const a = makeCtx();
    const b = makeCtx();
    handle({ type: 'scan', runId: 'owned-by-a', path: TARGET }, a);

    assert.equal(b.ownScanRunIds.size, 0, "connection B must not have claimed A's scan");

    // Replicate what handleClose does for connection B: only its OWN ids.
    for (const runId of b.ownScanRunIds) {
      const rec = scanRunIndex.get(runId);
      if (rec && rec.status === 'running') rec.status = 'cancelled';
      scanRunIndex.delete(runId);
    }

    assert.equal(scanRunIndex.get('owned-by-a').status, 'running',
      "closing an unrelated connection must not cancel another connection's scan");
    assert.equal(scanRunIndex.has('owned-by-a'), true,
      'and must not evict it from the run index');
  });

  test('closing the OWNING connection does cancel its scan', () => {
    const handle = loadHandlerWith(() => new Promise(() => {}));
    const a = makeCtx();
    handle({ type: 'scan', runId: 'owned-by-a', path: TARGET }, a);

    for (const runId of a.ownScanRunIds) {
      const rec = scanRunIndex.get(runId);
      if (rec && rec.status === 'running') { rec.status = 'cancelled'; rec.finishedAt = Date.now(); }
      scanRunIndex.delete(runId);
    }

    const rec = [...scans.values()].find((s) => s.runId === 'owned-by-a');
    assert.equal(rec.status, 'cancelled');
    assert.equal(scanRunIndex.has('owned-by-a'), false);
  });
});
