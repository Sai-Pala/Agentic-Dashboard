'use strict';

/**
 * The synthesized `scan-event` frame the deterministic engines emit.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * This module exists because the frame nests four levels deep and is easy to get subtly wrong,
 * and its own header says what a wrong one costs: the client cannot parse it, drops it, and the
 * scan reads as having produced no output. That is a silent failure with no error anywhere —
 * precisely the shape of bug the rest of this suite exists to catch, and it had no test at all.
 *
 * The assertions are on the exact envelope rather than on "an object was sent", because the only
 * thing that makes this frame useful is matching what the console renderer already reads.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { sendScanText } = require('../src/services/engines/emit');

const SCAN = { id: 'scan-1', runId: 'run-1' };

/** Capture what would have gone to the socket. */
function capture() {
  const sent = [];
  return { sent, send: (msg) => sent.push(msg) };
}

describe('sendScanText', () => {
  test('emits exactly one frame, keyed to both the scan and its run', () => {
    const { sent, send } = capture();
    sendScanText(send, SCAN, ['hello']);

    assert.equal(sent.length, 1);
    assert.equal(sent[0].type, 'scan-event');
    // Both ids: the client keys scan frames by scanId, and runId is what cancel bookkeeping and
    // the generic run handlers match on.
    assert.equal(sent[0].scanId, 'scan-1');
    assert.equal(sent[0].runId, 'run-1');
  });

  test('the payload keeps the assistant-text shape the console renderer reads', () => {
    const { sent, send } = capture();
    sendScanText(send, SCAN, ['hello']);

    // The whole point of the module: this nesting is what a real `claude -p` assistant event
    // looks like, so the client needs no separate branch for synthesized output.
    assert.deepEqual(sent[0].event, {
      type: 'assistant',
      message: { content: [{ type: 'text', text: 'hello' }] },
    });
  });

  test('a block of lines becomes one newline-joined text node, not one frame per line', () => {
    const { sent, send } = capture();
    sendScanText(send, SCAN, ['[high] `a.js:1` — One', '[low] `b.js:2` — Two']);

    assert.equal(sent.length, 1, 'callers pass a block; splitting it would reorder against stderr');
    assert.equal(sent[0].event.message.content.length, 1);
    assert.equal(
      sent[0].event.message.content[0].text,
      '[high] `a.js:1` — One\n[low] `b.js:2` — Two',
    );
  });

  test('an empty list still produces a well-formed frame', () => {
    const { sent, send } = capture();
    sendScanText(send, SCAN, []);

    assert.equal(sent.length, 1);
    assert.equal(sent[0].event.message.content[0].text, '');
  });
});
