'use strict';

/**
 * CHARACTERIZATION TESTS — WebSocket protocol.
 *
 * These tests describe what the server DOES today, not what it SHOULD do. A failure here means
 * observable WebSocket behaviour changed — that is the signal, not a bug report. Several things
 * asserted below are arguably wrong (see the `CONCERN:` comments); they are pinned deliberately
 * so the upcoming refactor — which collapses the four near-identical in-memory store families
 * (scans / per-finding runs) and their per-family WS
 * message names into one factory — can prove it changed nothing, including the warts.
 *
 * *** COST CONSTRAINT — DO NOT "IMPROVE" THESE TESTS INTO STARTING A REAL RUN ***
 * A successful `scan` spawns a real `claude -p` CLI
 * process: roughly $5 and ~6 minutes of wall clock per full scan, charged to a human. Every
 * message sent from this file is therefore chosen to hit a validation branch that `return`s
 * BEFORE `spawn('claude', ...)` is ever reached:
 *   - a target path that does not exist            -> `<family>-error`, returns before spawn
 *   - a target path that is a file, not a directory-> `<family>-error`, returns before spawn
 *   - an empty/absent target path                  -> `<family>-error`, returns before spawn
 *   - a runId failing ^[a-zA-Z0-9_-]+$             -> error, returns before anything else
 *   - a `run` whose agent name is invalid/unknown  -> error, returns before spawn
 * NEVER send one of these message types with a real directory. If you are adding a case and are
 * not certain it returns early, read the handler in server.js and confirm first.
 * The suite also asserts, at the end, that no scan record was created at all — the cheap
 * tripwire for "something actually started".
 *
 * Run: node --test test/ws-scan-protocol.test.js
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const WebSocket = require('ws');

const { startServer } = require('./helpers/server.js');

// 4574 is this file's port. Another characterization file owns 4575; the app's own default
// (4500) is whatever the developer happens to be running locally, so it is never used here.
const PORT = 4574;
const ORIGIN = `http://localhost:${PORT}`;

// A path that cannot exist. Under /private/tmp with a port-scoped suffix so a parallel test
// file can never create it out from under us.
const MISSING_DIR = `/private/tmp/agentic-dashboard-no-such-dir-${PORT}`;
// A path that exists and is definitively NOT a directory: this very file.
const A_FILE = __filename;

let server;
let wsUrl;

before(async () => {
  server = await startServer({ port: PORT, readyTimeoutMs: 150_000 });
  wsUrl = `ws://127.0.0.1:${PORT}`;
}, { timeout: 180_000 });

after(async () => {
  // Must run even if a test threw, or an orphan node process keeps holding 4574.
  if (server) await server.stop();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Open a client socket and buffer everything it receives.
 *
 * Resolves once the handshake succeeds; rejects with `{ statusCode }` attached when the server
 * refuses the upgrade (which is how origin enforcement surfaces to a client).
 */
function connect({ origin } = {}) {
  return new Promise((resolve, reject) => {
    const opts = {};
    if (origin !== undefined) opts.origin = origin;
    const ws = new WebSocket(wsUrl, opts);

    const messages = [];
    const waiters = [];

    ws.on('message', (raw) => {
      const text = raw.toString();
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { __unparseable: text };
      }
      messages.push(parsed);
      for (const w of waiters.slice()) {
        if (w.predicate(parsed)) {
          waiters.splice(waiters.indexOf(w), 1);
          w.resolve(parsed);
        }
      }
    });

    ws.on('unexpected-response', (_req, res) => {
      const err = new Error(`handshake rejected with ${res.statusCode}`);
      err.statusCode = res.statusCode;
      reject(err);
    });
    ws.on('error', (err) => reject(err));

    ws.on('open', () => {
      resolve({
        ws,
        messages,
        send: (obj) => ws.send(JSON.stringify(obj)),
        sendRaw: (data) => ws.send(data),
        /**
         * Resolve with the first buffered-or-future message matching `predicate`.
         * Scans already-received messages first, so a fast server reply can never be missed
         * by a waiter registered a tick later. Always rejects on timeout — never hangs.
         */
        waitFor: (predicate, { timeout = 4000, label = 'message' } = {}) => {
          const found = messages.find(predicate);
          if (found) return Promise.resolve(found);
          return new Promise((res, rej) => {
            const waiter = { predicate, resolve: res };
            waiters.push(waiter);
            setTimeout(() => {
              const i = waiters.indexOf(waiter);
              if (i === -1) return; // already resolved
              waiters.splice(i, 1);
              rej(new Error(
                `Timed out after ${timeout}ms waiting for ${label}. `
                + `Received so far: ${JSON.stringify(messages)}`,
              ));
            }, timeout).unref();
          });
        },
        close: () => new Promise((res) => {
          if (ws.readyState === WebSocket.CLOSED) return res();
          ws.once('close', res);
          ws.close();
        }),
      });
    });
  });
}

/** Open a socket with the normal allowed origin. */
const connectOk = () => connect({ origin: ORIGIN });

/** Assert a handshake is refused, and report the HTTP status the client saw. */
async function expectHandshakeRejected(origin) {
  let client = null;
  try {
    client = await connect({ origin });
  } catch (err) {
    return err;
  }
  await client.close();
  assert.fail(`Expected origin ${JSON.stringify(origin)} to be rejected, but the socket opened.`);
}

const byRunId = (type, runId) => (m) => m.type === type && m.runId === runId;

// ---------------------------------------------------------------------------
// 1. Origin enforcement (end-to-end, through verifyClient)
// ---------------------------------------------------------------------------

describe('WebSocket origin enforcement', () => {
  test('a browser on the app\'s own loopback origin is allowed to connect', async () => {
    const client = await connect({ origin: ORIGIN });
    assert.equal(client.ws.readyState, WebSocket.OPEN);
    await client.close();
  });

  test('127.0.0.1 on the app\'s own port is treated as the same origin as localhost', async () => {
    const client = await connect({ origin: `http://127.0.0.1:${PORT}` });
    assert.equal(client.ws.readyState, WebSocket.OPEN);
    await client.close();
  });

  test('the IPv6 loopback literal on the app\'s own port is allowed', async () => {
    const client = await connect({ origin: `http://[::1]:${PORT}` });
    assert.equal(client.ws.readyState, WebSocket.OPEN);
    await client.close();
  });

  test('a cross-site origin is refused at the handshake with 401', async () => {
    const err = await expectHandshakeRejected('https://evil.example');
    assert.equal(err.statusCode, 401);
  });

  test('a different loopback port is refused — localhost alone does not make it ours', async () => {
    // 4500 is the app's own default port, i.e. the most plausible confusable neighbour.
    const err = await expectHandshakeRejected(`http://localhost:4500`);
    assert.equal(err.statusCode, 401);
  });

  test('a loopback origin with no port at all is refused', async () => {
    const err = await expectHandshakeRejected('http://localhost');
    assert.equal(err.statusCode, 401);
  });

  test('a subdomain of localhost is refused', async () => {
    const err = await expectHandshakeRejected(`http://evil.localhost:${PORT}`);
    assert.equal(err.statusCode, 401);
  });

  test('an unparseable Origin header is refused', async () => {
    const err = await expectHandshakeRejected('not-a-url');
    assert.equal(err.statusCode, 401);
  });

  test('the literal string "null" Origin (sandboxed iframe / file://) is refused', async () => {
    // Worth pinning explicitly: `null` is a URL-shaped-looking value that is NOT parseable as
    // one, so it falls through the same catch as any other garbage rather than being special-cased.
    const err = await expectHandshakeRejected('null');
    assert.equal(err.statusCode, 401);
  });

  test('a non-browser client sending no Origin at all is allowed', async () => {
    // Deliberate, and documented in server.js: anything running locally outside a browser
    // already has this user's privileges. This is also what lets these tests connect.
    const client = await connect();
    assert.equal(client.ws.readyState, WebSocket.OPEN);
    await client.close();
  });

  test('REGRESSION: a non-http scheme on the right host and port is refused', async () => {
    // WAS A CONCERN (fixed): isAllowedWsOrigin() compared hostname and port only, never
    // `parsed.protocol`, so an origin that is genuinely *different* per the web platform's own
    // definition — scheme is part of an origin — was accepted as ours.
    await assert.rejects(() => connect({ origin: `ws://localhost:${PORT}` }));
    await assert.rejects(() => connect({ origin: `file://localhost:${PORT}` }));
  });

  test('https on the same host and port is still accepted', async () => {
    // http and https are both legitimate page origins for a locally served app, so the scheme
    // check must not become an http-only allowlist.
    const httpsClient = await connect({ origin: `https://localhost:${PORT}` });
    assert.equal(httpsClient.ws.readyState, WebSocket.OPEN);
    await httpsClient.close();
  });

  test('REGRESSION: an Origin carrying a path is refused', async () => {
    // WAS A CONCERN (fixed): `http://localhost:4574/some/path` is not a well-formed Origin at
    // all — a browser serializes an origin as scheme://host:port with no path — but URL
    // parsing discarded the path and the host+port check then passed.
    await assert.rejects(() => connect({ origin: `${ORIGIN}/some/path` }));
  });
});

// ---------------------------------------------------------------------------
// 2. Per-family validation errors (the duplication the refactor collapses)
// ---------------------------------------------------------------------------
//
// Each of the three whole-directory message families has its own error message type, chosen so
// a runId collision between families cannot route one family's message into another's client
// handler. The three handlers are otherwise line-for-line the same shape — which is exactly
// why the shapes below are pinned character-for-character.

describe('scan message validation (returns before any claude process is spawned)', () => {
  let client;
  before(async () => { client = await connectOk(); });
  after(async () => { if (client) await client.close(); });

  test('a scan of a path that does not exist answers scan-error naming the path', async () => {
    client.send({ type: 'scan', runId: 'scan-missing-1', path: MISSING_DIR });
    const msg = await client.waitFor(byRunId('scan-error', 'scan-missing-1'), { label: 'scan-error' });
    assert.deepEqual(msg, {
      type: 'scan-error',
      runId: 'scan-missing-1',
      message: `Path not found: ${MISSING_DIR}`,
    });
    // No `scanId` key at all: the scan record is only created after validation passes.
    assert.equal('scanId' in msg, false);
  });

  test('a scan of a file rather than a directory answers scan-error naming the path', async () => {
    client.send({ type: 'scan', runId: 'scan-file-1', path: A_FILE });
    const msg = await client.waitFor(byRunId('scan-error', 'scan-file-1'), { label: 'scan-error' });
    assert.deepEqual(msg, {
      type: 'scan-error',
      runId: 'scan-file-1',
      message: `Not a directory: ${A_FILE}`,
    });
  });

  test('a scan with an empty path answers scan-error asking for one', async () => {
    client.send({ type: 'scan', runId: 'scan-empty-1', path: '' });
    const msg = await client.waitFor(byRunId('scan-error', 'scan-empty-1'), { label: 'scan-error' });
    assert.deepEqual(msg, {
      type: 'scan-error',
      runId: 'scan-empty-1',
      message: 'A target directory path is required.',
    });
  });

  test('a scan with no path field at all is identical to an empty path', async () => {
    client.send({ type: 'scan', runId: 'scan-nopath-1' });
    const msg = await client.waitFor(byRunId('scan-error', 'scan-nopath-1'), { label: 'scan-error' });
    assert.equal(msg.message, 'A target directory path is required.');
  });

  test('a failed scan does not reserve its runId — the same runId can be reused immediately', async () => {
    client.send({ type: 'scan', runId: 'scan-reuse-1', path: MISSING_DIR });
    await client.waitFor(byRunId('scan-error', 'scan-reuse-1'), { label: 'first scan-error' });
    // Same runId again. Validation fails before `scanRunIndex.set()`, so nothing was registered
    // and this is NOT answered with "This runId is already active."
    const before = client.messages.length;
    client.send({ type: 'scan', runId: 'scan-reuse-1', path: MISSING_DIR });
    await sleep(400);
    const second = client.messages.slice(before);
    assert.equal(second.length, 1);
    assert.equal(second[0].message, `Path not found: ${MISSING_DIR}`);
  });
});
// ---------------------------------------------------------------------------
// 3. runId validation
// ---------------------------------------------------------------------------

describe('runId validation (^[a-zA-Z0-9_-]+$)', () => {
  let client;
  before(async () => { client = await connectOk(); });
  after(async () => { if (client) await client.close(); });

  const BAD_RUN_IDS = [
    ['a traversal-shaped runId', '../etc'],
    ['a runId containing a space', 'a b'],
    ['an empty runId', ''],
    ['a runId containing a slash', 'a/b'],
    ['a runId containing a dot', 'a.b'],
  ];

  for (const [label, runId] of BAD_RUN_IDS) {
    test(`scan refuses ${label} with a GENERIC error, not scan-error`, async () => {
      const before = client.messages.length;
      client.send({ type: 'scan', runId, path: MISSING_DIR });
      await sleep(350);
      const got = client.messages.slice(before);
      assert.equal(got.length, 1, `expected exactly one reply, got ${JSON.stringify(got)}`);
      // CONCERN: every OTHER scan validation failure answers `scan-error`, but an invalid runId
      // answers the generic `error` type used by per-finding runs. A client listening only for
      // `scan-error` (which is what the distinct-type-name design tells it to do) sees the scan
      // simply never respond. It also carries no `runId` — necessarily, since the runId is the
      // thing that was invalid — so it cannot be correlated back to the request that caused it.
      // is an inconsistency between the three near-identical handlers, not a deliberate rule.
      assert.deepEqual(got[0], { type: 'error', message: 'Invalid or missing runId.' });
    });
  }

  test('a scan message with no runId field at all is treated as an invalid runId', async () => {
    const before = client.messages.length;
    client.send({ type: 'scan', path: MISSING_DIR });
    await sleep(350);
    const got = client.messages.slice(before);
    assert.deepEqual(got, [{ type: 'error', message: 'Invalid or missing runId.' }]);
  });

  test('the run message refuses an invalid runId before it even looks at the agent name', async () => {
    const before = client.messages.length;
    // A perfectly valid agent name here; the runId check comes first, so it is never reached.
    client.send({ type: 'run', runId: 'a b', agent: 'no_such_agent_xyz' });
    await sleep(350);
    const got = client.messages.slice(before);
    assert.deepEqual(got, [{ type: 'error', message: 'Invalid or missing runId.' }]);
  });

  test('runIds are validated after trimming, so surrounding whitespace is accepted', async () => {
    // String(msg.runId).trim() runs before the regex test, so "  ok-1  " becomes "ok-1" and
    // passes — and the reply is keyed to the TRIMMED value, not what the client sent.
    client.send({ type: 'scan', runId: '  trimmed-1  ', path: MISSING_DIR });
    const msg = await client.waitFor(byRunId('scan-error', 'trimmed-1'), { label: 'trimmed scan-error' });
    assert.equal(msg.runId, 'trimmed-1');
  });
});

// ---------------------------------------------------------------------------
// 4. Agent-name validation on the generic `run` message
// ---------------------------------------------------------------------------

describe('agent-name validation on the run message (the name is joined into a filesystem path)', () => {
  let client;
  before(async () => { client = await connectOk(); });
  after(async () => { if (client) await client.close(); });

  const BAD_AGENTS = [
    ['a path traversal', '../../etc/passwd'],
    ['a bare ..', '..'],
    ['a nested path', 'agents/verify'],
    ['an absolute path', '/etc/passwd'],
    ['a name carrying the .md extension the server appends itself', 'verify.md'],
    ['an empty name', ''],
    ['a name with a null byte', 'verify\u0000'],
  ];
  // DANGER, for whoever edits this list next: the handler does `String(msg.agent).trim()` BEFORE
  // testing the regex, so a name like `'verify '` (trailing SPACE) trims down to the real
  // `verify` agent, passes validation, and spawns a real, paid `claude -p` run. Every entry
  // above must still be invalid AFTER trimming — a NUL qualifies, trim() does not strip it.

  for (const [label, agent] of BAD_AGENTS) {
    test(`${label} is refused before any file is read or process spawned`, async () => {
      const runId = `agent-bad-${BAD_AGENTS.findIndex((e) => e[1] === agent)}`;
      client.send({ type: 'run', runId, agent, context: 'irrelevant' });
      const msg = await client.waitFor(byRunId('error', runId), { label: `error for agent ${JSON.stringify(agent)}` });
      assert.deepEqual(msg, {
        type: 'error',
        runId,
        message: `Invalid agent name: ${agent}`,
      });
      // CONCERN (informational, not a fix): the rejected name is echoed straight back into the
      // message. Harmless for a local single-user tool, but it does mean attacker-controlled
      // text reaches the client verbatim — worth remembering if this UI ever renders it as HTML.
    });
  }

  test('a well-formed but non-existent agent name is refused as Unknown, not Invalid', async () => {
    // Distinct branch: passes the regex, fails fs.existsSync on agents/<name>.md. Still returns
    // before spawn, which is why it is safe to send here.
    client.send({ type: 'run', runId: 'agent-unknown-1', agent: 'no_such_agent_xyz', context: 'x' });
    const msg = await client.waitFor(byRunId('error', 'agent-unknown-1'), { label: 'unknown-agent error' });
    assert.deepEqual(msg, {
      type: 'error',
      runId: 'agent-unknown-1',
      message: 'Unknown agent: no_such_agent_xyz',
    });
  });

  // NOTE: there is deliberately NO test here for a VALID agent name (verify / remediation).
  // That path spawns `claude -p` and costs real money. Do not add one.
});

// ---------------------------------------------------------------------------
// 5. cancel
// ---------------------------------------------------------------------------

describe('cancel', () => {
  let client;
  before(async () => { client = await connectOk(); });
  after(async () => { if (client) await client.close(); });

  test('cancelling a runId the server has never seen is silently harmless', async () => {
    const before = client.messages.length;
    client.send({ type: 'cancel', runId: 'never-existed-anywhere' });
    await sleep(400);
    // No acknowledgement of any kind — cancel never replies, even on the happy path.
    assert.deepEqual(client.messages.slice(before), []);
    assert.equal(client.ws.readyState, WebSocket.OPEN);
  });

  test('cancel with no runId at all is silently harmless', async () => {
    const before = client.messages.length;
    client.send({ type: 'cancel' });
    await sleep(400);
    assert.deepEqual(client.messages.slice(before), []);
    assert.equal(client.ws.readyState, WebSocket.OPEN);
  });

  test('cancel is not runId-validated — a traversal-shaped runId is accepted and ignored', async () => {
    // CONCERN (recorded, not fixed): the cancel branch runs BEFORE the RUN_ID_RE check, and does
    // its own `String(msg.runId || '')` with no validation. Nothing unsafe follows from it today
    // (the value is only ever used as a Map key), but it is the one message type where the
    // "every runId from a client message is validated" invariant stated in CLAUDE.md's security
    // posture does not actually hold.
    const before = client.messages.length;
    client.send({ type: 'cancel', runId: '../../etc/passwd' });
    await sleep(400);
    assert.deepEqual(client.messages.slice(before), []);
    assert.equal(client.ws.readyState, WebSocket.OPEN);
  });

  test('the socket still serves normal messages after a no-op cancel', async () => {
    client.send({ type: 'scan', runId: 'after-cancel-1', path: MISSING_DIR });
    const msg = await client.waitFor(byRunId('scan-error', 'after-cancel-1'), { label: 'scan-error after cancel' });
    assert.equal(msg.type, 'scan-error');
  });

  // NOT COVERED HERE: cancel's actual bookkeeping (flipping a run/scan record to 'cancelled',
  // deleting the scanRunIndex entry, killing `children` entries and a scan's module children).
  // Reaching it through this socket would mean getting past the validation gates above, which
  // immediately spawns a real `claude -p` run costing real money.
  //
  // A seam does exist, though: `runIndex` and `scanRunIndex` are plain requires from
  // src/store/, so a fake in-flight record can be written directly. ws-scan-lifecycle.test.js
  // uses exactly that, plus a require.cache stub for the scanner, to cover the failure path and
  // per-connection scan ownership without spawning anything. Extend that file, not this one.
});

// ---------------------------------------------------------------------------
// 6. Unknown / malformed messages
// ---------------------------------------------------------------------------

describe('unknown and malformed messages never take the connection down', () => {
  let client;
  before(async () => { client = await connectOk(); });
  after(async () => { if (client) await client.close(); });

  test('non-JSON text gets a single "Malformed message." error and the socket stays open', async () => {
    const before = client.messages.length;
    client.sendRaw('this is not json at all');
    await sleep(400);
    assert.deepEqual(client.messages.slice(before), [{ type: 'error', message: 'Malformed message.' }]);
    assert.equal(client.ws.readyState, WebSocket.OPEN);
  });

  test('a binary frame is treated as malformed rather than crashing the parser', async () => {
    const before = client.messages.length;
    client.sendRaw(Buffer.from([0x00, 0x01, 0x02, 0xff]));
    await sleep(400);
    assert.deepEqual(client.messages.slice(before), [{ type: 'error', message: 'Malformed message.' }]);
    assert.equal(client.ws.readyState, WebSocket.OPEN);
  });

  test('valid JSON with an unrecognised type is silently ignored', async () => {
    const before = client.messages.length;
    client.send({ type: 'totally_unknown_message_type', runId: 'unknown-type-1' });
    await sleep(400);
    // CONCERN: no reply at all. `if (msg.type !== 'run') return;` is the last branch, so anything
    // unrecognised is dropped without an error — a client that mistypes a message type (or talks
    // to a server that no longer supports it) waits forever with no signal. Contrast with
    // malformed JSON, which does get an error back.
    assert.deepEqual(client.messages.slice(before), []);
    assert.equal(client.ws.readyState, WebSocket.OPEN);
  });

  test('valid JSON with no type field at all is silently ignored', async () => {
    const before = client.messages.length;
    client.send({ runId: 'no-type-1', path: MISSING_DIR });
    await sleep(400);
    assert.deepEqual(client.messages.slice(before), []);
    assert.equal(client.ws.readyState, WebSocket.OPEN);
  });

  test('a null type is silently ignored', async () => {
    const before = client.messages.length;
    client.send({ type: null });
    await sleep(400);
    assert.deepEqual(client.messages.slice(before), []);
    assert.equal(client.ws.readyState, WebSocket.OPEN);
  });

  test('a JSON array (not an object) is accepted as parseable and then ignored', async () => {
    const before = client.messages.length;
    client.sendRaw('[1,2,3]');
    await sleep(400);
    // Parses fine, has no `.type`, falls through to the same silent drop.
    assert.deepEqual(client.messages.slice(before), []);
    assert.equal(client.ws.readyState, WebSocket.OPEN);
  });

  test('a well-formed message sent after all of that garbage still gets its normal reply', async () => {
    // The point of this whole block: nothing above wedged the connection.
    client.send({ type: 'scan', runId: 'still-alive-1', path: MISSING_DIR });
    const msg = await client.waitFor(byRunId('scan-error', 'still-alive-1'), { label: 'post-garbage scan-error' });
    assert.equal(msg.message, `Path not found: ${MISSING_DIR}`);
    assert.equal(client.ws.readyState, WebSocket.OPEN);
  });

  test('the server process is still up and serving HTTP after every malformed frame above', async () => {
    const res = await fetch(`${server.baseUrl}/api/findings`);
    assert.equal(res.ok, true);
  });
});

// ---------------------------------------------------------------------------
// 7. Concurrency: two sockets, no cross-talk
// ---------------------------------------------------------------------------

describe('two concurrent connections', () => {
  let a;
  let b;
  before(async () => {
    a = await connectOk();
    b = await connectOk();
  });
  after(async () => {
    if (a) await a.close();
    if (b) await b.close();
  });

  test('each socket receives only its own errors, keyed to its own runIds', async () => {
    a.send({ type: 'scan', runId: 'sockA-scan', path: MISSING_DIR });
    b.send({ type: 'scan', runId: 'sockB-scan', path: MISSING_DIR });

    await a.waitFor(byRunId('scan-error', 'sockA-scan'), { label: 'A scan-error' });
    await b.waitFor(byRunId('scan-error', 'sockB-scan'), { label: 'B scan-error' });

    // Nothing addressed to the other socket ever arrived here.
    assert.equal(a.messages.some((m) => String(m.runId || '').startsWith('sockB-')), false,
      `socket A saw socket B's traffic: ${JSON.stringify(a.messages)}`);
    assert.equal(b.messages.some((m) => String(m.runId || '').startsWith('sockA-')), false,
      `socket B saw socket A's traffic: ${JSON.stringify(b.messages)}`);
  });

  test('the same runId used on both sockets is not a conflict — active-run tracking is per-connection', async () => {
    // `children` is created fresh inside each wss.on('connection') callback, so two tabs can use
    // identical runIds without colliding. (Both requests still fail validation here, so neither
    // ever registers anything — but the reply each socket gets is its own.)
    a.send({ type: 'scan', runId: 'shared-runid', path: MISSING_DIR });
    b.send({ type: 'scan', runId: 'shared-runid', path: MISSING_DIR });

    const fromA = await a.waitFor(byRunId('scan-error', 'shared-runid'), { label: 'A shared scan-error' });
    const fromB = await b.waitFor(byRunId('scan-error', 'shared-runid'), { label: 'B shared scan-error' });
    assert.deepEqual(fromA, fromB);
    assert.equal(a.messages.filter((m) => m.runId === 'shared-runid').length, 1);
    assert.equal(b.messages.filter((m) => m.runId === 'shared-runid').length, 1);
  });

  test('closing one socket leaves the other fully functional', async () => {
    const doomed = await connectOk();
    await doomed.close();
    a.send({ type: 'scan', runId: 'survivor-1', path: MISSING_DIR });
    const msg = await a.waitFor(byRunId('scan-error', 'survivor-1'), { label: 'survivor scan-error' });
    assert.equal(msg.type, 'scan-error');
  });
});

// ---------------------------------------------------------------------------
// Cost tripwire — must be last.
// ---------------------------------------------------------------------------

describe('cost tripwire', () => {
  test('no scan record was created by this entire suite', async () => {
    // Every message above is supposed to fail validation before its store record is written and
    // before `spawn('claude', ...)`. A non-empty array means a real (paid) run was started by
    // this test file, and the offending test must be fixed — not this assertion.
    const scans = await fetch(`${server.baseUrl}/api/scans`).then((r) => r.json());
    assert.deepEqual(scans, [], 'a scan record exists — something started a real scan');
  });

  test('no finding and no agent run was created — the store is still empty', async () => {
    // The findings store boots EMPTY (seedFindings() has been removed), so any finding at all
    // means a scan completed, and any non-triage stage run means a `run` message got past
    // agent-name validation and spawned claude. Both are paid operations.
    const findings = await fetch(`${server.baseUrl}/api/findings`).then((r) => r.json());
    assert.equal(Array.isArray(findings), true);
    assert.deepEqual(findings, [], 'a finding exists — something completed a real scan');

    for (const f of findings) {
      // Unreachable while the assertion above holds; kept so this stays a meaningful check if
      // boot-time seeding is ever reintroduced. `stageRuns` always carries all four keys, so
      // only the non-null ones count as real runs.
      const realStages = Object.entries(f.stageRuns || {})
        .filter(([, run]) => run !== null && run !== undefined)
        .map(([stage]) => stage);
      assert.deepEqual(
        realStages.filter((stage) => stage !== 'triage'),
        [],
        `finding ${f.id} has non-triage stage runs (${realStages.join(', ')}) — a real agent run was started`,
      );
    }
  });
});
