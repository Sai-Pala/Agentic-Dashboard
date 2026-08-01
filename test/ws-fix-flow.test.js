'use strict';

/**
 * ws-fix-flow.test.js — Phase 0 characterization tests for the write-capable "fix flow"
 * WebSocket messages: `remediate_preview`, `remediate_fix` and `remediate_all`
 * (server.js: handleRemediatePreviewMessage / handleRemediateFixMessage /
 * handleRemediateAllMessage, plus the checkCleanGitTarget safety gate they share).
 *
 * These lock in CURRENT behaviour, not desired behaviour. A failure here means the behaviour
 * CHANGED — which is only acceptable if that change was the point of the edit. Where the
 * recorded behaviour looks like a latent bug it is asserted AS-IS with a `CONCERN:` comment;
 * do not "fix" a failing assertion by editing server.js unless the change is deliberate.
 *
 * ===========================================================================
 * *** TWO HARD CONSTRAINTS — DO NOT "IMPROVE" THESE TESTS PAST THEM ***
 * ===========================================================================
 *
 * (a) COST. This app spawns real `claude -p` CLI child processes. A successful Remediation or
 *     Verify stage costs real money and real minutes. Every test in this file therefore
 *     exercises ONLY validation / precheck / error paths that `return` BEFORE any child
 *     process is spawned. Nothing here may be extended into a path that reaches
 *     spawnAgentStage(). The final test in this file asserts, as a backstop, that the finding
 *     under test still carries nothing but its synthetic `triage` run after the whole suite —
 *     i.e. that no agent stage ever started.
 *
 * (b) WRITES. `remediate_fix` and `remediate_all` can WRITE TO AND MODIFY REAL FILES ON DISK
 *     via applyRemediationPlan(). Every `path` these tests send points at a throwaway
 *     `fs.mkdtempSync` sandbox that is deleted in `after`. NEVER send a path pointing at this
 *     repository (or any real working tree) on a message that could reach the apply step.
 *
 * Both handlers that write are gated by checkCleanGitTarget(), the app's core safety property:
 * a fix may only be applied to a clean git working tree, so every write it makes is
 * inspectable (`git diff`) and revertible (`git checkout`) entirely outside this app. Those
 * gate tests are the most valuable ones here and are built from real temp git repos.
 *
 * The suite boots one real `node server.js` on port 4575 (4500 is the user's dev server;
 * 4574 belongs to the sibling scan-protocol suite) and drives it over a real WebSocket.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const WebSocket = require('ws');

const { startServer } = require('./helpers/server.js');

const PORT = 4575;
// server.js binds slowly on a cold filesystem cache; the helper polls until it answers.
const READY_TIMEOUT_MS = 120_000;
// Every assertion in this file is on a synchronous, pre-spawn error reply, so it arrives
// within milliseconds. This is a deadlock guard, not a budget.
const REPLY_TIMEOUT_MS = 8_000;

let server;
/** Every temp directory created by this suite, removed in `after`. */
const tempDirs = [];
/** The one finding these tests act on. Created over REST — that spawns nothing. */
let findingId;

/** Fixture paths, populated in `before`. */
const fixture = {
  notGit: null,        // a plain directory, no git at all
  dirtyGit: null,      // git repo with a tracked file modified but not committed
  cleanGit: null,      // git repo, one commit, nothing outstanding
  untrackedGit: null,  // git repo with zero commits and one untracked file
  fileNotDir: null,    // a regular file, not a directory
  missing: null,       // a path that does not exist
};

function mkTemp(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function gitCommitAll(cwd, message) {
  git(cwd, ['add', '-A']);
  git(cwd, ['-c', 'user.email=chartest@example.invalid', '-c', 'user.name=char test',
    'commit', '-q', '-m', message]);
}

/**
 * A WebSocket that buffers every server message and lets a test await the next one matching a
 * predicate, with a timeout so a behaviour change can never hang the suite forever.
 *
 * Each test opens its own socket, so the buffer only ever holds that test's traffic and
 * matching by runId (or by message text, for the runId-validation errors that carry none) is
 * unambiguous.
 */
class Client {
  constructor(ws) {
    this.ws = ws;
    this.messages = [];
    this.waiters = [];
    ws.on('message', (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        msg = { type: '__unparseable__', raw: raw.toString() };
      }
      this.messages.push(msg);
      for (const w of [...this.waiters]) {
        if (w.predicate(msg)) {
          this.waiters.splice(this.waiters.indexOf(w), 1);
          clearTimeout(w.timer);
          w.resolve(msg);
        }
      }
    });
  }

  static async open() {
    // The WebSocket handshake is origin-checked (isAllowedWsOrigin): a browser Origin must be
    // one of our own loopback origins on the served port, or the handshake is rejected.
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}`, { origin: `http://localhost:${PORT}` });
    await new Promise((resolve, reject) => {
      ws.once('open', resolve);
      ws.once('error', reject);
    });
    return new Client(ws);
  }

  send(payload) {
    this.ws.send(JSON.stringify(payload));
  }

  /** Resolve with the next (or already-buffered) message matching `predicate`. */
  next(predicate, timeoutMs = REPLY_TIMEOUT_MS) {
    const existing = this.messages.find(predicate);
    if (existing) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const waiter = { predicate, resolve };
      waiter.timer = setTimeout(() => {
        this.waiters.splice(this.waiters.indexOf(waiter), 1);
        reject(new Error(
          `Timed out after ${timeoutMs}ms waiting for a matching message. Received: ` +
          JSON.stringify(this.messages),
        ));
      }, timeoutMs);
      this.waiters.push(waiter);
    });
  }

  /** The next `{type:'error'}` carrying this runId. */
  errorFor(runId) {
    return this.next((m) => m.type === 'error' && m.runId === runId);
  }

  /** The next `{type:'error'}` with no runId field at all (the runId-validation rejections). */
  bareError() {
    return this.next((m) => m.type === 'error' && m.runId === undefined);
  }

  /** Resolve after `ms` with whatever matched, or null — for asserting a NON-reply. */
  async silenceFor(ms, predicate) {
    await new Promise((r) => setTimeout(r, ms));
    return this.messages.find(predicate) || null;
  }

  async close() {
    for (const w of this.waiters) clearTimeout(w.timer);
    this.waiters.length = 0;
    if (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING) {
      await new Promise((resolve) => {
        this.ws.once('close', resolve);
        this.ws.close();
        setTimeout(resolve, 1000);
      });
    }
  }
}

/** Run `fn` with a fresh socket, always closed afterwards. */
async function withClient(fn) {
  const client = await Client.open();
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}

before(async () => {
  fixture.notGit = mkTemp('fixflow-notgit-');
  fs.writeFileSync(path.join(fixture.notGit, 'app.js'), 'const q = "select 1";\n');

  fixture.dirtyGit = mkTemp('fixflow-dirty-');
  git(fixture.dirtyGit, ['init', '-q']);
  fs.writeFileSync(path.join(fixture.dirtyGit, 'app.js'), 'const q = "select 1";\n');
  gitCommitAll(fixture.dirtyGit, 'init');
  fs.writeFileSync(path.join(fixture.dirtyGit, 'app.js'), 'const q = "select 2";\n'); // uncommitted

  fixture.cleanGit = mkTemp('fixflow-clean-');
  git(fixture.cleanGit, ['init', '-q']);
  fs.writeFileSync(path.join(fixture.cleanGit, 'app.js'), 'const q = "select 1";\n');
  gitCommitAll(fixture.cleanGit, 'init');

  fixture.untrackedGit = mkTemp('fixflow-untracked-');
  git(fixture.untrackedGit, ['init', '-q']);
  fs.writeFileSync(path.join(fixture.untrackedGit, 'app.js'), 'const q = "select 1";\n');

  const fileHome = mkTemp('fixflow-file-');
  fixture.fileNotDir = path.join(fileHome, 'not-a-directory.txt');
  fs.writeFileSync(fixture.fileNotDir, 'plain file\n');
  fixture.missing = path.join(fileHome, 'this-path-does-not-exist');

  // Sanity-check the fixtures themselves, so a broken fixture fails here with a clear message
  // rather than as a confusing assertion failure inside a gate test.
  assert.equal(git(fixture.cleanGit, ['status', '--porcelain']).trim(), '',
    'cleanGit fixture must have a clean working tree');
  assert.notEqual(git(fixture.dirtyGit, ['status', '--porcelain']).trim(), '',
    'dirtyGit fixture must have uncommitted changes');
  assert.throws(() => git(fixture.notGit, ['status', '--porcelain']),
    'notGit fixture must not be inside any git repository (check $TMPDIR)');

  server = await startServer({ port: PORT, readyTimeoutMs: READY_TIMEOUT_MS });

  // POST /api/findings spawns nothing. A reasoning finding is created with one synthetic
  // `triage` run already attached (placeholderTriageRun) and NO remediation run — which is
  // exactly the state the "Fix has nothing to apply" guard exists for.
  const res = await fetch(`${server.baseUrl}/api/findings`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      title: 'characterization: fix-flow guard fixture',
      description: 'Created by test/ws-fix-flow.test.js. Never remediated, never fixed.',
      severity: 'high',
      scanType: 'reasoning',
      file: 'app.js:1',
      code: 'const q = "select 1";',
    }),
  });
  assert.equal(res.status, 201);
  const finding = await res.json();
  findingId = finding.id;
  assert.deepEqual(finding.runs.map((r) => r.agent), ['triage'],
    'a manually-added reasoning finding starts with exactly one synthetic triage run');
});

after(async () => {
  if (server) await server.stop();
  for (const dir of tempDirs) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch { /* best effort */ }
  }
});

// ---------------------------------------------------------------------------
// 1. Fix refuses to run when nothing has been proposed to apply.
//
// This is the single most valuable guard in the flow: it is what stops the one write-capable
// stage from running on nothing. Fix makes no LLM call of its own — it applies whatever
// `edit_plan` the most recent `remediation` run proposed — so with no remediation run there is
// no plan, and it must fail loudly rather than silently generating something new.
// ---------------------------------------------------------------------------
describe('remediate_fix: nothing proposed yet', () => {
  test('Fix refuses to apply anything when the finding has never been remediated', async () => {
    await withClient(async (client) => {
      client.send({
        type: 'remediate_fix',
        runId: 'fix-never-remediated',
        findingId,
        path: fixture.cleanGit,
      });
      const err = await client.errorFor('fix-never-remediated');
      assert.equal(err.type, 'error');
      assert.equal(err.findingId, findingId);
      assert.equal(err.message, 'No proposed fix to apply yet — run Remediate first.');
      // No run record is created for a rejected Fix: the server returns before pushing one.
      assert.equal(client.messages.some((m) => m.type === 'started'), false);
    });
  });

  // CONCERN (ordering, asserted as-is): handleRemediateFixMessage checks for a usable
  // `edit_plan` BEFORE it calls checkCleanGitTarget(). So for a finding that has never been
  // remediated, EVERY path shape — non-git, dirty, clean, nonexistent, a plain file — produces
  // the same "No proposed fix" message. The consequence is that `remediate_fix` performs no
  // path validation whatsoever on that branch: a caller can send a completely bogus path and
  // learn nothing about it. It is safe (nothing is written either way), but it means the
  // git-clean gate is UNREACHABLE for remediate_fix until a real remediation run with a plan
  // exists — and a remediation run can only be produced by a real (paid) `claude` call, so
  // these tests cannot exercise that branch of the gate at all. It is covered via
  // `remediate_all` below, which checks the same gate up front.
  for (const [label, key] of [
    ['a directory that is not a git repository', 'notGit'],
    ['a git repository with uncommitted changes', 'dirtyGit'],
    ['a clean git repository', 'cleanGit'],
    ['a path that does not exist', 'missing'],
    ['a path that is a file, not a directory', 'fileNotDir'],
  ]) {
    test(`Fix reports "no proposed fix" before it ever looks at the target path — ${label}`, async () => {
      await withClient(async (client) => {
        const runId = `fix-order-${key}`;
        client.send({ type: 'remediate_fix', runId, findingId, path: fixture[key] });
        const err = await client.errorFor(runId);
        assert.equal(err.message, 'No proposed fix to apply yet — run Remediate first.');
        // Specifically NOT a git-gate or path error, even for a bogus path.
        assert.doesNotMatch(err.message, /git repository|uncommitted changes|Path not found|Not a directory/);
      });
    });
  }

  test('Fix requires a target directory before it checks for a proposed plan', async () => {
    await withClient(async (client) => {
      client.send({ type: 'remediate_fix', runId: 'fix-no-path', findingId });
      const err = await client.errorFor('fix-no-path');
      assert.equal(err.message, 'A target directory is required to apply a fix.');
    });
  });

  test('Fix treats a whitespace-only path as no path at all', async () => {
    await withClient(async (client) => {
      client.send({ type: 'remediate_fix', runId: 'fix-blank-path', findingId, path: '   ' });
      const err = await client.errorFor('fix-blank-path');
      assert.equal(err.message, 'A target directory is required to apply a fix.');
    });
  });
});

// ---------------------------------------------------------------------------
// 2. The clean-git-tree gate — the app's core safety property.
//
// checkCleanGitTarget() refuses any write unless `git status --porcelain` against the target
// comes back both git-tracked and clean, so every edit that lands is inspectable and
// revertible outside this app. `remediate_all` checks it ONCE UP FRONT, before Remediate even
// runs, so the whole chain fails fast rather than paying for a proposal it then cannot apply.
//
// NOTE ON COVERAGE (deliberate, do not "fix"): the CLEAN-repo case is asserted only in the
// negative sense that it produces no gate error via the ordering tests above. Driving
// `remediate_all` at a clean repo would pass the gate and immediately spawn a real `claude`
// remediation stage — constraint (a). checkCleanGitTarget is not exported from server.js, so
// it cannot be unit-tested directly either. If it is ever exported, add a direct positive test.
// ---------------------------------------------------------------------------
describe('remediate_all: clean-git-tree gate', () => {
  test('the full pipeline refuses to start when the target is not a git repository at all', async () => {
    await withClient(async (client) => {
      client.send({
        type: 'remediate_all',
        remediationRunId: 'all-notgit-rem',
        fixRunId: 'all-notgit-fix',
        verifyRunId: 'all-notgit-ver',
        findingId,
        path: fixture.notGit,
      });
      const err = await client.errorFor('all-notgit-rem');
      // The error is reported against the FIRST stage's runId (the only one the client has a
      // placeholder for at click time), not the fix or verify runId.
      assert.equal(err.runId, 'all-notgit-rem');
      assert.equal(err.findingId, findingId);
      assert.ok(
        err.message.startsWith(`Applying a fix requires a git repository — "${fixture.notGit}" doesn't look like one: `),
        `unexpected non-git gate message: ${err.message}`,
      );
      // CONCERN: the tail of this message is Node's own execFileSync failure text, verbatim
      // ("Command failed: git status --porcelain"). It leaks the internal command rather than
      // saying "run git init here", and it will change if the git invocation changes.
      assert.match(err.message, /Command failed: git status --porcelain/);
      assert.equal(client.messages.some((m) => m.type === 'started'), false);
    });
  });

  test('the full pipeline refuses to start when the target tree has uncommitted changes', async () => {
    await withClient(async (client) => {
      client.send({
        type: 'remediate_all',
        remediationRunId: 'all-dirty-rem',
        fixRunId: 'all-dirty-fix',
        verifyRunId: 'all-dirty-ver',
        findingId,
        path: fixture.dirtyGit,
      });
      const err = await client.errorFor('all-dirty-rem');
      assert.equal(
        err.message,
        'Target directory has uncommitted changes. Commit or stash them first so the fix stays cleanly revertible.',
      );
      assert.equal(client.messages.some((m) => m.type === 'started'), false);
    });
  });

  test('an untracked-only working tree counts as dirty and is refused', async () => {
    // `git status --porcelain` reports untracked files too, so a freshly-`git init`ed repo
    // with no commits is "dirty" by this gate's definition. Recorded because it is the state a
    // user is most likely to be in when they first point the app at a scratch directory.
    await withClient(async (client) => {
      client.send({
        type: 'remediate_all',
        remediationRunId: 'all-untracked-rem',
        fixRunId: 'all-untracked-fix',
        verifyRunId: 'all-untracked-ver',
        findingId,
        path: fixture.untrackedGit,
      });
      const err = await client.errorFor('all-untracked-rem');
      assert.equal(
        err.message,
        'Target directory has uncommitted changes. Commit or stash them first so the fix stays cleanly revertible.',
      );
    });
  });

  test('the gate reports a missing path before it shells out to git', async () => {
    await withClient(async (client) => {
      client.send({
        type: 'remediate_all',
        remediationRunId: 'all-missing-rem',
        fixRunId: 'all-missing-fix',
        verifyRunId: 'all-missing-ver',
        findingId,
        path: fixture.missing,
      });
      const err = await client.errorFor('all-missing-rem');
      assert.equal(err.message, `Path not found: ${fixture.missing}`);
    });
  });

  test('the gate rejects a target that is a file rather than a directory', async () => {
    await withClient(async (client) => {
      client.send({
        type: 'remediate_all',
        remediationRunId: 'all-file-rem',
        fixRunId: 'all-file-fix',
        verifyRunId: 'all-file-ver',
        findingId,
        path: fixture.fileNotDir,
      });
      const err = await client.errorFor('all-file-rem');
      assert.equal(err.message, `Not a directory: ${fixture.fileNotDir}`);
    });
  });

  test('the full pipeline requires a target directory at all', async () => {
    await withClient(async (client) => {
      client.send({
        type: 'remediate_all',
        remediationRunId: 'all-nopath-rem',
        fixRunId: 'all-nopath-fix',
        verifyRunId: 'all-nopath-ver',
        findingId,
      });
      const err = await client.errorFor('all-nopath-rem');
      assert.equal(err.message, 'A target directory is required to run the full pipeline.');
    });
  });
});

// ---------------------------------------------------------------------------
// 3. remediate_preview is read-only: a directory check, and no git gate.
//
// Confirmed from server.js (handleRemediatePreviewMessage): its only path check is
// `fs.statSync(targetPath).isDirectory()`. There is NO checkCleanGitTarget call and no
// confirmation, deliberately — Remediate never writes anything (it is spawned with
// `--allowedTools Read,Grep,Glob` and only proposes an `edit_plan` in its verdict). The Fix
// stage is the separate, later step that applies it.
//
// Only the failing directory checks are exercised here. A preview against a REAL directory
// would pass validation and immediately spawn `claude` — constraint (a).
// ---------------------------------------------------------------------------
describe('remediate_preview: path validation only (no git gate)', () => {
  test('Remediate rejects a target path that does not exist', async () => {
    await withClient(async (client) => {
      client.send({ type: 'remediate_preview', runId: 'prev-missing', findingId, path: fixture.missing, context: 'x' });
      const err = await client.errorFor('prev-missing');
      assert.equal(err.message, `Path not found: ${fixture.missing}`);
      assert.equal(client.messages.some((m) => m.type === 'started'), false);
    });
  });

  test('Remediate rejects a target path that is a file rather than a directory', async () => {
    await withClient(async (client) => {
      client.send({ type: 'remediate_preview', runId: 'prev-file', findingId, path: fixture.fileNotDir, context: 'x' });
      const err = await client.errorFor('prev-file');
      assert.equal(err.message, `Not a directory: ${fixture.fileNotDir}`);
    });
  });

  test('Remediate requires a target directory', async () => {
    await withClient(async (client) => {
      client.send({ type: 'remediate_preview', runId: 'prev-nopath', findingId, context: 'x' });
      const err = await client.errorFor('prev-nopath');
      assert.equal(err.message, 'A target directory is required to propose a fix.');
    });
  });

  test('Remediate treats a whitespace-only path as no path at all', async () => {
    await withClient(async (client) => {
      client.send({ type: 'remediate_preview', runId: 'prev-blank', findingId, path: '\t \n' });
      const err = await client.errorFor('prev-blank');
      assert.equal(err.message, 'A target directory is required to propose a fix.');
    });
  });

  // CONCERN (asserted as-is): a NON-git directory is a perfectly acceptable target for
  // Remediate — no gate error is produced — even though the Fix stage that would apply its
  // proposal can never succeed there. The user can therefore pay for a proposal that is
  // structurally unappliable. Recorded here by NOT sending the message (doing so would spawn
  // `claude`); the behaviour follows directly from handleRemediatePreviewMessage having no
  // checkCleanGitTarget call, which the ordering tests above corroborate for remediate_all.
});

// ---------------------------------------------------------------------------
// 4. Unknown / missing findingId, for all three message types.
// ---------------------------------------------------------------------------
describe('unknown finding', () => {
  test('Remediate rejects a findingId the store has never seen', async () => {
    await withClient(async (client) => {
      client.send({ type: 'remediate_preview', runId: 'nf-preview', findingId: 'no-such-finding', path: fixture.cleanGit });
      const err = await client.errorFor('nf-preview');
      assert.equal(err.message, 'Unknown finding.');
      assert.equal(err.findingId, 'no-such-finding');
    });
  });

  test('Fix rejects a findingId the store has never seen', async () => {
    await withClient(async (client) => {
      client.send({ type: 'remediate_fix', runId: 'nf-fix', findingId: 'no-such-finding', path: fixture.cleanGit });
      const err = await client.errorFor('nf-fix');
      assert.equal(err.message, 'Unknown finding.');
    });
  });

  test('the full pipeline rejects a findingId the store has never seen, before the git gate', async () => {
    await withClient(async (client) => {
      client.send({
        type: 'remediate_all',
        remediationRunId: 'nf-all-rem',
        fixRunId: 'nf-all-fix',
        verifyRunId: 'nf-all-ver',
        findingId: 'no-such-finding',
        // A path that WOULD fail the git gate, proving the finding lookup happens first.
        path: fixture.notGit,
      });
      const err = await client.errorFor('nf-all-rem');
      assert.equal(err.message, 'Unknown finding.');
      assert.doesNotMatch(err.message, /git repository/);
    });
  });

  test('an omitted findingId is reported as an unknown finding, echoed back as null', async () => {
    await withClient(async (client) => {
      client.send({ type: 'remediate_fix', runId: 'nf-omitted', path: fixture.cleanGit });
      const err = await client.errorFor('nf-omitted');
      assert.equal(err.message, 'Unknown finding.');
      // CONCERN (asserted as-is): `msg.findingId ? String(msg.findingId) : null` coerces a
      // missing findingId to null and echoes null back, so the client cannot distinguish
      // "you forgot the id" from "that id is gone". Same message either way.
      assert.equal(err.findingId, null);
    });
  });
});

// ---------------------------------------------------------------------------
// 5. runId validation (RUN_ID_RE = /^[a-zA-Z0-9_-]+$/).
//
// runIds are keys into the `children` / `runIndex` maps, so a permissive one is a real
// correctness (and, historically, path-safety) hazard.
// ---------------------------------------------------------------------------
describe('runId validation', () => {
  const badRunIds = [
    ['containing a space', 'bad id'],
    ['containing a dot', 'bad.id'],
    ['containing a slash', 'bad/id'],
    ['attempting path traversal', '../escape'],
    ['empty', ''],
    ['whitespace only', '   '],
  ];

  for (const [label, runId] of badRunIds) {
    test(`Remediate rejects a runId ${label}`, async () => {
      await withClient(async (client) => {
        client.send({ type: 'remediate_preview', runId, findingId, path: fixture.cleanGit });
        const err = await client.bareError();
        assert.equal(err.message, 'Invalid or missing run id.');
      });
    });

    test(`Fix rejects a runId ${label}`, async () => {
      await withClient(async (client) => {
        client.send({ type: 'remediate_fix', runId, findingId, path: fixture.cleanGit });
        const err = await client.bareError();
        assert.equal(err.message, 'Invalid or missing run id.');
      });
    });
  }

  test('Fix rejects an entirely omitted runId', async () => {
    await withClient(async (client) => {
      client.send({ type: 'remediate_fix', findingId, path: fixture.cleanGit });
      const err = await client.bareError();
      assert.equal(err.message, 'Invalid or missing run id.');
    });
  });

  test('the full pipeline rejects the set if ANY of its three run ids is invalid', async () => {
    // Each of the three is validated; a single bad one fails the whole message.
    const cases = [
      { remediationRunId: 'bad id', fixRunId: 'ok-fix', verifyRunId: 'ok-ver' },
      { remediationRunId: 'ok-rem', fixRunId: 'bad id', verifyRunId: 'ok-ver' },
      { remediationRunId: 'ok-rem', fixRunId: 'ok-fix', verifyRunId: 'bad id' },
      { remediationRunId: 'ok-rem', fixRunId: 'ok-fix' }, // verifyRunId omitted entirely
    ];
    for (const ids of cases) {
      await withClient(async (client) => {
        client.send({ type: 'remediate_all', ...ids, findingId, path: fixture.notGit });
        const err = await client.bareError();
        // Note the plural: a distinct string from the single-stage handlers' message.
        assert.equal(err.message, 'Invalid or missing run id(s).');
      });
    }
  });

  // CONCERN (asserted as-is above): the runId-validation rejection is the ONLY error in these
  // handlers sent WITHOUT a `runId` or `findingId` field — every later error carries both. A
  // client that correlates precheck failures by runId (index.html's `precheckRunIds`) has
  // nothing to match this reply against, so an invalid runId can surface as silence in the UI.
  test('the runId rejection carries neither runId nor findingId, unlike every later error', async () => {
    await withClient(async (client) => {
      client.send({ type: 'remediate_fix', runId: 'bad id', findingId, path: fixture.cleanGit });
      const err = await client.bareError();
      assert.deepEqual(Object.keys(err).sort(), ['message', 'type']);
    });
  });

  test('a valid runId shape is accepted and the message proceeds to the next check', async () => {
    // Proves the regex is not rejecting legitimate ids: this one gets past runId validation
    // and lands on the finding lookup instead.
    await withClient(async (client) => {
      const runId = 'Run_9-ABC-xyz_123';
      client.send({ type: 'remediate_fix', runId, findingId: 'no-such-finding', path: fixture.cleanGit });
      const err = await client.errorFor(runId);
      assert.equal(err.message, 'Unknown finding.');
    });
  });
});

// ---------------------------------------------------------------------------
// 6. Message-envelope behaviour shared by the fix-flow types.
// ---------------------------------------------------------------------------
describe('message envelope', () => {
  test('a malformed (non-JSON) message is reported rather than crashing the socket', async () => {
    await withClient(async (client) => {
      client.ws.send('{not json');
      const err = await client.next((m) => m.type === 'error' && m.message === 'Malformed message.');
      assert.equal(err.message, 'Malformed message.');
      // The connection survives: a following valid message still gets its normal reply.
      client.send({ type: 'remediate_fix', runId: 'after-malformed', findingId, path: fixture.cleanGit });
      const next = await client.errorFor('after-malformed');
      assert.equal(next.message, 'No proposed fix to apply yet — run Remediate first.');
    });
  });

  test('an unrecognised message type is silently ignored, with no reply at all', async () => {
    // CONCERN (asserted as-is): the dispatcher falls through to `if (msg.type !== 'run') return;`
    // so a typo'd type (e.g. `remediate_fixx`) produces no error and no acknowledgement. A
    // client that renamed a message type would see the UI hang on an optimistic placeholder
    // rather than fail.
    await withClient(async (client) => {
      client.send({ type: 'remediate_fixx', runId: 'typo-run', findingId, path: fixture.cleanGit });
      const reply = await client.silenceFor(1200, (m) => m.runId === 'typo-run' || m.type === 'error');
      assert.equal(reply, null, `expected silence, got ${JSON.stringify(reply)}`);
    });
  });
});

// ---------------------------------------------------------------------------
// 7. Backstop: after every error path above, nothing ran and nothing was written.
//
// This is the assertion that enforces constraints (a) and (b) for the whole file. If a future
// edit turns any test above into a path that reaches spawnAgentStage() or
// applyRemediationPlan(), this fails.
// ---------------------------------------------------------------------------
describe('no side effects', () => {
  test('no agent stage ever started: the finding still carries only its synthetic triage run', async () => {
    const res = await fetch(`${server.baseUrl}/api/findings/${findingId}`);
    assert.equal(res.status, 200);
    const finding = await res.json();
    assert.deepEqual(finding.runs.map((r) => r.agent), ['triage'],
      'a remediation/fix/verify run appeared — some test reached a real agent stage');
    assert.equal(finding.runs[0].status, 'done');
  });

  test('no fixture working tree was modified by any rejected fix attempt', async () => {
    // The clean repo is still clean, and the dirty one is dirty in exactly the way it started:
    // nothing in this suite reached applyRemediationPlan().
    assert.equal(git(fixture.cleanGit, ['status', '--porcelain']).trim(), '');
    assert.equal(
      git(fixture.dirtyGit, ['status', '--porcelain']).trim().replace(/\s+/g, ' '),
      'M app.js',
    );
    assert.equal(fs.readFileSync(path.join(fixture.cleanGit, 'app.js'), 'utf8'), 'const q = "select 1";\n');
  });

  test('the server never logged spawning a claude child for these runs', () => {
    // Weak but cheap: a failed `claude` spawn surfaces in the server log. There should be no
    // trace of one, because no test here got past validation.
    assert.doesNotMatch(server.output(), /Failed to spawn claude/);
  });
});
