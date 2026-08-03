/**
 * Phase 0 — CHARACTERIZATION ("golden master") TESTS for the deterministic scan engine.
 * =====================================================================================
 *
 * WHAT THIS IS
 *   These tests do not assert that the engine is *correct*. They assert that the engine
 *   behaves *exactly as it does today* against a frozen fixture, so that a later refactor
 *   of sast-engine/ can prove it changed nothing.
 *
 * HOW TO READ A FAILURE
 *   A failure here means "behaviour changed", NOT necessarily "behaviour broke". If the
 *   change was intentional, re-record the snapshot. If it was not, you just caught a
 *   regression. Either way: look at what moved before deciding which one it was.
 *
 * HOW TO RE-RECORD
 *   On a snapshot mismatch the test prints an "ACTUAL (paste this to re-record)" block to
 *   stderr containing the full normalized value. Copy it over the corresponding
 *   EXPECTED_* constant below and note in the commit message why it changed.
 *
 * FIXTURE
 *   test/fixtures/vuln-app/{app.js,auth.js,db.js} — a tiny deliberately-insecure Express
 *   app. Its line numbers are load-bearing: editing those files shifts every recorded
 *   line and will fail these tests. The fixture files carry a "Frozen" header saying so.
 *
 * MODULE SCOPE
 *   The repo root package.json has no "type" field, so this file is CommonJS, while
 *   sast-engine/ has its own package.json with "type":"module". The engine is therefore
 *   loaded with a dynamic import() from inside async test bodies — the same pattern
 *   server.js uses in loadSastEngine().
 *
 * KNOWN QUIRKS RECORDED (NOT FIXED) BY THESE TESTS — see the individual tests for detail:
 *   - GitHistoryScanner reads the *enclosing* repository's git log, so it emits findings
 *     that have nothing to do with the fixture. Deliberately excluded from the snapshot
 *     because it is not reproducible across checkouts.
 *   - enumerateSurface() finds ZERO routes in the fixture, because its router-object
 *     allowlist does not include `publicRouter`/`adminRouter`.
 *   - NO_RATE_LIMIT_LOGIN fires on a plain `require('./auth')` line.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const FIXTURE_DIR = path.join(__dirname, 'fixtures', 'vuln-app');

// Agents walk every file in the target, so give each test real headroom even though this
// fixture is three small files.
const SLOW = { timeout: 120000 };

// ---------------------------------------------------------------------------
// Engine loading + normalization helpers
// ---------------------------------------------------------------------------

let _enginePromise = null;
function loadEngine() {
  if (!_enginePromise) {
    _enginePromise = Promise.all([
      import('../sast-engine/rules/index.js'),
      import('../sast-engine/enumerate.js'),
    ]).then(([agentsIndex, enumerate]) => ({
      buildOrchestratorAsync: agentsIndex.buildOrchestratorAsync,
      listBuiltInAgents: agentsIndex.listBuiltInAgents,
      enumerateSurface: enumerate.enumerateSurface,
      renderWorklist: enumerate.renderWorklist,
    }));
  }
  return _enginePromise;
}

/**
 * GitHistoryScanner shells out to `git log --all` in the target directory. The fixture is
 * not its own repository, so git resolves upward to Agentic-Dashboard itself and the
 * scanner reports secrets from THIS repo's history — file paths that don't even exist
 * inside the fixture. That output changes with every commit, so it cannot be snapshotted.
 * Recorded (not fixed) by its own test below; excluded from the findings golden master.
 */
const isHistoryFinding = (f) => f.category === 'history';

/**
 * Collapse a raw engine finding to the four fields a refactor must preserve, with an
 * absolute file path rewritten repo-relative to the fixture so the snapshot is portable.
 */
function normalizeFindings(findings) {
  return findings
    .filter((f) => !isHistoryFinding(f))
    .map((f) => ({
      rule: f.rule,
      file: path.relative(FIXTURE_DIR, path.resolve(FIXTURE_DIR, f.file)),
      line: f.line,
      severity: f.severity,
    }))
    .sort(
      (a, b) =>
        a.file.localeCompare(b.file) ||
        a.line - b.line ||
        a.rule.localeCompare(b.rule),
    );
}

/** Run the full deterministic engine once and hand back everything the tests need. */
async function runEngine() {
  const engine = await loadEngine();
  const orchestrator = await engine.buildOrchestratorAsync(FIXTURE_DIR);
  const scope = { fired: false, realTotal: null, skipped: null };
  const result = await orchestrator.runAll(FIXTURE_DIR, {
    onScopeReady: (realTotal, skipped) => {
      scope.fired = true;
      scope.realTotal = realTotal;
      scope.skipped = skipped;
    },
  });
  return { engine, result, scope };
}

// The shared run is memoized: several tests assert different aspects of the same scan, and
// re-running the whole orchestrator per test buys nothing. The determinism test below
// deliberately does NOT use this cache.
let _sharedRunPromise = null;
function sharedRun() {
  if (!_sharedRunPromise) _sharedRunPromise = runEngine();
  return _sharedRunPromise;
}

/**
 * deepStrictEqual, but on mismatch it first dumps the actual value in a paste-ready form.
 * assert's own diff is useless for re-recording a 8-element array of objects.
 */
function assertSnapshot(actual, expected, label) {
  const actualJson = JSON.stringify(actual, null, 2);
  if (actualJson !== JSON.stringify(expected, null, 2)) {
    console.error(
      `\n===== ${label}: ACTUAL (paste this to re-record) =====\n` +
        `${actualJson}\n` +
        `===== end ${label} =====\n`,
    );
  }
  assert.deepStrictEqual(
    actual,
    expected,
    `${label} changed. This is a characterization test: the engine now behaves ` +
      `differently than when this snapshot was recorded. See the ACTUAL block printed ` +
      `above to re-record if the change was intentional.`,
  );
}

// ---------------------------------------------------------------------------
// RECORDED SNAPSHOTS — generated by running the engine, not by hand.
// ---------------------------------------------------------------------------

/**
 * Every non-history finding runAll() produces on the fixture, sorted by file/line/rule.
 *
 * Notes on individual entries — recorded as-is, NOT fixed:
 *   - NO_RATE_LIMIT_LOGIN @ app.js:6 lands on `const { requireAdmin } = require('./auth');`.
 *     There is no login route in the fixture at all; the rule matches on the word "auth".
 *     A textbook false positive, deliberately preserved so a refactor can't quietly change it.
 *   - SQL_INJECTION_TEMPLATE_LITERAL and VIBE_NO_PARAMETERIZED_QUERY both fire on app.js:18.
 *     Two rules, one line — this is the overlap dedupeAdjacentSameRule() does NOT collapse
 *     (it only collapses one rule across adjacent lines, not two rules on the same line).
 */
const EXPECTED_FINDINGS = [
  { rule: 'NO_RATE_LIMIT_LOGIN', file: 'app.js', line: 6, severity: 'medium' },
  { rule: 'PRIVILEGED_SURFACE_AUTHENTICATED_NOT_AUTHORIZED', file: 'app.js', line: 13, severity: 'high' },
  { rule: 'SQL_INJECTION_TEMPLATE_LITERAL', file: 'app.js', line: 18, severity: 'critical' },
  { rule: 'VIBE_NO_PARAMETERIZED_QUERY', file: 'app.js', line: 18, severity: 'critical' },
  { rule: 'TAINT_COMMAND_INJECTION', file: 'app.js', line: 25, severity: 'critical' },
  { rule: 'SECURITY_CONTROL_NEVER_APPLIED', file: 'auth.js', line: 6, severity: 'high' },
  { rule: 'SAFE_HELPER_NEVER_USED', file: 'auth.js', line: 12, severity: 'medium' },
  { rule: 'HARDCODED_SECRET', file: 'auth.js', line: 16, severity: 'high' },
];

/**
 * enumerateSurface() on the fixture.
 *
 * RE-RECORDED after a deliberate fix. This snapshot used to be `[]`, which was the engine's
 * real behaviour: ast-extract.js gated route extraction on a fixed ROUTER_OBJECTS allowlist
 * (`app`, `router`, `server`, `api`, `r`), so the fixture's routes — hanging off
 * `publicRouter` and `adminRouter` — were invisible, while mounts were found because
 * `app.use(...)` matched. That was not a cosmetic hole: this manifest feeds the reasoning
 * review pass's worklist, so on any codebase that names its routers the paid authorization
 * review ran against an empty route list and reported nothing.
 *
 * ast-extract.js now derives the router set per file (collectRouterNames), so all four routes
 * are enumerated. The four entries below ARE the fix — if this ever reverts to `[]`, route
 * extraction has regressed to the allowlist.
 */
const EXPECTED_ROUTES = [
  { method: 'GET', path: '/search', file: 'app.js', line: 17 },
  { method: 'GET', path: '/ping', file: 'app.js', line: 22 },
  { method: 'GET', path: '/safe', file: 'app.js', line: 29 },
  { method: 'GET', path: '/users', file: 'app.js', line: 33 },
];

const EXPECTED_MOUNTS = [
  { prefix: '/admin', mounted: 'adminRouter', middleware: ['requireUser'], file: 'app.js', line: 13 },
  { prefix: '/public', mounted: 'publicRouter', middleware: [], file: 'app.js', line: 14 },
];

/**
 * requireAdmin is defined and exported in auth.js but applied to nothing — callCount 0.
 * safeQuery is the same shape (safe helper nobody calls). requireUser is applied once, at
 * the /admin mount. These three call counts are what drive UnusedGuardAgent's findings
 * above, so they are the load-bearing half of that rule.
 */
const EXPECTED_SECURITY_FUNCTIONS = [
  { name: 'requireUser', file: 'app.js', line: 35, callCount: 1, externalCallCount: 0 },
  { name: 'requireAdmin', file: 'auth.js', line: 6, callCount: 0, externalCallCount: 0 },
  { name: 'safeQuery', file: 'auth.js', line: 12, callCount: 0, externalCallCount: 0 },
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('sast-engine golden master (fixture: test/fixtures/vuln-app)', () => {
  test('runAll() produces the recorded set of findings', SLOW, async () => {
    const { result } = await sharedRun();
    const actual = normalizeFindings(result.findings);

    assertSnapshot(actual, EXPECTED_FINDINGS, 'findings');
    // Guard the count separately so a same-length swap still reads clearly in the output.
    assert.equal(actual.length, 8, 'expected 8 non-history findings on the fixture');
  });

  test('GitHistoryScanner leaks the enclosing repo into the scan (recorded, not fixed)', SLOW, async () => {
    const { result } = await sharedRun();
    const history = result.findings.filter(isHistoryFinding);

    // Not asserting a count or content: `git log --all --max-count=50` runs against
    // Agentic-Dashboard itself (the fixture is not its own git repo), so this output
    // changes with every commit and differs on a fresh clone. What IS invariant, and
    // what the assertion below pins, is the *shape* of the leak: the scanner reports
    // line 0 and a file path resolved under the fixture directory that does not exist
    // there. If a refactor ever scopes this scanner to the target directory, these
    // findings disappear and this test's body becomes vacuously true — which is fine,
    // but the snapshot in EXPECTED_FINDINGS must then be re-checked for new entries.
    for (const f of history) {
      assert.equal(f.line, 0, 'history findings carry no real line number');
      assert.equal(f.rule, 'GIT_HISTORY_SECRET');
      assert.equal(
        require('node:fs').existsSync(path.resolve(FIXTURE_DIR, f.file)),
        false,
        'history finding points at a path that does not exist inside the fixture — ' +
          'confirming it came from the enclosing repository, not the scanned target',
      );
    }
  });

  test('onScopeReady() fires and its totals account for every built-in agent', SLOW, async () => {
    const { engine, scope } = await sharedRun();
    const builtInCount = engine.listBuiltInAgents().length;

    assert.equal(scope.fired, true, 'onScopeReady must fire before any agent completes');
    assert.equal(typeof scope.realTotal, 'number');
    assert.ok(Array.isArray(scope.skipped), 'skipped must be a list of agent names');

    // THE invariant the live scan card's progress bar depends on: its denominator is
    // realTotal, and a slot that can never be filled leaves the bar permanently stalled.
    assert.equal(
      scope.realTotal + scope.skipped.length,
      builtInCount,
      `realTotal (${scope.realTotal}) + skipped (${scope.skipped.length}) must equal the ` +
        `number of registered built-in agents (${builtInCount})`,
    );

    // Recorded values on this fixture (a plain Express app: no AI/mobile/CI/Roblox signals).
    assert.equal(builtInCount, 32, 'built-in agent count changed');
    assert.equal(scope.realTotal, 15, 'number of agents relevant to the fixture changed');
    assert.equal(scope.skipped.length, 17);
  });

  test('PRECISION: the parameterized query on app.js:30 is NOT reported', SLOW, async () => {
    const { result } = await sharedRun();

    // app.js:30 is db.query('SELECT * FROM items WHERE id = ?', [req.query.id], ...) —
    // correctly written code. A scanner that flags this is worse than one that misses a
    // bug, because it trains people to ignore it. This is the single most important
    // assertion in the file.
    const onSafeLine = result.findings.filter(
      (f) => path.basename(f.file || '') === 'app.js' && f.line === 30,
    );
    assert.deepStrictEqual(
      onSafeLine.map((f) => f.rule),
      [],
      'a finding was reported on the deliberately-safe parameterized query at app.js:30',
    );

    // Also assert it more broadly: no injection-category finding anywhere near that line.
    const nearby = result.findings.filter(
      (f) =>
        path.basename(f.file || '') === 'app.js' &&
        f.category === 'injection' &&
        f.line >= 29 &&
        f.line <= 31,
    );
    assert.equal(nearby.length, 0, 'injection finding reported inside the safe /safe handler');
  });

  test('TAINT: cross-line req.query.host -> exec() is reported with its source line', SLOW, async () => {
    const { result } = await sharedRun();

    // app.js:23 `const host = req.query.host;` -> app.js:25 `exec(cmd, ...)`.
    // Source and sink are on different lines, so no line-local pattern agent can see this;
    // only TaintFlowAgent can. Findings carry no `agent` field, so the rule name is the
    // only handle on which agent produced it.
    const taint = result.findings.filter((f) => f.rule === 'TAINT_COMMAND_INJECTION');
    assert.equal(taint.length, 1, 'expected exactly one TAINT_COMMAND_INJECTION finding');

    const f = taint[0];
    assert.equal(path.basename(f.file), 'app.js');
    assert.equal(f.line, 25, 'sink line');
    assert.equal(f.severity, 'critical');
    assert.equal(f.category, 'dataflow');
    assert.equal(f.cwe, 'CWE-78');
    assert.equal(f.taintSourceLine, 23, 'taint source line');
    assert.ok(
      f.taintSourceLine < f.line,
      `taintSourceLine (${f.taintSourceLine}) must precede the sink line (${f.line}) — ` +
        'the agent only fires on a source strictly above its sink, which is what keeps ' +
        'it from restating a same-line finding another agent already reports',
    );
  });

  test('enumerateSurface() returns the recorded routes, mounts and call counts', SLOW, async () => {
    const engine = await loadEngine();
    const surface = engine.enumerateSurface(FIXTURE_DIR);

    const routes = surface.routes
      .map((r) => ({ method: r.method, path: r.path, file: r.file, line: r.line }))
      .sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
    assertSnapshot(routes, EXPECTED_ROUTES, 'surface.routes');

    const mounts = surface.mounts
      .map((m) => ({
        prefix: m.prefix,
        mounted: m.mounted,
        middleware: m.middleware,
        file: m.file,
        line: m.line,
      }))
      .sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
    assertSnapshot(mounts, EXPECTED_MOUNTS, 'surface.mounts');

    const fns = surface.securityFunctions
      .map((f) => ({
        name: f.name,
        file: f.file,
        line: f.line,
        callCount: f.callCount,
        externalCallCount: f.externalCallCount,
      }))
      .sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
    assertSnapshot(fns, EXPECTED_SECURITY_FUNCTIONS, 'surface.securityFunctions');

    // The headline case, asserted directly so it can't be lost in a snapshot re-record:
    // /admin is mounted with requireUser (authentication) while requireAdmin
    // (authorization) is defined and never applied anywhere.
    const requireAdmin = surface.securityFunctions.find((f) => f.name === 'requireAdmin');
    assert.ok(requireAdmin, 'requireAdmin must be enumerated as a security function');
    assert.equal(requireAdmin.callCount, 0, 'requireAdmin is defined but never applied');
    assert.deepStrictEqual(requireAdmin.callSites, []);

    const adminMount = surface.mounts.find((m) => m.prefix === '/admin');
    assert.deepStrictEqual(adminMount.middleware, ['requireUser']);
  });

  test('runAll() is deterministic across repeated runs', SLOW, async () => {
    // Fresh orchestrators on purpose — the memoized sharedRun() would prove nothing here.
    const first = normalizeFindings((await runEngine()).result.findings);
    const second = normalizeFindings((await runEngine()).result.findings);

    assert.deepStrictEqual(
      second,
      first,
      'two identical scans of the same directory produced different findings — the engine ' +
        'has become order- or timing-dependent, which makes every other snapshot here flaky',
    );
    // And that both still match the recorded master, not just each other.
    assertSnapshot(first, EXPECTED_FINDINGS, 'findings (repeat run)');
  });
});
