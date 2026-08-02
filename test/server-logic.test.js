/**
 * Characterization tests for the pure decision logic in server.js.
 *
 * These lock in CURRENT behaviour, not desired behaviour. A failure here means the
 * behaviour changed — which is only OK if that change was the point of the edit. They exist so
 * a later refactor (splitting server.js into modules, collapsing duplicated store families)
 * can prove it changed nothing.
 *
 * Where the recorded behaviour looks like a latent bug, it is asserted AS-IS with a
 * `CONCERN:` comment. Do not "fix" a failing assertion by changing server.js unless the
 * behaviour change is deliberate.
 *
 * Imports come straight from the modules that own each function, so a failure points at one.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { deriveStatus, latestRunByAgent } = require('../src/store/findings/status.js');
const { toListItem } = require('../src/store/findings/list-item.js');
const { csvEscape } = require('../src/store/findings/csv.js');
const { toScanListItem } = require('../src/store/scans.js');
const {
  priorityFromSeverityConfidence,
  normalizeSeverity,
  placeholderTriageRun,
  severityRank,
} = require('../src/services/taxonomy.js');
const { extractVerdict } = require('../src/services/verdict.js');
const {
  dedupeAdjacentSameRule,
  parseFileLine,
  isDuplicateOfReasoning,
} = require('../src/services/merge.js');
const { planReviewShards, renderAdjudicationWorklist } = require('../src/services/engines/plan.js');
const { isAllowedWsOrigin } = require('../src/ws/origin.js');

// ---------------------------------------------------------------------------
// Cross-site WebSocket hijacking guard.
//
// These are NOT characterization tests — they assert intended behaviour for a fix, and they
// failed against the code as it stood before it. The same-origin policy does not cover
// WebSockets, so without this check any page the user visited could open a socket to the
// local server and drive `remediate_fix`, which writes to their repository.
// ---------------------------------------------------------------------------
describe('isAllowedWsOrigin', () => {
  test('accepts our own loopback origins on the served port', () => {
    for (const o of ['http://localhost:4500', 'http://127.0.0.1:4500']) {
      assert.equal(isAllowedWsOrigin(o, 4500), true, `${o} should be allowed`);
    }
  });

  test('rejects an arbitrary website — the cross-site hijacking case', () => {
    for (const o of ['https://evil.example', 'http://evil.example:4500', 'https://attacker.test/path']) {
      assert.equal(isAllowedWsOrigin(o, 4500), false, `${o} must be rejected`);
    }
  });

  test('rejects a different port on loopback — same host is not the same origin', () => {
    assert.equal(isAllowedWsOrigin('http://localhost:3000', 4500), false);
  });

  test('rejects a hostname that merely contains localhost', () => {
    // Guards against a substring-style check ever being reintroduced here, which is the
    // same class of bug as guardKindOf's unanchored privilege regex.
    assert.equal(isAllowedWsOrigin('http://localhost.evil.example:4500', 4500), false);
    assert.equal(isAllowedWsOrigin('http://notlocalhost:4500', 4500), false);
  });

  test('allows a missing Origin — non-browser clients (curl, tests, CLIs)', () => {
    // A browser always sends Origin and script cannot forge it, so absence means the caller
    // is not a browser. Anything running locally outside a browser already has this user's
    // privileges, so rejecting it buys nothing.
    assert.equal(isAllowedWsOrigin(undefined, 4500), true);
    assert.equal(isAllowedWsOrigin('', 4500), true);
  });

  test('rejects an unparseable Origin rather than being lenient', () => {
    assert.equal(isAllowedWsOrigin('not a url', 4500), false);
  });

  test('scheme is part of the origin, so a non-http scheme on the right host is rejected', () => {
    // Found by the WebSocket protocol tests: the check compared hostname and port only, so
    // anything that parsed with the right host/port passed regardless of scheme.
    assert.equal(isAllowedWsOrigin('ws://localhost:4500', 4500), false);
    assert.equal(isAllowedWsOrigin('file://localhost:4500', 4500), false);
    assert.equal(isAllowedWsOrigin('chrome-extension://localhost:4500', 4500), false);
    // http and https are both legitimate page origins for a locally served app.
    assert.equal(isAllowedWsOrigin('http://localhost:4500', 4500), true);
    assert.equal(isAllowedWsOrigin('https://localhost:4500', 4500), true);
  });

  test('an Origin carrying a path did not come from a browser and is rejected', () => {
    // A real Origin header is scheme://host:port with no path component.
    assert.equal(isAllowedWsOrigin('http://localhost:4500/evil', 4500), false);
  });
});

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** A finished agent run, overridable field by field. */
const run = (over = {}) => ({
  runId: 'run-1',
  agent: 'triage',
  status: 'done',
  verdict: null,
  ...over,
});

/** A finding shell — deriveStatus only ever reads `.runs`. */
const withRuns = (...runs) => ({ runs });

/** A sast-engine-shaped finding, as dedupeAdjacentSameRule sees it. */
const detFinding = (file, rule, line) => ({ file, rule, line });

/** "file:rule:line" for readable dedupe assertions. */
const ids = (list) => list.map((f) => `${f.file}:${f.rule}:${f.line}`);

// ---------------------------------------------------------------------------
// deriveStatus — the finding status state machine
// ---------------------------------------------------------------------------

describe('deriveStatus', () => {
  test('a finding with no runs at all is new', () => {
    assert.equal(deriveStatus(withRuns()), 'new');
  });

  test('a run still in flight puts the finding in review', () => {
    assert.equal(deriveStatus(withRuns(run({ status: 'running' }))), 'in_review');
  });

  test('an errored run puts the finding in review rather than surfacing the error as a status', () => {
    assert.equal(deriveStatus(withRuns(run({ status: 'error' }))), 'in_review');
  });

  test('a cancelled run puts the finding in review', () => {
    assert.equal(deriveStatus(withRuns(run({ status: 'cancelled' }))), 'in_review');
  });

  test('a false_positive verdict closes the finding', () => {
    assert.equal(deriveStatus(withRuns(run({ verdict: { verdict: 'false_positive' } }))), 'closed');
  });

  test('a duplicate verdict closes the finding', () => {
    assert.equal(deriveStatus(withRuns(run({ verdict: { verdict: 'duplicate' } }))), 'closed');
  });

  test('verify verdict verified_fixed is its own terminal status', () => {
    assert.equal(
      deriveStatus(withRuns(run({ agent: 'verify', verdict: { verdict: 'verified_fixed' } }))),
      'verified_fixed',
    );
  });

  test('verified_fixed only counts when the verify agent said it', () => {
    // The branch is agent-gated, so the same verdict word from any other agent falls through.
    assert.equal(
      deriveStatus(withRuns(run({ agent: 'remediation', verdict: { verdict: 'verified_fixed' } }))),
      'in_review',
    );
  });

  test('verify verdicts still_vulnerable, partially_fixed and inconclusive all fall through to in_review', () => {
    for (const v of ['still_vulnerable', 'partially_fixed', 'inconclusive']) {
      assert.equal(
        deriveStatus(withRuns(run({ agent: 'verify', verdict: { verdict: v } }))),
        'in_review',
        `verify/${v}`,
      );
    }
  });

  test('a remediation run with corrected_code and a confirmed verdict is remediation_generated', () => {
    assert.equal(
      deriveStatus(withRuns(run({
        agent: 'remediation',
        verdict: { verdict: 'confirmed', corrected_code: 'const q = db.query(sql, [id]);' },
      }))),
      'remediation_generated',
    );
  });

  test('a remediation run with corrected_code and a needs_review verdict is also remediation_generated', () => {
    assert.equal(
      deriveStatus(withRuns(run({
        agent: 'remediation',
        verdict: { verdict: 'needs_review', corrected_code: 'x' },
      }))),
      'remediation_generated',
    );
  });

  test('remediation_generated is checked BEFORE remediation_ready (order guard)', () => {
    // This finding satisfies BOTH branches: agent remediation + corrected_code + confirmed,
    // and confirmed with no next_agent. Swapping the two branch positions would make this
    // 'remediation_ready' instead — that is the regression this test exists to catch.
    const finding = withRuns(run({
      agent: 'remediation',
      verdict: { verdict: 'confirmed', corrected_code: 'fixed()', next_agent: null },
    }));
    assert.equal(deriveStatus(finding), 'remediation_generated');
  });

  test('remediation_generated is checked AFTER the closed branch (order guard)', () => {
    // corrected_code is present, but the verdict is false_positive — closed must win. If the
    // two branches were swapped the corrected_code check would still not fire (it requires
    // confirmed/needs_review), so this pins the *closed* precedence specifically.
    assert.equal(
      deriveStatus(withRuns(run({
        agent: 'remediation',
        verdict: { verdict: 'false_positive', corrected_code: 'fixed()' },
      }))),
      'closed',
    );
  });

  test('remediation_generated is checked AFTER verified_fixed (order guard)', () => {
    // Not reachable in practice (verify never writes corrected_code) but pins the ordering:
    // if the remediation branch moved above the verify branch this would flip.
    assert.equal(
      deriveStatus(withRuns(run({
        agent: 'verify',
        verdict: { verdict: 'verified_fixed', corrected_code: 'x' },
      }))),
      'verified_fixed',
    );
  });

  test('a remediation run whose corrected_code is null falls through to remediation_ready', () => {
    assert.equal(
      deriveStatus(withRuns(run({
        agent: 'remediation',
        verdict: { verdict: 'confirmed', corrected_code: null },
      }))),
      'remediation_ready',
    );
  });

  test('an empty-string corrected_code is treated as no corrected code at all', () => {
    // CONCERN: the check is truthiness, not `!= null`, so a model that returns "" (rather than
    // null) for "no drop-in replacement" is indistinguishable from one that omitted the field.
    // Recorded as-is.
    assert.equal(
      deriveStatus(withRuns(run({
        agent: 'remediation',
        verdict: { verdict: 'confirmed', corrected_code: '' },
      }))),
      'remediation_ready',
    );
  });

  test('confirmed with no next_agent means the pipeline has nothing queued: remediation_ready', () => {
    assert.equal(deriveStatus(withRuns(run({ verdict: { verdict: 'confirmed' } }))), 'remediation_ready');
  });

  test('confirmed WITH a next_agent stays in review because another stage is expected', () => {
    assert.equal(
      deriveStatus(withRuns(run({ verdict: { verdict: 'confirmed', next_agent: 'remediation' } }))),
      'in_review',
    );
  });

  test('needs_review maps to in_review', () => {
    assert.equal(deriveStatus(withRuns(run({ verdict: { verdict: 'needs_review' } }))), 'in_review');
  });

  test('an unrecognised verdict word falls through to the generic in_review default', () => {
    assert.equal(deriveStatus(withRuns(run({ verdict: { verdict: 'wat' } }))), 'in_review');
  });

  test('a completed run with no verdict object at all is in_review, not a crash', () => {
    assert.equal(deriveStatus(withRuns(run({ verdict: null }))), 'in_review');
  });

  test('only the LAST run decides the status, earlier ones are ignored', () => {
    const finding = withRuns(
      run({ verdict: { verdict: 'false_positive' } }),
      run({ verdict: { verdict: 'confirmed' } }),
    );
    assert.equal(deriveStatus(finding), 'remediation_ready');
  });
});

// ---------------------------------------------------------------------------
// dedupeAdjacentSameRule — collapse one condition observed repeatedly, keep distinct sites
// ---------------------------------------------------------------------------

describe('dedupeAdjacentSameRule', () => {
  test('the same rule on consecutive lines of one file collapses to its first occurrence', () => {
    const out = dedupeAdjacentSameRule([
      detFinding('a.js', 'NO_SECURITY_HEADERS', 10),
      detFinding('a.js', 'NO_SECURITY_HEADERS', 11),
      detFinding('a.js', 'NO_SECURITY_HEADERS', 12),
    ]);
    assert.deepEqual(ids(out), ['a.js:NO_SECURITY_HEADERS:10']);
  });

  test('THE SAME RULE ON DISTANT LINES STAYS AS SEPARATE FINDINGS', () => {
    // Three separate SQL injections in one file are three real findings. This is the invariant
    // the whole adjacency test exists to protect.
    const out = dedupeAdjacentSameRule([
      detFinding('db.js', 'SQL_INJECTION', 12),
      detFinding('db.js', 'SQL_INJECTION', 80),
      detFinding('db.js', 'SQL_INJECTION', 200),
    ]);
    assert.deepEqual(ids(out), [
      'db.js:SQL_INJECTION:12',
      'db.js:SQL_INJECTION:80',
      'db.js:SQL_INJECTION:200',
    ]);
  });

  test('different rules on adjacent lines are never collapsed together', () => {
    const out = dedupeAdjacentSameRule([
      detFinding('a.js', 'SQL_INJECTION', 10),
      detFinding('a.js', 'HARDCODED_SECRET', 11),
    ]);
    assert.deepEqual(ids(out), ['a.js:SQL_INJECTION:10', 'a.js:HARDCODED_SECRET:11']);
  });

  test('the same rule on adjacent lines of DIFFERENT files is never collapsed', () => {
    const out = dedupeAdjacentSameRule([
      detFinding('a.js', 'R1', 10),
      detFinding('b.js', 'R1', 11),
    ]);
    assert.deepEqual(ids(out), ['a.js:R1:10', 'b.js:R1:11']);
  });

  test('a gap of exactly 3 lines still counts as adjacent and collapses', () => {
    // Boundary: ADJACENT_RULE_LINES is 3 and the test is `> 3`.
    const out = dedupeAdjacentSameRule([detFinding('a.js', 'R1', 10), detFinding('a.js', 'R1', 13)]);
    assert.deepEqual(ids(out), ['a.js:R1:10']);
  });

  test('a gap of 4 lines is far enough apart to stay two findings', () => {
    const out = dedupeAdjacentSameRule([detFinding('a.js', 'R1', 10), detFinding('a.js', 'R1', 14)]);
    assert.deepEqual(ids(out), ['a.js:R1:10', 'a.js:R1:14']);
  });

  test('a group can never span more than the adjacency window', () => {
    // WAS A BUG (fixed): the comparison ran against the *previous* line rather than the line
    // that opened the group, so a rule firing every <= 3 lines chained arbitrarily far down a
    // file and 10/12/14/16 collapsed into a single finding despite the ends being 6 lines
    // apart. Distance is the whole signal this function relies on to tell "one condition
    // observed repeatedly" from "several distinct sites", so an unbounded chain silently
    // discarded the distinct ones. Now anchored to the group's first line.
    const out = dedupeAdjacentSameRule([
      detFinding('a.js', 'R1', 10),
      detFinding('a.js', 'R1', 12),
      detFinding('a.js', 'R1', 14),
      detFinding('a.js', 'R1', 16),
    ]);
    assert.deepEqual(ids(out), ['a.js:R1:10', 'a.js:R1:14']);
  });

  test('a long runaway chain splits into bounded groups rather than one finding', () => {
    const out = dedupeAdjacentSameRule(
      [10, 12, 14, 16, 18, 20].map((n) => detFinding('a.js', 'R1', n)),
    );
    assert.deepEqual(ids(out), ['a.js:R1:10', 'a.js:R1:14', 'a.js:R1:18']);
  });

  test('a genuinely tight cluster still collapses to one', () => {
    // The fix must not over-correct: hits within the window are still one condition.
    const out = dedupeAdjacentSameRule([
      detFinding('a.js', 'R1', 10),
      detFinding('a.js', 'R1', 11),
      detFinding('a.js', 'R1', 13),
    ]);
    assert.deepEqual(ids(out), ['a.js:R1:10']);
  });

  test('the input ordering is preserved, not the line-sorted grouping order', () => {
    // Grouping sorts by line internally to find adjacency, but the surviving findings come back
    // in the engine's own (severity) order.
    const out = dedupeAdjacentSameRule([
      detFinding('a.js', 'R1', 200),
      detFinding('a.js', 'R1', 10),
      detFinding('a.js', 'R1', 11),
    ]);
    assert.deepEqual(ids(out), ['a.js:R1:200', 'a.js:R1:10']);
  });

  test('findings with no line number are all treated as line 0 and collapse together', () => {
    // CONCERN: a rule with no line info can never produce more than one finding per file.
    const out = dedupeAdjacentSameRule([
      detFinding('a.js', 'R1', undefined),
      detFinding('a.js', 'R1', undefined),
    ]);
    assert.equal(out.length, 1);
  });

  test('an empty finding list comes back empty', () => {
    assert.deepEqual(dedupeAdjacentSameRule([]), []);
  });

  test('a single finding is returned untouched, by identity', () => {
    const f = detFinding('a.js', 'R1', 5);
    const out = dedupeAdjacentSameRule([f]);
    assert.equal(out.length, 1);
    assert.equal(out[0], f);
  });
});

// ---------------------------------------------------------------------------
// priorityFromSeverityConfidence — the deterministic severity+confidence -> priority table
// ---------------------------------------------------------------------------

describe('priorityFromSeverityConfidence', () => {
  // Full matrix as the table currently defines it.
  const MATRIX = [
    ['critical', 'high', 'p0'],
    ['critical', 'medium', 'p0'],
    ['critical', 'low', 'p1'],
    ['high', 'high', 'p0'],
    ['high', 'medium', 'p1'],
    ['high', 'low', 'p1'],
    ['medium', 'high', 'p2'],
    ['medium', 'medium', 'p2'],
    ['medium', 'low', 'p3'],
    ['low', 'high', 'p3'],
    ['low', 'medium', 'p3'],
    ['low', 'low', 'p3'],
    ['informational', 'high', 'p3'],
    ['informational', 'medium', 'p3'],
    ['informational', 'low', 'p3'],
  ];

  for (const [severity, confidence, expected] of MATRIX) {
    test(`${severity} severity at ${confidence} confidence is ${expected}`, () => {
      assert.equal(priorityFromSeverityConfidence(severity, confidence), expected);
    });
  }

  test('only "low" confidence downgrades critical — an unrecognised confidence is treated as high-ish', () => {
    // CONCERN: the branches test `confidence === 'low'` / `=== 'high'` rather than validating
    // the vocabulary, so a typo'd confidence silently takes the more urgent branch for
    // critical (p0) and the less urgent one for high (p1). Recorded as-is.
    assert.equal(priorityFromSeverityConfidence('critical', 'bogus'), 'p0');
    assert.equal(priorityFromSeverityConfidence('high', 'bogus'), 'p1');
    assert.equal(priorityFromSeverityConfidence('medium', 'bogus'), 'p2');
  });

  test('an unrecognised or missing severity falls to p3, same as low/informational', () => {
    assert.equal(priorityFromSeverityConfidence('bogus', 'high'), 'p3');
    assert.equal(priorityFromSeverityConfidence(undefined, 'high'), 'p3');
    assert.equal(priorityFromSeverityConfidence(null, 'low'), 'p3');
  });

  test('severity matching is case-sensitive, so "Critical" is not treated as critical', () => {
    // CONCERN: callers must normalize first (normalizeSeverity does lowercase); this function
    // does not. Recorded as-is.
    assert.equal(priorityFromSeverityConfidence('Critical', 'high'), 'p3');
  });
});

// ---------------------------------------------------------------------------
// normalizeSeverity
// ---------------------------------------------------------------------------

describe('normalizeSeverity', () => {
  test('npm/pip "moderate" is normalized to this app\'s "medium"', () => {
    assert.equal(normalizeSeverity('moderate'), 'medium');
  });

  test('normalization is case-insensitive', () => {
    assert.equal(normalizeSeverity('MODERATE'), 'medium');
    assert.equal(normalizeSeverity('High'), 'high');
  });

  test('every known severity passes through unchanged', () => {
    for (const sev of ['critical', 'high', 'medium', 'low', 'informational']) {
      assert.equal(normalizeSeverity(sev), sev);
    }
  });

  test('an unknown, empty or missing severity defaults to medium', () => {
    // CONCERN: the fallback is medium, not low — an unparseable advisory severity is silently
    // promoted into the middle of the scale rather than the bottom.
    for (const bad of ['bogus', '', null, undefined, 5]) {
      assert.equal(normalizeSeverity(bad), 'medium', String(bad));
    }
  });
});

// ---------------------------------------------------------------------------
// placeholderTriageRun
// ---------------------------------------------------------------------------

describe('placeholderTriageRun', () => {
  test('produces a completed synthetic triage run, so the loop never points at a stage that cannot run', () => {
    const r = placeholderTriageRun('high');
    assert.equal(r.agent, 'triage');
    assert.equal(r.status, 'done');
    assert.equal(typeof r.runId, 'string');
    assert.ok(r.runId.length > 0);
    assert.equal(typeof r.startedAt, 'number');
    assert.equal(typeof r.finishedAt, 'number');
    assert.equal(r.fullText, '');
    assert.equal(typeof r.verdict, 'object');
    assert.notEqual(r.verdict, null);
  });

  test('the verdict is a neutral needs_review at low confidence, tagged manual-placeholder', () => {
    const r = placeholderTriageRun('high');
    assert.deepEqual(r.verdict, {
      verdict: 'needs_review',
      severity_confirmed: 'high',
      confidence: 'low',
      priority: 'p1',
      reasoning: 'No scan or source directory to verify against.',
      owasp: null,
      asvs: null,
      cwe: null,
      nist_800_53: [],
      next_agent: null,
      source: 'manual-placeholder',
    });
  });

  test('priority is derived from the given severity at low confidence, not hardcoded', () => {
    assert.equal(placeholderTriageRun('critical').verdict.priority, 'p1');
    assert.equal(placeholderTriageRun('high').verdict.priority, 'p1');
    assert.equal(placeholderTriageRun('medium').verdict.priority, 'p3');
    assert.equal(placeholderTriageRun('low').verdict.priority, 'p3');
  });

  test('severity is echoed through verbatim, unvalidated', () => {
    // CONCERN: no normalizeSeverity() call here, so whatever the caller passes lands in the
    // verdict as-is.
    assert.equal(placeholderTriageRun('moderate').verdict.severity_confirmed, 'moderate');
  });

  test('each call gets its own runId', () => {
    assert.notEqual(placeholderTriageRun('high').runId, placeholderTriageRun('high').runId);
  });

  test('the synthetic run leaves a finding in_review via deriveStatus', () => {
    assert.equal(deriveStatus({ runs: [placeholderTriageRun('high')] }), 'in_review');
  });
});

// ---------------------------------------------------------------------------
// extractVerdict — pull the first ```json fenced block out of an agent's output
// ---------------------------------------------------------------------------

describe('extractVerdict', () => {
  test('parses a well-formed json fenced block', () => {
    assert.deepEqual(extractVerdict('```json\n{"verdict":"confirmed"}\n```'), { verdict: 'confirmed' });
  });

  test('finds the block even when surrounded by prose on both sides', () => {
    const text = 'Here is what I found.\n\n```json\n{"verdict":"needs_review","cwe":"CWE-89"}\n```\n\nHope that helps.';
    assert.deepEqual(extractVerdict(text), { verdict: 'needs_review', cwe: 'CWE-89' });
  });

  test('text with no fenced json block returns null', () => {
    assert.equal(extractVerdict('I could not determine anything.'), null);
  });

  test('an uppercase ```JSON fence is still parsed', () => {
    // REGRESSION GUARD (was a latent bug, fixed): the fence match was case-sensitive, so a
    // model emitting ```JSON produced verdict null. The run still reported success, so the
    // finding silently got no triage and no status change — a paid agent run that yielded
    // nothing while looking healthy.
    assert.deepEqual(extractVerdict('```JSON\n{"verdict":"confirmed"}\n```'), { verdict: 'confirmed' });
    assert.deepEqual(extractVerdict('```Json\n{"verdict":"confirmed"}\n```'), { verdict: 'confirmed' });
  });

  test('null or undefined input returns null rather than throwing', () => {
    assert.doesNotThrow(() => extractVerdict(null));
    assert.equal(extractVerdict(null), null);
    assert.equal(extractVerdict(undefined), null);
  });

  test('malformed JSON inside the block returns null rather than throwing', () => {
    assert.doesNotThrow(() => extractVerdict('```json\n{oops, not json}\n```'));
    assert.equal(extractVerdict('```json\n{oops, not json}\n```'), null);
  });

  test('when several json blocks are present the FIRST one wins', () => {
    const text = '```json\n{"which":"first"}\n```\nthen\n```json\n{"which":"second"}\n```';
    assert.deepEqual(extractVerdict(text), { which: 'first' });
  });

  test('a top-level JSON array is returned as-is (the scan agent returns one)', () => {
    assert.deepEqual(extractVerdict('```json\n[{"title":"a"}]\n```'), [{ title: 'a' }]);
  });

  test('an unlabelled ``` fence is NOT matched, only ```json', () => {
    assert.equal(extractVerdict('```\n{"verdict":"confirmed"}\n```'), null);
  });

  // NOTE: this used to assert `extractVerdict('```JSON…') === null`, recording the
  // case-sensitive fence as a CONCERN. That bug is now fixed, so the assertion was inverted
  // deliberately (see the uppercase-fence regression guard above) rather than deleted — the
  // behaviour change is intentional and should be visible in the diff.

  test('an unterminated fence yields null rather than a partial parse', () => {
    assert.equal(extractVerdict('```json\n{"a":1}'), null);
  });

  test('empty input returns null', () => {
    assert.equal(extractVerdict(''), null);
  });
});

// ---------------------------------------------------------------------------
// parseFileLine / isDuplicateOfReasoning — the reasoning-vs-deterministic merge comparison
// ---------------------------------------------------------------------------

describe('parseFileLine', () => {
  test('splits the "path:line" convention into path and numeric line', () => {
    assert.deepEqual(parseFileLine('src/routes/a.js:42'), { file: 'src/routes/a.js', line: 42 });
  });

  test('a path with no line yields a null line rather than 0', () => {
    assert.deepEqual(parseFileLine('src/a.js'), { file: 'src/a.js', line: null });
  });

  test('empty, null and undefined all yield a fully null location', () => {
    for (const v of ['', null, undefined]) {
      assert.deepEqual(parseFileLine(v), { file: null, line: null }, String(v));
    }
  });

  test('surrounding whitespace is trimmed', () => {
    assert.deepEqual(parseFileLine('  src/a.js:42  '), { file: 'src/a.js', line: 42 });
  });

  test('line 0 parses as 0, which is falsy but not null', () => {
    assert.deepEqual(parseFileLine('a.js:0'), { file: 'a.js', line: 0 });
  });

  test('with two trailing numbers the LAST is taken as the line', () => {
    assert.deepEqual(parseFileLine('a.js:12:34'), { file: 'a.js:12', line: 34 });
  });

  test('on POSIX a Windows-style backslash path is NOT normalized', () => {
    // CONCERN: the function splits on path.sep and rejoins with '/', which is a no-op when
    // path.sep is already '/'. The stated intent ("a Windows-style path from the model still
    // compares equal") therefore only holds when the server itself runs on Windows — on
    // macOS/Linux a model-emitted `src\a.js` will never match sast-engine's `src/a.js`.
    const parsed = parseFileLine('src\\a.js:7');
    assert.equal(parsed.line, 7);
    assert.equal(parsed.file, process.platform === 'win32' ? 'src/a.js' : 'src\\a.js');
  });
});

describe('isDuplicateOfReasoning', () => {
  const at = (loc) => ({ file: loc });

  test('two hits in the same file within 2 lines are the same issue', () => {
    assert.equal(isDuplicateOfReasoning(at('a.js:10'), [at('a.js:12')]), true);
    assert.equal(isDuplicateOfReasoning(at('a.js:10'), [at('a.js:8')]), true);
    assert.equal(isDuplicateOfReasoning(at('a.js:10'), [at('a.js:10')]), true);
  });

  test('3 lines apart is far enough to be a distinct finding', () => {
    assert.equal(isDuplicateOfReasoning(at('a.js:10'), [at('a.js:13')]), false);
  });

  test('the same line in a different file is never a duplicate', () => {
    assert.equal(isDuplicateOfReasoning(at('a.js:10'), [at('b.js:10')]), false);
  });

  test('a finding with no resolvable line always survives the merge', () => {
    // Business-logic / attack-surface findings usually have no line — nothing to compare.
    assert.equal(isDuplicateOfReasoning(at('a.js'), [at('a.js:10')]), false);
    assert.equal(isDuplicateOfReasoning(at(null), [at('a.js:10')]), false);
  });

  test('a kept finding with no line cannot absorb anything', () => {
    assert.equal(isDuplicateOfReasoning(at('a.js:10'), [at('a.js')]), false);
  });

  test('nothing kept yet means nothing is a duplicate', () => {
    assert.equal(isDuplicateOfReasoning(at('a.js:10'), []), false);
  });
});

// ---------------------------------------------------------------------------
// severityRank
// ---------------------------------------------------------------------------

describe('severityRank', () => {
  test('ranks most severe first, with moderate tied to medium', () => {
    assert.equal(severityRank('critical'), 0);
    assert.equal(severityRank('high'), 1);
    assert.equal(severityRank('medium'), 2);
    assert.equal(severityRank('moderate'), 2);
    assert.equal(severityRank('low'), 3);
    assert.equal(severityRank('informational'), 4);
  });

  test('is case-insensitive', () => {
    assert.equal(severityRank('CRITICAL'), 0);
  });

  test('an unknown or missing severity sorts last, below informational', () => {
    for (const v of ['bogus', '', null, undefined]) {
      assert.equal(severityRank(v), 5, String(v));
    }
  });

  test('sorting a mixed list puts critical first and unknown last', () => {
    const sorted = ['low', 'bogus', 'critical', 'moderate', 'high']
      .sort((a, b) => severityRank(a) - severityRank(b));
    assert.deepEqual(sorted, ['critical', 'high', 'moderate', 'low', 'bogus']);
  });
});

// ---------------------------------------------------------------------------
// csvEscape
// ---------------------------------------------------------------------------

describe('csvEscape', () => {
  test('a value with no comma, quote or newline is emitted bare', () => {
    assert.equal(csvEscape('plain'), 'plain');
  });

  test('a comma forces quoting', () => {
    assert.equal(csvEscape('a,b'), '"a,b"');
  });

  test('an embedded quote is doubled and the field quoted', () => {
    assert.equal(csvEscape('say "hi"'), '"say ""hi"""');
  });

  test('a newline forces quoting', () => {
    assert.equal(csvEscape('line1\nline2'), '"line1\nline2"');
  });

  test('null and undefined become an empty field', () => {
    assert.equal(csvEscape(null), '');
    assert.equal(csvEscape(undefined), '');
  });

  test('non-strings are stringified, including falsy ones', () => {
    assert.equal(csvEscape(0), '0');
    assert.equal(csvEscape(false), 'false');
  });

  test('a carriage return alone does NOT trigger quoting', () => {
    // CONCERN: the test regex is /[",\n]/ — a lone \r (no \n) is emitted unquoted and can
    // break a strict CSV parser.
    assert.equal(csvEscape('a\rb'), 'a\rb');
  });
});

// ---------------------------------------------------------------------------
// latestRunByAgent
// ---------------------------------------------------------------------------

describe('latestRunByAgent', () => {
  test('returns the LAST run of that agent, not the first', () => {
    const runs = [
      { agent: 'triage', status: 'done', verdict: { n: 1 } },
      { agent: 'remediation', status: 'done', verdict: { n: 2 } },
      { agent: 'triage', status: 'error', verdict: { n: 3 } },
    ];
    assert.deepEqual(latestRunByAgent(runs, 'triage'), { status: 'error', verdict: { n: 3 } });
  });

  test('projects only status and verdict, dropping runId and fullText', () => {
    const out = latestRunByAgent([{ agent: 'fix', status: 'done', verdict: null, runId: 'x', fullText: 'y' }], 'fix');
    assert.deepEqual(Object.keys(out), ['status', 'verdict']);
  });

  test('an agent that never ran returns null', () => {
    assert.equal(latestRunByAgent([{ agent: 'triage', status: 'done' }], 'fix'), null);
    assert.equal(latestRunByAgent([], 'fix'), null);
  });
});

// ---------------------------------------------------------------------------
// list-item projections — the shapes the store-family refactor must not change
// ---------------------------------------------------------------------------

describe('toListItem', () => {
  const finding = {
    id: 'f1',
    title: 'SQL injection',
    severity: 'high',
    scanType: 'reasoning',
    rule: 'SQL_INJECTION',
    file: 'db.js:12',
    description: 'concatenated query',
    status: 'in_review',
    createdAt: 5,
    runs: [
      { runId: 'r1', agent: 'triage', status: 'done', verdict: { verdict: 'confirmed' } },
      { runId: 'r2', agent: 'fix', status: 'done', verdict: { verdict: 'applied' } },
    ],
  };

  test('projects a fixed set of keys regardless of which optional fields the finding carries', () => {
    assert.deepEqual(Object.keys(toListItem(finding)), [
      'id', 'title', 'severity', 'scanType', 'rule', 'file', 'description', 'code',
      'packageName', 'packageVersion', 'fixedVersion', 'endpoint', 'method', 'status',
      'createdAt', 'runCount', 'latestRun', 'stageRuns', 'sourceScanId', 'flow',
    ]);
  });

  test('absent optional fields are normalized to null, never left undefined', () => {
    const item = toListItem(finding);
    for (const k of ['code', 'packageName', 'packageVersion', 'fixedVersion', 'endpoint', 'method', 'sourceScanId', 'flow']) {
      assert.equal(item[k], null, k);
    }
  });

  test('latestRun is the last run and runCount is the total', () => {
    const item = toListItem(finding);
    assert.equal(item.runCount, 2);
    assert.deepEqual(item.latestRun, { agent: 'fix', status: 'done', verdict: { verdict: 'applied' } });
  });

  test('stageRuns carries each of the four loop stages independently, null when never run', () => {
    const item = toListItem(finding);
    assert.deepEqual(Object.keys(item.stageRuns), ['triage', 'remediation', 'fix', 'verify']);
    assert.deepEqual(item.stageRuns.triage, { status: 'done', verdict: { verdict: 'confirmed' } });
    assert.deepEqual(item.stageRuns.fix, { status: 'done', verdict: { verdict: 'applied' } });
    assert.equal(item.stageRuns.remediation, null);
    assert.equal(item.stageRuns.verify, null);
  });

  test('a finding with no runs has a null latestRun and a zero runCount', () => {
    const item = toListItem({ ...finding, runs: [] });
    assert.equal(item.latestRun, null);
    assert.equal(item.runCount, 0);
  });
});

describe('toScanListItem', () => {
  test('projects the full scan list-item key set', () => {
    assert.deepEqual(Object.keys(toScanListItem({ findingIds: [] })), [
      'id', 'runId', 'path', 'instruction', 'branch', 'app', 'scanType', 'scope',
      'baseBranch', 'diffFileCount', 'status', 'error', 'findingIds', 'startedAt',
      'finishedAt', 'budgetEnabled', 'reasoningCostUsd', 'agentsRun', 'agentsSkipped',
    ]);
  });

  test('budgetEnabled defaults to true when the field was never set', () => {
    assert.equal(toScanListItem({}).budgetEnabled, true);
    assert.equal(toScanListItem({ budgetEnabled: false }).budgetEnabled, false);
    assert.equal(toScanListItem({ budgetEnabled: true }).budgetEnabled, true);
  });

  test('agentsSkipped is normalized to an array, agentsRun is passed through as-is', () => {
    assert.deepEqual(toScanListItem({}).agentsSkipped, []);
    assert.deepEqual(toScanListItem({ agentsSkipped: ['a'] }).agentsSkipped, ['a']);
    assert.equal(toScanListItem({}).agentsRun, undefined);
  });
});

// ---------------------------------------------------------------------------
// planReviewShards — risk-ordered packing of the review pass's worklist
// ---------------------------------------------------------------------------

describe('planReviewShards', () => {
  const routes = (n, file, middleware = []) => Array.from({ length: n }, () => ({ file, middleware }));

  test('a target with no HTTP surface yields one unscoped shard', () => {
    const out = planReviewShards({ routes: [] }, [], '/t', { maxShards: 6 });
    assert.deepEqual(out, { list: [{ files: null, routeCount: 0 }], totalRoutes: 0, reviewedRoutes: 0, skippedRoutes: 0 });
  });

  test('a missing or malformed surface is treated the same as no routes', () => {
    for (const surface of [null, undefined, {}, { routes: 'nope' }]) {
      assert.deepEqual(planReviewShards(surface, [], '/t', { maxShards: 6 }).list, [{ files: null, routeCount: 0 }]);
    }
  });

  test('routes below the shard size all fit in a single shard', () => {
    const out = planReviewShards({ routes: routes(5, 'a.js') }, [], '/t', { maxShards: 6 });
    assert.deepEqual(out.list, [{ files: ['a.js'], routeCount: 5 }]);
    assert.equal(out.skippedRoutes, 0);
  });

  test('a 31-route fixture stays a single shard (the pre-sharding behaviour is preserved)', () => {
    const out = planReviewShards({ routes: routes(31, 'app.js') }, [], '/t', { maxShards: 6 });
    assert.equal(out.list.length, 1);
    assert.equal(out.reviewedRoutes, 31);
  });

  test('a single file with more routes than the shard size becomes its own oversized shard, never split', () => {
    const out = planReviewShards({ routes: routes(50, 'big.js') }, [], '/t', { maxShards: 6 });
    assert.deepEqual(out.list, [{ files: ['big.js'], routeCount: 50 }]);
    assert.equal(out.skippedRoutes, 0);
  });

  test('routes beyond what maxShards can hold are reported as skipped, not silently dropped', () => {
    const surface = { routes: [...routes(40, 'a.js'), ...routes(40, 'b.js'), ...routes(40, 'c.js')] };
    const out = planReviewShards(surface, [], '/t', { maxShards: 2 });
    assert.equal(out.list.length, 2);
    assert.equal(out.totalRoutes, 120);
    assert.equal(out.reviewedRoutes, 80);
    assert.equal(out.skippedRoutes, 40);
  });

  test('a file with no middleware at all outranks one guarded by a privilege check', () => {
    const surface = { routes: [...routes(30, 'guarded.js', ['requireAdmin']), ...routes(30, 'open.js', [])] };
    const out = planReviewShards(surface, [], '/t', { maxShards: 1 });
    assert.deepEqual(out.list, [{ files: ['open.js'], routeCount: 30 }]);
    assert.equal(out.skippedRoutes, 30);
  });

  test('authenticated-but-not-authorized outranks a properly privileged guard', () => {
    const surface = { routes: [...routes(20, 'authz.js', ['requireAdmin']), ...routes(20, 'authn.js', ['requireUser'])] };
    const out = planReviewShards(surface, [], '/t', { maxShards: 1 });
    assert.deepEqual(out.list[0].files, ['authn.js', 'authz.js']);
  });

  test('dangerous sinks in a file raise its review priority', () => {
    const surface = {
      routes: [...routes(20, 'x.js', ['requireAdmin']), ...routes(20, 'y.js', ['requireAdmin'])],
      sinks: Array.from({ length: 9 }, () => ({ file: 'y.js' })),
    };
    const out = planReviewShards(surface, [], '/t', { maxShards: 1 });
    assert.deepEqual(out.list[0].files, ['y.js', 'x.js']);
  });

  test('existing deterministic findings in a file raise its review priority, matched by relative path', () => {
    const surface = { routes: [...routes(20, 'x.js', ['requireAdmin']), ...routes(20, 'y.js', ['requireAdmin'])] };
    const out = planReviewShards(surface, [{ file: '/t/y.js' }, { file: '/t/y.js' }], '/t', { maxShards: 1 });
    assert.deepEqual(out.list[0].files, ['y.js', 'x.js']);
  });

  test('camelCase predicate middleware (canEdit) counts as a privilege check', () => {
    const surface = { routes: [...routes(10, 'pred.js', ['canEditOrder']), ...routes(10, 'plain.js', ['requireUser'])] };
    const out = planReviewShards(surface, [], '/t', { maxShards: 1 });
    // plain.js scores 2/route (authenticated, not authorized); pred.js scores 0.
    assert.equal(out.list[0].files[0], 'plain.js');
  });
});

// ---------------------------------------------------------------------------
// renderAdjudicationWorklist — prompt text handed to the adjudication pass
// ---------------------------------------------------------------------------

describe('renderAdjudicationWorklist', () => {
  test('renders a finding with an index, relative location, code context and dataflow note', () => {
    const out = renderAdjudicationWorklist([{
      title: 'SQLi',
      rule: 'SQL_INJECTION',
      severity: 'critical',
      file: '/t/src/db.js',
      line: 12,
      description: 'Concatenated   query\n  here',
      codeContext: [{ line: 11, text: 'const q =' }, { line: 12, text: 'db.query(q)' }],
      verified: true,
      taintSourceLine: 9,
    }], '/t');

    assert.match(out, /^\[0\] SQLi\n/);
    assert.match(out, /Location: src\/db\.js:12/);
    assert.match(out, /already re-checked against surrounding code/);
    assert.match(out, /Dataflow: untrusted input enters at line 9, reaches the sink at line 12\./);
    // Description whitespace is collapsed to a single line.
    assert.match(out, /Concatenated query here/);
    // Code lines: 4-space indent + a right-aligned 5-wide line number + " | " + the text.
    assert.match(out, /\n {7}11 \| const q =\n {7}12 \| db\.query\(q\)$/);
  });

  test('a finding with no file, rule or code context degrades to explicit placeholders', () => {
    const out = renderAdjudicationWorklist([{ rule: null, file: null, line: null, description: '', codeContext: [] }], '/t');
    assert.match(out, /^\[0\] Untitled\n/);
    assert.match(out, /Rule: n\/a \| Severity as matched: unknown \| Location: \(no file\)/);
    assert.match(out, /\(no code context captured\)/);
    assert.doesNotMatch(out, /Dataflow:/);
  });

  test('the index is the array position, which is what adjudication verdicts key back to', () => {
    const out = renderAdjudicationWorklist([
      { title: 'a', file: '/t/a.js', line: 1, codeContext: [] },
      { title: 'b', file: '/t/b.js', line: 2, codeContext: [] },
    ], '/t');
    assert.match(out, /\[0\] a/);
    assert.match(out, /\[1\] b/);
  });

  test('an empty finding list renders as an empty string', () => {
    assert.equal(renderAdjudicationWorklist([], '/t'), '');
  });

  test('no dataflow line when the taint source is at or after the sink', () => {
    const out = renderAdjudicationWorklist([{ title: 'x', file: '/t/a.js', line: 5, taintSourceLine: 5, codeContext: [] }], '/t');
    assert.doesNotMatch(out, /Dataflow:/);
  });
});

// ---------------------------------------------------------------------------
// Input validation on the scan message.
//
// These are NOT characterization tests — they assert intended behaviour for two fixes, and both
// failed against the code as it stood before them.
// ---------------------------------------------------------------------------
const { BRANCH_NAME_RE, SCAN_TYPES } = require('../src/config.js');

describe('BRANCH_NAME_RE', () => {
  // baseBranch is interpolated into a git argument as `${baseBranch}...HEAD`. execFileSync means
  // no shell, but git still reads a leading `-` as an OPTION rather than a ref.
  test('accepts the branch names people actually use', () => {
    for (const b of ['main', 'develop', 'feature/add-auth', 'release-1.2.3', 'a_b.c', 'v2', 'user/x.y-z']) {
      assert.equal(BRANCH_NAME_RE.test(b), true, `${b} is a legal branch name and must be accepted`);
    }
  });

  test('rejects anything git would read as an option', () => {
    for (const b of ['-O/tmp/pwned', '--exit-code', '-', '--output', '-p']) {
      assert.equal(BRANCH_NAME_RE.test(b), false, `${b} must not reach git as an argument`);
    }
  });

  test('rejects traversal-shaped values', () => {
    // `..` is illegal in a refname anyway, so nothing valid is lost by excluding it.
    for (const b of ['..', 'a/../b', '../../etc/passwd']) {
      assert.equal(BRANCH_NAME_RE.test(b), false, `${b} must be rejected`);
    }
  });

  test('rejects empty', () => {
    assert.equal(BRANCH_NAME_RE.test(''), false);
  });
});

describe('SCAN_TYPES', () => {
  test("is reasoning-only — every scan is the hybrid, there is one dispatch", () => {
    // Leaving 'sca' here let a hand-crafted WebSocket message run both PAID reasoning passes
    // while the UI labelled the result an "SCA scan".
    assert.deepEqual(SCAN_TYPES, ['reasoning']);
  });

  test("an 'sca' scanType therefore falls back to reasoning rather than being honoured", () => {
    // Mirrors src/ws/scan.js: SCAN_TYPES.includes(msg.scanType) ? msg.scanType : 'reasoning'
    const resolve = (t) => (SCAN_TYPES.includes(t) ? t : 'reasoning');
    assert.equal(resolve('sca'), 'reasoning');
    assert.equal(resolve('reasoning'), 'reasoning');
    assert.equal(resolve(undefined), 'reasoning');
  });

  test('findings keep their own sca kind — a different axis from scan records', () => {
    const { FINDING_SCAN_TYPES } = require('../src/config.js');
    assert.ok(FINDING_SCAN_TYPES.includes('sca'), 'the dependency audit still produces sca findings');
  });
});
