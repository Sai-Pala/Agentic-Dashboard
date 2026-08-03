'use strict';

/**
 * The handoff between the two scan engines.
 *
 * These four behaviours are where the deterministic and reasoning halves meet, and each was
 * previously wired so that one half degraded the other. All of it is pure decision logic — no
 * subprocess, no `claude`, nothing spent — so unlike the passes themselves it can be asserted
 * directly.
 *
 * Each test names the failure it exists to prevent. If one goes red, the question is not "is the
 * assertion stale" but "did the two halves stop cooperating again".
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { buildCoverageSummary, selectForAdjudication } = require('../src/services/engines/plan');
const { findingFromSastEngine } = require('../src/store/findings');

/** Minimal stand-in for the loaded engine — only listBuiltInAgents() is consulted. */
function fakeEngine(names) {
  return {
    listBuiltInAgents: () => names.map((name) => ({
      name, category: 'web', description: `checks ${name}`,
    })),
  };
}

describe('coverage summary reflects what actually ran', () => {
  test('an agent that ran is listed as covered', () => {
    const text = buildCoverageSummary(fakeEngine(['InjectionTester']), {});
    assert.match(text, /InjectionTester/);
    assert.match(text, /do not spend effort re-deriving/);
  });

  test('a SKIPPED agent is named as a gap, never as covered', () => {
    // The regression: listBuiltInAgents() returns every built-in regardless of what ran, so a
    // scan where shouldRun() gated out half the engine still told the reasoning pass all of it
    // was handled — steering the only pass that could still cover those classes away from them.
    const text = buildCoverageSummary(
      fakeEngine(['InjectionTester', 'MobileScanner']),
      { skipped: ['MobileScanner'] },
    );
    const [covered, gaps] = text.split('NOT covered by the deterministic engine');
    assert.ok(gaps, 'a gap section must exist when an agent was skipped');
    assert.doesNotMatch(covered, /MobileScanner/, 'a skipped agent must not appear as covered');
    assert.match(gaps, /MobileScanner/);
    assert.match(covered, /InjectionTester/);
  });

  test('a FAILED agent is a gap too, and its "(reason)" suffix is stripped when matching', () => {
    const text = buildCoverageSummary(
      fakeEngine(['InjectionTester', 'SecretScanner']),
      { failed: ['SecretScanner (timed out after 180000ms)'] },
    );
    const [covered, gaps] = text.split('NOT covered by the deterministic engine');
    assert.doesNotMatch(covered, /SecretScanner/);
    assert.match(gaps, /SecretScanner/);
  });

  test('with nothing skipped or failed there is no gap section at all', () => {
    const text = buildCoverageSummary(fakeEngine(['InjectionTester']), { skipped: [], failed: [] });
    assert.doesNotMatch(text, /NOT covered/);
  });
});

describe('agreement between engines is merged, not resolved by deletion', () => {
  const scan = { id: 'scan-1' };
  const patternFinding = {
    rule: 'TAINT_SQL_INJECTION', title: 'SQL Injection via String Concatenation',
    severity: 'high', confidence: 'high', file: '/repo/src/db.js', line: 20,
    description: 'Concatenated query.', cwe: 'CWE-89', owasp: 'A03', verified: true,
    codeContext: [{ line: 20, text: 'db.query("SELECT " + id)' }],
  };
  const reasoningFinding = {
    title: 'Unauthenticated report export lets any caller dump another tenant\'s rows',
    description: 'The handler trusts a tenant id from the query string and never checks it '
      + 'against the session, so any authenticated user can read any tenant.',
    severity: 'high', file: 'src/db.js:21',
  };

  test('the merged finding keeps the reasoning pass\'s prose', () => {
    // The regression: the reasoning finding was dropped whenever a pattern fired within two
    // lines. The pattern hit carries the structured half; the reasoning finding carries the only
    // explanation of why it matters, and that was the half being thrown away.
    const merged = findingFromSastEngine(patternFinding, scan, '/repo', null, reasoningFinding);
    assert.equal(merged.title, reasoningFinding.title);
    assert.equal(merged.description, reasoningFinding.description);
  });

  test('the merged finding keeps the pattern engine\'s structured fields', () => {
    const merged = findingFromSastEngine(patternFinding, scan, '/repo', null, reasoningFinding);
    assert.equal(merged.rule, 'TAINT_SQL_INJECTION');
    assert.equal(merged.file, 'src/db.js:20');
    assert.ok(merged.code, 'code context from the pattern engine must survive the merge');
  });

  test('independent agreement is recorded as confirmed, by both engines', () => {
    const merged = findingFromSastEngine(patternFinding, scan, '/repo', null, reasoningFinding);
    const triage = merged.runs[0].verdict;
    assert.equal(triage.verdict, 'confirmed');
    assert.equal(triage.source, 'both-engines');
  });

  test('corroboration stays visible even when adjudication sets the source', () => {
    // The regression this prevents: `source` can only hold one value, so a merged finding that
    // was also adjudicated reported source 'reasoning-adjudication' and the merge became
    // invisible — which is exactly how a real merge was first mistaken for "the merge never
    // fired" when checking a live scan.
    const merged = findingFromSastEngine(
      patternFinding, scan, '/repo',
      { verdict: 'confirmed', reasoning: 'Real.' },
      reasoningFinding,
    );
    const triage = merged.runs[0].verdict;
    assert.equal(triage.source, 'reasoning-adjudication');
    assert.equal(triage.corroborated, true, 'the merge must remain visible independently of source');
  });

  test('an uncorroborated finding says so', () => {
    const plain = findingFromSastEngine(patternFinding, scan, '/repo', null, null);
    assert.equal(plain.runs[0].verdict.corroborated, false);
  });

  test('an explicit false-positive adjudication still wins over agreement', () => {
    // Corroboration is two engines pattern-matching the same spot; adjudication is a pass that
    // read the surrounding code. The latter is better evidence and must not be overridden.
    const merged = findingFromSastEngine(
      patternFinding, scan, '/repo',
      { verdict: 'false_positive', reasoning: 'Parameterised two lines above.' },
      reasoningFinding,
    );
    assert.equal(merged.runs[0].verdict.verdict, 'false_positive');
  });

  test('without corroboration nothing changes', () => {
    const plain = findingFromSastEngine(patternFinding, scan, '/repo', null, null);
    assert.equal(plain.title, patternFinding.title);
    assert.equal(plain.runs[0].verdict.source, 'sast-engine-verifier');
  });
});

describe('adjudication slots are spread across rules', () => {
  /** n findings of one rule, as [index, finding] pairs in the shape reasoning.js builds. */
  const entries = (rule, n, from = 0) =>
    Array.from({ length: n }, (_, i) => [from + i, { rule, title: rule, severity: 'high' }]);

  test('one prolific rule cannot starve a rarer one', () => {
    // The regression: slots were filled by static per-pattern severity, so 20 identical `high`
    // unpinned-Action findings sorted first and took every slot — `slice(0, 10)` would select 10
    // Action pins and zero SQL injections, and the SQL findings were then shown unreviewed.
    //
    // The prolific rule may still take more than the cap once the rarer rules have had their
    // share, because leaving adjudication slots unspent helps nobody. What the cap guarantees is
    // that the rare rule is served FIRST.
    const adjudicable = [...entries('CICD_UNPINNED_ACTION', 20), ...entries('TAINT_SQL', 5, 20)];
    const chosen = selectForAdjudication(adjudicable, 10, 3);
    const chosenRules = chosen.map(([, f]) => f.rule);
    assert.equal(
      chosenRules.filter((r) => r === 'TAINT_SQL').length, 3,
      'the rarer rule must get its full per-rule share before the prolific one takes the rest',
    );
    assert.equal(chosen.length, 10, 'the budget is still fully spent');
  });

  test('leftover budget is still spent — the cap shapes priority, it does not shrink the total', () => {
    const adjudicable = entries('ONLY_RULE', 20);
    const chosen = selectForAdjudication(adjudicable, 10, 3);
    assert.equal(chosen.length, 10, 'all 10 slots must be used even with one rule available');
  });

  test('fewer findings than slots selects all of them', () => {
    const adjudicable = [...entries('A', 2), ...entries('B', 2, 2)];
    assert.equal(selectForAdjudication(adjudicable, 40, 3).length, 4);
  });

  test('severity order survives selection', () => {
    // reasoning.js sorts by severity before calling, and maps verdicts back by position, so the
    // returned order must still be the input order.
    const adjudicable = [...entries('A', 5), ...entries('B', 5, 5)];
    const chosen = selectForAdjudication(adjudicable, 8, 3);
    const indices = chosen.map(([i]) => i);
    assert.deepEqual(indices, [...indices].sort((a, b) => a - b));
  });
});
