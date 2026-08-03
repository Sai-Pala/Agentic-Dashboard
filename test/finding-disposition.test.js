'use strict';

/**
 * What the app did to a finding after an engine reported it.
 *
 * Every one of these was previously silent, and the silence was the bug. A severity the
 * adjudicator rewrote was displayed as if the engine had assigned it. Five sibling matches folded
 * into one row left no trace anywhere in the app. A finding closed as a false positive said
 * "closed" without saying who decided.
 *
 * The assertion that matters most is the LAST one: a severity that was NOT applied must not be
 * reported as a change. `severity_confirmed` on a reasoning finding sits in the verdict beside a
 * `severity` that still disagrees with it — calling that a downgrade asserts a change to a row
 * that never happened.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { findingFromSastEngine, findingFromLLMScan } = require('../src/store/findings');
const { groupAdjacentSameRule, dedupeAdjacentSameRule } = require('../src/services/merge');

const SCAN = { id: 'scan-1' };
const PATTERN = {
  rule: 'SQL_INJECTION', title: 'SQL injection', severity: 'critical', confidence: 'high',
  file: '/repo/src/db.js', line: 12, description: 'concatenated query', verified: true,
};

describe('severity rewrites', () => {
  test('an adjudicator downgrade records both ends and the direction', () => {
    const f = findingFromSastEngine(PATTERN, SCAN, '/repo', { verdict: 'confirmed', severity: 'low' });
    assert.equal(f.severity, 'low', 'the downgrade is applied to the finding');
    assert.deepEqual(f.disposition, {
      severityFrom: 'critical',
      severityTo: 'low',
      severityDirection: 'down',
      severityChangedBy: 'the adjudicator',
      severityApplied: true,
    });
  });

  test('an upgrade is recorded as an upgrade', () => {
    const f = findingFromSastEngine({ ...PATTERN, severity: 'low' }, SCAN, '/repo',
      { verdict: 'confirmed', severity: 'critical' });
    assert.equal(f.disposition.severityDirection, 'up');
  });

  test('no adjudication means no disposition at all', () => {
    // The common case must add nothing to the wire shape.
    assert.equal(findingFromSastEngine(PATTERN, SCAN, '/repo').disposition, null);
  });

  test('an adjudicator that agrees on severity records no change', () => {
    const f = findingFromSastEngine(PATTERN, SCAN, '/repo', { verdict: 'confirmed', severity: 'critical' });
    assert.equal(f.disposition, null);
  });

  test('a reasoning severity that was NOT applied is not reported as a downgrade', () => {
    // THE point of severityApplied. The finding still shows 'critical'; only the verdict says
    // 'low'. Labelling this "Severity ↓ critical → low" would claim the row was changed.
    const f = findingFromLLMScan({
      title: 'Broken access control', description: 'no authz check', severity: 'critical',
      severity_confirmed: 'low', verdict: 'confirmed', file: 'src/a.js:4',
    }, SCAN);
    assert.equal(f.severity, 'critical', 'the row is unchanged');
    assert.equal(f.disposition.severityApplied, false);
    assert.equal(f.disposition.severityFrom, 'critical');
    assert.equal(f.disposition.severityTo, 'low');
  });
});

describe('closures', () => {
  test('a false positive names who closed it', () => {
    const f = findingFromSastEngine(PATTERN, SCAN, '/repo', { verdict: 'false_positive' });
    assert.equal(f.status, 'closed');
    assert.equal(f.disposition.closedAs, 'false_positive');
    assert.equal(f.disposition.closedBy, 'the adjudicator');
  });

  test('a duplicate is closed and labelled as one', () => {
    const f = findingFromLLMScan({
      title: 'Dup', description: 'same as above', severity: 'medium', verdict: 'duplicate', file: 'src/a.js:1',
    }, SCAN);
    assert.equal(f.status, 'closed');
    assert.equal(f.disposition.closedAs, 'duplicate');
  });

  test('a confirmed finding carries no closure', () => {
    const f = findingFromSastEngine(PATTERN, SCAN, '/repo', { verdict: 'confirmed' });
    assert.equal(f.disposition, null);
  });
});

describe('corroboration and collapse', () => {
  test('agreement between the engines is flagged', () => {
    const f = findingFromSastEngine(PATTERN, SCAN, '/repo', null,
      { title: 'SQLi in the user lookup', description: 'id flows unsanitised into the query' });
    assert.equal(f.disposition.corroborated, true);
  });

  test('a finding records how many siblings were folded into it', () => {
    const f = findingFromSastEngine(PATTERN, SCAN, '/repo', null, null, 4);
    assert.equal(f.disposition.collapsed, 4);
  });
});

describe('adjacent-rule grouping reports what it absorbed', () => {
  const at = (line) => ({ file: 'src/a.js', rule: 'XSS', line, severity: 'high' });

  test('the survivor carries a count of the hits it stands for', () => {
    // 10, 11, 12 collapse into 10; 40 is far enough away to stand alone.
    const { kept, absorbed } = groupAdjacentSameRule([at(10), at(11), at(12), at(40)]);
    assert.equal(kept.length, 2);
    assert.equal(absorbed.get(kept[0]), 2, 'two hits folded into the first');
    assert.equal(absorbed.get(kept[1]), 0, 'the distant one absorbed nothing');
  });

  test('distinct sites of one rule absorb nothing', () => {
    // The load-bearing invariant of the collapse: three SQL injections in one file are three.
    const { kept, absorbed } = groupAdjacentSameRule([at(10), at(50), at(90)]);
    assert.equal(kept.length, 3);
    for (const f of kept) assert.equal(absorbed.get(f), 0);
  });

  test('the old single-return helper still behaves identically', () => {
    // dedupeAdjacentSameRule is characterization-tested elsewhere; this only pins that
    // refactoring it into a delegate did not change what it returns.
    const input = [at(10), at(11), at(12), at(40)];
    assert.deepEqual(dedupeAdjacentSameRule(input), groupAdjacentSameRule(input).kept);
  });
});
