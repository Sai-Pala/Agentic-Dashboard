'use strict';

/**
 * Mapping Opengrep results onto the engine finding shape.
 *
 * This sits on the scan path and is the whole seam between the new deterministic engine and
 * everything downstream — merge, dedupe, corroboration, adjudication and the triage table all
 * consume the shape produced here. A silent mapping error does not throw; it produces findings
 * that are subtly wrong (a critical rendered as medium, a CWE dropped, a taint span lost), which
 * is exactly the class of bug characterization tests exist to pin.
 *
 * The fixtures are trimmed from a real `opengrep scan --config=p/default --json` run against
 * DVNA, not hand-invented, so the field shapes are the ones the binary actually emits.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const {
  toEngineFinding, mapSeverity, ruleIdOf, titleOf, owaspOf, taintSourceLineOf,
} = require('../src/services/engines/opengrep');

/** A taint-mode result: ERROR severity, HIGH impact, with a dataflow trace. */
const SQLI = {
  check_id: 'javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection',
  path: 'core/appHandler.js',
  start: { line: 11, col: 21 },
  end: { line: 11, col: 26 },
  extra: {
    message: 'Detected SQL statement that is tainted by $EVENT object.',
    severity: 'ERROR',
    lines: '\tdb.sequelize.query(query, {',
    metadata: {
      cwe: ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],
      owasp: ['A01:2017 - Injection', 'A03:2021 - Injection', 'A05:2025 - Injection'],
      confidence: 'HIGH', likelihood: 'HIGH', impact: 'HIGH',
      vulnerability_class: ['SQL Injection'],
    },
    dataflow_trace: {
      taint_source: ['CliLoc', [{ path: 'core/appHandler.js', start: { line: 10, col: 58 } }, 'req.body']],
      taint_sink: ['CliLoc', [{ path: 'core/appHandler.js', start: { line: 11, col: 21 } }, 'query']],
    },
  },
};

describe('severity mapping', () => {
  test('ERROR with HIGH impact is critical, ERROR alone is high', () => {
    // Impact separates the two. Without it, an injection rule and a config nit both land at the
    // same level, and the triage list stops ordering by anything meaningful.
    assert.equal(mapSeverity(SQLI), 'critical');
    assert.equal(mapSeverity({ extra: { severity: 'ERROR', metadata: { impact: 'LOW' } } }), 'high');
    assert.equal(mapSeverity({ extra: { severity: 'ERROR', metadata: {} } }), 'high');
  });

  test('WARNING and INFO map straight across', () => {
    assert.equal(mapSeverity({ extra: { severity: 'WARNING', metadata: {} } }), 'medium');
    assert.equal(mapSeverity({ extra: { severity: 'INFO', metadata: {} } }), 'low');
  });

  test('an unrecognised severity defaults to medium rather than throwing', () => {
    assert.equal(mapSeverity({ extra: {} }), 'medium');
    assert.equal(mapSeverity({}), 'medium');
  });
});

describe('rule identity', () => {
  test('the rule id is the last dot-segment, not the full path', () => {
    // finding.rule is what the triage table GROUPS by, so it has to be the short stable name.
    // The full check_id would make every finding its own group.
    assert.equal(ruleIdOf(SQLI.check_id), 'express-sequelize-injection');
  });

  test('a malformed check_id still yields something usable', () => {
    assert.equal(ruleIdOf('single'), 'single');
    assert.equal(ruleIdOf(''), 'opengrep');
    assert.equal(ruleIdOf(undefined), 'opengrep');
  });

  test('titles are humanised from the rule id', () => {
    assert.equal(titleOf('express-sequelize-injection'), 'Express Sequelize Injection');
    assert.equal(titleOf('template-explicit-unescape'), 'Template Explicit Unescape');
  });
});

describe('taxonomy', () => {
  test('the current OWASP edition wins when a rule lists several', () => {
    assert.equal(owaspOf(SQLI.extra.metadata), 'A03:2021 - Injection');
  });

  test('no owasp metadata yields null, not undefined or a crash', () => {
    assert.equal(owaspOf({}), null);
    assert.equal(owaspOf(undefined), null);
  });
});

describe('taint source extraction', () => {
  test('the source line is read out of the nested dataflow trace', () => {
    // This is what lets readFlowSpan() render the real source→sink span instead of one line.
    // The tuple shape (["CliLoc", [location, text]]) is Opengrep's, not something to simplify.
    assert.equal(taintSourceLineOf(SQLI), 10);
  });

  test('a non-taint finding has no source line rather than a wrong one', () => {
    assert.equal(taintSourceLineOf({ extra: {} }), null);
    assert.equal(taintSourceLineOf({ extra: { dataflow_trace: {} } }), null);
    assert.equal(taintSourceLineOf({ extra: { dataflow_trace: { taint_source: ['CliLoc'] } } }), null);
  });
});

describe('toEngineFinding', () => {
  const f = toEngineFinding(SQLI, '/repo');

  test('produces the fields the finding factory consumes', () => {
    assert.equal(f.rule, 'express-sequelize-injection');
    assert.equal(f.severity, 'critical');
    assert.equal(f.confidence, 'high');
    assert.equal(f.line, 11);
    assert.equal(f.taintSourceLine, 10);
    assert.ok(f.cwe.startsWith('CWE-89'));
    assert.equal(f.owasp, 'A03:2021 - Injection');
  });

  test('relative paths are resolved against the target', () => {
    // The factory calls toRepoRelative() on this, and a relative path there produces a broken
    // location that Fix and live-code Verify cannot act on.
    assert.equal(f.file, '/repo/core/appHandler.js');
  });

  test('an already-absolute path is left alone', () => {
    const abs = toEngineFinding({ ...SQLI, path: '/elsewhere/a.js' }, '/repo');
    assert.equal(abs.file, '/elsewhere/a.js');
  });

  test('verified is null — "not checked", never a fabricated pass', () => {
    // There is no second-pass verifier behind Opengrep. null lands these at needs_review;
    // `false` would mark them suspect and `true` would invent a verification that never ran.
    assert.equal(f.verified, null);
    assert.match(f.verifierNote, /not independently re-checked/i);
  });

  test('the matched line becomes code context', () => {
    assert.deepEqual(f.codeContext, [{ text: '\tdb.sequelize.query(query, {' }]);
  });

  test('a result with no metadata at all still maps without throwing', () => {
    const bare = toEngineFinding({ check_id: 'x.y.bare-rule', path: 'a.js', start: { line: 3 }, extra: {} }, '/repo');
    assert.equal(bare.rule, 'bare-rule');
    assert.equal(bare.title, 'Bare Rule');
    assert.equal(bare.severity, 'medium');
    assert.equal(bare.confidence, 'medium');
    assert.equal(bare.cwe, null);
    assert.equal(bare.owasp, null);
    assert.deepEqual(bare.codeContext, []);
  });
});
