/**
 * The three functions that turn engine output into Finding records.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * These sit on the scan path but were untested, because two of the three consume output from a
 * `claude -p` run and the suite must never trigger one (see the cost tripwire in the WS tests).
 * That gap let a real break ship: findingFromLLMScan imported SEVERITIES from src/config, where
 * it does not exist — it lives in services/taxonomy. Every call threw a TypeError, so any Hybrid
 * Scan producing a reasoning finding would have crashed at finding-creation time.
 *
 * Nothing else caught it. The golden test covers only the deterministic engine, and the REST and
 * WebSocket suites never get far enough to build a finding.
 *
 * So the first thing each test here does is call the factory with a realistic payload. Simply
 * not throwing is most of the value; the assertions on shape are the rest.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const {
  findingFromSastEngine,
  findingFromDepVuln,
  findingFromLLMScan,
} = require('../src/store/findings');

const SCAN = { id: 'scan-1' };
const latestTriage = (f) => f.runs.filter((r) => r.agent === 'triage').pop();

describe('findingFromSastEngine', () => {
  const raw = {
    rule: 'SQL_INJECTION', title: 'SQL injection', severity: 'critical', confidence: 'high',
    file: '/repo/src/db.js', line: 12, description: 'concatenated query',
    cwe: 'CWE-89', owasp: 'A03', verified: true,
    // Sample vulnerable source: the literal `${id}` is the point, it is what a real
    // concatenated query looks like.
    // eslint-disable-next-line no-template-curly-in-string
    codeContext: [{ text: 'const q = `SELECT ${id}`;' }],
  };

  test('builds a finding and does not throw', () => {
    const f = findingFromSastEngine(raw, SCAN, '/repo');
    assert.equal(f.scanType, 'reasoning');
    assert.equal(f.rule, 'SQL_INJECTION');
    assert.equal(f.sourceScanId, 'scan-1');
    assert.ok(f.id && f.createdAt);
  });

  test('the file path is made relative to the scan target, with the line appended', () => {
    assert.equal(findingFromSastEngine(raw, SCAN, '/repo').file, 'src/db.js:12');
  });

  test('is born already triaged — the loop has no live triage stage to fall back on', () => {
    const t = latestTriage(findingFromSastEngine(raw, SCAN, '/repo'));
    assert.ok(t, 'a scan-sourced finding must carry a synthetic triage run');
    assert.equal(t.status, 'done');
    assert.equal(t.verdict.verdict, 'confirmed');       // verified === true
    assert.equal(t.verdict.source, 'sast-engine-verifier');
  });

  test('an unverified finding lands as needs_review, not as suspect', () => {
    // verified is null for anything below the VerifierAgent severity floor — "not checked",
    // which is a different thing from "checked and doubted".
    const t = latestTriage(findingFromSastEngine({ ...raw, verified: null }, SCAN, '/repo'));
    assert.equal(t.verdict.verdict, 'needs_review');
  });

  test('ASVS and NIST are empty — sast-engine has no mapping data (documented gap)', () => {
    const t = latestTriage(findingFromSastEngine(raw, SCAN, '/repo'));
    assert.equal(t.verdict.asvs, null);
    assert.deepEqual(t.verdict.nist_800_53, []);
    assert.equal(t.verdict.cwe, 'CWE-89');   // these two DO come from the pattern
    assert.equal(t.verdict.owasp, 'A03');
  });

  test('an adjudication verdict overrides the engine, and is marked as its own source', () => {
    const t = latestTriage(findingFromSastEngine(raw, SCAN, '/repo', {
      verdict: 'false_positive', reasoning: 'parameterized', severity: 'low', confidence: 'high',
    }));
    assert.equal(t.verdict.verdict, 'false_positive');
    assert.equal(t.verdict.source, 'reasoning-adjudication');
    assert.equal(t.verdict.reasoning, 'parameterized');
  });

  test('a finding adjudicated false_positive is still created, just closed', () => {
    // Never dropped: a wrong adjudication should cost visibility, not evidence.
    const f = findingFromSastEngine(raw, SCAN, '/repo', { verdict: 'false_positive' });
    assert.ok(f.id);
    assert.equal(f.status, 'closed');
  });

  test('a same-line finding carries no dataflow span', () => {
    assert.equal(findingFromSastEngine(raw, SCAN, '/repo').flow, null);
  });
});

describe('findingFromDepVuln', () => {
  const vuln = { name: 'lodash', range: '<4.17.21', title: 'Prototype pollution', severity: 'high', cve: 'CVE-2020-8203', fix: '4.17.21' };

  test('builds an SCA finding and does not throw', () => {
    const f = findingFromDepVuln(vuln, SCAN);
    assert.equal(f.scanType, 'sca');
    assert.equal(f.packageName, 'lodash');
    assert.equal(f.fixedVersion, '4.17.21');
    assert.equal(f.rule, 'CVE-2020-8203');
  });

  test('carries NO triage run — SCA findings never enter the remediation loop', () => {
    assert.deepEqual(findingFromDepVuln(vuln, SCAN).runs, []);
  });
});

describe('findingFromLLMScan', () => {
  const rf = {
    title: 'Missing authorization on refund', description: 'any user can refund any order',
    severity: 'high', file: 'src/routes/orders.js:44', rule: 'BROKEN_ACCESS_CONTROL',
    verdict: 'confirmed', confidence: 'high', severity_confirmed: 'critical', priority: 'p0',
    reasoning: 'no ownership check', owasp: 'A01', asvs: 'V4.1.3', cwe: 'CWE-639',
    nist_800_53: ['AC-3', 'AC-6'], endpoint: '/api/orders/:id/refund', method: 'post',
  };

  test('builds a finding and does not throw — the regression this file exists for', () => {
    const f = findingFromLLMScan(rf, SCAN);
    assert.equal(f.scanType, 'reasoning');
    assert.equal(f.file, 'src/routes/orders.js:44');
    assert.equal(f.endpoint, '/api/orders/:id/refund');
  });

  test('keeps the full framework mapping the reasoning pass assigned itself', () => {
    // Unlike the deterministic half, the pass that found the issue also maps it, so ASVS and
    // NIST are real here. This is the asymmetry documented in docs/agents.md.
    const t = latestTriage(findingFromLLMScan(rf, SCAN));
    assert.equal(t.verdict.asvs, 'V4.1.3');
    assert.deepEqual(t.verdict.nist_800_53, ['AC-3', 'AC-6']);
    assert.equal(t.verdict.source, 'reasoning-scan');
  });

  test('honours severity_confirmed and priority when the model supplies them', () => {
    const t = latestTriage(findingFromLLMScan(rf, SCAN));
    assert.equal(t.verdict.severity_confirmed, 'critical');
    assert.equal(t.verdict.priority, 'p0');
  });

  test('falls back safely when the model omits or invents taxonomy values', () => {
    const t = latestTriage(findingFromLLMScan({
      ...rf, verdict: 'nonsense', confidence: 'wildly-sure', severity_confirmed: 'catastrophic',
      priority: 'p9', nist_800_53: 'not-an-array',
    }, SCAN));
    assert.equal(t.verdict.verdict, 'needs_review');
    assert.equal(t.verdict.confidence, 'medium');
    assert.equal(t.verdict.severity_confirmed, 'high');   // falls back to the reported severity
    assert.ok(['p0', 'p1', 'p2', 'p3'].includes(t.verdict.priority));
    assert.deepEqual(t.verdict.nist_800_53, []);
  });

  test('a finding with no resolvable line still builds', () => {
    // Most business-logic findings have no file:line at all; they must not be dropped.
    const f = findingFromLLMScan({ ...rf, file: null }, SCAN);
    assert.equal(f.file, null);
    assert.ok(latestTriage(f));
  });
});
