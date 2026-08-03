'use strict';

/**
 * The two halves of the findings store that nothing else exercises: the dataflow span a finding
 * carries, and the CSV export.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * Both were invisible to the suite. readFlowSpan arrived with the Opengrep swap — it is what
 * turns `taintSourceLine` into the source -> sink listing the detail view renders — and it is
 * almost entirely boundary conditions: four guards, a size cap, and a file read that can fail
 * long after the scan that recorded the path. buildFindingsCsv had its whole body uncovered,
 * which for an export means a column silently landing in the wrong place is a change no test
 * would notice.
 *
 * The span assertions are deliberately about the EDGES rather than the happy path. Every guard
 * exists to stop a nonsensical span reaching the UI, and an off-by-one in the cap or in the
 * slice is exactly the kind of thing that renders as a plausible-looking wrong answer.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { readFlowSpan, buildFindingsCsv, csvEscape, findings } = require('../src/store/findings');
const { scans } = require('../src/store/scans');

/* ── dataflow spans ─────────────────────────────────────────────────────────────────────── */

let root;
let sourceFile;

before(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'findings-store-'));
  sourceFile = path.join(root, 'app.js');
  // 40 lines, each naming its own 1-based number, so a slice that is off by one is obvious
  // in the assertion rather than merely being the wrong length.
  fs.writeFileSync(sourceFile, Array.from({ length: 40 }, (_, i) => `line ${i + 1}`).join('\n'));
});

after(() => {
  fs.rmSync(root, { recursive: true, force: true });
  findings.clear();
  scans.clear();
});

describe('readFlowSpan', () => {
  const span = (over) => readFlowSpan({ file: sourceFile, taintSourceLine: 10, line: 14, ...over });

  test('reads the real lines from source to sink, numbered from the source line', () => {
    const s = span();
    assert.equal(s.sourceLine, 10);
    assert.equal(s.sinkLine, 14);
    // Inclusive of both ends: the source line and the sink line are both part of the flow.
    assert.deepEqual(s.lines, [
      { n: 10, text: 'line 10' },
      { n: 11, text: 'line 11' },
      { n: 12, text: 'line 12' },
      { n: 13, text: 'line 13' },
      { n: 14, text: 'line 14' },
    ]);
  });

  test('a finding with no taint source has no flow — the common non-taint rule', () => {
    assert.equal(span({ taintSourceLine: null }), null);
    assert.equal(span({ taintSourceLine: undefined }), null);
  });

  test('a finding with no sink line has no flow', () => {
    assert.equal(span({ line: null }), null);
  });

  test('a source at or after the sink is not a flow', () => {
    assert.equal(span({ taintSourceLine: 14 }), null, 'same line is not a span');
    assert.equal(span({ taintSourceLine: 20 }), null, 'source below the sink is incoherent');
  });

  test('line 0 is rejected rather than read as a falsy sentinel', () => {
    assert.equal(span({ taintSourceLine: 0 }), null);
    assert.equal(span({ line: 0 }), null);
  });

  /**
   * The cap is the difference between an explanation and a wall of code. Both sides of it are
   * asserted because a `>` silently becoming a `>=` costs the widest legitimate span there is,
   * and nothing else in the app would report the loss.
   */
  test('a span exactly at the 25-line cap is kept', () => {
    const s = span({ taintSourceLine: 5, line: 30 });
    assert.ok(s, 'a 25-line gap is the widest span still worth rendering');
    assert.equal(s.lines.length, 26);
  });

  test('a span one line past the cap falls back to no flow', () => {
    assert.equal(span({ taintSourceLine: 4, line: 30 }), null);
  });

  test('an unreadable file degrades to no flow instead of throwing', () => {
    // The path is a snapshot taken at scan time; the file may since have moved or been deleted,
    // and a finding must still render.
    assert.equal(span({ file: path.join(root, 'gone.js') }), null);
    assert.equal(span({ file: null }), null);
  });
});

/* ── CSV export ─────────────────────────────────────────────────────────────────────────── */

describe('csvEscape', () => {
  test('leaves values needing no quoting untouched', () => {
    assert.equal(csvEscape('plain'), 'plain');
    assert.equal(csvEscape(42), '42');
  });

  test('null and undefined become empty rather than the strings "null"/"undefined"', () => {
    assert.equal(csvEscape(null), '');
    assert.equal(csvEscape(undefined), '');
  });

  test('quotes anything carrying a comma, quote or newline, and doubles inner quotes', () => {
    assert.equal(csvEscape('a,b'), '"a,b"');
    assert.equal(csvEscape('say "hi"'), '"say ""hi"""');
    assert.equal(csvEscape('one\ntwo'), '"one\ntwo"');
  });
});

/**
 * A real CSV row parser, because a naive `split(',')` is wrong on this very output — the first
 * finding's title carries a quoted comma, which silently shifts every column after it by one.
 * Asserting through a correct parser is the only way a column-order regression is detectable.
 */
function parseCsvRow(row) {
  const cells = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < row.length; i++) {
    const c = row[i];
    if (quoted) {
      if (c === '"' && row[i + 1] === '"') { cell += '"'; i++; }
      else if (c === '"') quoted = false;
      else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { cells.push(cell); cell = ''; }
    else cell += c;
  }
  cells.push(cell);
  return cells;
}

describe('buildFindingsCsv', () => {
  const COLUMN_COUNT = 26;

  before(() => {
    findings.clear();
    scans.clear();
    scans.set('scan-1', { id: 'scan-1', path: '/repo' });

    findings.set('f-old', {
      id: 'f-old',
      title: 'Older finding, with a comma',
      scanType: 'reasoning',
      status: 'needs_review',
      severity: 'high',
      rule: 'SQL_INJECTION',
      file: 'src/db.js:12',
      sourceScanId: 'scan-1',
      createdAt: 1000,
      runs: [
        { agent: 'triage', verdict: { verdict: 'needs_review', confidence: 'low' } },
        {
          agent: 'remediation',
          verdict: {
            verdict: 'confirmed', severity_confirmed: 'critical', confidence: 'high',
            priority: 'p0', owasp: 'A03', cwe: 'CWE-89',
            nist_800_53: ['SI-10', 'SI-15'],
            root_cause: 'concatenated query', fix_guidance: 'parameterize', effort: 'low',
          },
        },
      ],
    });

    findings.set('f-new', {
      id: 'f-new',
      title: 'Newer finding',
      scanType: 'sca',
      status: 'new',
      severity: 'medium',
      packageName: 'lodash',
      packageVersion: '4.17.20',
      fixedVersion: '4.17.21',
      sourceScanId: null,
      createdAt: 2000,
      runs: [],
    });
  });

  const rows = () => buildFindingsCsv().split('\r\n');
  const cellsOf = (i) => parseCsvRow(rows()[i]);
  /** Read a cell by header name, so a column insertion cannot quietly invalidate an assertion. */
  const col = (rowIndex, name) => cellsOf(rowIndex)[cellsOf(0).indexOf(name)];

  test('rows are CRLF-separated, with a header and one row per finding', () => {
    assert.equal(rows().length, 3);
    assert.equal(cellsOf(0).length, COLUMN_COUNT);
  });

  test('findings are ordered oldest first, not by insertion or id', () => {
    assert.equal(col(1, 'id'), 'f-old');
    assert.equal(col(2, 'id'), 'f-new');
  });

  test('every row has exactly the header column count, quoted commas included', () => {
    for (const [i, row] of rows().entries()) {
      assert.equal(parseCsvRow(row).length, COLUMN_COUNT, `row ${i} has the wrong shape: ${row}`);
    }
  });

  test('a comma inside a title is quoted, and survives a round trip intact', () => {
    assert.ok(rows()[1].includes('"Older finding, with a comma"'), 'must be quoted on the wire');
    assert.equal(col(1, 'title'), 'Older finding, with a comma');
  });

  test('verdict columns come from the LATEST run, not the first', () => {
    // Triage said needs_review/low; remediation ran after and said confirmed/high.
    assert.equal(col(1, 'verdict'), 'confirmed');
    assert.equal(col(1, 'severity_confirmed'), 'critical');
    assert.equal(col(1, 'confidence'), 'high');
    assert.equal(col(1, 'latest_agent'), 'remediation');
    assert.equal(col(1, 'run_count'), '2');
  });

  test('a multi-value NIST mapping is joined into one cell rather than splitting the row', () => {
    assert.equal(col(1, 'nist_800_53'), 'SI-10; SI-15');
  });

  test('the source scan path is resolved, and a dangling scan id leaves it empty', () => {
    assert.equal(col(1, 'source_scan_path'), '/repo');
    // Deleting a scan leaves its findings behind with a now-dangling sourceScanId; the export
    // must still produce a row for them rather than throwing.
    assert.equal(col(2, 'source_scan_path'), '');
  });

  test('a finding with no runs still exports, with empty verdict columns', () => {
    assert.equal(col(2, 'verdict'), '');
    assert.equal(col(2, 'run_count'), '0');
    assert.equal(col(2, 'latest_agent'), '');
    assert.equal(col(2, 'package_name'), 'lodash', 'its own fields still land');
  });

  test('createdAt is exported as an ISO timestamp', () => {
    assert.equal(col(1, 'created_at'), new Date(1000).toISOString());
  });
});
